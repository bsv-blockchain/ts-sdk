import type {
  Invoice,
  RemittanceOptionId,
  Termination
} from '../types.js'
import type { ModuleContext } from '../types.js'
import type { RemittanceModule } from '../RemittanceModule.js'
import type { CommsLayer } from '../CommsLayer.js'
import type {
  WalletInterface,
  WalletCounterparty,
  PubKeyHex,
  OriginatorDomainNameStringUnder250Bytes,
  WalletProtocol
} from '../../wallet/Wallet.interfaces.js'
import { createNonce } from '../../auth/utils/createNonce.js'
import P2PKH from '../../script/templates/P2PKH.js'
import PublicKey from '../../primitives/PublicKey.js'

/**
 * BRC-29-like payment option terms.
 *
 * This module intentionally keeps option terms minimal:
 * - Amount is taken from the invoice total (and validated as satoshis)
 * - The payer derives the payee's per-payment public key using wallet.getPublicKey with a stable protocolID
 */
export interface Brc29OptionTerms {
  /** Payment amount in satoshis. */
  amountSatoshis: number
  /** Which output index to internalize, default 0. */
  outputIndex?: number
  /** Optionally override the protocolID used in getPublicKey. */
  protocolID?: WalletProtocol
  /** Optional labels for createAction. */
  labels?: string[]
  /** Optional description for createAction. */
  description?: string
}

/**
 * Settlement artifact carried in the settlement message.
 */
export interface Brc29SettlementArtifact {
  customInstructions: {
    derivationPrefix: string
    derivationSuffix: string
  }
  transaction: unknown
  amountSatoshis: number
  outputIndex?: number
}

/**
 * Receipt data for BRC-29 settlements.
 */
export interface Brc29ReceiptData {
  /** Result returned from wallet.internalizeAction, if accepted. */
  internalizeResult?: unknown
  /** Human-readable rejection reason, if rejected. */
  rejectedReason?: string
  /** If rejected with refund, contains the refund payment token. */
  refund?: {
    token: Brc29SettlementArtifact
    feeSatoshis: number
  }
}

export interface NonceProvider {
  createNonce: (wallet: WalletInterface, scope: WalletCounterparty, originator?: unknown) => Promise<string>
}

export interface LockingScriptProvider {
  /** Converts a public key string to a P2PKH locking script hex. */
  pubKeyToP2PKHLockingScript: (publicKey: string) => Promise<string> | string
}

/**
 * Default nonce provider using SDK createNonce.
 */
export const DefaultNonceProvider: NonceProvider = {
  async createNonce (wallet, scope, originator) {
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined
    return await createNonce(wallet, scope, origin)
  }
}

/**
 * Default locking script provider using SDK P2PKH template.
 */
export const DefaultLockingScriptProvider: LockingScriptProvider = {
  async pubKeyToP2PKHLockingScript (publicKey: string) {
    const address = PublicKey.fromString(publicKey).toAddress()
    return new P2PKH().lock(address).toHex()
  }
}

export interface Brc29RemittanceModuleConfig {
  /** Default protocolID to use with wallet.getPublicKey. */
  protocolID?: WalletProtocol
  /** Labels applied to created actions. */
  labels?: string[]
  /** Description applied to created actions. */
  description?: string
  /** Output description for created actions. */
  outputDescription?: string

  /**
   * Fee charged on refunds, in satoshis.
   */
  refundFeeSatoshis?: number

  /**
   * Minimum refund to issue. If refund would be smaller, module will reject without refund.
   */
  minRefundSatoshis?: number

  /** How wallet internalizes the payment. */
  internalizeProtocol?: 'wallet payment' | 'basket insertion'

  nonceProvider?: NonceProvider
  lockingScriptProvider?: LockingScriptProvider
}

export interface BasicBrc29FactoryConfig extends Brc29RemittanceModuleConfig {
  /**
   * Comms layer for the module factory. (Not used by BasicBRC29, probably should be removed.)
   */
  comms: CommsLayer
}

/**
 * BRC-29-based remittance module.
 *
 * This is the PeerPay v1 flow rewritten as a RemittanceModule:
 * - payer creates a payment action to a derived P2PKH output
 * - payer sends { tx, derivationPrefix, derivationSuffix } as settlement artifact
 * - payee internalizes the tx output using wallet.internalizeAction
 * - optional rejection can include a refund token embedded in the termination details
 */
export class Brc29RemittanceModule
implements RemittanceModule<Brc29OptionTerms, Brc29SettlementArtifact, Brc29ReceiptData> {
  readonly id: RemittanceOptionId = 'brc29.p2pkh'
  readonly name = 'BSV (BRC-29 derived P2PKH)'
  readonly allowUnsolicitedSettlements = false

  private readonly protocolID: WalletProtocol
  private readonly labels: string[]
  private readonly description: string
  private readonly outputDescription: string
  private readonly refundFeeSatoshis: number
  private readonly minRefundSatoshis: number
  private readonly internalizeProtocol: 'wallet payment' | 'basket insertion'
  private readonly nonceProvider: NonceProvider
  private readonly lockingScriptProvider: LockingScriptProvider

  constructor (cfg: Brc29RemittanceModuleConfig = {}) {
    // PeerPay v1’s protocolID default:
    this.protocolID = cfg.protocolID ?? [2, '3241645161d8']
    this.labels = cfg.labels ?? ['peerpay']
    this.description = cfg.description ?? 'PeerPay v2 payment'
    this.outputDescription = cfg.outputDescription ?? 'Payment for remittance invoice'
    this.refundFeeSatoshis = cfg.refundFeeSatoshis ?? 1000
    this.minRefundSatoshis = cfg.minRefundSatoshis ?? 1000
    this.internalizeProtocol = cfg.internalizeProtocol ?? 'wallet payment'
    this.nonceProvider = cfg.nonceProvider ?? DefaultNonceProvider
    this.lockingScriptProvider = cfg.lockingScriptProvider ?? DefaultLockingScriptProvider
  }

  async createOption (args: { threadId: string; invoice: Invoice }, _ctx: ModuleContext): Promise<Brc29OptionTerms> {
    const amountSatoshis = parseSatoshisFromInvoiceTotal(args.invoice)
    return {
      amountSatoshis,
      outputIndex: 0,
      protocolID: this.protocolID,
      labels: this.labels,
      description: this.description
    }
  }

  async buildSettlement (
    args: { threadId: string; invoice?: Invoice; option: Brc29OptionTerms; note?: string },
    ctx: ModuleContext
  ): Promise<{ action: 'settle'; artifact: Brc29SettlementArtifact } | { action: 'terminate'; termination: Termination }> {
    const { wallet, originator } = ctx
    const invoice = args.invoice
    if (invoice == null) {
      return terminate('brc29.invoice_required', 'BRC-29 settlement requires an invoice.')
    }

    const amountSatoshis = args.option.amountSatoshis
    if (!Number.isFinite(amountSatoshis) || amountSatoshis <= 0) {
      return terminate('brc29.invalid_amount', 'BRC-29 settlement requires a positive satoshi amount.')
    }

    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined

    try {
      // Create per-payment derivation values.
      const derivationPrefix = await this.nonceProvider.createNonce(wallet, 'self', origin)
      const derivationSuffix = await this.nonceProvider.createNonce(wallet, 'self', origin)

      // Derive payee public key.
      const protocolID = args.option.protocolID ?? this.protocolID
      const keyID = `${derivationPrefix} ${derivationSuffix}`

      const { publicKey } = await wallet.getPublicKey(
        {
          protocolID,
          keyID,
          counterparty: invoice.payee
        },
        origin
      )

      if (typeof publicKey !== 'string' || publicKey.trim() === '') {
        return terminate('brc29.public_key_missing', 'Failed to derive payee public key for BRC-29 settlement.')
      }

      const lockingScript = await this.lockingScriptProvider.pubKeyToP2PKHLockingScript(publicKey)
      if (typeof lockingScript !== 'string' || lockingScript.trim() === '') {
        return terminate('brc29.locking_script_missing', 'Failed to produce P2PKH locking script.')
      }

      const action = await wallet.createAction(
        {
          description: args.option.description ?? this.description,
          labels: args.option.labels ?? this.labels,
          outputs: [
            {
              satoshis: amountSatoshis,
              lockingScript,
              customInstructions: JSON.stringify({
                derivationPrefix,
                derivationSuffix,
                payee: invoice.payee,
                threadId: args.threadId,
                note: args.note
              }),
              outputDescription: this.outputDescription
            }
          ],
          options: {
            randomizeOutputs: false
          }
        },
        origin
      )

      const tx = action.tx ?? action.signableTransaction?.tx
      if (tx == null) {
        return terminate('brc29.missing_tx', 'wallet.createAction did not return a transaction.')
      }

      return {
        action: 'settle',
        artifact: {
          customInstructions: { derivationPrefix, derivationSuffix },
          transaction: tx,
          amountSatoshis,
          outputIndex: args.option.outputIndex ?? 0
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return terminate('brc29.build_failed', `BRC-29 settlement failed: ${message}`)
    }
  }

  async acceptSettlement (
    args: { threadId: string; invoice?: Invoice; settlement: Brc29SettlementArtifact; sender: PubKeyHex },
    ctx: ModuleContext
  ): Promise<{ action: 'accept'; receiptData?: Brc29ReceiptData } | { action: 'terminate'; termination: Termination }> {
    const { wallet, originator } = ctx
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined

    try {
      const outputIndex = args.settlement.outputIndex ?? 0
      const internalizeResult = await wallet.internalizeAction(
        {
          tx: args.settlement.transaction as unknown as number[],
          outputs: [
            {
              paymentRemittance: {
                derivationPrefix: args.settlement.customInstructions.derivationPrefix,
                derivationSuffix: args.settlement.customInstructions.derivationSuffix,
                senderIdentityKey: args.sender
              },
              outputIndex,
              protocol: this.internalizeProtocol
            }
          ],
          labels: this.labels,
          description: 'PeerPay v2 payment received'
        },
        origin
      )

      return { action: 'accept', receiptData: { internalizeResult } }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return terminate('brc29.internalize_failed', `Failed to internalize BRC-29 settlement: ${message}`)
    }
  }

  async processReceipt (
    args: { threadId: string; invoice?: Invoice; receiptData: Brc29ReceiptData; sender: PubKeyHex },
    ctx: ModuleContext
  ): Promise<void> {
    const refundToken = args.receiptData.refund?.token
    if (refundToken == null) return

    const { wallet, originator } = ctx
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined
    await wallet.internalizeAction(
      {
        tx: refundToken.transaction as unknown as number[],
        outputs: [
          {
            paymentRemittance: {
              derivationPrefix: refundToken.customInstructions.derivationPrefix,
              derivationSuffix: refundToken.customInstructions.derivationSuffix,
              senderIdentityKey: args.sender
            },
            outputIndex: refundToken.outputIndex ?? 0,
            protocol: this.internalizeProtocol
          }
        ],
        labels: this.labels,
        description: 'PeerPay v2 refund received'
      },
      origin
    )
  }

  async rejectSettlement (
    args: {
      threadId: string
      invoice?: Invoice
      settlement: Brc29SettlementArtifact
      sender: PubKeyHex
      reason?: string
    },
    ctx: ModuleContext
  ): Promise<Brc29ReceiptData> {
    const reason = args.reason ?? 'Payment rejected'

    const amount = args.settlement.amountSatoshis
    const fee = this.refundFeeSatoshis
    const refund = amount - fee

    if (refund < this.minRefundSatoshis) {
      // Reject without refund, mirroring PeerPay v1's “too small after fee” behavior.
      return { rejectedReason: `${reason} (amount too small to refund after fee)` }
    }

    const acceptance = await this.acceptSettlement(
      {
        threadId: args.threadId,
        invoice: args.invoice,
        settlement: args.settlement,
        sender: args.sender
      },
      ctx
    )
    if (acceptance.action === 'terminate') {
      return { rejectedReason: `${reason} (failed to internalize payment)` }
    }

    const refundToken = await this.createPaymentToken(
      {
        recipient: args.sender,
        amountSatoshis: refund
      },
      ctx
    )

    return {
      rejectedReason: reason,
      refund: {
        token: refundToken,
        feeSatoshis: fee
      }
    }
  }

  /**
   * Creates a BRC-29 payment token for a recipient.
   *
   * We reuse buildSettlement by constructing a “fake invoice” whose payee is the recipient.
   * This keeps the BRC-29 logic centralized and ensures refunds use the same derivation pattern.
   */
  private async createPaymentToken (
    args: { recipient: PubKeyHex; amountSatoshis: number },
    ctx: ModuleContext
  ): Promise<Brc29SettlementArtifact> {
    const fakeInvoice: Invoice = {
      kind: 'invoice',
      threadId: 'refund',
      payee: args.recipient,
      payer: 'refund-sender',
      createdAt: ctx.now(),
      lineItems: [],
      total: { value: String(args.amountSatoshis), unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
      invoiceNumber: 'refund',
      options: {}
    }

    const option: Brc29OptionTerms = {
      amountSatoshis: args.amountSatoshis,
      outputIndex: 0,
      protocolID: this.protocolID,
      labels: this.labels,
      description: 'Refund'
    }

    const result = await this.buildSettlement({ threadId: 'refund', invoice: fakeInvoice, option }, ctx)
    if (result.action === 'terminate') {
      throw new Error(result.termination.message)
    }
    return result.artifact
  }
}

/**
 * Creates a Basic BRC-29 remittance module instance.
 */
export function createBasicBrc29Module (cfg: BasicBrc29FactoryConfig): Brc29RemittanceModule {
  const { comms: _comms, ...rest } = cfg
  void _comms
  return new Brc29RemittanceModule(rest)
}

function terminate (code: string, message: string, details?: unknown): { action: 'terminate'; termination: Termination } {
  return { action: 'terminate', termination: { code, message, details } }
}

function parseSatoshisFromInvoiceTotal (invoice: Invoice): number {
  const { total } = invoice
  if (total.unit.namespace !== 'bsv' || total.unit.code !== 'sat') {
    throw new Error(
      `BRC-29 module requires invoice.total to be denominated in bsv:sat (got ${total.unit.namespace}:${total.unit.code})`
    )
  }
  const n = Number(total.value)
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new Error('BRC-29 module requires invoice.total.value to be an integer satoshi string')
  }
  return n
}
