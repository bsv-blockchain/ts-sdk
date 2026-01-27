import type {
  Invoice,
  RemittanceOptionId,
  Termination
} from '../types.js'
import type { ModuleContext } from '../types.js'
import type { RemittanceModule } from '../RemittanceModule.js'
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
  /** The recipient of the payment */
  payee: PubKeyHex
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
  transaction: number[]
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
  async createNonce(wallet, scope, originator) {
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined
    return await createNonce(wallet, scope, origin)
  }
}

/**
 * Default locking script provider using SDK P2PKH template.
 */
export const DefaultLockingScriptProvider: LockingScriptProvider = {
  async pubKeyToP2PKHLockingScript(publicKey: string) {
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

/**
 * BRC-29-based remittance module.
 * - payer creates a payment action to a derived P2PKH output
 * - payer sends { tx, derivationPrefix, derivationSuffix } as settlement artifact
 * - payee internalizes the tx output using wallet.internalizeAction
 * - optional rejection can include a refund token embedded in the termination details
 */
export class Brc29RemittanceModule
  implements RemittanceModule<Brc29OptionTerms, Brc29SettlementArtifact, Brc29ReceiptData> {
  readonly id: RemittanceOptionId = 'brc29.p2pkh'
  readonly name = 'BSV (BRC-29 derived P2PKH)'
  readonly allowUnsolicitedSettlements = true

  private readonly protocolID: WalletProtocol
  private readonly labels: string[]
  private readonly description: string
  private readonly outputDescription: string
  private readonly refundFeeSatoshis: number
  private readonly minRefundSatoshis: number
  private readonly internalizeProtocol: 'wallet payment' | 'basket insertion'
  private readonly nonceProvider: NonceProvider
  private readonly lockingScriptProvider: LockingScriptProvider

  constructor(cfg: Brc29RemittanceModuleConfig = {}) {
    // BRC-29 Protocol.
    this.protocolID = cfg.protocolID ?? [2, '3241645161d8']
    this.labels = cfg.labels ?? ['brc29']
    this.description = cfg.description ?? 'BRC-29 payment'
    this.outputDescription = cfg.outputDescription ?? 'Payment for remittance invoice'
    this.refundFeeSatoshis = cfg.refundFeeSatoshis ?? 1000
    this.minRefundSatoshis = cfg.minRefundSatoshis ?? 1000
    this.internalizeProtocol = cfg.internalizeProtocol ?? 'wallet payment'
    this.nonceProvider = cfg.nonceProvider ?? DefaultNonceProvider
    this.lockingScriptProvider = cfg.lockingScriptProvider ?? DefaultLockingScriptProvider
  }

  async buildSettlement(
    args: { threadId: string; option: Brc29OptionTerms; note?: string },
    ctx: ModuleContext
  ): Promise<{ action: 'settle'; artifact: Brc29SettlementArtifact } | { action: 'terminate'; termination: Termination }> {
    const { wallet, originator } = ctx

    let option: Brc29OptionTerms
    try {
      option = ensureValidOption(args.option)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return terminate('brc29.invalid_option', message)
    }

    const amountSatoshis = option.amountSatoshis
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined

    try {
      // Create per-payment derivation values.
      const derivationPrefix = await this.nonceProvider.createNonce(wallet, 'self', origin)
      const derivationSuffix = await this.nonceProvider.createNonce(wallet, 'self', origin)

      // Derive payee public key.
      const protocolID = option.protocolID ?? this.protocolID
      const keyID = `${derivationPrefix} ${derivationSuffix}`

      const { publicKey } = await wallet.getPublicKey(
        {
          protocolID,
          keyID,
          counterparty: option.payee
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
          description: option.description ?? this.description,
          labels: option.labels ?? this.labels,
          outputs: [
            {
              satoshis: amountSatoshis,
              lockingScript,
              customInstructions: JSON.stringify({
                derivationPrefix,
                derivationSuffix,
                payee: option.payee,
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
      if (!isAtomicBeef(tx)) {
        return terminate('brc29.invalid_tx', 'wallet.createAction returned an invalid transaction payload.')
      }

      return {
        action: 'settle',
        artifact: {
          customInstructions: { derivationPrefix, derivationSuffix },
          transaction: tx,
          amountSatoshis: option.amountSatoshis,
          outputIndex: option.outputIndex ?? 0
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return terminate('brc29.build_failed', `BRC-29 settlement failed: ${message}`)
    }
  }

  async acceptSettlement(
    args: { threadId: string; settlement: Brc29SettlementArtifact; sender: PubKeyHex },
    ctx: ModuleContext
  ): Promise<{ action: 'accept'; receiptData?: Brc29ReceiptData } | { action: 'terminate'; termination: Termination }> {
    const { wallet, originator } = ctx
    const origin = originator as OriginatorDomainNameStringUnder250Bytes | undefined
    console.log('acceptSettlement', args)
    try {
      const settlement = ensureValidSettlement(args.settlement)
      const outputIndex = settlement.outputIndex ?? 0
      debugger
      const internalizeResult = await wallet.internalizeAction(
        {
          tx: settlement.transaction,
          outputs: [
            {
              paymentRemittance: {
                derivationPrefix: settlement.customInstructions.derivationPrefix,
                derivationSuffix: settlement.customInstructions.derivationSuffix,
                senderIdentityKey: args.sender
              },
              outputIndex,
              protocol: this.internalizeProtocol
            }
          ],
          labels: this.labels,
          description: 'BRC-29 payment received'
        },
        origin
      )

      return { action: 'accept', receiptData: { internalizeResult } }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return terminate('brc29.internalize_failed', `Failed to internalize BRC-29 settlement: ${message}`)
    }
  }
}

function terminate(code: string, message: string, details?: unknown): { action: 'terminate'; termination: Termination } {
  return { action: 'terminate', termination: { code, message, details } }
}

function ensureValidOption(option: Brc29OptionTerms): Brc29OptionTerms {
  if (option == null || typeof option !== 'object') {
    throw new Error('BRC-29 option terms are required')
  }
  const amountSatoshis = (option as Brc29OptionTerms).amountSatoshis
  if (!Number.isInteger(amountSatoshis) || amountSatoshis <= 0) {
    throw new Error('BRC-29 option amount must be a positive integer')
  }
  const outputIndex = (option as Brc29OptionTerms).outputIndex
  if (outputIndex != null && (!Number.isInteger(outputIndex) || outputIndex < 0)) {
    throw new Error('BRC-29 option outputIndex must be a non-negative integer')
  }
  const protocolID = (option as Brc29OptionTerms).protocolID
  if (protocolID != null) {
    if (!Array.isArray(protocolID) || protocolID.length !== 2) {
      throw new Error('BRC-29 option protocolID must be a tuple [number, string]')
    }
    const [protocolNumber, protocolString] = protocolID
    if (!Number.isInteger(protocolNumber) || protocolNumber < 0 || !isNonEmptyString(protocolString)) {
      throw new Error('BRC-29 option protocolID must be a tuple [number, string]')
    }
  }
  const labels = (option as Brc29OptionTerms).labels
  if (labels != null && (!Array.isArray(labels) || labels.some((label) => !isNonEmptyString(label)))) {
    throw new Error('BRC-29 option labels must be a list of non-empty strings')
  }
  const description = (option as Brc29OptionTerms).description
  if (description != null && !isNonEmptyString(description)) {
    throw new Error('BRC-29 option description must be a non-empty string')
  }
  return option
}

function ensureValidSettlement(settlement: Brc29SettlementArtifact): Brc29SettlementArtifact {
  if (settlement == null || typeof settlement !== 'object') {
    throw new Error('BRC-29 settlement artifact is required')
  }
  const instructions = settlement.customInstructions
  if (instructions == null || typeof instructions !== 'object') {
    throw new Error('BRC-29 settlement requires customInstructions')
  }
  if (!isNonEmptyString(instructions.derivationPrefix) || !isNonEmptyString(instructions.derivationSuffix)) {
    throw new Error('BRC-29 settlement derivation values are required')
  }
  const amountSatoshis = settlement.amountSatoshis
  if (!Number.isInteger(amountSatoshis) || amountSatoshis <= 0) {
    throw new Error('BRC-29 settlement amount must be a positive integer')
  }
  const outputIndex = settlement.outputIndex
  if (outputIndex != null && (!Number.isInteger(outputIndex) || outputIndex < 0)) {
    throw new Error('BRC-29 settlement outputIndex must be a non-negative integer')
  }
  if (!isAtomicBeef(settlement.transaction)) {
    throw new Error('BRC-29 settlement transaction must be a non-empty byte array')
  }
  return settlement
}

function isAtomicBeef(tx: unknown): tx is number[] {
  if (!Array.isArray(tx) || tx.length === 0) return false
  return tx.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}
