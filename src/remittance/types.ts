import { Base64String, WalletInterface } from '@bsv/sdk'
import { HexString, OutpointString } from 'mod.js'

/**
 * Types for core Remittance protocol.
 *
 * The goal is to keep the core protocol:
 * - UTXO-friendly (transactions and partial transactions can be carried as artifacts)
 * - Denomination-agnostic (amounts are typed, not forced to satoshis)
 * - Module-oriented (remittance option payloads are opaque to the core)
 */

export type IdentityKey = string
export type ThreadId = string
export type RemittanceOptionId = string
export type UnixMillis = number

export interface Unit {
  /** Namespace for disambiguation, e.g. 'bsv', 'iso4217', 'token'. */
  namespace: string
  /** Unit code within the namespace, e.g. 'sat', 'USD', 'mnee'. */
  code: string
  /** Optional decimal places for display/normalization. */
  decimals?: number
}

export interface Amount {
  /** Decimal string. Avoid floats at the protocol layer. */
  value: string
  unit: Unit
}

export const SAT_UNIT: Unit = { namespace: 'bsv', code: 'sat', decimals: 0 }

export interface LineItem {
  id?: string
  description: string
  /** Decimal string, e.g. '1', '2', '0.5'. */
  quantity?: string
  unitPrice?: Amount
  /** Total amount for the line (optional if derivable). */
  amount?: Amount
  metadata?: Record<string, unknown>
}

/**
 * Shared commercial/metadata fields for invoice and receipt-like instruments.
 *
 * NOTE: "payee" and "payer" are identity keys, not addresses.
 * Payment addresses / scripts are settlement-module concerns.
 */
export interface InstrumentBase {
  threadId: ThreadId
  payee: IdentityKey
  payer: IdentityKey
  note?: string
  lineItems: LineItem[]
  total: Amount
  invoiceNumber?: string
  createdAt: UnixMillis
  arbitrary?: Record<string, unknown>
}

/**
 * Invoice (solicitation) that contains N remittance options.
 *
 * Each remittance option is keyed by a module id.
 * The payload for each option is module-defined and opaque to the core.
 *
 * This is where “UTXO offers” live: a module option payload can include a partial tx template,
 * UTXO references, scripts, overlay anchors, SPV, etc. The manager does not interpret them.
 */
export interface Invoice extends InstrumentBase {
  kind: 'invoice'
  expiresAt?: UnixMillis
  options: Record<RemittanceOptionId, unknown>
}

/** 
 * An identity certificate request.
 *
 * Contains a list of requested certificate types, fields from each, plus acceptable certifiers.
 */
export interface IdentityVerificationRequest {
  kind: 'identityVerificationRequest'
  threadId: ThreadId
  /** Details of the requested certificates. */
  request: {
    /** Map of certificate types to requested fields from each. */
    types: Record<string, string[]>
    /** List of acceptable certifier identity keys. */
    certifiers: IdentityKey[]
  }
}

/**
 * An identity certificate response.
 * 
 * Contains certificates issued by the certifiers named in the corresponding request, with fields revealed to the counterparty.
 */
export interface IdentityVerificationResponse {
  kind: 'identityVerificationResponse'
  threadId: ThreadId
  /** List of certificates issued by the certifiers named in the corresponding request, with fields revealed to the counterparty. */
  certificates: Array<{
    /** Certificate type, e.g. base64 Type ID corresponding to 'personalId', 'businessId', etc. */
    type: Base64String
    /** Certifier identity key. */
    certifier: IdentityKey
    /** Subject identity key. */
    subject: IdentityKey
    /** The certificate's encrypted fields that have been signed. */
    fields: Record<string, Base64String>
    /** Signature over the cert. */
    signature: HexString
    /** Certificate serial number. */
    serialNumber: Base64String
    /** Revocation outpoint. If spent on-chain, the certificate is invalid. */
    revocationOutpoint: OutpointString
    /** Field revelation keys for the counterparty. */
    keyringForVerifier: Record<string, Base64String>
  }>
}

/**
 * An identity verification acknowledgment.
 *
 * A simple ack message indicating that a requested identity verification has been completed successfully.
 */
export interface IdentityVerificationAcknowledgment {
  kind: 'identityVerificationAcknowledgment'
  threadId: ThreadId
}

/**
 * A settlement attempt.
 *
 * This is module-agnostic: "artifact" can be a transaction, a partial transaction,
 * a stablecoin transfer result, even a fiat card-payment approval code, etc.
 */
export interface Settlement {
  kind: 'settlement'
  threadId: ThreadId
  moduleId: RemittanceOptionId
  optionId: RemittanceOptionId
  sender: IdentityKey
  createdAt: UnixMillis
  artifact: unknown
  note?: string
}

/**
 * Receipt issued by the payee (or service provider).
 *
 * The manager treats "accepted" as a top-level boolean; module-specific details go in receiptData.
 *
 * A receipt could be a PDF, a photo/oroof-of-delivery, a copy of the payment transaction, etc.
 */
export interface Receipt {
  kind: 'receipt'
  threadId: ThreadId
  moduleId: RemittanceOptionId
  optionId: RemittanceOptionId
  payee: IdentityKey
  payer: IdentityKey
  createdAt: UnixMillis
  accepted: boolean
  receiptData: unknown
}

/**
 * Termination details for failed operations.
 */
export interface Termination {
  /** Reason code (module-specific). */
  code: string
  /** Human-readable message. */
  message: string
  /** Optional module-specific details. */
  details?: unknown
}

/**
 * Transport message format expected from the CommsLayer.
 *
 * It closely matches the message-box-client shapes:
 * messageId, sender, body, etc.
 */
export interface PeerMessage {
  messageId: string
  sender: IdentityKey
  recipient: IdentityKey
  messageBox: string
  body: string
}

/**
 * Protocol envelope kinds.
 * Everything runs in “threads” and carries a threadId.
 */
export type RemittanceKind =
  | 'invoice'
  | 'identityVerificationRequest'
  | 'identityVerificationResponse'
  | 'identityVerificationAcknowledgment'
  | 'settlement'
  | 'receipt'
  | 'termination'

/**
 * Protocol envelope.
 *
 * This is what RemittanceManager serializes into the CommsLayer message body.
 */
export interface RemittanceEnvelope<K extends RemittanceKind = RemittanceKind, P = unknown> {
  /** Protocol version. */
  v: 1
  /** Envelope id (idempotency key). Not the transport messageId. */
  id: string
  kind: K
  threadId: ThreadId
  createdAt: UnixMillis
  payload: P
}

/**
 * Simple logger interface.
 */
export interface LoggerLike {
  log: (...args: any[]) => void
  warn: (...args: any[]) => void
  error: (...args: any[]) => void
}

/**
 * Context object passed to module methods.
 */
export interface ModuleContext {
  wallet: WalletInterface
  /** Optional originator domain forwarded to wallet methods. */
  originator?: unknown
  now: () => number
  logger?: LoggerLike
}
