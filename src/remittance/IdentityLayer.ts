import type {
  IdentityVerificationRequest,
  IdentityVerificationResponse,
  IdentityVerificationAcknowledgment,
  ThreadId,
  ModuleContext,
  Termination
} from './types.js'
import { PubKeyHex } from '../wallet/Wallet.interfaces.js'

/**
 * The Identity Layer handles identity certificate exchange and verification.
 * It is optional and pluggable.
 * Modules can use it to request/verify identity before accepting settlements.
 *
 * The runtime configuration can be used to determine whether and at what point identity
 * exchange occurs: before invoicing, before settlement, etc.
 *
 * Makers and takers can both implement this layer as needed, and request/respond to
 * identity verification at different points in the protocol.
 */
export interface IdentityLayer {
  /** Determine which certificates to request from a counterparty. */
  determineCertificatesToRequest: (args: { counterparty: PubKeyHex; threadId: ThreadId }, ctx: ModuleContext) => Promise<IdentityVerificationRequest>
  /** Respond to an incoming identity verification request. */
  respondToRequest: (
    args: { counterparty: PubKeyHex; threadId: ThreadId; request: IdentityVerificationRequest },
    ctx: ModuleContext
  ) => Promise<{ action: 'respond'; response: IdentityVerificationResponse } | { action: 'terminate'; termination: Termination }>
  /** Assess whether received certificates satisfy the requirements for transaction settlement. */
  assessReceivedCertificateSufficiency: (counterparty: PubKeyHex, received: IdentityVerificationResponse, threadId: ThreadId) => Promise<IdentityVerificationAcknowledgment | Termination>
}
