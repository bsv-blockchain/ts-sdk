import TransactionSignature from '../../primitives/TransactionSignature.js'
import Transaction from '../../transaction/Transaction.js'
import Script from '../Script.js'
import { verifyNotNull } from '../../primitives/utils.js'

/**
 * Computes the signature scope flags from the given signing parameters.
 */
export function computeSignatureScope(
  signOutputs: 'all' | 'none' | 'single',
  anyoneCanPay: boolean
): number {
  let signatureScope = TransactionSignature.SIGHASH_FORKID
  if (signOutputs === 'all') {
    signatureScope |= TransactionSignature.SIGHASH_ALL
  }
  if (signOutputs === 'none') {
    signatureScope |= TransactionSignature.SIGHASH_NONE
  }
  if (signOutputs === 'single') {
    signatureScope |= TransactionSignature.SIGHASH_SINGLE
  }
  if (anyoneCanPay) {
    signatureScope |= TransactionSignature.SIGHASH_ANYONECANPAY
  }
  return signatureScope
}

/**
 * Resolves and validates the source transaction details needed for signing.
 * Returns the resolved sourceTXID, sourceSatoshis, lockingScript, and otherInputs.
 */
export function resolveSourceDetails(
  tx: Transaction,
  inputIndex: number,
  providedSourceSatoshis?: number,
  providedLockingScript?: Script
): {
  sourceTXID: string
  sourceSatoshis: number
  lockingScript: Script
  otherInputs: typeof tx.inputs
} {
  const input = tx.inputs[inputIndex]

  const otherInputs = tx.inputs.filter(
    (_, index) => index !== inputIndex
  )

  const sourceTXID = input.sourceTXID ?? input.sourceTransaction?.id('hex')
  if (sourceTXID == null || sourceTXID === undefined) {
    throw new Error(
      'The input sourceTXID or sourceTransaction is required for transaction signing.'
    )
  }
  if (sourceTXID === '') {
    throw new Error(
      'The input sourceTXID or sourceTransaction is required for transaction signing.'
    )
  }
  const sourceSatoshis = providedSourceSatoshis ??
    input.sourceTransaction?.outputs[input.sourceOutputIndex].satoshis
  if (sourceSatoshis == null || sourceSatoshis === undefined) {
    throw new Error(
      'The sourceSatoshis or input sourceTransaction is required for transaction signing.'
    )
  }
  const lockingScript = providedLockingScript ??
    input.sourceTransaction?.outputs[input.sourceOutputIndex]
      .lockingScript
  if (lockingScript == null) {
    throw new Error(
      'The lockingScript or input sourceTransaction is required for transaction signing.'
    )
  }

  return { sourceTXID, sourceSatoshis, lockingScript, otherInputs }
}

/** Parameters for formatting the transaction preimage */
export interface FormatPreimageParams {
  tx: Transaction
  inputIndex: number
  signatureScope: number
  sourceTXID: string
  sourceSatoshis: number
  lockingScript: Script
  otherInputs: Transaction['inputs']
  inputSequence?: number
}

/**
 * Formats the transaction preimage for signing.
 */
export function formatPreimage(params: FormatPreimageParams): number[] {
  const { tx, inputIndex, signatureScope, sourceTXID, sourceSatoshis, lockingScript, otherInputs, inputSequence } = params
  const input = tx.inputs[inputIndex]
  return TransactionSignature.format({
    sourceTXID,
    sourceOutputIndex: verifyNotNull(input.sourceOutputIndex, 'input.sourceOutputIndex must have value'),
    sourceSatoshis,
    transactionVersion: tx.version,
    otherInputs,
    inputIndex,
    outputs: tx.outputs,
    inputSequence: inputSequence ?? verifyNotNull(input.sequence, 'input.sequence must have value'),
    subscript: lockingScript,
    lockTime: tx.lockTime,
    scope: signatureScope
  })
}
