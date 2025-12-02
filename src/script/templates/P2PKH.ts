import OP from '../OP.js'
import ScriptTemplate from '../ScriptTemplate.js'
import { fromBase58Check, verifyNotNull } from '../../primitives/utils.js'
import LockingScript from '../LockingScript.js'
import UnlockingScript from '../UnlockingScript.js'
import Transaction from '../../transaction/Transaction.js'
import PrivateKey from '../../primitives/PrivateKey.js'
import TransactionSignature from '../../primitives/TransactionSignature.js'
import { sha256 } from '../../primitives/Hash.js'
import Script from '../Script.js'

/**
 * P2PKH (Pay To Public Key Hash) class implementing ScriptTemplate.
 *
 * This class provides methods to create Pay To Public Key Hash locking and unlocking scripts, including the unlocking of P2PKH UTXOs with the private key.
 */
export default class P2PKH implements ScriptTemplate {
  /**
   * Creates a P2PKH locking script for a given public key hash or address string
   *
   * @param {number[] | string} pubkeyhash or address - An array or address representing the public key hash.
   * @returns {LockingScript} - A P2PKH locking script.
   */
  lock (pubkeyhash: string | number[]): LockingScript {
    let data: number[]
    if (typeof pubkeyhash === 'string') {
      const hash = fromBase58Check(pubkeyhash)
      if (hash.prefix[0] !== 0x00 && hash.prefix[0] !== 0x6f) {
        throw new Error('only P2PKH is supported')
      }
      data = hash.data as number[]
    } else {
      data = pubkeyhash
    }
    if (data.length !== 20) {
      throw new Error('P2PKH hash length must be 20 bytes')
    }
    return new LockingScript([
      { op: OP.OP_DUP },
      { op: OP.OP_HASH160 },
      { op: data.length, data },
      { op: OP.OP_EQUALVERIFY },
      { op: OP.OP_CHECKSIG }
    ])
  }

  /**
   * Creates a function that generates a P2PKH unlocking script along with its signature and length estimation.
   *
   * The returned object contains:
   * 1. `sign` - A function that, when invoked with a transaction and an input index,
   *    produces an unlocking script suitable for a P2PKH locked output.
   * 2. `estimateLength` - A function that returns the estimated length of the unlocking script in bytes.
   *
   * @param {PrivateKey} privateKey - The private key used for signing the transaction.
   * @param {'all'|'none'|'single'} signOutputs - The signature scope for outputs.
   * @param {boolean} anyoneCanPay - Flag indicating if the signature allows for other inputs to be added later.
   * @param {number} sourceSatoshis - Optional. The amount being unlocked. Otherwise the input.sourceTransaction is required.
   * @param {Script} lockingScript - Optional. The lockinScript. Otherwise the input.sourceTransaction is required.
   * @returns {Object} - An object containing the `sign` and `estimateLength` functions.
   */
  unlock (
    privateKey: PrivateKey,
    signOutputs: 'all' | 'none' | 'single' = 'all',
    anyoneCanPay: boolean = false,
    sourceSatoshis?: number,
    lockingScript?: Script
  ): {
      sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>
      estimateLength: () => Promise<108>
    } {
    return {
      sign: async (tx: Transaction, inputIndex: number) => {
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
        sourceSatoshis ||=
          input.sourceTransaction?.outputs[input.sourceOutputIndex].satoshis
        if (sourceSatoshis == null || sourceSatoshis === undefined) {
          throw new Error(
            'The sourceSatoshis or input sourceTransaction is required for transaction signing.'
          )
        }
        lockingScript ||=
          input.sourceTransaction?.outputs[input.sourceOutputIndex]
            .lockingScript
        if (lockingScript == null) {
          throw new Error(
            'The lockingScript or input sourceTransaction is required for transaction signing.'
          )
        }

        const preimage = TransactionSignature.format({
          sourceTXID,
          sourceOutputIndex: verifyNotNull(input.sourceOutputIndex, 'input.sourceOutputIndex must have value'),
          sourceSatoshis,
          transactionVersion: tx.version,
          otherInputs,
          inputIndex,
          outputs: tx.outputs,
          inputSequence: verifyNotNull(input.sequence, 'input.sequence must have value'),
          subscript: lockingScript,
          lockTime: tx.lockTime,
          scope: signatureScope
        })

        const rawSignature = privateKey.sign(sha256(preimage))
        const sig = new TransactionSignature(
          rawSignature.r,
          rawSignature.s,
          signatureScope
        )
        const sigForScript = sig.toChecksigFormat()
        const pubkeyForScript = privateKey
          .toPublicKey()
          .encode(true) as number[]
        return new UnlockingScript([
          { op: sigForScript.length, data: sigForScript },
          { op: pubkeyForScript.length, data: pubkeyForScript }
        ])
      },
      estimateLength: async () => {
        // public key (1+33) + signature (1+73)
        // Note: We add 1 to each element's length because of the associated OP_PUSH
        return 108
      }
    }
  }
}
