import TransactionSignature from '../../primitives/TransactionSignature.js'
import { Hash, Utils } from '../../primitives/index.js'
import Script from '../Script.js'
import Spend from '../Spend.js'
import Transaction from '../../transaction/Transaction.js'
import { sighashTestData, sighashTestDataWip } from './sighashTestData.js'

describe('Chronicle Tests', () => {

  it('spend bip143 input', () => {
    const rawTx =
      '0100000001cc5988c346027ca1f6870422616d022caf216f537f3d4994f7a7d46a8bf0758a020000006b483045022100f1c0bfe5e7c9c5559ede2b1e2b98aeaac295218406df1d66af397f615350599202201ad5d39c6706e1cc5cdc297ee5cd5d5f79d237a1c4b16c5b4646c284f2eeeabe41210245c6e32afad67f6177b02cfc2878fce2a28e77ad9ecbc6356960c020c592d867ffffffff0302000000000000001976a914a4429da7462800dedc7b03a4fc77c363b8de40f588ac000000000000000020006a4c1c507573682d5468652d427574746f6e2e617070207c204c616d6264610a32f201000000001976a914296b03a4dd56b3b0fe5706c845f2edff22e84d7388ac00000000'
    const lockingScript =
      '76a914296b03a4dd56b3b0fe5706c845f2edff22e84d7388ac'
    const ok = validateUnlockScript(rawTx, 0, lockingScript, 32649741)
    expect(ok).toBe(true)
    // preimage 182 byes
    // "010000002987eea6ff44b0a0c38a4c81cc92c052f6bcb7e3cfa2f59e3af1f7a73433a6fc3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044cc5988c346027ca1f6870422616d022caf216f537f3d4994f7a7d46a8bf0758a020000001976a914296b03a4dd56b3b0fe5706c845f2edff22e84d7388ac0d32f20100000000ffffffffa4cd3e7fef24c9653d7a12c404e428b5bb9ac1c5d3a9ddc5a4b9331536df94d50000000041000000"
    // sighash
    // "f40a770ed6f1952973387579d7c7d14719d2bdce871fb449b6fa3d5cca35fbcf"
  })

  it('spend OTDA', () => {
    const rawTx =
      // block 300000, txid 7301b595279ece985f0c415e420e425451fcf7f684fcce087ba14d10ffec1121
      '01000000014dff4050dcee16672e48d755c6dd25d324492b5ea306f85a3ab23b4df26e16e9000000008c493046022100cb6dc911ef0bae0ab0e6265a45f25e081fc7ea4975517c9f848f82bc2b80a909022100e30fb6bb4fb64f414c351ed3abaed7491b8f0b1b9bcd75286036df8bfabc3ea5014104b70574006425b61867d2cbb8de7c26095fbc00ba4041b061cf75b85699cb2b449c6758741f640adffa356406632610efb267cb1efa0442c207059dd7fd652eeaffffffff020049d971020000001976a91461cf5af7bb84348df3fd695672e53c7d5b3f3db988ac30601c0c060000001976a914fd4ed114ef85d350d6d40ed3f6dc23743f8f99c488ac00000000'
    const lockingScript =
      // input sourceTxid e9166ef24d3bb23a5af806a35e2b4924d325ddc655d7482e6716eedc5040ff4d vout 0
      // 'OP_DUP OP_HASH160 5478d152bb557ac994c9793cece77d4295ed37e3 OP_EQUALVERIFY OP_CHECKSIG'
      '76a9145478d152bb557ac994c9793cece77d4295ed37e388ac'
    const ok = validateUnlockScript(rawTx, 0, lockingScript, 36473000000, true)
    expect(ok).toBe(true)
    // preimage 148 bytes
    // "01000000014dff4050dcee16672e48d755c6dd25d324492b5ea306f85a3ab23b4df26e16e9000000001976a9145478d152bb557ac994c9793cece77d4295ed37e388acffffffff020049d971020000001976a91461cf5af7bb84348df3fd695672e53c7d5b3f3db988ac30601c0c060000001976a914fd4ed114ef85d350d6d40ed3f6dc23743f8f99c488ac0000000001000000"
    // sighash
		// "bdf9e0f5600d64bf3754919bd181f5e3848440ef7b351150abcb1ca3a54d3eb9",
  })

  /**
   * At present only the first two test vectors added as real transaction (pre and post fork) compute a sighash known to match a valid signagure.
   * The remaining test vectors come from bitcoin-sv-staging repo as of 2025-06-23, but appear to be at least somewhat randomly generated.
   * The "scope" (SigHashType) values are all over the place.
   * Working with Teranode team to determine correct preimage values...
   */
  it('sighashTestData', () => {
    let log = ''
    let i = -1
    for (const t of sighashTestData) {
      i++
      const tx = Transaction.fromHex(t.rawTxHex)
      const script = Script.fromHex(t.scriptHex)
      const input = tx.inputs[t.inputIndex]
      if (input.unlockingScript?.chunks.length != 2)
        continue;
      const otherInputs = [...tx.inputs]
      otherInputs.splice(t.inputIndex, 1)
      const params = {
        sourceTXID: input.sourceTXID!,
        sourceOutputIndex: input.sourceOutputIndex,
        sourceSatoshis: t.satoshis,
        transactionVersion: tx.version,
        otherInputs,
        outputs: tx.outputs,
        inputIndex: t.inputIndex,
        subscript: Script.fromHex(t.scriptHex),
        inputSequence: input.sequence ?? 0xffffffff, // Default to max sequence number
        lockTime: tx.lockTime,
        scope: t.hashType,
      }
      let ok = false
      let okReg = false
      let okOTDA = false
      {
        const sighash = t.sighashReg
        const buf = TransactionSignature.format(params)
        const ret = Utils.toHex(Hash.hash256(buf).reverse())
        if (ret === sighash) {
          ok = true
          okReg = true
        }
        if (!okReg)
          log += `${i+1} Reg ${okReg} ${!okReg ? ret : ''}\n`
      }
      {
        const sighash = t.sighashOTDA
        const buf = TransactionSignature.formatOTDA(params)
        const ret = Utils.toHex(Hash.hash256(buf).reverse())
        if (ret === sighash) {
          ok = true
          okOTDA = true
        }
        if (!okOTDA)
          log += `${i+1} OTDA ${okOTDA} ${!okOTDA ? ret : ''}\n`
      }
    }
    //console.log(log)
    //expect(log).toBe('')
  })

  it('wip sighashTestData', () => {
    let log = ''
    let i = -1
    for (const t of sighashTestDataWip) {
      i++
      const tx = Transaction.fromHex(t.rawTxHex)
      const script = Script.fromHex(t.scriptHex)
      const input = tx.inputs[t.inputIndex]
      const otherInputs = [...tx.inputs]
      otherInputs.splice(t.inputIndex, 1)
      const params = {
        sourceTXID: input.sourceTXID!,
        sourceOutputIndex: input.sourceOutputIndex,
        sourceSatoshis: t.satoshis,
        transactionVersion: tx.version,
        otherInputs,
        outputs: tx.outputs,
        inputIndex: t.inputIndex,
        subscript: Script.fromHex(t.scriptHex),
        inputSequence: input.sequence ?? 0xffffffff, // Default to max sequence number
        lockTime: tx.lockTime,
        scope: t.hashType,
      }
      let ok = false
      let okReg = false
      let okOTDA = false
      {
        const sighash = t.sighashReg
        const buf = TransactionSignature.format(params)
        const ret = Utils.toHex(Hash.hash256(buf).reverse())
        if (ret === sighash) {
          ok = true
          okReg = true
        }
        if (!okReg)
          log += `${i+1} Reg ${okReg} ${!okReg ? ret : ''}\n`
      }
      {
        const sighash = t.sighashOTDA
        const buf = TransactionSignature.formatOTDA(params)
        const ret = Utils.toHex(Hash.hash256(buf).reverse())
        if (ret === sighash) {
          ok = true
          okOTDA = true
        }
        if (!okOTDA)
          log += `${i+1} OTDA ${okOTDA} ${!okOTDA ? ret : ''}\n`
      }
    }
    console.log(log)
    expect(log).toBe('')
  })
})

function verifyTruthy<T> (v: T | undefined): T {
  if (v == null) throw new Error('must have value')
  return v
}

function validateUnlockScript (
  spendingRawTx: string,
  vin: number,
  lockingScript: string,
  amount: number,
  isRelaxed?: boolean
): boolean {
  const spendingTx = Transaction.fromHex(spendingRawTx)
  const ls = Script.fromHex(lockingScript)

  const spend = new Spend({
    sourceTXID: verifyTruthy(spendingTx.inputs[vin].sourceTXID),
    sourceOutputIndex: verifyTruthy(spendingTx.inputs[vin].sourceOutputIndex),
    sourceSatoshis: amount,
    lockingScript: ls,
    transactionVersion: spendingTx.version,
    otherInputs: spendingTx.inputs.filter((v, i) => i !== vin),
    inputIndex: vin,
    unlockingScript: verifyTruthy(spendingTx.inputs[vin].unlockingScript),
    outputs: spendingTx.outputs,
    inputSequence: verifyTruthy(spendingTx.inputs[vin].sequence),
    lockTime: spendingTx.lockTime,
    isRelaxed
  })

  const valid = spend.validate()
  return valid
}
