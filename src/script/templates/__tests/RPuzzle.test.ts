import RPuzzle from '../RPuzzle'
import Spend from '../../Spend'
import LockingScript from '../../LockingScript'
import Transaction from '../../../transaction/Transaction'
import PrivateKey from '../../../primitives/PrivateKey'
import BigNumber from '../../../primitives/BigNumber'
import Curve from '../../../primitives/Curve'

const ZERO_TXID = '0'.repeat(64)

function getRValue (k: BigNumber): number[] {
  const c = new Curve()
  let r = c.g.mul(k).x?.umod(c.n)?.toArray()
  if (r == null) return []
  if (r[0] > 127) r = [0, ...r]
  return r
}

async function buildRPuzzleSpend (
  puz: RPuzzle,
  k: BigNumber,
  privateKey: PrivateKey,
  r: number[],
  signOutputs: 'all' | 'none' | 'single' = 'all',
  anyoneCanPay: boolean = false
): Promise<Spend> {
  const lockingScript: LockingScript = puz.lock(r)
  const sourceTx = new Transaction(1, [], [{ lockingScript, satoshis: 1 }], 0)
  const spendTx = new Transaction(
    1,
    [{ sourceTransaction: sourceTx, sourceOutputIndex: 0, sequence: 0xffffffff }],
    [{ lockingScript: LockingScript.fromASM('OP_1'), satoshis: 1 }],
    0
  )
  const unlockingScript = await puz.unlock(k, privateKey, signOutputs, anyoneCanPay).sign(spendTx, 0)
  return new Spend({
    sourceTXID: sourceTx.id('hex'),
    sourceOutputIndex: 0,
    sourceSatoshis: 1,
    lockingScript,
    transactionVersion: 1,
    otherInputs: [],
    outputs: spendTx.outputs,
    inputIndex: 0,
    unlockingScript,
    inputSequence: 0xffffffff,
    lockTime: 0
  })
}

describe('RPuzzle – additional coverage', () => {
  const k = new BigNumber(12345678)
  const privateKey = new PrivateKey(1)
  const r = getRValue(k)

  describe('signOutputs variations', () => {
    it('signs with signOutputs=none', async () => {
      const puz = new RPuzzle()
      const spend = await buildRPuzzleSpend(puz, k, privateKey, r, 'none')
      expect(spend.validate()).toBe(true)
    })

    it('signs with signOutputs=single', async () => {
      const puz = new RPuzzle()
      const spend = await buildRPuzzleSpend(puz, k, privateKey, r, 'single')
      expect(spend.validate()).toBe(true)
    })

    it('signs with anyoneCanPay=true', async () => {
      const puz = new RPuzzle()
      const spend = await buildRPuzzleSpend(puz, k, privateKey, r, 'all', true)
      expect(spend.validate()).toBe(true)
    })
  })

  describe('estimateLength', () => {
    it('returns 108', async () => {
      const puz = new RPuzzle()
      const result = await puz.unlock(k, privateKey).estimateLength()
      expect(result).toBe(108)
    })
  })

  describe('missing source transaction', () => {
    it('throws when input has no sourceTransaction', async () => {
      const puz = new RPuzzle()
      const lockingScript = puz.lock(r)
      // Construct a tx where the input has no sourceTransaction
      const spendTx = new Transaction(
        1,
        [{ sourceTXID: ZERO_TXID, sourceOutputIndex: 0, sequence: 0xffffffff }],
        [],
        0
      )
      await expect(
        puz.unlock(k, privateKey).sign(spendTx, 0)
      ).rejects.toThrow('The source transaction is needed')
    })
  })

  describe('hash type variants', () => {
    it('SHA256 RPuzzle round-trips using hashed r value', async () => {
      const { sha256 } = await import('../../../primitives/Hash')
      const hashedR = sha256(r)
      const puz = new RPuzzle('SHA256')
      const spend = await buildRPuzzleSpend(puz, k, privateKey, hashedR)
      expect(spend.validate()).toBe(true)
    })

    it('SHA1 RPuzzle round-trips using hashed r value', async () => {
      const { sha1 } = await import('../../../primitives/Hash')
      const hashedR = sha1(r)
      const puz = new RPuzzle('SHA1')
      const spend = await buildRPuzzleSpend(puz, k, privateKey, hashedR)
      expect(spend.validate()).toBe(true)
    })

    it('RIPEMD160 RPuzzle round-trips using hashed r value', async () => {
      const { ripemd160 } = await import('../../../primitives/Hash')
      const hashedR = ripemd160(r)
      const puz = new RPuzzle('RIPEMD160')
      const spend = await buildRPuzzleSpend(puz, k, privateKey, hashedR)
      expect(spend.validate()).toBe(true)
    })

    it('HASH160 RPuzzle round-trips using hashed r value', async () => {
      const { hash160 } = await import('../../../primitives/Hash')
      const hashedR = hash160(r)
      const puz = new RPuzzle('HASH160')
      const spend = await buildRPuzzleSpend(puz, k, privateKey, hashedR)
      expect(spend.validate()).toBe(true)
    })
  })
})
