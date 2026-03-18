import Transaction from '../Transaction'
import LockingScript from '../../script/LockingScript'
import UnlockingScript from '../../script/UnlockingScript'
import { toArray } from '../../primitives/utils'

// Known EF-format transaction hex (BRC-30)
const KNOWN_EF_HEX =
  '010000000000000000ef01ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff3e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac00000000'

// Known BEEF V1 hex (non-Atomic, has no atomicTxid)
const KNOWN_BEEF_V1_HEX =
  '0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000'

describe('Transaction – additional coverage', () => {
  describe('fromHexEF', () => {
    it('parses a known EF hex string', () => {
      const tx = Transaction.fromHexEF(KNOWN_EF_HEX)
      expect(tx).toBeInstanceOf(Transaction)
      expect(tx.inputs).toHaveLength(1)
      expect(tx.outputs).toHaveLength(1)
    })
  })

  describe('fromAtomicBEEF – non-atomic BEEF', () => {
    it('throws when passed a regular BEEF with no atomicTxid', () => {
      const beefBytes = toArray(KNOWN_BEEF_V1_HEX, 'hex')
      expect(() => Transaction.fromAtomicBEEF(beefBytes)).toThrow(
        'beef must conform to BRC-95 and must contain the subject txid.'
      )
    })
  })

  describe('addInput', () => {
    it('throws when both sourceTXID and sourceTransaction are undefined', () => {
      const tx = new Transaction()
      expect(() =>
        tx.addInput({
          sourceOutputIndex: 0,
          unlockingScript: new UnlockingScript(),
          sequence: 0xffffffff
        })
      ).toThrow('A reference to an an input transaction is required')
    })

    it('sets sequence to 0xffffffff when not provided', () => {
      const tx = new Transaction()
      tx.addInput({
        sourceTXID: '00'.repeat(32),
        sourceOutputIndex: 0,
        unlockingScript: new UnlockingScript()
      })
      expect(tx.inputs[0].sequence).toBe(0xffffffff)
    })
  })

  describe('addOutput', () => {
    it('throws when satoshis is undefined and change is not true', () => {
      const tx = new Transaction()
      expect(() =>
        tx.addOutput({
          lockingScript: new LockingScript()
        })
      ).toThrow('either satoshis must be defined or change must be set to true')
    })

    it('throws when satoshis is negative', () => {
      const tx = new Transaction()
      expect(() =>
        tx.addOutput({
          lockingScript: new LockingScript(),
          satoshis: -1
        })
      ).toThrow('satoshis must be a positive integer or zero')
    })

    it('throws when lockingScript is null', () => {
      const tx = new Transaction()
      expect(() =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        tx.addOutput({ satoshis: 100, lockingScript: null as any })
      ).toThrow('lockingScript must be defined')
    })
  })

  describe('addP2PKHOutput', () => {
    it('adds a change output when satoshis is omitted', () => {
      const tx = new Transaction()
      // Pass a 20-byte hash directly to avoid base58 parsing
      const pubKeyHash = new Array(20).fill(0x01)
      tx.addP2PKHOutput(pubKeyHash)
      expect(tx.outputs).toHaveLength(1)
      expect(tx.outputs[0].change).toBe(true)
    })
  })

  describe('hash / id', () => {
    it('returns hex string from hash("hex")', () => {
      const tx = new Transaction()
      const h = tx.hash('hex')
      expect(typeof h).toBe('string')
      expect((h as string)).toHaveLength(64)
    })

    it('returns binary array from id() without enc', () => {
      const tx = new Transaction()
      const id = tx.id()
      expect(Array.isArray(id)).toBe(true)
      expect(id).toHaveLength(32)
    })
  })

  describe('toHexAtomicBEEF', () => {
    it('produces a hex string from toHexAtomicBEEF()', () => {
      const sourceTx = new Transaction(
        1,
        [],
        [{ lockingScript: new LockingScript(), satoshis: 1000 }],
        0
      )
      const tx = new Transaction(1, [], [{ lockingScript: new LockingScript(), satoshis: 900 }], 0)
      tx.addInput({
        sourceTXID: sourceTx.id('hex'),
        sourceTransaction: sourceTx,
        sourceOutputIndex: 0,
        unlockingScript: new UnlockingScript(),
        sequence: 0xffffffff
      })
      const hex = tx.toHexAtomicBEEF()
      expect(typeof hex).toBe('string')
      expect(hex.length).toBeGreaterThan(0)
    })
  })

  describe('getFee', () => {
    it('throws when an input has no sourceTransaction', () => {
      const tx = new Transaction()
      tx.addInput({
        sourceTXID: '00'.repeat(32),
        sourceOutputIndex: 0,
        unlockingScript: new UnlockingScript()
      })
      expect(() => tx.getFee()).toThrow(
        'Source transactions or sourceSatoshis are required for all inputs to calculate fee'
      )
    })
  })

  describe('sign', () => {
    it('throws when an output has undefined satoshis and change is not set', async () => {
      const tx = new Transaction(
        1,
        [],
        [{ lockingScript: new LockingScript(), satoshis: undefined, change: false }],
        0
      )
      await expect(tx.sign()).rejects.toThrow(
        'One or more transaction outputs is missing an amount'
      )
    })

    it('throws when an output has undefined satoshis and change is true (uncomputed change)', async () => {
      const tx = new Transaction(
        1,
        [],
        [{ lockingScript: new LockingScript(), satoshis: undefined, change: true }],
        0
      )
      await expect(tx.sign()).rejects.toThrow(
        'There are still change outputs with uncomputed amounts'
      )
    })
  })

  describe('toEF / writeEF error paths', () => {
    it('throws when an input has no sourceTransaction during EF serialization', () => {
      // sourceTXID is defined so addInput passes, but sourceTransaction is undefined
      const tx = new Transaction()
      tx.addInput({
        sourceTXID: '00'.repeat(32),
        sourceOutputIndex: 0,
        unlockingScript: new UnlockingScript()
      })
      expect(() => tx.toEF()).toThrow(
        'All inputs must have source transactions when serializing to EF format'
      )
    })
  })

  describe('toBinary / writeTransactionBody error paths', () => {
    it('throws when an input has no sourceTXID and no sourceTransaction', () => {
      // Bypass addInput validation by constructing directly
      const tx = new Transaction(
        1,
        [
          {
            sourceOutputIndex: 0,
            unlockingScript: new UnlockingScript(),
            sequence: 0xffffffff
            // no sourceTXID, no sourceTransaction
          }
        ],
        [],
        0
      )
      expect(() => tx.toBinary()).toThrow('sourceTransaction is undefined')
    })

    it('throws when an input has no unlockingScript during serialization', () => {
      const tx = new Transaction(
        1,
        [
          {
            sourceTXID: '00'.repeat(32),
            sourceOutputIndex: 0,
            sequence: 0xffffffff
            // no unlockingScript
          }
        ],
        [],
        0
      )
      expect(() => tx.toBinary()).toThrow('unlockingScript is undefined')
    })
  })
})
