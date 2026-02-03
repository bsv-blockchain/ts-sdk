import BeefTx from '../../transaction/BeefTx'
import BeefParty from '../../transaction/BeefParty'
import { Beef, BEEF_V1, BEEF_V2 } from '../../transaction/Beef'
import Transaction from '../../transaction/Transaction'
import { fromBase58 } from '../../primitives/utils'

// The following imports allow full type checking by the VsCode editor, but tests will fail to run:
/*
import BeefTx from '../BeefTx'
import Beef from '../Beef'
import BeefParty from "../BeefParty"
import { BEEF_V1, BEEF_V2 } from "../Beef"
import Transaction from "../Transaction"
import { fromBase58 } from "../../primitives/utils"
*/

describe('Beef tests', () => {
  jest.setTimeout(99999999)

  const chainTracker = {
    currentHeight: async () => 1631619, // Mock function returning the current height as a Promise<number>
    isValidRootForHeight: async (root: string, height: number) => {
      const knownRoots = {
        1631619:
          'a3dd0604ac7a431a90d19f04b073b00007963947163f98e38a23229c43c69b0a',
        875732:
          'a19c54129ab996c72cda7721b4555b47d11b21e1fe67aa63c59843edb302b6c2',
        1651724:
          '0fa8e6a2a8860eaec7365217c1cf64a905dc7936342b36a86566f933187f8c62',
      }

      if (knownRoots[height] !== undefined) {
        return root === knownRoots[height]
      }

      return false
    }
  }

  test('0_mergeTransaction', async () => {
    const beef = Beef.fromString(beefs[0])
    expect(beef.toHex()).toBe(beefs[0])
    expect(beef.toLogString()).toBe(beefs0Log)
    expect(Beef.fromBinary(beef.toBinary()).toLogString()).toBe(beefs0Log)

    const btx = beef.txs[0]

    if (beef.txs[0].tx == null) {
      throw new Error('Transaction is undefined') // ✅ Ensure tx is valid
    }
    beef.txs[0] = new BeefTx(beef.txs[0].tx, 0)

    expect(Beef.fromBinary(beef.toBinary()).toLogString()).toBe(beefs0Log)
    beef.txs[0]._tx = undefined
    beef.txs[0]._rawTx = undefined
    beef.txs[0]._txid = undefined

    expect(() => beef.txs[0].txid).toThrow('Internal')
    expect(() => beef.toBinary()).toThrow('Internal')

    beef.txs[0] = btx // Restore the original transaction

    const tx = Transaction.fromHex(txs[0])
    beef.mergeTransaction(tx)
    expect(beef.toLogString()).toBe(log2)

    {
      const beef = Beef.fromString(beefs[0])
      beef.mergeTransaction(Transaction.fromHex(txs[0]))
      expect(beef.isValid(undefined)).toBe(true)
      expect(await beef.verify(chainTracker, undefined)).toBe(true)
      // This should be the existing value, leaving beef both structurally and computedRoots valid.
      beef.bumps[0].path[1][0].hash =
        '36ebdb404ec59871c8e2b00e41d8090d28a0d8a190d44606e895dd0d013bca00'
      expect(beef.isValid(undefined)).toBe(true)
      expect(await beef.verify(chainTracker, undefined)).toBe(true)
      // Now make the bump structurally valid, but with an invalid computed root.
      beef.bumps[0].path[1][0].hash =
        'ffffdb404ec59871c8e2b00e41d8090d28a0d8a190d44606e895dd0d013bca00'
      expect(beef.isValid(undefined)).toBe(true)
      expect(await beef.verify(chainTracker, undefined)).toBe(false)
    }

    {
      const btx = new BeefTx(tx.toBinary(), undefined)
      expect(btx.rawTx).toEqual(tx.toBinary())
    }

    {
      const btx = new BeefTx(
        'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07',
        undefined
      )
      expect(btx.rawTx).toBe(undefined)
    }

    const r = beef.sortTxs()
    expect(r.missingInputs.length).toBe(0)
    expect(beef.toLogString()).toBe(log2)

    {
      const b = new Beef()
      b.mergeTxidOnly(
        'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
      )
      const bin = b.toBinary()
      const b2 = Beef.fromBinary(bin)
      expect(b2.txs[0].isTxidOnly).toBe(true)
      expect(b2.txs[0].txid).toBe(
        'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
      )
    }

    {
      const beef = new Beef()
      beef.mergeTransaction(Transaction.fromHex(txs[0]))
      const { missingInputs } = beef.sortTxs()
      expect(missingInputs).toEqual([
        'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
      ])

      const beef0 = Beef.fromString(beefs[0])
      beef.mergeBump(beef0.bumps[0])

      if (beef0.txs[0].rawTx == null) {
        throw new Error('rawTx is undefined') // ✅ Prevents TypeScript error
      }
      beef.mergeRawTx(beef0.txs[0].rawTx, undefined) // ✅ Safe assignment

      expect(beef.isValid(false)).toBe(true)
    }

    {
      const beef = new Beef()
      beef.mergeRawTx(Transaction.fromHex(txs[0]).toBinary())
      // Transactions are not rooted in bumps.
      expect(beef.isValid(false)).toBe(false)
    }

    {
      const version = 4290641921
      expect(() => Beef.fromString(beefs[1])).toThrow(
        `Serialized BEEF must start with ${BEEF_V1} or ${BEEF_V2} but starts with ${version}`
      )
    }
  })

  test('1_all merkleRoots equal', async () => {
    const beef = Beef.fromString(beefs[0])
    expect(beef.isValid(undefined)).toBe(true)
    const mp = beef.bumps[0]
    mp.path[0].push({
      offset: 2,
      hash: 'd0ae03111611f04a4c6e45a0a93f62f69c5594b64b369c0262289695feb2f991',
      txid: true,
      duplicate: false
    })
    mp.path[0].push({
      offset: 3,
      hash: undefined,
      txid: false,
      duplicate: true
    })
    expect(beef.isValid(undefined)).toBe(true)
    mp.path[0][2].hash =
      'ffae03111611f04a4c6e45a0a93f62f69c5594b64b369c0262289695feb2f991'
    expect(beef.isValid(undefined)).toBe(false)
    expect(await beef.verify(chainTracker, undefined)).toBe(false)
  })

  test('2_allowTxidOnly', async () => {
    const beef = Beef.fromString(beefs[0])
    expect(beef.isValid(undefined)).toBe(true)
    beef.mergeTxidOnly(
      'd0ae03111611f04a4c6e45a0a93f62f69c5594b64b369c0262289695feb2f991'
    )
    expect(beef.isValid(undefined)).toBe(false)
    expect(beef.isValid(true)).toBe(true)
  })

  test('3_removeExistingTxid', async () => {
    const beef = Beef.fromString(beefs[0])
    expect(beef.isValid(undefined)).toBe(true)
    expect(beef.txs.length).toBe(1)
    beef.removeExistingTxid(
      'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
    )
    expect(beef.isValid(undefined)).toBe(true)
    expect(beef.txs.length).toBe(0)
  })

  test('4_mergeTransaction with parent txs', async () => {
    {
      const beef = Beef.fromString(beefs[0])
      const tx1 = beef.txs[0]?.tx
      if (tx1 == null) {
        throw new Error('tx1 is undefined')
      }

      const tx2 = Transaction.fromHex(txs[0])
      const input = tx2.inputs.find((i) => i.sourceTXID === tx1.id('hex'))
      if (input == null) {
        throw new Error('Input not found in transaction inputs.')
      }
      input.sourceTransaction = tx1

      const beefB = new Beef()
      beefB.mergeTransaction(tx2)
      expect(beefB.isValid(undefined)).toBe(false)
      expect(beefB.txs.length).toBe(2)
      beefB.mergeBump(beef.bumps[0])
      beefB.mergeBump(beef.bumps[0])
      expect(beefB.isValid(undefined)).toBe(true)
    }
    {
      const beef = Beef.fromString(beefs[0])
      const tx1 = beef.txs[0]?.tx
      if (tx1 == null) {
        throw new Error('tx1 is undefined')
      }

      tx1.merklePath = beef.bumps[0]
      const tx2 = Transaction.fromHex(txs[0])
      const input = tx2.inputs.find((i) => i.sourceTXID === tx1.id('hex'))
      if (input == null) {
        throw new Error('Input not found in transaction inputs.')
      }
      input.sourceTransaction = tx1

      const beefB = new Beef()
      beefB.mergeTransaction(tx2)
      expect(beefB.isValid(undefined)).toBe(true)
      expect(beefB.txs.length).toBe(2)
    }
  })

  test('5_mergeBeef', async () => {
    {
      const beef = Beef.fromString(beefs[0])
      const beefB = Beef.fromString(beefs[0])
      beef.mergeBeef(beefB)
      expect(beef.isValid(undefined)).toBe(true)
    }
    {
      const beef = Beef.fromString(beefs[0])
      const beefB = Beef.fromString(beefs[0])
      beef.mergeBeef(beefB.toBinary())
      expect(beef.isValid(undefined)).toBe(true)
    }
    {
      const beef = Beef.fromString(beefs[0])
      const beefB = new Beef()
      beefB.mergeRawTx(Transaction.fromHex(txs[0]).toBinary(), 0)
      beef.mergeBeef(beefB)
      expect(beef.isValid(undefined)).toBe(true)
    }
    {
      const beef = Beef.fromString(beefs[0])
      const beefB = new Beef()
      beefB.mergeTransaction(Transaction.fromHex(txs[0]))
      beef.mergeBeef(beefB)
      expect(beef.isValid(undefined)).toBe(true)
    }
    {
      const beef = Beef.fromString(beefs[0])
      const beefB = new Beef()
      beefB.mergeTxidOnly(
        'd0ae03111611f04a4c6e45a0a93f62f69c5594b64b369c0262289695feb2f991'
      )
      beef.mergeBeef(beefB)
      expect(beef.isValid(true)).toBe(true)
    }
  })

  test('6_BeefParty', async () => {
    const bp = new BeefParty(['b', 'c'])
    expect(bp.isParty('a')).toBe(false)
    expect(bp.isParty('b')).toBe(true)

    bp.addKnownTxidsForParty('a', ['1'])
    bp.addKnownTxidsForParty('a', ['2'])
    bp.addKnownTxidsForParty('b', ['3', '4'])
    bp.addKnownTxidsForParty('c', ['2', '3'])

    expect(() => bp.addParty('a')).toThrow('Party a already exists.')
    expect(() => bp.getKnownTxidsForParty('z')).toThrow('Party z is unknown.')

    expect(bp.getKnownTxidsForParty('a')).toEqual(['1', '2'])
    expect(bp.getKnownTxidsForParty('b')).toEqual(['3', '4'])
    expect(bp.getKnownTxidsForParty('c')).toEqual(['2', '3'])

    {
      const v = bp.getTrimmedBeefForParty('a').toLogString()
      expect(v).toBe(`BEEF with 0 BUMPS and 2 Transactions, isValid false
  TX 0
    txid: 3
    txidOnly
  TX 1
    txid: 4
    txidOnly
`)
    }
    {
      const v = bp.getTrimmedBeefForParty('b').toLogString()
      expect(v).toBe(`BEEF with 0 BUMPS and 2 Transactions, isValid false
  TX 0
    txid: 1
    txidOnly
  TX 1
    txid: 2
    txidOnly
`)
    }
    {
      const v = bp.getTrimmedBeefForParty('c').toLogString()
      expect(v).toBe(`BEEF with 0 BUMPS and 2 Transactions, isValid false
  TX 0
    txid: 1
    txidOnly
  TX 1
    txid: 4
    txidOnly
`)
    }
  })

  test('6b_trimKnownTxids_removes_unreferenced_bumps', async () => {
    // Create a beef with multiple transactions and bumps
    const beef = Beef.fromString(beefs[0])
    
    // Verify initial state
    const initialBumpCount = beef.bumps.length
    const initialTxCount = beef.txs.length
    expect(initialBumpCount).toBe(1)
    expect(initialTxCount).toBe(1)
    
    // Add some txid-only transactions that don't have bumps
    beef.mergeTxidOnly('txid1')
    beef.mergeTxidOnly('txid2')
    beef.mergeTxidOnly('txid3')
    
    expect(beef.txs.length).toBe(4)
    expect(beef.bumps.length).toBe(1)
    
    // Get the txid of the transaction with a bump
    const txWithBump = beef.txs.find(tx => tx.bumpIndex !== undefined)
    expect(txWithBump).toBeTruthy()
    
    // Trim all txid-only transactions
    beef.trimKnownTxids(['txid1', 'txid2', 'txid3'])
    
    // Verify txids were removed
    expect(beef.txs.length).toBe(1)
    expect(beef.bumps.length).toBe(1) // Bump should still be there because it's referenced
    
    // Now test removing the transaction that has the bump
    // First, make it txidOnly
    const originalTxid = txWithBump!.txid
    beef.makeTxidOnly(originalTxid)
    
    // Now trim it
    beef.trimKnownTxids([originalTxid])
    
    // The bump should be removed since no transactions reference it anymore
    expect(beef.txs.length).toBe(0)
    expect(beef.bumps.length).toBe(0)
  })

  test('6c_trimKnownTxids_updates_bump_indices', async () => {
    // Use existing beef with bumps
    const beef = Beef.fromString(beefs[0])
    
    const initialBumpCount = beef.bumps.length
    const initialTxCount = beef.txs.length
    
    // Find transaction with bump
    const txWithBump = beef.txs.find(tx => tx.bumpIndex !== undefined)
    expect(txWithBump).toBeTruthy()
    const originalBumpIndex = txWithBump!.bumpIndex
    
    // Add some txid-only transactions
    beef.mergeTxidOnly('known1')
    beef.mergeTxidOnly('known2')
    
    expect(beef.txs.length).toBe(initialTxCount + 2)
    expect(beef.bumps.length).toBe(initialBumpCount)
    
    // Trim the known txids
    beef.trimKnownTxids(['known1', 'known2'])
    
    // Verify bump count didn't change (all bumps are still referenced)
    expect(beef.bumps.length).toBe(initialBumpCount)
    
    // Verify transaction count decreased
    expect(beef.txs.length).toBe(initialTxCount)
    
    // Verify bumpIndex is still correct
    const txAfterTrim = beef.txs.find(tx => tx.txid === txWithBump!.txid)
    expect(txAfterTrim?.bumpIndex).toBe(originalBumpIndex)
  })

  test('7_AtomicBeef', async () => {
    {
      const beef = Beef.fromString(beefs[0])
      expect(beef.toHex()).toBe(beefs[0])
      beef.sortTxs()
      const beefHex = beef.toHex()

      const tx = beef.txs[beef.txs.length - 1]?.tx
      if (tx == null) {
        throw new Error('Transaction (tx) is undefined.')
      }

      expect(tx).toBeTruthy()
      const atomic = tx.toAtomicBEEF(true)

      // Verify that atomic BEEF can be deserialized.
      const beef2 = Beef.fromBinary(atomic)
      // The merkle path isn't linked to tx by default.
      expect(beef2.toHex()).not.toBe(beefHex)
      {
        const atx = beef.findAtomicTransaction(tx.id('hex'))
        if (atx == null) {
          throw new Error('Atomic transaction (atx) not found.')
        }
        const atomic = atx.toAtomicBEEF(true)

        // Verify that atomic BEEF can be deserialized.
        const beef2 = Beef.fromBinary(atomic)
        // The merkle path now is linked to tx by default.
        expect(beef2.toHex()).toBe(beefHex)
      }
    }
    {
      const beef = Beef.fromString(beefs[0])
      expect(beef.toHex()).toBe(beefs[0])
      beef.mergeTransaction(Transaction.fromHex(txs[0]))
      beef.sortTxs()
      const beefHex = beef.toHex()

      const tx = beef.txs[beef.txs.length - 1]?.tx
      if (tx == null) {
        throw new Error('Transaction (tx) is undefined.')
      }

      expect(tx).toBeTruthy()
      const atx = beef.findAtomicTransaction(tx.id('hex'))
      if (atx == null) {
        throw new Error('Atomic transaction (atx) not found.')
      }

      const atomic = atx.toAtomicBEEF()
      // Verify that atomic BEEF can be deserialized.
      const beef2 = Beef.fromBinary(atomic)
      expect(beef2.toHex()).toBe(beefHex)
    }
  })

  test('8_toBinaryAtomic', async () => {
    const beef = Beef.fromString(beefs[0])
    const tx = Transaction.fromHex(txs[0])
    beef.mergeTransaction(tx)
    beef.sortTxs()
    beef.toLogString()
    const atomic = beef.toBinaryAtomic(tx.id('hex'))
    const t2 = Transaction.fromAtomicBEEF(atomic)
    const beef2 = t2.toAtomicBEEF()
    expect(atomic).toEqual(beef2)
  })
  test('9_sortTxs', async () => {
    {
      const beef = new Beef()
      beef.mergeTxidOnly('a')
      const btx = beef.mergeTxidOnly('b')
      btx.inputTxids = ['a']
      beef.sortTxs()
      expect(beef.txs[1].txid).toBe('b')
    }
    {
      const beef = new Beef()
      const atx = beef.mergeTxidOnly('a')
      beef.mergeTxidOnly('b')
      atx.inputTxids = ['b']
      beef.sortTxs()
      expect(beef.txs[1].txid).toBe('a')
    }
  })

  test('10_deserialize beef with extra leaves', async () => {
    const b58Beef = b58Beef10
    const beef = Beef.fromBinary(fromBase58(b58Beef))
    expect(beef.isValid()).toBe(true)
    const abeef = beef.toBinaryAtomic(beef.txs[beef.txs.length - 1].txid)
    const pbeef = Beef.fromBinary(abeef)
    pbeef.addComputedLeaves()
    const pbeefBinary = pbeef.toBinary()
    expect(pbeefBinary).toBeTruthy()
    expect(beef.isValid()).toBe(true)
    expect(await beef.verify(chainTracker)).toBe(true)
  })

  test('11_wrongBumpTxid', async () => {
    const b = Beef.fromString(wrongBumpTxid)
    const valid = b.isValid()
    expect(valid).toBe(false)
  })

  test('12_bumpIndexEncoding', async () => {
    const b = Beef.fromString(bumpIndexEncoding)
    // These are in the incorrect order!
    expect(b.txs[1].txid).toBe('147050ccef091ca3d7a36661ca0928aa93a3a9a6dfe565977c2f56179d7a6159')
    expect(b.txs[0].txid).toBe('0e579e9741f522e15536874090d20da7572a7e1ddd4bf42740f40e17c3605604')
    const valid = b.isValid()
    expect(valid).toBe(true)
    expect(b.version).toBe(BEEF_V1)
    const bytes = b.toBinary()
    {
      const b = Beef.fromBinary(bytes)
      // These are now in the correct order!
      expect(b.txs[0].txid).toBe('147050ccef091ca3d7a36661ca0928aa93a3a9a6dfe565977c2f56179d7a6159')
      expect(b.txs[1].txid).toBe('0e579e9741f522e15536874090d20da7572a7e1ddd4bf42740f40e17c3605604')
      const valid = b.isValid()
      expect(valid).toBe(true)
      expect(b.version).toBe(BEEF_V1)
    }
  })
})

const b58Beef10 =
  'gno9MC7VXii1KoCkc2nsVyYJpqzN3dhBzYATETJcys62emMKfpBof4R7GozwYEaSapUtnNvqQ57aaYYjm3U2dv9eUJ1sV46boHkQgppYmAz9YH8FdZduV8aJayPViaKcyPmbDhEw6UW8TM5iFZLXNs7HBnJHUKCeTdNK4FUEL7vAugxAV9WUUZ43BZjJk2SmSeps9TCXjt1Ci9fKWp3d9QSoYvTpxwzyUFHjRKtbUgwq55ZfkBp5bV2Bpz9qSuKywKewW7Hh4S1nCUScwwzpKDozb3zic1V9p2k8rQxoPsRxjUJ8bjhNDdsN8d7KukFuc3n47fXzdWttvnxwsujLJRGnQbgJuknQqx3KLf5kJXHzwjG6TzigZk2t24qeB6d3hbYiaDr2fFkUJBL3tukTHhfNkQYRXuz3kucVDzvejHyqJaF51mXG8BjMN5aQj91ZJXCaPVqkMWCzmvyaqmXMdRiJdSAynhXbQK91xf6RwdNhz1tg5f9B6oJJMhsi9UYSVymmax8VLKD9AKzBCBDcfyD83m3jyS1VgKGZn3SkQmr6bsoWq88L3GsMnnmYUGogvdAYarTqg3pzkjCMxHzmJBMN6ofnUk8c1sRTXQue7BbyUaN5uZu3KW6CmFsEfpuqVvnqFW93TU1jrPP2S8yz8AexAnARPCKE8Yz7RfVaT6RCavwQKL3u5iookwRWEZXW1QWmM37yJWHD87SjVynyg327a1CLwcBxmE2CB48QeNVGyQki4CTQMqw2o8TMhDPJej1g68oniAjBcxBLSCs7KGvK3k7AfrHbCMULX9CTibYhCjdFjbsbBoocqJpxxcvkMo1fEEiAzZuiBVZQDYktDdTVbhKHvYkW25HcYX75NJrpNAhm7AjFeKLzEVxqAQkMfvTufpESNRZF4kQqg2Rg8h2ajcKTd5cpEPwXCrZLHm4EaZEmZVbg3QNfGhn7BJu1bHMtLqPD4y8eJxm2uGrW6saf6qKYmmu64F8A667NbD4yskPRQ1S863VzwGpxxmgLc1Ta3R46jEqsAoRDoZVUaCgBBZG3Yg1CTgi1EVBMXU7qvY4n3h8o2FLCEMWY4KadnV3iD4FbcdCmg4yxBosNAZgbPjhgGjCimjh4YsLd9zymGLmivmz2ZBg5m3xaiXT9NN81X9C1JUujd'

const txs: string[] = [
  // 0
  '0100000001074d631cc91344daf964cb8b1f43fd3439b804eb673cbe82d9bde3dcc6394abd020000006b48304502210096e24b07db278344a32c12667bac0d38ea87b28e9c52f3630ff7c11760d4002e02201b9dc879465c82152920f650828bfabba0d0bc8f7e15b568b196f1fa7e2cb4644121034e6dcc60f278b83e3e7b2b6570c13a184f4cf27a279199625c981adfe42de997ffffffff03b706000000000000fdc20421029b09fdddfae493e309d3d97b919f6ab2902a789158f6f78489ad903b7a14baeaac2131546f446f44744b7265457a6248594b466a6d6f42756475466d53585855475a474d3004a1edf497c9db470e7862d8c8319b4312f197a18db529a5839ba7c7e4f4dcee4ff4b4651a2a30040ef0aab1c2a4386620b96cb068c2ad2bc06ed90cebed65643710497f785f48c91482ac86893dd675c3de5d7db2e305fb30a588c75282f062367dee1dd4d930502f64f043c45cd1f220f875ff749f5449c99b29a200a86287a842a4f1df21dafda06a1b39b590b33b15109ee8a700728f1a80016ed370f639b35c9d079dea938d7fe451a52c744605a64a89ac7ebfcf692ef345a1e41fba055c197f7e3f608196001ed150bd56883970f3b8954a63aa70e4fa1c33799d43caaacf7ca30f8e873a6a20a04b1508f851633fcb4f30de75954747e702775b143c668c3b80cef96001980f05a8322726a567a379a2901db030057400bf0484c0852b1ec42cdaae6bf9f258ba0c914d83a96522d63b46a71571087fc4ad4ea0be0f6f354e7f638a7c316ceca3be69698104c1662ce0d5f4334b3327377497f9bb8605388c86a5a3928b22dbafd20a488442862c0ea4cd72778ae3b1bfd1d517299969f553b21173f75b530d1c19e23835dbc423c0ab5d3a894560a064951e237d2956db5d007d2132721a949849df49c5c5ab21f9eacb9ea5aa704c37cd101c17bee37954eae01472096f0e3e52b9f98d46426f35437c76c643c6f5d4d0a5ceb89d03a31c451d7882a527c9e78abf01f6178446cd74a7ad4190f364cc79fccc91583f3521e706bd548dc19633234fe96e40e19ef6424b252691e2183484cbf088e965066d4b93b80de927f3426e71f265152d898537c6112ed4500b8b7f23d033c18bad6c3ae5a2e069b03af5b619a334713f367082d41fdff8d5b17ab90a8aff224fbec3a8ca93828fe18c24b54fdcffdd9ee53c40808a4d233a56ed6f21bda0ebf1f4375785f2427da484ba9cdcd45bd28f8072e885bcb687c575ed00bea520508e795b32b7c882ffdd36062e9f748fddbb99a71e7afaed26c24e631ccce19ceb92f1920fb45ae30b58dde09389062eccf1292c55aca96e7eae53a3b6721a568b1bc8f1bad201c0e3b3fe7caec178e491dc12e97a0d0448136f7fb9970c7b053a85a553927a2273682eb2ae4c41c12f1d893d427f659048bbfa6c4be0682d8226d21e4b522e0a2d575655dea64d36d1e0f5719d4f6d06b47f4b4e32731652f0c12e28a9642e90d049b0fbc2c2c94079106c017ad85a81882344ddb71e3c5de31f5b42df9c269e1f64e36b3179ef5e9581fc57c1ed919962ba11686ef0e0a40694f8733bd1e2232196ca4f35c33df1b27872bd3aa0e258601192e50ec5bb64c6ae1a60f580cb6434048c7a419a76028f95442ce5c628f1324281ca3e8050c7ea8a90c3782a6df2cfee5d735e43f518bc215017cd036f70011312204bf885c615b1d1601626de7a1ff9ff21a44818fa19b7a8ed241b6f16380c9e376c6c7a2f48414269e4a3f130ac5c01a7ca8ad4af044ed4288657f59b675e89287c3811c8e81ba1c75f68b8ec85a35d15b5f1cee0fa25874730450221008d6e0b7d98442477d5637fc12fa871f224fd82194d2c3d8e524a12e389ddc35602206286a3b292ef3bac9f047c842a3e9b418102617546e9dc6f9dcc6653c82e645c6d75c8000000000000001976a9142e1ba3aade0562035e69630cb40024f403c0599e88ac77420000000000001976a914eeea6c76530f46d0f2a20ad522c4a6886bad686d88ac00000000'
]
const beefs: string[] = [
  // 0
  '0100beef01fe83e5180002020000ffc5b2a2bf5860e98e3e4dbeee031efa3b39d7d5c1ed7ee51e42663a0002777c0102074d631cc91344daf964cb8b1f43fd3439b804eb673cbe82d9bde3dcc6394abd01010000ca3b010ddd95e80646d490a1d8a0280d09d8410eb0e2c87198c54e40dbeb3601010000000170db5fb358f367564f07bfd1aed51ac63493ccb8ee6220a531b8905c6b4ab778020000006b4830450221008469135692bc1e7c14988f884161ae228dcfa9e3b30fca4ef0c22beac0a54ab4022004ed0c41d06c63ad3cd8193228347c5cc00a0d564e9cd11f8c72fb445bb9053e4121033a5b51483b43898ef6e1faf504167def7ad2755a1e0f68278c65f8162b7b811dffffffff03b706000000000000fdc23021029b09fdddfae493e309d3d97b919f6ab2902a789158f6f78489ad903b7a14baeaac2131546f446f44744b7265457a6248594b466a6d6f42756475466d53585855475a474d3030bbf64267d1333e65ff33de8b7aa497187ea5c74b0721d143bb82c6cdb0f803b264d2298a57e7c21b257e8ea76be83e7a0659595c1cfa3d095458f5a0360be6593124e5dd798fd94ab939f7d596687d30c12d820a2a708c4c369211fd5f6e3d05a9e92fced4afa6bf0be8cbf8636db2925a7534f2bfc5ffeb43f9fd25cfea55e93d195db2ae454a3dea254ae6117027beb080b5c5fb6b6f36ae0ba077ed3767462d61fa8acede7051ae717aaeef257508f897e03fdcf4a85f80639131e98a5fe3ba0abf7f94fd87ffa1e56bd45fd7b27ba02c9518fe04d5101a97d2d509ec6e8409559297eef4f82ea76831702964476c14055571e9a0b4fca25ae57042d9a4cd7d72d90ea48edd1d2b1e36c8cadc84d5ec91c5e766ca4afc43bf055500b1e4f8cc9ddfdf6272271a3e5d23e75c0d70c78feffa1e45900a3f4011d29f1b29257cb12553736840a1afb01f80c6ce7099763078f64fee5defeef5c0349b145053b2c066afd58417df9ef54ce46a0463d259d0ae1555812a672ad5fb94f5328d0b061aba715d91c8468711effcd83e745b404c8348096099618aa45bdee66900df6a156f559381fd1d1f8bed0092f92801f690a27726ad1e37e2850ca9c4a15ad5ab546836c947700411f340bc22f832b68ecd33ff7115295c1d2ac1a33c63344e8c208f78faad38daa2349051266e5337ba767964c57edee2094e2d96f256e61bed4d9cf68d6d60b4252ef90be29133271753efe6ac16c3091b18d163441e464083b11fa676604852ce63ba84d61610f7fb6f8176c3745d67b2d828a0ffe394fe96eef298f776bfc16fd7f80a15fe85de47dea4e5f48f9b694255289283f6b5bcebc954c38c59549e4b0e264545f2ac974fbc7dfe41b12cf0de8ca80a7f5100a7fc7eeb543868935c48f0c31d351d0a7e99186d995daa1356c72de6864370df7852b2a94cbc9328b0823d44955e0bd19172df78679654945845c64ff0598fb1c6695270efa20f8849fd391a63bb90e6dd803c735699a3507dad970f500e20c181627f4d5e8e2aa801fb0e88bda2126292133b8ebddf94641e9a76115942683e2df34b2c31803d4a156148303c279f384322f1a5dee1c5f1b1ff7616313642e7e1041bd72fcaec8ebd1427d4d111937571bf4cecac930d85db31074a3d3a0f96c1356c71fc751cd66353011e269ae76c3c48a72c8f575fcbc797a936e21bf4f295345edf188fda6a08c437f3171f9b5f830c23b9793c1a6f8928ef7410e4a6f37d185a3eee8d10c687eb4513fbda765607ce5afa57f8a4ed81b13b7a6df94540b105fea1e7956de57b2567e24bc73ac7c5502fc3b2287f6e9230f982e58b2b4448bb4130ef81d5e00a6a987ffb6d73219c0391bee3e564213f81a2852beeb40a5ac0f496a19af87ab12f971f90ebbd5532d343f32b1073d2562e48d7103b1a86151ef5df2536915688132c294b3578947f037c6436dd77d63bc33ec225d9ab1228e296df1b2f33750ed12b85a0e451c51e55a1bb5398b40dfd9d3a26887cb9b2540282adda194e93f9d07e21a7026d22e58f371b9f9e515f3b8b6f1351f9c42e35d643bf056e20a932a10d54ca40d62c880bdba97c696c4f6f7d889f65849def09b3deecf6934806213773629aa18cd477c22bab89bdde206c861281ce862a95e66dd01e3954c429bb85c18ee62e107512a87d7ee7950b6dcbf11a0593e7209ff6f9b4808b9a8fa640a3566a632ad86aa83e9e7b84f252077fc4191554995c0f88f882050176d58579bfd17adf3f85e36808e31ea0874b8a13a928d1b678db77e32d4583dd176faf52aecd214464455b8f57cd2d376646cbe9dd10fb5e25240c98c4346816c6c3be751390b6684ee7f16be1f89f98b3fb1cee35ec1995c036375385792af5bfa4a884b8b2a0f2c534facf4e2e333fd3d2ff9608c5f8c9dccef920a4a5df9c436c0bf20f4174146b523e70ec5af9ff178a16cc2fe80ee5b900312191f4cf99cf705c78293e183e717d748c49d9a96b31e6c286fd669787fc214e006f8c3ad94847e6972520c23cb521d2f0ad0547460cf4f2c25b1a7874ca018efc03a6362ade6603a29ff22490e6009346902554212a44219a7eb640fe1428b4b7939642575537aba9a29f022b4a400f503245acf830f9f4965d6e10284c2f32b14602acfb4692197cfe45c12283d866da99edbbf661e8f52392777c7850d5f889e788167a3edd08ac614503389c224bf8f2d0499171a23c5871548b769e99ec08de30eb08ece6989fef53786fe91b07139b03b1982c10d86cbb0e96b41976df17e1a6b5226603f3e734778773e76ca940529bbbca6d55b062441c5c42bd8ed280cb5cff3024c44d50db574c8c7089d9c07180d8c29f20c03ab4beb71ac122dd0f6c121da54c06296baaad38668af5bdf7b988d8b01c7029fb67fa0f2f69eb64aac897039dac3556f87688525ac47d5ab1302f34c0b776feca3d5b553e3ffeaef181d510a4d03b2e20930df7b965e450ba2630c9d76145956ed163f70d19c9ad5107f597573a884706a50141830520570e90e0fc50f654e266f13c6de5cc35746ef71fcdd6eb60da9739e1c1914908a46895b6d219abffd1189b0ef50b86dcfdbf4ab743c6b3f6c64c3a41f3c5a59a5d0c43bbeaf6ca8d124c294adf682c6289786fe1c1516dd29f61aa0fec908b107b67fff16c46e8010c631924701c994725d0c96cae59e9b51cc273def39b53e6b4fb0690871dc1ec58f8216821bb0536b7b639ac1ed855a9a45c07b534072f056b572c09282a636634e2ea00a69bca95e79e6da826e1356ec113977b69528cb426d1044b8058150024518e79b9cb9d6401b346e37da900ec7bd3688a55a758c882f5600bdf825bf922f43e9ee5d505016177e31033aea5befe6992d4141196e0979f4c386754fef88b28761cc26682494bd3a12442b2e7b10bfba61fc1c832c4309d74af1cb913a88575498acec7a636379a0db516bab2ec2860b7e25826a1b671c2a80f9194a3e555f61d6a82ff7e5a7804a92d709ad5da401a25b4786c0633efea1a1d60699a79056d3fa6c1e7a3868b14a0571bd726e6a4e61a82cf2b51b9d4002b5d5793412d3216e2d9ac4f95831aa84a16f9a5e5497b573d1e34d6426dc517b9e76afaeb11e943d14f3dbf830ffddd3e0f6ed92d56b0c7ca6112e3896a222b64675f54bbecc3c5149c5c683e2772c403f0779f1340ce350bbbbc8230ae972629a8567762a56506468889448a2f30fa0e965e8007c74da14604239af955b7fcd4548c91333562e4e297d2bb6e708970e8bd02f3250fb6d7ec1855f79f75ddda5dc7beee1a9c8def899642f7c2c92f1f87506a78844572a3adde7e5d23863cef2b93d27db939f758ac286cdcb07cf278eeca61638fc658b180c3fe973d67fdf171e100dc53a4582c2f26eb970fd84ef23c137d49e701c6a989615195a3c3ac32fa931d7e9a88bd0aac294f22c4c58cee8e1d836e59f5bf790960818fbab840fad6c25140703157c1e3f6cf3b35f0072f3ab41f214ac6b238efc1d9246a96063b08168296ccc7071407619ebecaca009d01da4f65711fba34abed725572e47392bfac740b2a176d3900b6f2dde52721f21ec2725890e687245c068620ee2620070021d54ba98f55416c099f2eda6b78305c19dac2660392e29e19c2f8220e577258b66822dcca3afa44a9a62c1646a091ed32b40758ccbfd9c5a9e5b31915baf4c6d44ff2bfd01c86fe4ae494b98e2a5c9d53c4dee5acc94a0ea36d8d862b1c6b8ca196af8ba77cc6f5f50689135a6b7f2f683b5bc12421f0cc558f6cda85d361d177eccfc05e8fce0da9649920e9efb050fef8519392a8fa40b023000bee7a2e771000381af2efb8fca570924e9129628542563579966da1c7b40b03c4f0edb5959d83df9f0e49935de83d92dbfaae02b18074bec2bc863c27da3b841d92b878dcf9f54d66c819033d9f263fe66d4c9e2878d4371cedeb9a181cda09c5011038b791d130c0b9816f6cddc0d4d674465977d699255821cafbfe2f48d84e065a1b86174fa042e5f372f57970c51b264bb4d7b80ddeffb2140b22e2d294fde9beac0145540ccd655a371cb9a0ff2e927ab940158371d5774ee9c1be2e6dc5120af16721d039ca855d3ce1c41cbea5a9c36c352ed672c5257ada6dc46ca3a532b2abf0568f73cbcb7cbeb4a5b33058b19235f4dd429fa537743ed7fd72547b9fa0321ff6d6ff1d1ce1e687b15d6f6c90895dee587b635aeb961ee9c06c1e52b8b3cd70b3add50c9fb1a186f4cdc03002b1407f987002da73be92a1982462b2fad53e92e751f5dd16ae4b97df05c054897caedc45e83f0a1d36320be4c4b42c6efdffc5b2720ff74469aa091603fc02e5651d6be2aa978c15b501c9cc2e1b0f2b3c9df97c65be65150a9b04945229cb87120ed435599a58360334e000b38075a557b124be2cd5399eda7a9f418516f8464464845c385ea036fc76521bfce6550f5113a0ef044862b50b01a2cde257c1f134eb2bfcfde880957be198c222d044af4d0ac86ea5ff99b837b3ae92ac8f4799dd768faba456c47d4575145ff1bcf84cac9b4bdeb6f8ccca1e1a0939951f84ae48dc4aa880a309443b9ec0bf94af2a843364a471e1fea482d9fbd231419a86365c1e53e6914aa23bd797e52b92ab7be0ffb7bd0ed3f4e75c64cc79c3dc1408c7bb12c9a480218870c4d3ff1987815b84b9bd4e80381649a04fa0f2befcc7940a42ad0796688ca86c61d471a3cf79b48d4072af72bf7c98825f09e9d4aae7b170283531467ee46c9b5b051769aedd0e357c21bbd92b5f73906a1d893d48267b8bc704a1fffc6dac5a604376bfdee6c93dea1856a1b9295a3b81d982b82004bd4eb01c9cf9347bbde0605034f7b0d45295fec392cbeabf6f2ebee705d03f32e78367a02f258adf4b079cbefee8febf71f35a3f27f33bb335ed4eaa15b4516b8bc70de738c488253a3bff94b3dfec8be3c8ceba004cb5f7f5f5424efbce4b3772c5b6440d8c800ecf1edf13ef4021e66117a5b611e9b04a4bdc3de412dba27f85ecac4148f458b0a96f444521e28e1ed18c5a40cb9ccbaa54a60810a66e7f4f2de0519e3bd06dd5df334f365731a8eb04c899158d7a63f3e2b673333b29a182b42e2e86a1d41264203b7b3121e6c1fcc5bd761fd0bc72f7d3f506fd04ace4131e42ab8044802a160dba7c23ba27fb75954d3c254b9701b43f1ea0e9327609087ced8360523d20260c7eb0d4eeeccf5f3095d74a9f517c187a586ab7b7f33ce3f0e5ee410257a5b8ee2351839aef687dea5b0c7db16daa4c8852e8d22a60598a3933493f6124038cf1cbd9a60d3fa9368e610aabca6af3cbb5f77616370c36398ab0bb8d7de2f14f7d6f149dfd282943b61dd6dd3c1e3f333d558389d8fce9d467e7d8e6c38778d5061db663e0b92e80cc7d07ef088811143c0c06bf3a3f9c0585d6a3ad1d4873c8024d06b955e0f7613fc24c3945a77b174cfb5973c00a8defd8a331e55d2c5272aa1ee7934dda411275cda8c0923defc7e738402fcf2341425a04728c40ca4b7fdfe476591daf9459800a61a09dabb070bfcbd45de6e9add3a8f891b8e5d630fc837bd3dacf8956e0ad21fb68faabb8eb00ae1f3eba5fac7460c4810aa0dc2db3e6a7be28ababad0a14fbd4ac1a7785d8865c025f7089b2bc7247674b3dfd6434df994428e9b7ee4be53d86b0e7339ed960f51cc458284a078a5e5768523da5d18cf9d9ffc7c36c12cd1bf9911b119d86ccd99521c41ff6397a4ed688e721a9d97c48b0871b6af3aa7d86a3c8bc2c6674e068531d2cde288efc2047fed9ff1f90ea2dc827f4d7fc933f40812aa8dd1c0fe518af9e3a5b9cac505e0156c3717b56e0c56d1d2f0f88f6f49a6911ae742383675f9dfe1440bc33fe25d8695641fc12a479bca5ebcdf127640f8ae70db3306900835c9d8c5634dcc13997df3b729348e205203312feccc584db9b94f9aa2d88f9e19813d9b509861adc7a3c8e307779cb139de65bbd63167fc9fa8ab1ffe2629080791d0d36fbec6af1c52553660718817f75a3eb901085dc80faca246f13d4a0b18fd6952128ec55e2f06b1352dc558fdddd5504c07897e7239c3877187f1b65bf4cce08f42b9fc6a8949dc13489225550665ce745b25a57cbf71e5f912339fb1e8c59e1f84977751327ecc35e3b17c540dad321e8f7f7fd5c96034e6d1abfbcb7bb2b3be7102c0a07e555ce6ba31001065375fe945cd8a3344558a2f8cccb7d9cbe76dd12097045eb0caa6d836724fcaad4414671dd257be056738d17c6a03b0af5a6b53d0376064373a0b40d746224bb90755f4b2bd0c03215000692efcb544b7b32a10a1ba1a9ccce627424b839dc07f48e9d0eb4ad12232ab9c2d51213863c69d460ad593d1dfb4165bd331a0ac3c34626b8f5c8806a62a7ca4bd78c7308526a92c18d42d6dd1dcc7bf95d89443005347ca76e72bfbd42a65f666e61447b45f1b4f88da12e27c0b14fb30cae1886ce1eae6fcb4b84058d5f190b103636889544f80e6337a4998b0ff1476c6a758e36daa4d9add245541ca8f9964f41498bbbc28cfc3346592f80463fba20dfd1cbf89ab7ed4cd8630e35524663900deb99dc2a871884f59668d908f11a37b767d89bb04dbac20ebdec6965e6151b793b0b83811c42b0346d6c84047432b9432df71aed83e6a1ae3af9bedd1bb9c710079f8ac5dff96c0bf36432097ecdd1bcdb5889d1c40256ebbee21b23627bf6b5c0ab57ba2cbceb5aa06b248c04765aeb9b50148da2d45a00cf280acbb35e15cfc6708e52c783d32940a6329879d076a5288cb2f40ac5e6c667f24770f358982553049f31a63127d4d98b255b7f5b56c6868d4488e44627bd44bf3a16fa7ee1672e1dc60a2f1dde87cc1af4474fdea9a9680c2edbae493f7c7f243dedce299ee3555d7e2959985e9ea51b10619bd0b3b47d12c8a5a829d5d818ccca3c3a004c4e0dae76aaea5b8a5e9a8f3a741c68f9f4ef4217dee17595a0535af442adac69aee9e899213910bd1b21bd7c9b88367d2ba5c38ebb16d0d58c427414f6bdda57d145559bb55d8dd11344a0e2a916b2c067410a9dae3cdb48dbd02c884f9acd7bb88ccff1f22be83da137d1f3006f0536aba5494b5e7b5ee42598c3c1fe0e86b50b28c752d639368f12e71cf6effce34461d437f4240e7d41803e020ade6dc6795bfa75bdb7f26b862b8209d770c45aa9dda2934f3ff2136880dcaf2166a0f7746f13c93fb730a821ff3a9cc4f99e28471f291d30131b0cacd54adda038a5f5ddd18499b80ca5769cf1d769a6e0f790de58fbe10facb3a70f0eb186688b2ab59396729422f4577cedf63a3bb79d7a62e071c73a2a65ea97f8a7e0f1a9f1b10ff00e77832f841c67cc932aa3dd841b46d602e56627e56a6ed5aacb040bedf3f0edfae500276b59f7f149c6303ee5b709dfeb90e2c7e9f24f277111dd16a4723b760d454af304418df87c65633eca4b17089dc6c32db9b64ec75e82a553306b634ae36adee8a851a2f802b2615e5964710dc44015a1920870479a2f8af92134a328b81508935796a97c3909bb1c2fa38cb39b53300280f59bfde0b434a08d9dcf17386f712879ab04c396e3669c490319c770b28f6a518d2187bfbf9535b6a819f03aef70766ebe2b22e6bb67ab364470e2d1d3d4f44fac058c4cd7da4f9b9939786d90f99c59fb28883642a14a6ced2f6fe0d7bf2241a7e14bd3cec85629ad228715d52c4b5095ba276e0c9e0bdf544b6f7322bf384c9cac27a08bc9bb88e8789a03dbc93851b0ba99cf002e0d81b1bae4236db1438ea25f3206113897cced52e53406ffaed7b91e024f42a16face62e222beaedeb1b3ee3ae8dd88f452a9a501b3ba5935ac0e800e7c9cf6d17e2a875038204de5d489907ef453a5a61d07cf878d60372a42353b97a06700967ef35c2660683e9c33848c9c6b827653a4aa45062969919cd63b8e96cf09f25c79616fbbc32d761408330b3da4b053edee8351a3f1cf3f5845996f3f9b17d510ba1492c7591123fbf52b934476397e9a59c7ed89aa97dcda8c3d09088ad828cd9194044482c1f08144b5d8f5328be47a28f56acf7bb541feb7e112e585fbb64b77e1416686a4a1297f80959dd9b997781e507bc59b86661cd09c21a56f8f671c9dc54c18176fffa40aa778afdadc8fb4586de353d63e67f4fef20a7102347546a2454a10d6cd515ed38c0a8dacc62e6f771969cda93bed3710df94dac47bf617d42749226c9419fa2278c49f45b5dd94d550d7a5343079d63eed98685ce6fa118b7922f5f0b8859e920dc1d7db5e1e87d2f9d29a1e3f43034e2d9e8acc8829d971677b0e31c68af84c5e899c5bf35b2b815027268098b23c37c22a4f59cc36887f512e37ef876f51174a5e72a9760f4d2d621f7f8bf1f503ae40398aed25c6c5c53eef6b21466fed458fbfd2974445114d0fa07ba6c0f2783c31148eb125a83e58a96a5072dc7479aef9c49ee338bc9c23f5a249bb29e99b5c49b42e94e8ec329413325cf0b4d603ea696d22af5e7de7cc07a4e5cb31739805bf7d756ea4b0c97e31a1325647d2c6a8b7ca9182b51ac5380f691a57f6b1b51494f88f30ecb628992e8517a75f46b23e03b0cc6042464b3864c872c9197f75f7af8c5fbeb89778434a5da2db86d69c148aa3db16c25f9c8830228e35bc45d8fcdf492d4bb9c4aa38683c500d71306d61f5363115166c9e26f551fe6675ed41d0c41d0e1acd14ffc7fa86e109c8c82edc49e42f4d406f91a4a0181aeeb779ebf4ee9915e3a6c368ae8ddad263d2b0c7483020d580edbef929b1004b9d028fd10e33819d626d36b7514b12f1bf0618144ab84fed7f0318b2ea314cf24b4c723ca260d6abc3edf0c174339bc28c1d2d5d9ff465df94568f36b33645797fcaf09d27980ecf42ace0e79fdcafba302b41bbcd71c06ac848d61f29a8f8f6046227847e50f03c8d351b4709e1cac619d8e56b4b1ea4a17e6bb96bec5b8af10007d93bb6eda15ce299e65be6a0526a1edc75f5fa216e35847b07193bcdd3c1d12454828e0f82212faeadb3e5893407251037f030f37d1875b12dea920f427e7fba5e3d1dbe9b399842e893a1fcbcf20b4bdeb00413c6fc00f110a31b50181fcb39c4539bc591084d2e138de9575d693bc2553343c17aafb91a72ef6e702a05455dfc2901339f6674298d08bd4b453fba94e9d742d9381c5af6d312f19d1a35716e53196d702c08e4afb92114473d661abb9b05a61f37c2171ecf0491b01516769cbde1c1e541597a4eb4fb81d8a6adfb4e581cccff2ab737bec496ebf045ab46a106fe5041bda2de254e988f29f7ae73d88b2238158fb4df835c722f1af80cd372ae0eb604d0e33bce6a221071f8b75be5317e823209917c857f72b83c0502726cee3e66d30e311af16932170a9d969470b118e57a2bcc56645c37a2440004423bda6d152bfbda7a4d32c22c3f29afa1c192906538825896cc3888f355dbf7cfae28900eb8ea0f0799a36246ac45fb2186fe7e609675cf0fae0c6152a8b2436a6ea2b2bde7b25ab14d7cb2299710bf4fd5962551ddb6b7ce13a536bdd15a01206b81f671edef0b1777dc6451ec696579bab5b9efbd624b1dd76e16cf00e1fa1bd4ec2d36db64579577acd73f83ed6fab2fdda46ed0ec6a38699da95434a26409fc1e95b8c3a5cad036570df511ed16a0643441accaa3693ceb2bb41ebda880b566b7a91f862b00f7a52b11803c9357cfbe9a5745591e478dc5aa5b089be48b6dd635e9cf28e48f601b58ede60d854b2043870882f70afc7222b107a6803caa9a0ee6e3d334068c5fafda8ade49d7e61a8a3d09cb7f34aa19a0643ca6c92af44b89702c9581112a9850f2e14cc79a13e730da2f6f759a01807221ed8a70d480e03c6938fe9d2e42204157463729c069e9165998505529b89045d2eebd0ab684b08b0d6e15cc76f2784ac00448887eb61a8424c9ee72f17a536b0ec6ad66a01602e5b074b3a586bca3b6f388798ee0a4308a23d3461d68332bed582096d500639a3884e1982c7a9967d10a172f360f3adf5f18bf129f4e3d77494c03ee3066ced49af5009b8d3be5aefcccc676f9b3bb01023f32d07f11820c110e3f2a8758d5f309b7e1bfb3ec52b42e939c4ebdee22be4359e4c3ef8ab39f281c54b0460ad0cec3989ded74680765d7dd36c6477d9b9cace3b4b6e54167eb612dc7637f99174d461d0dd353c50162af8688107e358bbf6d98c6f4a43af52cab696bbc34b007531ffbc6c111a3842df7376280eb61ae5886210afb199c4aff96ac9da26e2307200c166643753c015869ab9a7df4f868dfb6f0b43e8920ed4fe89ac2b1bb78f5a8dd8d633b86b9ac65f963f23b5a8dc4125aadb81f095663f0a707c666206e490ada2c87e9fb507586a428e71b292ff75fcf858b1959e1050302d5333567bd0bcdb663b3db94a60107f436703048d5541a11132337e3dd8c4888d9a002c5370ac6523881f89dff5cafc597f1cae3e50d38e81d6ea9c5325a9cfafe5fb41b7d054ff915531ba4c67e5f0a554caf47d4b0bf8f8f45ead6833b36024be4ec9a6c2ff19f19b9ed24b5f94691d3ba7ce51ebeed5207ac81bea9fa9b5f997e2b6d2b2b0df7b101d82d3d0fbbe88e5fce747061664a86cea9ac18c385805b35fedc33991c3279481cd51f8e6acc9b2c2e8c872a04607cf0d4836395c0eb8aea23a4075f62a49dcd92b83d5903da36ed9634b9c57382dd710b4e2c16667709d75396624511bf814a857cf4133b558641881075d5a5cea16f792314225065b7f75a71579506f4edc2bb8990dcb64fed15f1113cb5d3a481c16c2cebe02bea15113293956472adc27eb56dcc8c7cb10ec1a3b26f3205af03200c2ba62ddbfcf4f7e3f04023c871ce06f25da52279ecb1c5ff9e4755cca33a70abb3a41dd06ccbb7d27acae3afac7e23a989b068d7711cd28006229b1c65ed558933ef9365ba9b2833d3acdb40af53d6a34922b4882706008976823f68dd5b49e5842bf051a9e6fecafa51c30858c1bc239b96d7db81d4c4c528cb2cc7348e75fd2d82c14986b0b4eabb4e89907cf09702bcd6a80aed43231b96d96a43c58c47f6c4c20cfdfe50ca038e8cb17f8804510b98611f95bfe252d9fddb9853cc15a2db16eabf525dd20a88d7e51a28e55fc05f3049b0fc5c653653986154b61e9f7a43d45279373dde85c0c00025e5f9131564f2e7ee95182b4ee2e3caab6b1d245c9dfdc1ba92733647d1baae6f95b7ed1430c4f2f49d6d60798023994a696b9d755fe5a0eeb76f33ce0f76cb7779576824c226237a7c04c913a262e5034c67ab069f7789955243b485e8a1134d9e9d2df54bc4e35581678231198ccacbed6e64f74eb46374d416998da2d2f790b67616968fddd2f66b3aff90b7d31b57dc58b6a451126ea247b9227fee9f4812784f5d1fdd0c6415312c2437e65370d1fc0d6af75632bfa9491b42581dd1222d86a35a9b8c62b8a40c17cf498fc9c7b9e73a2fecee04fdf675384b827db211b337395f75044500b860ff57f74b728a3dec154dac8c02d4fad1c00595acd62cd2cc9f571ea85271339b3eefbb78d96859d08f7ca8dec81a4050f483abe690edb24b8e1aac153e66284086c6491050eb3ec9debcdb57aca8418e9e3a9ddad7e2ed418032c673b61790fc369e8a20985305fef7d1ab646dedb2bb698c5b39a980d647cfe91ae2357449a0f466273356403ba368a4193d330ef1fceca9884c1d409d4d4f7008a254d6ce93360c32da56f3eda993c12bd28f0ef88715a1687aac0fa21cbda8f1fc94b3afa5031be7b1960edff9ea50f6fec010454c793a080172e73dc558cb7579f93eefb82d4158859a436d0de49f498a828dff8f37aa7639fc26d9b4202705fcbb64e17655f8500ac3b2dded4c8236df87f21f1015f5104b34c467d76daf36bc3bbaf20129dabec018886ea57e52877b653cb2745e8f9f2a050260cc6a599f285b21d11404af5cc2d6484b6ee8c25fb0af3de368e0131b12faa5769692051eec5881f4b69491314596ba769f4fd0c16d3e6e32eba6dccdbd1f9f4312578f95d9f41a8e9f448749f19c75c41f4c85eb70bcce938f7bbf024e36ff958dc73eae7736122bed22190cde316cab43ee31bceb04e802c6f0c8130a21be986e6f01e5ae925acd4cf9ac8e3d1e06e0b2898e71173b46767dce530eaeb26d0118419a8aaa3c636482a4864fe012a12da762ec56067b081a81cd415fd4df9a021c9f0e439967f34af70d2c2643e3704743b8bc57f70df5410d1d13283ac343c4de171e0c1cd70477b076f9c731a514e0f1db7de2032ac09ac4f526668b0db18c4b8f828bcb52b22a18c27d4f75be45844e5e9e8e0781858a8e43cc4414cb635bcc030d1a03560635dab49d0737ed079f81de5c5459b5eba61e97ee210651a2cf880de6a5930f8f0827cafb1e6f8067522f2fb53f41b3f9fcfe8fa967fd49134a44c08332512d0bf194d18cdf20e88b0297cebfd4e6e2df2bf0b4fadac1957d99ff57aa651bd59854b17495c7d96b32de101389b27b488b944f5c9eeb40199bc4556a858395754f814fe80bc894357c779851375493c3cb8d8dd997a319d37b24a7fbf7743a4fd900988872a909a3a70cf26d3b13f2aafcc3be4a40bc35e66e37e20e7d817e71a1e724f6151909a4a1a2303bf1a4d5bcbe7aea43b88c607e9c0bf7d3e100624303dc8bb34364784db2081b3e8cc16077981d9b87e53250408237595d229a11eae01e3d166e3fed5a383d23e4dcef5fcc43c1c346951ebec9d81a82c143494ef5215f1a1e955da431eb7478cd9b4d9a8e82974628d9168be4fdc8ba118841ed02f132ab48a18377eb549d13935b3085ca80afed03686167d76701d15aab0679ff3215de87a5a28a6e4632607ca8680c29c9f7e6d8d31d762f87158cc971765f09b6038d25da0e290ef8020d4010380fb8c190f92f7e5a098e3b1206fa59bb04ab186f142b778f85f340a3f79944d06f7c2a8dcbf70681caabf38b680b138cabc6031b1a222ffd2b2ffdd03f5fc1bb8478fd6d35d84a772e932b6d57041ebfd7e4a356459d3dff446cabf067d649e1574dd78bfd9c7a5a77f71d6160f6c1c87b440d7345a5d4d734c3ac4954f5d4671691e4856bf56176f764c60283f254a682fff98c9b82839c3c72c3b9e7d0e9149fc0a8ce3ac530eb5909fefa213a8451424918e2586801b0ce7ee22a1dd2a85f5e14817b7e47b5f96766773886c23385669716f3e5cb1f82df136965dd6ea6ad12e49da817c5e0772cfefe80e12bd5a67fa05a89ae539c07ff7c1ccc038dfcbca44c42929a9942c1794928966ca700af0182c0565871948c4dbb94132033814adf5bd30cf5b57176e79c5914a39b7cfc3cfdbc0e9658b134353bd173f77975507ea10841446eff1917662b67792f98264731794e973eb9f999639dbe9717844dd864c88e9809390996bbac698f3f18999c91ab398196aea0cbf98f51aa2ef7add98da8d78af043d38978101ecf7b14e505c4cb00b7db664ba11f2e8691619a5e3afc19b1cae2e74226ef28e6800f345ab71f6d572bdde821e8d59e1930307e008f530b88eaffdf7795e15e5b1ee329c73ee669c17d5ae8fa8acbeb7a4c6ea3da33ce3035747c8316bb25da26c298dda9fec61e09d564a048f3684a267310f90ddacc0ad39577f425f7b90fac388408c0ed940cc6123eebfb3f2c4a7217c30b1b81fcbb7918a496c245c6b28179225cdf6779e805a444ea83a09663a98279597398c309b01007fb1e6830b5793774878abe30eabff6a91fcb6a933748be5317e54cffffecf828d7662d62a95b16da92b678b67628af2f57a88d1bd19849ebf7f725c52b8eaa41973588d8c6e04865f0eb71994eb4e2aadd27ea5735b8fe56107cda864a545b26dee7a049259186682ff080e9488b73122142eb21ce57c13a8de56e876c031cea03024fca8b2e789598271495e7548be0c884cbeef9cf9ead62f2c7abf5b2a07ade1ff284047663bfad76d34bc58a007df59c1e797f4e35e66504284cc9143ae932883c305b1c0ef1ffe44aeb6b49f2c529b056f75d9e6b5d79632d2b41efc42e0a49145b11e031184961b8d7e7b6ebaf200287714ca3f68aaf21f60aa286ff44b8d323567c047363cd04bf4c2d37083a77d1b3fc0196b732a7bdcd1cb156ef9bb6c448b1e53c3520fda502629fe3c028f75429bce4734a93c5ec791eaa637610a5ca6868731af1fdb176de514b03613d07e6469287d8e975d6dbf52995ea60533c65774172740f3ddf2c3f5424011669b0f5a26ffd856da7f3e732e5b8f43632c390a02e1d7ac33685bbb74c71610a9b3f6df6e80211efc540394d92cd68dc90f461470aa5161db65b1e821626d1f2504e6520c346d87330199f89805ddfd684234638b27c503a28a3e67a848ce8e778d0381f687f3b21d2690aa3417211fc9336ed887de3c1628077167824c485e78db5c0a1667fd0adba4ce155b04e65d9cf1ede9de42410efc4b372957bf1cadbecbef63bd10a31d42755b8951c224afbaaf477b2e4a9515ed05fdeaf47f2a27c33c51e173f893fc9ac84053d27d250ab037c3d997783d539938197179ae43f80d1e4c9563c7c7c9609f361bd40929b3073ace22da267a29be06ab758b42964de9d73b5597c932d20ca64d71a2bf1097e521230d7b20d834ea147d61d9da2188d40f200d4c24ed326ad98d0aa1b484fe72c6664dd1899e8b5ef53db26e7887a0e2e104c4574dcdf6b8f2b21bf81a5fb42d89ceebb87293b48db8cb069ff1e4a8cf9055d1295d27351604cdba2d201369569895df4ec1e624e7f46337c85d2cf9cd04e58c09e4c0f51bf1f285b5b9d0bd0d3a69548e0e46f71897de0efe7b51943706ccb72479298b5e658b5147be8a095a7e5f260656c70f3105a2a38b9b0883d60d54269bb0590b0b84f4e2ff349f0014cbd5d60e25976d5f050731bce0a101f296ccf005e8170dccc56f0202bd4b43261d861d408b3c1b483391c186a55533ff8add6c33ac76db9b5170b9ed9023f605d911f458c07fe05bbd49813222c6673a1f69a6d6fd6296251c5e6efe74dfb7a46182200f4a3f0971463cafdfb1cd1179d2336d29a2c7ee041e9f3ae86ddf0a3d8094649500c40bfae2b4be93241b8aed106bf0e75e124cc9eae2817a075ba2192f49f887ada96dd6c01098caa3e063400473477995d464f3886be6a758587bbfd0efed1c4d9795c942dd08d2b915c47b545a2986142b9dcc0ed542247caabf0eeb583389f00e12464703093d313522478bd5dafd4854f3cd60dfffb6e1ee402c7b9b9f776a419a36016b370a89515cc3b26e6de6662e3c98e4030f956f040e61ba391a4dc96c3a8d936a36f6f5c40a2903a222bb349bab11735c0c9f4a370a71f1edffa0ca24771ba824a783d33a36284ee516b331208a4221a03fbdff190ae7fd7c8b66d4b7b647b6fea0dc3cf00a5525325ea598771d992ea57d892bd73c24fef3688b2c277fca2b046afd40c0b943eded80ebf39191019d211f599ad05619d14135f04c7debb056040a5e11b906c0bd636208c7cead2c6f13f0de29c2e6b88995bc651ca14536c6dfa19eb0e70f75374e7d999126675355abf65bc51c8041e33306b7ea200f37396a2815e3a22954c69038c684a3262e12f9f411b9f9528b2a3656212f6abbb5a5803f164eacbd23b376ddd2c26cc86c6446f9d31e5a540867f0009e7db061c1d6e37cf568d970e1f7bd3c0e1ba95228e056a551b398a1cba3149c5314d7f2ffd37b2ed1068aa35b5c94ad50e949b0d2b316efa163f988bef7b75d6e040b6ed3138edfa6f8d445982c44b478492635b054b1a8ec493f3e2fbb2a042d22073396d9a74a9e76308ab1f5a03ad78f31bb1ddca89cf510f7fb60bc3dc9961fd0c5ccfa259664bf8aa8aaf15b135514eccba7302c34e4b64898a24ae1bf12a04af55e46809a00866b8ca823c12ca6956ecf5fa1261e3d549116ac8b8cf98b73e1bc75b8a7a9bd7828dd850449bdd7747bbf33d9605e02e486266324dfb570ad8cb54d49fe3c088cb7f5942f28b839c744c9b19b4ff4d1cd5b199c17a7d426b06a58a517711f1afd87279170d480b2297f4565315af3c97e85f08145afcf1753f076410d9a02a7c09fdf92bc744e0902585af615cfa97dc6a88c293c0715355e3adf2d7ffad280bba33d12cce2d9da4e5b61792d36df41d6504bbf90cb1a96784e7b633a26594d1cefc08fd092e999bae0ba4c445fb0734443273fb3db7c7d4a47d404fbef2313f8b9d975353544452738d2eb1da18774f5cef784cfcae6f1703ae3d41de8c3b38432681b977f48a0841bb4286fd33cafc41cba19e107f2021868be8ad6ca5cb310a75d4c8d04a32636500c491530c4c5ac63af61dae76c33762d5ce14014f23c150255dc3c8646e6d112978c83a2f2dc3cf8892ea6abbe6cc2bbeeb38c93af8dd24a89f258304d2108645cd74dc82e6a74d5c93d48bb14536039b1c8ff562d9fe186502a90771da17048ae23a21088dc929b94d1f985462bccd9f2ee8c4d9d7a35505e794c62b298484f09b7a15187ac8151df0f7bcdfa7d049bb1eca5bbbaea701b4c14320df121e19919b1544d27008a3def6cd3b6bb2c81fd700750d013e3818b9248ec06e7b78368101de9a69e71d22e61cdd0c08de40dc54d2af107e33b9fbee98622ad3f0728fb8caa9095b52f1528840fa1b77115fb3025be3ca2b94b09a655440ceba4e000f51fa5fa404813f35d02f518f2a768e48dacbb2c295a02f5a20bf8fcad2e6a63b58d0ff4488230479fa99045b4cfa95e044543307ed4df218a741b216e90dcd3fd4f209cc2da7636f939623777e78790fcd332617d7d25942cc098ecf59cc4bf68d8e9ae2bd99dd5aa0094d5bf2c9a8ddef3424f586527d2e2d381cfe39210fa1d6526d6dfd1f3052f556962cfdde3b936792bf801040a818fe1da25449a1e66c12a06413b12760d77bb37b430be3340847f74b5225821996a7b8e536c1f33a75ec30a7fbab5668c912f48321759924eadb15d031b4d3b29099a6ae8c35c3caa534f2f103e4b3d54c9dc011adaa2e56dc6237dc3e01bd79b1fecfdc48d9c105ce59ff17dc1b728f8bb8ac7a4ac6a9a64ed84eba5a0754e2055d65c555ec3c713c0ee841aa965a1d3b1790d624e0691a8d1d1664d1a0da0991379ef180da9fe96306d05825231b59559c0cf36ea8ab6ea26076ca2430bd594f6326ff1eea03d46d786f060131a766253f7bc26acbf343a7a8bddfa41beedd385e1a2e360b9be7d40b30bf661203c09e2d9745395405079af3fb5c5757fe4d22d1a6a4cf05067ef2a84631cd9c765418de6f65a63452581b3547d51c998fd81c9d37f99879b2e4cb520bbf2d4609c7aa7abb2be405d726585473045022100b5ab57821ae8ee2d5d40470a973677ac39e451bd75cfec720d6ad3c210004ae9022015e735795d7e1ad14a5bd3ef17f88cba33e2fcbd8b8e1747ba885ba832abf6d16d75c8000000000000001976a91474554560513fc8310b70ce00b3ccc330d6e14be888ac974a0000000000001976a914f6ad38864bc27ffc5d8cfac952ea128f5412c46f88ac000000000100',
  // 1
  '0100beff01fe83e5'
]

const beefs0Log = `BEEF with 1 BUMPS and 1 Transactions, isValid true
  BUMP 0
    block: 1631619
    txids: [
      'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
    ]
  TX 0
    txid: bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07
    bumpIndex: 0
    rawTx length=12719
`

const log2 = `BEEF with 1 BUMPS and 2 Transactions, isValid true
  BUMP 0
    block: 1631619
    txids: [
      'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
    ]
  TX 0
    txid: bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07
    bumpIndex: 0
    rawTx length=12719
  TX 1
    txid: e002e4b69ab071c42796c0e92241d5ce7c16749ae8f41427d19007044bcb55f3
    rawTx length=1455
    inputs: [
      'bd4a39c6dce3bdd982be3c67eb04b83934fd431f8bcb64f9da4413c91c634d07'
    ]
`

const wrongBumpTxid = '0100beef01fe4e6d0c001002fd909002088a382ec07a8cf47c6158b68e5822852362102d8571482d1257e0b7527e1882fd91900065cb01218f2506bb51155d243e4d6b32d69d1b5f2221c52e26963cfd8cf7283201fd4948008d7a44ae384797b0ae84db0c857e8c1083425d64d09ef8bc5e2e9d270677260501fd25240060f38aa33631c8d70adbac1213e7a5b418c90414e919e3a12ced63dd152fd85a01fd1312005ff132ee64a7a0c79150a29f66ef861e552d3a05b47d6303f5d8a2b2a09bc61501fd080900cc0baf21cf06b9439dfe05dce9bdb14ddc2ca2d560b1138296ef5769851a84b301fd85040063ccb26232a6e1d3becdb47a0f19a67a562b754e8894155b3ae7bba10335ce5101fd430200e153fc455a0f2c8372885c11af70af904dcf44740b9ebf3b3e5b2234cce550bc01fd20010077d5ea69d1dcc379dde65d6adcebde1838190118a8fae928c037275e78bd87910191000263e4f31684a25169857f2788aeef603504931f92585f02c4c9e023b2aa43d1014900de72292e0b3e5eeacfa2b657bf4d46c885559b081ee78632a99b318c1148d85c01250068a5f831ca99b9e7f3720920d6ea977fd2ab52b83d1a6567dafa4c8cafd941ed0113006a0b91d83f9056b702d6a8056af6365c7da626fc3818b815dd4b0de22d05450f0108009876ce56b68545a75859e93d200bdde7880d46f39384818b259ed847a9664ddf010500990bc5e95cacbc927b5786ec39a183f983fe160d52829cf47521c7eb369771c30103004fe794e50305f590b6010a51d050bf47dfeaabfdb949c5ee0673f577a59537d70100004dad44a358aea4d8bc1917912539901f5ae44e07a4748e1a9d3018814b0759d00201000000027b0a1b12c7c9e48015e78d3a08a4d62e439387df7e0d7a810ebd4af37661daaa000000006a47304402207d972759afba7c0ffa6cfbbf39a31c2aeede1dae28d8841db56c6dd1197d56a20220076a390948c235ba8e72b8e43a7b4d4119f1a81a77032aa6e7b7a51be5e13845412103f78ec31cf94ca8d75fb1333ad9fc884e2d489422034a1efc9d66a3b72eddca0fffffffff7f36874f858fb43ffcf4f9e3047825619bad0e92d4b9ad4ba5111d1101cbddfe010000006a473044022043f048043d56eb6f75024808b78f18808b7ab45609e4c4c319e3a27f8246fc3002204b67766b62f58bf6f30ea608eaba76b8524ed49f67a90f80ac08a9b96a6922cd41210254a583c1c51a06e10fab79ddf922915da5f5c1791ef87739f40cb68638397248ffffffff03e8030000000000001976a914b08f70bc5010fb026de018f19e7792385a146b4a88acf3010000000000001976a9147d48635f889372c3da12d75ce246c59f4ab907ed88acf7000000000000001976a914b8fbd58685b6920d8f9a8f1b274d8696708b51b088ac00000000010001000000018ae36502fdc82837319362c488fb9cb978e064daf600bbfc48389663fc5c160c000000006a47304402204a04841f6f626d30e21200e1c404ea80e319b643fe86f08e709413a89a493a4b022038a2e3e25a813d8d540c1a572fa8ec5fa2d2434bcea78d17902dcccddcc1c9484121028fd1afeee81361e801800afb264e35cdce3037ec6f7dc4f1d1eaba7ad519c948ffffffff01c8000000000000001976a9148ce2d21f9a75e98600be76b25b91c4fef6b40bcd88ac0000000000'

const bumpIndexEncoding = '0100beef01fe6e621900010200008cdbd6fe227cfafa6be4500cae6140c84b2ead61318063e92bdb6974f869cf33010259617a9d17562f7c9765e5dfa6a9a393aa2809ca6166a3d7a31c09efcc50701402010000000159617a9d17562f7c9765e5dfa6a9a393aa2809ca6166a3d7a31c09efcc507014130000006b4830450221009399820c643e5f2699b07ffa3289b22c6124e1317fd1ec41fb2431047dcf552f02201b7ee3ee3422fe1c33d8869a34a28fadddb9b790b3c5b332b7fafaaa8d4b413c4121029b15053bc379e2378cd6a84fb40b761b4e400faa4efd09280443731d4b3f8a8cffffffff0201000000000000001976a91423f2562a8092ed24eddc77c74387b44c561692a188ac03000000000000001976a9144ed83e2b3aae481f7fa48321024eb3d8e1f7417888ac00000000000100000001ee353cb1f4cb2b19bf7d2328f3c0a5fa2bd1aa94d0795934dd1d63756583b0ac000000006b4830450221009e779c3f04bb056da180b50ad3972b6fd552c52bd6337f572f08ca656625a4530220648e1fc5872d9bc3846f78edd79b4dc406dfecbab359e46b53c7d478747141684121022280e60c665907fb88a97f5e74dd4e1db0eba60a4dad18158ea8eb9495e242daffffffff2005000000000000001976a914e073bf1bf7b6160f7f68403a374717fdc4cce86d88ac4a000000000000001976a9145bbe83249067ec745d8e270c121c651f56ec2cf188ac42030000000000001976a914983a29113517769da9eace0ec25b760ad09c5f5988ac05000000000000001976a91402c75f3ec99db76e6cd2658a7c83c8bf21a0d14b88ac05000000000000001976a914de454fbce4e1be341d11cd5545664771f72d184088ac25000000000000001976a914b5c2a6831b5cdbc8985517f5d912064449ad118088ac3d010000000000001976a914e4566d91c063f99f7418f12d670b5da320160c8188ac05000000000000001976a914616dc74c3945895eafdac8da9174f95b4d91d75b88ac03010000000000001976a91476ae1c3f2c01a9a5f2aa7696cc9b89ea55b0d01688ac0d000000000000001976a9146d805d21013cc20351e5cd55ecaa7dcee59f2fde88ac05000000000000001976a914613408f68bdde1ff3f77a96abd4956a472766acf88ac21000000000000001976a914d7f0bcfa5b5cad93574a960627db60af8dac277c88ac05000000000000001976a9147e088fe21413442569fa59b6a5bf7e8fe6db71e388ac05000000000000001976a914e5ff336cbffc4ffef544ff4d131de68bf9b0aa1488ac05000000000000001976a9142145b563cd2766ba08d33ca0ecb5a6679268dfb788ac05000000000000001976a914da990487dff4910c8891cebcd00a569011f4f05188ac05000000000000001976a914100daf8fa5add521fb87b46ff51657728626c5fe88ac07000000000000001976a914de900668ddecd73f498c8560b8770231bef9616b88ac05000000000000001976a914dd08ccc14ebdcc534bb2320e7d3dba624a7ecd5388ac05000000000000001976a9141c5b5915e67a840fdcefd0db0ca1a1dfaaf4f3cf88ac06000000000000001976a91441815c6352756937fe6b2b17586dd6b39560321188ac05000000000000001976a91471dca8f8631f145ad5721f8387a764ae0ef2599888ac1d000000000000001976a9147e2621372c66ca3c6e6fca8cdb7eac42405d37fe88ac05000000000000001976a914d745ec07218bde8d179d49e4a6feca7f744f57e388ac05000000000000001976a91499456246822c4270ae73d6c7d8e1af690d1d31dd88ac05000000000000001976a914176dc7f479059d28593021e63bcb66bae6c2cc5388ac05000000000000001976a914a48809ce3c763a0a34c24ab2646fdf10cffdbc6588ac05000000000000001976a914e314da9f12f6bd888da53faa616890a2dce9eeb488ac05000000000000001976a91418f9185bb0ca144d934bd4845b3968d545e7ec8188ac17010000000000001976a9149db831932668077f8eebf597976ec61fc6ab90d588ac09000000000000001976a91479b349601390a6216994d44ca618db71e6e811ef88ac06000000000000001976a91451d25ac626a4b7c281b4200a3dcf34caae43f0df88ac000000000100'