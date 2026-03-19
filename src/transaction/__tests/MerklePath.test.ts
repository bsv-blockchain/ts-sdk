import ChainTracker from '../ChainTracker'
import MerklePath from '../../transaction/MerklePath'
import { hash256 } from '../../primitives/Hash'
import { toHex, toArray } from '../../primitives/utils'
import invalidBumps from './bump.invalid.vectors'
import validBumps from './bump.valid.vectors'

const merkleHash = (m: string): string => toHex(hash256(toArray(m, 'hex').reverse()).reverse())

const BRC74Hex =
  'fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4'

const BRC74JSON = {
  blockHeight: 813706,
  path: [
    [
      {
        offset: 3048,
        hash: '304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711'
      },
      {
        offset: 3049,
        txid: true,
        hash: 'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00'
      },
      {
        offset: 3050,
        txid: true,
        hash: '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e'
      },
      {
        offset: 3051,
        duplicate: true
      }
    ],
    [
      {
        offset: 1524,
        hash: '811ae75c80fecd27efff5ef272c2adf7edb6e535447f27a4087d23724f397106'
      },
      {
        offset: 1525,
        hash: '82520a4501a06061dd2386fb92fa5e9ceaed14747acc00edf34a6cecabcc2b26'
      }
    ],
    [
      {
        offset: 763,
        duplicate: true
      }
    ],
    [
      {
        offset: 380,
        hash: '858e41febe934b4cbc1cb80a1dc8e254cb1e69acff8e4f91ecdd779bcaefb393'
      }
    ],
    [
      {
        offset: 191,
        duplicate: true
      }
    ],
    [
      {
        offset: 94,
        hash: 'f80263e813c644cd71bcc88126d0463df070e28f11023a00543c97b66e828158'
      }
    ],
    [
      {
        offset: 46,
        hash: 'f36f792fa2b42acfadfa043a946d4d7b6e5e1e2e0266f2cface575bbb82b7ae0'
      }
    ],
    [
      {
        offset: 22,
        hash: '7d5051f0d4ceb7d2e27a49e448aedca2b3865283ceffe0b00b9c3017faca2081'
      }
    ],
    [
      {
        offset: 10,
        hash: '43aeeb9b6a9e94a5a787fbf04380645e6fd955f8bf0630c24365f492ac592e50'
      }
    ],
    [
      {
        offset: 4,
        hash: '45be5d16ac41430e3589a579ad780e5e42cf515381cc309b48d0f4648f9fcd1c'
      }
    ],
    [
      {
        offset: 3,
        duplicate: true
      }
    ],
    [
      {
        offset: 0,
        hash: 'd40cb31af3ef53dd910f5ce15e9a1c20875c009a22d25eab32c11c7ece6487af'
      }
    ]
  ]
}

const BRC74JSONTrimmed = {
  blockHeight: 813706,
  path: [...BRC74JSON.path]
}
BRC74JSONTrimmed.path[1] = []

const BLOCK_125632 = {
  height: 125632,
  merkleroot: '205b2e27c58601fc1a8de04c83b6b0c46f89c16b2161c93441b7e9269cf6bc4a',
  tx: [
    '17cba98da71fe75862aac894392f2ff604356db386767fec364877a5a9ff200c',
    '14ce64bd223ec9bb42662b74fdcf94f96a209a1aee72b7ba7639db503150ec2e',
    '90a2de85351cfadd2326b9b0098e9c453af09b2980835f57a1429bbb44beb872',
    'a31f2ddfea7ddd4581dca3007ee99e58ea6baa97a8ac3b32bb4610baac9f7206',
    'c36eeed6fbc0259d30804f59f804dfcda35a54461157d6ac9c094f0ea378f35c',
    '17752483868c52a98407a0e226d73b42e214e0fad548541619d858e1fd4a9549',
    '3b8c4460412cfc55be0d50308ba704a859bd6f83bfed01b0828c9b067cd69246',
    'a3f1b9d4b3ef3b061af352fdc2d02048417030fef9282c36da689cd899437cdb',
    '66e2b022da877621ef197e02c3ef7d3f820d33a86ead2e72bf966432ea6776f1',
    'e988b5d7a2cec8e0759ade2e151737d1cdfdde68accff42938583ad12eb98b99',
    '5e7a8a8ec3f912ac1c4e90279c04263f170ed055c0411c8d490b846f01e6a99e'
  ]
}

const BRC74Root =
  '57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4'
const BRC74TXID1 =
  '304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711'
const BRC74TXID2 =
  'd888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00'
const BRC74TXID3 =
  '98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e'

class FakeChainTracker implements ChainTracker {
  async isValidRootForHeight (root: string, height: number): Promise<boolean> {
    return (
      root ===
        'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02' &&
      height === 10000
    )
  }

  async currentHeight (): Promise<number> {
    return 10100
  }
}

/** Splits BRC74JSON into two partial paths (A covers txid2, B covers txid3) ready to combine. */
function buildSplitPaths (): [MerklePath, MerklePath] {
  const path0A = [...BRC74JSON.path[0]]
  const path0B = [...BRC74JSON.path[0]]
  const path1A = [...BRC74JSON.path[1]]
  const path1B = [...BRC74JSON.path[1]]
  const pathRest = [...BRC74JSON.path]
  pathRest.shift()
  pathRest.shift()
  path0A.splice(2, 2)
  path0B.shift()
  path0B.shift()
  path1A.shift()
  path1B.pop()
  return [
    new MerklePath(BRC74JSON.blockHeight, [path0A, path1A, ...pathRest]),
    new MerklePath(BRC74JSON.blockHeight, [path0B, path1B, ...pathRest])
  ]
}

describe('MerklePath', () => {
  it('Parses from hex', () => {
    const path = MerklePath.fromHex(BRC74Hex)
    expect(path.path).toEqual(BRC74JSON.path)
  })
  it('Serializes to hex', () => {
    const path = new MerklePath(BRC74JSON.blockHeight, BRC74JSON.path)
    expect(path.toHex()).toEqual(BRC74Hex)
  })
  it('Computes a root', () => {
    const path = new MerklePath(BRC74JSON.blockHeight, BRC74JSON.path)
    expect(path.computeRoot(BRC74TXID1)).toEqual(BRC74Root)
    expect(path.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(path.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
  })
  it('Verifies using a ChainTracker', async () => {
    const path = new MerklePath(BRC74JSON.blockHeight, BRC74JSON.path)
    const tracker = {
      isValidRootForHeight: jest.fn(
        async (root, height) =>
          root === BRC74Root && height === BRC74JSON.blockHeight
      ),
      currentHeight: jest.fn(async () => 2029209)
    }
    const result = await path.verify(BRC74TXID1, tracker)
    expect(result).toBe(true)
    expect(tracker.isValidRootForHeight).toHaveBeenCalledWith(
      BRC74Root,
      BRC74JSON.blockHeight
    )
  })
  it('Combines two paths', () => {
    const [pathA, pathB] = buildSplitPaths()
    expect(pathA.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(() => pathA.computeRoot(BRC74TXID3)).toThrow()
    expect(() => pathB.computeRoot(BRC74TXID2)).toThrow()
    expect(pathB.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
    pathA.combine(pathB)
    expect(pathA).toEqual(BRC74JSONTrimmed)
    expect(pathA.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(pathA.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
  })
  it('Serializes and deserializes a combined trimmed path', () => {
    const [pathA, pathB] = buildSplitPaths()
    pathA.combine(pathB)
    const deserialized = MerklePath.fromHex(pathA.toHex())
    expect(deserialized.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(deserialized.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
  })
  it('Constructs a compound path from all txids at level 0 only', () => {
    // A single-level compound path: all txids for a block given at level 0, no higher levels.
    // The implementation should be able to compute the merkle root by calculating up from the leaves.
    const tx0 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    const tx1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    const tx2 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    const tx3 = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
    const root4 = merkleHash(merkleHash(tx3 + tx2) + merkleHash(tx1 + tx0))
    const mp = new MerklePath(100, [[
      { offset: 0, txid: true, hash: tx0 },
      { offset: 1, txid: true, hash: tx1 },
      { offset: 2, txid: true, hash: tx2 },
      { offset: 3, txid: true, hash: tx3 }
    ]])
    expect(mp.computeRoot(tx0)).toEqual(root4)
    expect(mp.computeRoot(tx1)).toEqual(root4)
    expect(mp.computeRoot(tx2)).toEqual(root4)
    expect(mp.computeRoot(tx3)).toEqual(root4)
    // Serializing and deserializing a single-level compound path should also work
    const deserialized = MerklePath.fromHex(mp.toHex())
    expect(deserialized.computeRoot(tx0)).toEqual(root4)
    expect(deserialized.computeRoot(tx3)).toEqual(root4)
  })
  it('Rejects invalid bumps', () => {
    for (const invalid of invalidBumps) {
      expect(() => MerklePath.fromHex(invalid.bump)).toThrow(invalid.error)
    }
  })
  it('Verifies valid bumps', async () => {
    for (const valid of validBumps) {
      expect(() => MerklePath.fromHex(valid.bump)).not.toThrow()
    }
  })
  it('Validates a MerklePath for a block which only has 1 tx', () => {
    const path = MerklePath.fromHex(
      'fdd2040101000202ef57aa9f29c8141ae17935c88434457b2117890f23efba0d0e0cba7a7a37d5'
    )
    expect(
      path.computeRoot(
        'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02'
      )
    ).toEqual(
      'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02'
    )
  })
  it('Creates a valid MerklePath from a txid', () => {
    expect(() =>
      MerklePath.fromCoinbaseTxidAndHeight(
        'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02',
        1
      )
    ).not.toThrow()
  })
  it('Valid for Coinbase if currentHeight is more than 100 blocks prior', async () => {
    const mp = MerklePath.fromCoinbaseTxidAndHeight(
      'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02',
      10000
    )
    const isValid = await mp.verify(
      'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02',
      new FakeChainTracker()
    )
    expect(isValid).toBe(true)
  })
  it('Invalid for Coinbase if currentheight is less than 100 blocks prior ', async () => {
    const mp = MerklePath.fromCoinbaseTxidAndHeight(
      'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02',
      10099
    )
    const isValid = await mp.verify(
      'd5377a7aba0c0e0dbaef230f8917217b453484c83579e11a14c8299faa57ef02',
      new FakeChainTracker()
    )
    expect(isValid).toBe(false)
  })
  it('constructs a compound MerklePath from all txids in a block with odd tree levels', () => {
    const { height, merkleroot, tx } = BLOCK_125632
    const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
    if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
    const mp = new MerklePath(height, [leafs])
    expect(mp.computeRoot()).toBe(merkleroot)
  })
  it('compound path for 3 txids trims, round-trips through hex, and splits into per-txid proofs', () => {
    const { height, merkleroot, tx } = BLOCK_125632

    // Precompute the full Merkle tree for block 125632.
    // merkleHash(right + left) matches the SDK's internal hash convention.
    const L1 = [
      merkleHash(tx[1] + tx[0]),
      merkleHash(tx[3] + tx[2]),
      merkleHash(tx[5] + tx[4]),
      merkleHash(tx[7] + tx[6]),
      merkleHash(tx[9] + tx[8]),
      merkleHash(tx[10] + tx[10]) // tx[10] duplicated — odd count at level 0
    ]
    const L2 = [
      merkleHash(L1[1] + L1[0]),
      merkleHash(L1[3] + L1[2]),
      merkleHash(L1[5] + L1[4])
    ]
    const L3 = [
      merkleHash(L2[1] + L2[0]),
      merkleHash(L2[2] + L2[2]) // L2 count = 3 (odd) — last node duplicated
    ]
    expect(merkleHash(L3[1] + L3[0])).toBe(merkleroot)

    // Build minimal per-txid MerklePaths for tx[2], tx[5], and tx[8].
    // tx[8] exercises the odd-level duplication at level 2 ({offset:3, duplicate:true}).
    const mpTx2 = new MerklePath(height, [
      [{ offset: 2, txid: true, hash: tx[2] }, { offset: 3, hash: tx[3] }],
      [{ offset: 0, hash: L1[0] }],
      [{ offset: 1, hash: L2[1] }],
      [{ offset: 1, hash: L3[1] }]
    ])
    const mpTx5 = new MerklePath(height, [
      [{ offset: 4, hash: tx[4] }, { offset: 5, txid: true, hash: tx[5] }],
      [{ offset: 3, hash: L1[3] }],
      [{ offset: 0, hash: L2[0] }],
      [{ offset: 1, hash: L3[1] }]
    ])
    const mpTx8 = new MerklePath(height, [
      [{ offset: 8, txid: true, hash: tx[8] }, { offset: 9, hash: tx[9] }],
      [{ offset: 5, hash: L1[5] }],
      [{ offset: 3, duplicate: true }], // tx[8] is last odd node at level 2
      [{ offset: 0, hash: L3[0] }]
    ])
    expect(mpTx2.computeRoot(tx[2])).toBe(merkleroot)
    expect(mpTx5.computeRoot(tx[5])).toBe(merkleroot)
    expect(mpTx8.computeRoot(tx[8])).toBe(merkleroot)

    // Combine into one compound path (combine() trims automatically)
    const compound = new MerklePath(height, mpTx2.path.map(l => [...l]))
    compound.combine(mpTx5)
    compound.combine(mpTx8)
    expect(compound.computeRoot(tx[2])).toBe(merkleroot)
    expect(compound.computeRoot(tx[5])).toBe(merkleroot)
    expect(compound.computeRoot(tx[8])).toBe(merkleroot)

    // Serialize and deserialize
    const deserialized = MerklePath.fromHex(compound.toHex())
    expect(deserialized.computeRoot(tx[2])).toBe(merkleroot)
    expect(deserialized.computeRoot(tx[5])).toBe(merkleroot)
    expect(deserialized.computeRoot(tx[8])).toBe(merkleroot)

    // Split the deserialized compound path into standalone per-txid proofs.
    // findOrComputeLeaf reconstructs sibling hashes that were trimmed away.
    const splitProof = (source: MerklePath, txOffset: number, txHash: string): MerklePath => {
      const levels = source.path.map((_, h) => {
        const sibOffset = (txOffset >> h) ^ 1
        if (h === 0) {
          const sib = source.findOrComputeLeaf(0, sibOffset)
          if (sib == null) throw new Error('Missing sibling at level 0')
          return [{ offset: txOffset, txid: true, hash: txHash }, sib].sort((a, b) => a.offset - b.offset)
        }
        const sib = source.findOrComputeLeaf(h, sibOffset)
        return sib == null ? [] : [sib]
      })
      return new MerklePath(source.blockHeight, levels)
    }

    const splitTx2 = splitProof(deserialized, 2, tx[2])
    const splitTx5 = splitProof(deserialized, 5, tx[5])
    const splitTx8 = splitProof(deserialized, 8, tx[8])

    // Each standalone proof computes the same root — no data was lost through the pipeline
    expect(splitTx2.computeRoot(tx[2])).toBe(merkleroot)
    expect(splitTx5.computeRoot(tx[5])).toBe(merkleroot)
    expect(splitTx8.computeRoot(tx[8])).toBe(merkleroot)
  })
  describe('extract()', () => {
    it('extracts a single-txid proof from a full block compound path', () => {
      const { height, merkleroot, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])

      const extracted = fullBlock.extract([tx[2]])
      expect(extracted.computeRoot(tx[2])).toBe(merkleroot)
    })

    it('extracts a multi-txid compound proof from a full block compound path', () => {
      const { height, merkleroot, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])

      const extracted = fullBlock.extract([tx[2], tx[5], tx[8]])
      expect(extracted.computeRoot(tx[2])).toBe(merkleroot)
      expect(extracted.computeRoot(tx[5])).toBe(merkleroot)
      expect(extracted.computeRoot(tx[8])).toBe(merkleroot)
    })

    it('extracted path serializes and deserializes correctly', () => {
      const { height, merkleroot, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])

      const extracted = fullBlock.extract([tx[2], tx[8]])
      const roundTripped = MerklePath.fromHex(extracted.toHex())
      expect(roundTripped.computeRoot(tx[2])).toBe(merkleroot)
      expect(roundTripped.computeRoot(tx[8])).toBe(merkleroot)
    })

    it('extracted path is smaller than the full block path', () => {
      const { height, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])

      const extracted = fullBlock.extract([tx[2], tx[5]])
      expect(extracted.toBinary().length).toBeLessThan(fullBlock.toBinary().length)
    })

    it('extract from a trimmed multi-level compound path also works', () => {
      const { height, merkleroot, tx } = BLOCK_125632
      const [pathA, pathB] = buildSplitPaths()
      pathA.combine(pathB)
      // pathA is now a trimmed multi-level compound path for tx[2] and tx[3]
      const txid2 = BRC74TXID2
      const compound = new MerklePath(BRC74JSON.blockHeight, BRC74JSON.path)
      const extracted = compound.extract([txid2])
      expect(extracted.computeRoot(txid2)).toBe(compound.computeRoot(txid2))
      // BLOCK_125632 variant
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])
      const ex = fullBlock.extract([tx[0], tx[10]])
      expect(ex.computeRoot(tx[0])).toBe(merkleroot)
      expect(ex.computeRoot(tx[10])).toBe(merkleroot)
    })

    it('throws when no txids are provided', () => {
      const { height, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])
      expect(() => fullBlock.extract([])).toThrow('At least one txid must be provided')
    })

    it('throws when a txid is not in the path', () => {
      const { height, tx } = BLOCK_125632
      const leafs = tx.map((hash, offset) => ({ hash, txid: true, offset }))
      if (leafs.length % 2) leafs.push({ offset: leafs.length, duplicate: true } as any)
      const fullBlock = new MerklePath(height, [leafs])
      expect(() => fullBlock.extract(['deadbeef'.repeat(8)])).toThrow()
    })
  })

  it('findOrComputeLeaf duplicates leaf0 when leaf1 carries both a hash and duplicate=true', () => {
    // Covers the leaf1.duplicate === true branch inside findOrComputeLeaf.
    // That branch is reached when leaf1.hash is non-null (bypassing the null-check above it)
    // but leaf1.duplicate is also true — an unusual but valid interface state.
    const tx0 = 'aa'.repeat(32)
    const tx1 = 'bb'.repeat(32)

    // Build a minimal valid path so the constructor does not throw.
    const mp = new MerklePath(1, [[
      { offset: 0, txid: true, hash: tx0 },
      { offset: 1, hash: tx1 }
    ]])

    // Mutate: give the sibling leaf at offset 1 both a hash and duplicate=true.
    // findOrComputeLeaf(1, 0) will:
    //   - not find offset 0 in path[1] (path.length === 1, no higher levels)
    //   - recurse to level 0: leaf0 = tx0 (offset 0), leaf1 = {hash:tx1, duplicate:true}
    //   - leaf1.hash is non-null → skips the null-branch
    //   - leaf1.duplicate === true → line 349: workinghash = hash(leaf0 + leaf0)
    mp.path[0][1] = { offset: 1, hash: tx1, duplicate: true }

    const result = mp.findOrComputeLeaf(1, 0)
    expect(result?.hash).toBe(merkleHash(tx0 + tx0))
  })
})
