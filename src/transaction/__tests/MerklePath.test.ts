import ChainTracker from '../ChainTracker'
import MerklePath from '../../transaction/MerklePath'
import invalidBumps from './bump.invalid.vectors'
import validBumps from './bump.valid.vectors'

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
    const pathAJSON = {
      blockHeight: BRC74JSON.blockHeight,
      path: [path0A, path1A, ...pathRest]
    }
    const pathBJSON = {
      blockHeight: BRC74JSON.blockHeight,
      path: [path0B, path1B, ...pathRest]
    }
    const pathA = new MerklePath(pathAJSON.blockHeight, pathAJSON.path)
    const pathB = new MerklePath(pathBJSON.blockHeight, pathBJSON.path)
    expect(pathA.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(() => pathA.computeRoot(BRC74TXID3)).toThrow()
    expect(() => pathB.computeRoot(BRC74TXID2)).toThrow()
    expect(pathB.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
    pathA.combine(pathB)
    expect(pathA).toEqual(BRC74JSONTrimmed)
    expect(pathA.computeRoot(BRC74TXID2)).toEqual(BRC74Root)
    expect(pathA.computeRoot(BRC74TXID3)).toEqual(BRC74Root)
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
})
