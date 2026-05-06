import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  CIRCUIT_LAYOUT,
  CircuitBuilder,
  SECP256K1_G,
  SECP256K1_N,
  SECP256K1_P,
  addLimbsLE,
  bigintToU16LimbsLE,
  buildCircuitAir,
  compareLimbsLE,
  compressPoint,
  decompressPublicKey,
  hmacSha256,
  isCanonicalLimbsLE,
  isOnCurve,
  mulLimbsLE,
  pointAddWithBranch,
  proveCircuit,
  reduceLimbsLE,
  scalarMultiply,
  secpFieldAdd,
  secpFieldMul,
  secpFieldSquare,
  secpFieldSub,
  sha256CompressBlock,
  sha256Digest,
  sha256Pad,
  subLimbsLE,
  u16LimbsToBigintLE,
  validateCircuitTrace,
  validateScalar,
  verifyCircuit
} from '../brc69/circuit/index'
import {
  evaluateAirTrace
} from '../brc69/stark/index'

describe('BRC-69 circuit primitives', () => {
  it('builds and validates circuit substrate traces', () => {
    const program = new CircuitBuilder()
      .assertBool(1)
      .assertByte(255)
      .assertU16(65535)
      .assertAdd(7n, 9n, 16n)
      .assertMul(7n, 9n, 63n)
      .copyNextA(42n)
      .noop()
      .assertZero(0n)
      .build()

    program.trace.rows[6][CIRCUIT_LAYOUT.a] = 42n
    expect(() => validateCircuitTrace(program)).not.toThrow()

    const air = buildCircuitAir(program)
    expect(evaluateAirTrace(air, program.trace.rows).valid).toBe(true)

    const starkOptions = {
      blowupFactor: 4,
      numQueries: 2,
      maxRemainderSize: 2,
      maskDegree: 0,
      cosetOffset: 3n
    }
    const proof = proveCircuit(program, starkOptions)
    expect(verifyCircuit(program, proof, starkOptions)).toBe(true)

    proof.traceOpenings[0].row[CIRCUIT_LAYOUT.a] += 1n
    expect(verifyCircuit(program, proof, starkOptions)).toBe(false)
  })

  it('rejects malformed circuit rows', () => {
    const program = new CircuitBuilder()
      .assertU16(17)
      .copyNextA(5n)
      .noop()
      .build()
    program.trace.rows[2][CIRCUIT_LAYOUT.a] = 5n

    const badOpcode = cloneProgram(program)
    badOpcode.trace.rows[0][CIRCUIT_LAYOUT.op] = 99n
    expect(() => validateCircuitTrace(badOpcode)).toThrow()

    const badCopy = cloneProgram(program)
    badCopy.trace.rows[2][CIRCUIT_LAYOUT.a] = 6n
    expect(() => validateCircuitTrace(badCopy)).toThrow()

    const badWidth = cloneProgram(program)
    badWidth.trace.rows[0] = badWidth.trace.rows[0].slice(1)
    expect(() => validateCircuitTrace(badWidth)).toThrow()

    const nonPowerOfTwo = cloneProgram(program)
    nonPowerOfTwo.trace.rows = nonPowerOfTwo.trace.rows.slice(0, 3)
    expect(() => validateCircuitTrace(nonPowerOfTwo)).toThrow()

    const badSelector = cloneProgram(program)
    badSelector.trace.rows[0][CIRCUIT_LAYOUT.enabled] = 2n
    expect(() => validateCircuitTrace(badSelector)).toThrow()

    const badBoundary = new CircuitBuilder().assertZero(1n).build()
    expect(evaluateAirTrace(buildCircuitAir(badBoundary), badBoundary.trace.rows).valid).toBe(false)
  })

  it('validates limb range, carries, comparison, and reduction helpers', () => {
    const max = (1n << 256n) - 1n
    const limbs = bigintToU16LimbsLE(max, 16)
    expect(u16LimbsToBigintLE(limbs)).toBe(max)
    expect(() => bigintToU16LimbsLE(1n << 256n, 16)).toThrow()

    const add = addLimbsLE([0xffff, 0xffff], [1], 2)
    expect(add.limbs).toEqual([0, 0])
    expect(add.carry).toBe(1)

    const sub = subLimbsLE([0], [1], 2)
    expect(sub.limbs).toEqual([0xffff, 0xffff])
    expect(sub.borrow).toBe(1)

    const mul = mulLimbsLE([0xffff], [0xffff])
    expect(u16LimbsToBigintLE(mul)).toBe(0xfffen * 0x10000n + 1n)
    expect(reduceLimbsLE([0xffff, 0xffff], 97n, 2)).toEqual(
      bigintToU16LimbsLE(0xffffffffn % 97n, 2)
    )

    expect(compareLimbsLE([1, 2], [1, 1])).toBe(1)
    expect(isCanonicalLimbsLE(bigintToU16LimbsLE(SECP256K1_P - 1n, 16), SECP256K1_P)).toBe(true)
    expect(isCanonicalLimbsLE(bigintToU16LimbsLE(SECP256K1_P, 16), SECP256K1_P)).toBe(false)
    expect(() => addLimbsLE([1], [1], 0)).toThrow()
    expect(() => isCanonicalLimbsLE([1], 0n)).toThrow()
  })

  it('computes secp256k1 field arithmetic against BigInt references', () => {
    const a = 0xffffffffffffffffn
    const b = 0x123456789abcdefn
    expect(secpFieldAdd(a, b)).toBe((a + b) % SECP256K1_P)
    expect(secpFieldSub(a, b)).toBe((a - b + SECP256K1_P) % SECP256K1_P)
    expect(secpFieldMul(a, b)).toBe((a * b) % SECP256K1_P)
    expect(secpFieldSquare(b)).toBe((b * b) % SECP256K1_P)
  })

  it('computes SHA-256 and HMAC-SHA256 vectors', () => {
    expect(bytesToHex(sha256Digest([]))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb924' +
      '27ae41e4649b934ca495991b7852b855'
    )
    expect(bytesToHex(sha256Digest(ascii('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223' +
      'b00361a396177a9cb410ff61f20015ad'
    )
    const multiBlock = ascii('a'.repeat(100))
    expect(bytesToHex(sha256Digest(multiBlock))).toBe(
      '2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e'
    )

    const key = new Array(20).fill(0x0b)
    const message = ascii('Hi There')
    expect(bytesToHex(hmacSha256(key, message))).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b' +
      '881dc200c9833da726e9376c2e32cff7'
    )
    expect(bytesToHex(hmacSha256([1, 2, 3], multiBlock))).toBe(
      '3384870211b94103fbc50db84e14d5211ebe3e4f2b6f45725d21b0c0d2e89b52'
    )
  })

  it('exposes SHA-256 padding and compression failures', () => {
    const padded = sha256Pad(ascii('abc'))
    expect(padded).toHaveLength(64)
    expect(padded[3]).toBe(0x80)

    const initial = {
      words: [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
      ]
    }
    const compressed = sha256CompressBlock(initial, padded)
    expect(compressed.words).toHaveLength(8)

    const tampered = padded.slice()
    tampered[10] ^= 1
    expect(sha256CompressBlock(initial, tampered).words).not.toEqual(
      compressed.words
    )
    expect(() => sha256CompressBlock({ words: [1] }, padded)).toThrow()
    expect(() => sha256Pad([256])).toThrow()
  })

  it('validates secp256k1 points and scalar multiplication', () => {
    expect(isOnCurve(SECP256K1_G)).toBe(true)
    const aliceScalar = 7n
    const bobScalar = 11n

    const alicePoint = scalarMultiply(aliceScalar)
    expect(compressPoint(alicePoint)).toEqual(nodePublicKey(aliceScalar))

    const bobPoint = decompressPublicKey(nodePublicKey(bobScalar))
    const shared = scalarMultiply(aliceScalar, bobPoint)
    expect(compressPoint(shared)).toEqual(
      nodePublicKey((aliceScalar * bobScalar) % SECP256K1_N)
    )

    const anyone = scalarMultiply(1n)
    expect(compressPoint(anyone)).toEqual(nodePublicKey(1n))

    const maxScalarPoint = scalarMultiply(SECP256K1_N - 1n)
    expect(isOnCurve(maxScalarPoint)).toBe(true)

    expect(() => validateScalar(0n)).toThrow()
    expect(() => validateScalar(SECP256K1_N)).toThrow()
    expect(() => decompressPublicKey([0x04, ...new Array(32).fill(0)])).toThrow()
    expect(() => pointAddWithBranch(
      { x: 1n, y: 1n },
      { x: 0n, y: 0n, infinity: true }
    )).toThrow()

    const { branch } = pointAddWithBranch(SECP256K1_G, SECP256K1_G)
    expect(branch).toBe(2)
  })
})

function cloneProgram (
  program: ReturnType<CircuitBuilder['build']>
): ReturnType<CircuitBuilder['build']> {
  return {
    ...program,
    trace: {
      ...program.trace,
      rows: program.trace.rows.map(row => row.slice())
    }
  }
}

function ascii (value: string): number[] {
  return Array.from(value, char => char.charCodeAt(0))
}

function bytesToHex (bytes: number[]): string {
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function nodePublicKey (scalar: bigint): number[] {
  const vectors = new Map<bigint, string>([
    [1n, '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
    [7n, '025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc'],
    [11n, '03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb'],
    [77n, '0259dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e']
  ])
  const vector = vectors.get(scalar)
  if (vector === undefined) throw new Error('Missing secp256k1 test vector')
  return hexToBytes(vector)
}

function hexToBytes (hex: string): number[] {
  const bytes: number[] = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(Number.parseInt(hex.slice(i, i + 2), 16))
  }
  return bytes
}
