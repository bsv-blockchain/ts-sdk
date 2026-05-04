import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  AirDefinition,
  F,
  buildMerkleTree,
  buildTypedFieldMerkleTree,
  commitTraceLde,
  commitTypedTraceLde,
  fft,
  fieldElementLeaves,
  proveTypedStark,
  typedColumnFromBigints,
  typedColumnToBigints,
  typedFieldAdd,
  typedFieldElement,
  typedFieldMul,
  typedFieldPow,
  typedFieldSub,
  typedFieldToBigint,
  typedFieldTraceFromRows,
  typedFft,
  typedIfft,
  verifyTypedStark
} from '../brc97/index'

describe('BRC-97 typed STARK backend primitives', () => {
  it('matches BigInt Goldilocks arithmetic', () => {
    const values = [
      0n,
      1n,
      F.p - 1n,
      F.p - 2n,
      (1n << 32n) - 1n,
      1n << 32n,
      (1n << 63n) + 12345n
    ]
    for (let i = 0; i < 64; i++) {
      values.push(F.normalize(
        BigInt(i * 92821 + 17) *
        BigInt(i * 131071 + 99) +
        BigInt(i * i * 65537)
      ))
    }
    for (let i = 0; i < values.length; i++) {
      const left = values[i]
      const right = values[(i * 7 + 3) % values.length]
      const a = typedFieldElement(left)
      const b = typedFieldElement(right)

      expect(typedFieldToBigint(typedFieldAdd(a, b)))
        .toBe(F.add(F.normalize(left), F.normalize(right)))
      expect(typedFieldToBigint(typedFieldSub(a, b)))
        .toBe(F.sub(F.normalize(left), F.normalize(right)))
      expect(typedFieldToBigint(typedFieldMul(a, b)))
        .toBe(F.mul(F.normalize(left), F.normalize(right)))
      expect(typedFieldToBigint(typedFieldPow(a, 13n)))
        .toBe(F.pow(F.normalize(left), 13n))
    }
  })

  it('matches BigInt FFT and inverse FFT', () => {
    const values = Array.from({ length: 16 }, (_, index) =>
      BigInt(index * index + 3)
    )
    const typed = typedColumnFromBigints(values)
    const typedEvaluations = typedFft(typed)

    expect(typedColumnToBigints(typedEvaluations)).toEqual(fft(values))
    expect(typedColumnToBigints(typedIfft(typedEvaluations)))
      .toEqual(values.map(value => F.normalize(value)))
  })

  it('matches BigInt Merkle leaf serialization', () => {
    const values = Array.from({ length: 8 }, (_, index) =>
      BigInt(index * 19 + 5)
    )
    const typed = typedColumnFromBigints(values)
    const typedTree = buildTypedFieldMerkleTree(typed)
    const bigintTree = buildMerkleTree(fieldElementLeaves(values))

    expect(typedTree.root).toEqual(bigintTree.root)
  })

  it('commits a typed column-major trace with the same Merkle root as BigInt', () => {
    const rows = Array.from({ length: 8 }, (_, row) =>
      Array.from({ length: 3 }, (_, column) =>
        BigInt((row + 1) * (column + 5) + row * row)
      )
    )
    const options = {
      blowupFactor: 4,
      cosetOffset: 3n,
      maskCoefficients: [
        [11n, 12n],
        [21n, 22n],
        [31n, 32n]
      ]
    }
    const typed = commitTypedTraceLde(typedFieldTraceFromRows(rows), options)
    const bigint = commitTraceLde(rows, options)

    expect(typed.traceLength).toBe(bigint.traceLength)
    expect(typed.traceWidth).toBe(bigint.traceWidth)
    expect(typed.ldeSize).toBe(bigint.ldeSize)
    expect(typed.tree.root).toEqual(bigint.tree.root)
  })

  it('proves and verifies a small AIR through the typed wrapper', () => {
    const rows = Array.from({ length: 8 }, (_, row) => [BigInt(row + 3)])
    const air: AirDefinition = {
      traceWidth: 1,
      boundaryConstraints: [
        { row: 0, column: 0, value: 3n },
        { row: 7, column: 0, value: 10n }
      ],
      evaluateTransition: (current, next) => [
        F.sub(next[0], F.add(current[0], 1n))
      ]
    }
    const proof = proveTypedStark(air, typedFieldTraceFromRows(rows), {
      blowupFactor: 4,
      numQueries: 2,
      maxRemainderSize: 4,
      maskDegree: 1,
      cosetOffset: 3n,
      maskSeed: ascii('typed-stark-small-air')
    })

    expect(verifyTypedStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset
    })).toBe(true)
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
