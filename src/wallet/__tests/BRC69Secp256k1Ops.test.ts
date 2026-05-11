import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildSecp256k1AffineAddTraceBundle,
  buildSecp256k1FieldAddTrace,
  buildSecp256k1FieldLinearAir,
  buildSecp256k1FieldMulAir,
  buildSecp256k1FieldMulTrace,
  buildSecp256k1FieldSubTrace,
  evaluateAirTrace,
  proveSecp256k1AffineAdd,
  proveSecp256k1FieldLinear,
  proveSecp256k1FieldMul,
  secp256k1AffineAddMetrics,
  secp256k1FieldLinearMetrics,
  secp256k1FieldMulMetrics,
  secp256k1FieldToLimbs52,
  secp256k1FieldFromLimbs52,
  verifySecp256k1AffineAdd,
  verifySecp256k1FieldLinear,
  verifySecp256k1FieldMul
} from '../brc69/stark/index'
import {
  SECP256K1_P,
  pointAdd,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 secp256k1 field and point op prototypes', () => {
  it('proves 5x52 secp256k1 field addition and subtraction', () => {
    const add = buildSecp256k1FieldAddTrace(SECP256K1_P - 5n, 9n)
    expect(add.c).toBe(4n)
    expect(add.q).toBe(1n)
    expect(evaluateAirTrace(buildSecp256k1FieldLinearAir(add), add.rows).valid)
      .toBe(true)

    const addProof = proveSecp256k1FieldLinear(add, {
      numQueries: 2,
      maskSeed: ascii('secp-field-add-mask')
    })
    expect(verifySecp256k1FieldLinear(add, addProof, { numQueries: 2 }))
      .toBe(true)
    expect(secp256k1FieldLinearMetrics(addProof).proofBytes).toBeGreaterThan(0)

    const sub = buildSecp256k1FieldSubTrace(3n, 9n)
    expect(sub.c).toBe(SECP256K1_P - 6n)
    expect(sub.q).toBe(-1n)
    expect(evaluateAirTrace(buildSecp256k1FieldLinearAir(sub), sub.rows).valid)
      .toBe(true)

    const bad = sub.rows.map(row => row.slice())
    bad[0][sub.layout.c] += 1n
    expect(evaluateAirTrace(buildSecp256k1FieldLinearAir(sub), bad).valid)
      .toBe(false)
  })

  it('proves 5x52 secp256k1 multiplication through 10x26 internal limbs', () => {
    const a = scalarMultiply(7n).x
    const b = scalarMultiply(11n).x
    const trace = buildSecp256k1FieldMulTrace(a, b)

    expect(evaluateAirTrace(buildSecp256k1FieldMulAir(trace), trace.rows).valid)
      .toBe(true)
    expect(secp256k1FieldFromLimbs52(secp256k1FieldToLimbs52(trace.c)))
      .toBe(trace.c)

    const proof = proveSecp256k1FieldMul(trace, {
      numQueries: 2,
      maskSeed: ascii('secp-field-mul-mask')
    })
    expect(verifySecp256k1FieldMul(trace, proof, { numQueries: 2 }))
      .toBe(true)
    expect(secp256k1FieldMulMetrics(proof)).toMatchObject({
      limbBits: 52,
      limbCount: 5,
      activeRows: 20,
      paddedRows: 32
    })

    const bad = trace.rows.map(row => row.slice())
    bad[0][trace.layout.a26] += 1n
    expect(evaluateAirTrace(buildSecp256k1FieldMulAir(trace), bad).valid)
      .toBe(false)
  })

  it('proves a distinct affine point addition as field-op proof bundle', () => {
    const left = scalarMultiply(7n)
    const right = scalarMultiply(11n)
    const bundle = buildSecp256k1AffineAddTraceBundle(left, right)

    expect(bundle.witness.result).toEqual(pointAdd(left, right))

    const proof = proveSecp256k1AffineAdd(bundle, {
      numQueries: 2,
      maskSeed: ascii('secp-affine-add-mask')
    })

    expect(verifySecp256k1AffineAdd(bundle, proof, { numQueries: 2 }))
      .toBe(true)
    expect(secp256k1AffineAddMetrics(proof)).toMatchObject({
      linearProofs: 6,
      mulProofs: 4
    })
    expect(secp256k1AffineAddMetrics(proof).totalProofBytes).toBeGreaterThan(0)
  })

  it('locks field-op proof domains and public input digests', () => {
    const left = scalarMultiply(13n)
    const right = scalarMultiply(17n)
    const bundle = buildSecp256k1AffineAddTraceBundle(left, right)
    const proof = proveSecp256k1AffineAdd(bundle, {
      numQueries: 2,
      transcriptDomain: 'caller-domain-must-not-leak',
      publicInputDigest: ascii('caller-digest-must-not-leak'),
      maskSeed: ascii('secp-affine-add-locked-domain-mask')
    })

    expect(verifySecp256k1AffineAdd(bundle, proof, { numQueries: 2 }))
      .toBe(true)
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
