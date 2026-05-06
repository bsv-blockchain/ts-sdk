import {
  FieldElement,
  assertPowerOfTwo,
  getPowerOfTwoRootOfUnity
} from './Field.js'
import {
  TypedFieldColumn,
  cloneTypedFieldColumn,
  typedFieldAdd,
  typedFieldAddInto,
  typedFieldColumn,
  typedFieldColumnToBigints,
  typedFieldElement,
  typedFieldInv,
  typedFieldMul,
  typedFieldMulInto,
  typedFieldSubInto,
  typedFieldToBigint
} from './TypedField.js'

const TYPED_FFT_BIT_REVERSE_CACHE = new Map<number, Uint32Array>()
const TYPED_FFT_TWIDDLE_CACHE = new Map<string, TypedFieldColumn>()
const TYPED_COSET_POWER_CACHE = new Map<string, TypedFieldColumn>()

function bitReverseIndex (value: number, bits: number): number {
  let reversed = 0
  for (let i = 0; i < bits; i++) {
    reversed = (reversed << 1) | (value & 1)
    value >>= 1
  }
  return reversed
}

function bitReversePermutation (size: number): Uint32Array {
  const cached = TYPED_FFT_BIT_REVERSE_CACHE.get(size)
  if (cached !== undefined) return cached
  const bits = Math.log2(size)
  const permutation = new Uint32Array(size)
  for (let i = 0; i < size; i++) permutation[i] = bitReverseIndex(i, bits)
  TYPED_FFT_BIT_REVERSE_CACHE.set(size, permutation)
  return permutation
}

export function typedFft (
  values: TypedFieldColumn,
  inverse: boolean = false
): TypedFieldColumn {
  const n = values.lo.length
  if (values.hi.length !== n) {
    throw new Error('Typed FFT lane length mismatch')
  }
  assertPowerOfTwo(n)

  const permutation = bitReversePermutation(n)
  const out = {
    lo: new Uint32Array(n),
    hi: new Uint32Array(n)
  }
  for (let i = 0; i < n; i++) {
    const target = permutation[i]
    out.lo[target] = values.lo[i]
    out.hi[target] = values.hi[i]
  }

  const mulScratch = new Uint32Array(2)
  const sumScratch = new Uint32Array(2)
  const diffScratch = new Uint32Array(2)
  for (let len = 2; len <= n; len <<= 1) {
    const twiddles = typedFftTwiddles(len, inverse)

    for (let start = 0; start < n; start += len) {
      const half = len >> 1
      for (let j = 0; j < half; j++) {
        const leftIndex = start + j
        const rightIndex = leftIndex + half
        const leftLo = out.lo[leftIndex]
        const leftHi = out.hi[leftIndex]
        typedFieldMulInto(
          out.lo[rightIndex],
          out.hi[rightIndex],
          twiddles.lo[j],
          twiddles.hi[j],
          mulScratch
        )
        const rightLo = mulScratch[0]
        const rightHi = mulScratch[1]
        typedFieldAddInto(leftLo, leftHi, rightLo, rightHi, sumScratch)
        typedFieldSubInto(leftLo, leftHi, rightLo, rightHi, diffScratch)
        out.lo[leftIndex] = sumScratch[0]
        out.hi[leftIndex] = sumScratch[1]
        out.lo[rightIndex] = diffScratch[0]
        out.hi[rightIndex] = diffScratch[1]
      }
    }
  }

  if (inverse) {
    const invN = typedFieldInv(typedFieldElement(BigInt(n)))
    for (let i = 0; i < n; i++) {
      typedFieldMulInto(out.lo[i], out.hi[i], invN.lo, invN.hi, mulScratch)
      out.lo[i] = mulScratch[0]
      out.hi[i] = mulScratch[1]
    }
  }

  return out
}

function typedFftTwiddles (
  len: number,
  inverse: boolean
): TypedFieldColumn {
  const key = `${len}:${inverse ? 1 : 0}`
  const cached = TYPED_FFT_TWIDDLE_CACHE.get(key)
  if (cached !== undefined) return cached
  let root = typedFieldElement(getPowerOfTwoRootOfUnity(len))
  if (inverse) root = typedFieldInv(root)
  const half = len >> 1
  const twiddles = {
    lo: new Uint32Array(half),
    hi: new Uint32Array(half)
  }
  const scratch = new Uint32Array(2)
  let currentLo = 1
  let currentHi = 0
  for (let i = 0; i < half; i++) {
    twiddles.lo[i] = currentLo
    twiddles.hi[i] = currentHi
    typedFieldMulInto(currentLo, currentHi, root.lo, root.hi, scratch)
    currentLo = scratch[0]
    currentHi = scratch[1]
  }
  TYPED_FFT_TWIDDLE_CACHE.set(key, twiddles)
  return twiddles
}

export function typedIfft (
  evaluations: TypedFieldColumn
): TypedFieldColumn {
  return typedFft(evaluations, true)
}

export function typedInterpolateEvaluations (
  evaluations: TypedFieldColumn
): TypedFieldColumn {
  return typedIfft(evaluations)
}

export function typedEvaluatePolynomialOnCoset (
  coefficients: TypedFieldColumn,
  evaluationSize: number,
  cosetOffset: FieldElement
): TypedFieldColumn {
  assertPowerOfTwo(evaluationSize)
  if (coefficients.lo.length > evaluationSize) {
    throw new Error('Typed polynomial degree exceeds evaluation domain')
  }
  const padded = {
    lo: new Uint32Array(evaluationSize),
    hi: new Uint32Array(evaluationSize)
  }
  const powers = typedCosetPowers(coefficients.lo.length, cosetOffset)
  const scratch = new Uint32Array(2)
  for (let i = 0; i < coefficients.lo.length; i++) {
    typedFieldMulInto(
      coefficients.lo[i],
      coefficients.hi[i],
      powers.lo[i],
      powers.hi[i],
      scratch
    )
    padded.lo[i] = scratch[0]
    padded.hi[i] = scratch[1]
  }
  return typedFft(padded)
}

function typedCosetPowers (
  length: number,
  cosetOffset: FieldElement
): TypedFieldColumn {
  const normalizedOffset = typedFieldElement(cosetOffset)
  const key = `${length}:${normalizedOffset.lo}:${normalizedOffset.hi}`
  const cached = TYPED_COSET_POWER_CACHE.get(key)
  if (cached !== undefined) return cached
  const powers = {
    lo: new Uint32Array(length),
    hi: new Uint32Array(length)
  }
  const scratch = new Uint32Array(2)
  let currentLo = 1
  let currentHi = 0
  for (let i = 0; i < length; i++) {
    powers.lo[i] = currentLo
    powers.hi[i] = currentHi
    typedFieldMulInto(
      currentLo,
      currentHi,
      normalizedOffset.lo,
      normalizedOffset.hi,
      scratch
    )
    currentLo = scratch[0]
    currentHi = scratch[1]
  }
  TYPED_COSET_POWER_CACHE.set(key, powers)
  return powers
}

export function typedCosetLowDegreeExtend (
  values: TypedFieldColumn,
  blowupFactor: number,
  cosetOffset: FieldElement
): TypedFieldColumn {
  assertPowerOfTwo(blowupFactor)
  const coefficients = typedInterpolateEvaluations(values)
  return typedEvaluatePolynomialOnCoset(
    coefficients,
    values.lo.length * blowupFactor,
    cosetOffset
  )
}

export function typedColumnFromBigints (
  values: FieldElement[]
): TypedFieldColumn {
  return typedFieldColumn(values)
}

export function typedColumnToBigints (
  column: TypedFieldColumn
): FieldElement[] {
  return typedFieldColumnToBigints(column)
}

export function typedEvaluatePolynomial (
  coefficients: TypedFieldColumn,
  point: FieldElement
): FieldElement {
  let result = typedFieldElement(0n)
  const x = typedFieldElement(point)
  for (let i = coefficients.lo.length - 1; i >= 0; i--) {
    result = typedFieldAdd(
      typedFieldMul(result, x),
      { lo: coefficients.lo[i], hi: coefficients.hi[i] }
    )
  }
  return typedFieldToBigint(result)
}

export function cloneTypedPolynomialColumn (
  column: TypedFieldColumn
): TypedFieldColumn {
  return cloneTypedFieldColumn(column)
}

export function typedApplyVanishingMask (
  coefficients: TypedFieldColumn,
  traceDomainSize: number,
  maskCoefficients: FieldElement[]
): TypedFieldColumn {
  assertPowerOfTwo(traceDomainSize)
  if (maskCoefficients.length === 0) return cloneTypedFieldColumn(coefficients)
  const length = Math.max(
    coefficients.lo.length,
    traceDomainSize + maskCoefficients.length
  )
  const out = {
    lo: new Uint32Array(length),
    hi: new Uint32Array(length)
  }
  out.lo.set(coefficients.lo)
  out.hi.set(coefficients.hi)
  const scratch = new Uint32Array(2)
  for (let i = 0; i < maskCoefficients.length; i++) {
    const mask = typedFieldElement(maskCoefficients[i])
    typedFieldSubInto(out.lo[i], out.hi[i], mask.lo, mask.hi, scratch)
    out.lo[i] = scratch[0]
    out.hi[i] = scratch[1]
    const highIndex = i + traceDomainSize
    typedFieldAddInto(
      out.lo[highIndex],
      out.hi[highIndex],
      mask.lo,
      mask.hi,
      scratch
    )
    out.lo[highIndex] = scratch[0]
    out.hi[highIndex] = scratch[1]
  }
  return out
}
