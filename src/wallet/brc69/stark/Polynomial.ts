import {
  F,
  FieldElement,
  assertPowerOfTwo,
  getPowerOfTwoCosetDomain,
  getPowerOfTwoRootOfUnity
} from './Field.js'

function bitReverseIndex (value: number, bits: number): number {
  let reversed = 0
  for (let i = 0; i < bits; i++) {
    reversed = (reversed << 1) | (value & 1)
    value >>= 1
  }
  return reversed
}

const FFT_BIT_REVERSE_CACHE = new Map<number, Uint32Array>()
const FFT_TWIDDLE_CACHE = new Map<string, FieldElement[]>()

function bitReverseCopy (values: FieldElement[]): FieldElement[] {
  const n = values.length
  const permutation = bitReversePermutation(n)
  const out = new Array<FieldElement>(n)
  for (let i = 0; i < n; i++) {
    out[permutation[i]] = values[i]
  }
  return out
}

function bitReversePermutation (size: number): Uint32Array {
  const cached = FFT_BIT_REVERSE_CACHE.get(size)
  if (cached !== undefined) return cached
  const bits = Math.log2(size)
  const permutation = new Uint32Array(size)
  for (let i = 0; i < size; i++) permutation[i] = bitReverseIndex(i, bits)
  FFT_BIT_REVERSE_CACHE.set(size, permutation)
  return permutation
}

export function fft (
  values: FieldElement[],
  inverse: boolean = false
): FieldElement[] {
  const n = values.length
  assertPowerOfTwo(n)
  const out = bitReverseCopy(values.map(v => F.normalize(v)))

  for (let len = 2; len <= n; len <<= 1) {
    const twiddles = fftTwiddles(len, inverse)

    for (let start = 0; start < n; start += len) {
      const half = len >> 1
      for (let j = 0; j < half; j++) {
        const u = out[start + j]
        const v = F.mul(out[start + j + half], twiddles[j])
        out[start + j] = F.add(u, v)
        out[start + j + half] = F.sub(u, v)
      }
    }
  }

  if (inverse) {
    const invN = F.inv(BigInt(n))
    for (let i = 0; i < n; i++) {
      out[i] = F.mul(out[i], invN)
    }
  }

  return out
}

function fftTwiddles (
  len: number,
  inverse: boolean
): FieldElement[] {
  const key = `${len}:${inverse ? 1 : 0}`
  const cached = FFT_TWIDDLE_CACHE.get(key)
  if (cached !== undefined) return cached
  let root = getPowerOfTwoRootOfUnity(len)
  if (inverse) root = F.inv(root)
  const half = len >> 1
  const twiddles = new Array<FieldElement>(half)
  let current = 1n
  for (let i = 0; i < half; i++) {
    twiddles[i] = current
    current = F.mul(current, root)
  }
  FFT_TWIDDLE_CACHE.set(key, twiddles)
  return twiddles
}

export function ifft (evaluations: FieldElement[]): FieldElement[] {
  return fft(evaluations, true)
}

export function evaluatePolynomial (
  coefficients: FieldElement[],
  point: FieldElement
): FieldElement {
  point = F.normalize(point)
  let result = 0n
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = F.add(F.mul(result, point), F.normalize(coefficients[i]))
  }
  return result
}

export function trimPolynomial (
  coefficients: FieldElement[]
): FieldElement[] {
  let end = coefficients.length
  while (end > 0 && coefficients[end - 1] === 0n) end--
  return coefficients.slice(0, end)
}

export function degreeOfPolynomial (
  coefficients: FieldElement[]
): number {
  return trimPolynomial(coefficients).length - 1
}

export function degreeLessThan (
  coefficients: FieldElement[],
  bound: number
): boolean {
  if (!Number.isSafeInteger(bound) || bound < 0) {
    throw new Error('Degree bound must be a non-negative safe integer')
  }
  return degreeOfPolynomial(coefficients.map(v => F.normalize(v))) < bound
}

export function lowDegreeExtend (
  coefficients: FieldElement[],
  blowupFactor: number
): FieldElement[] {
  assertPowerOfTwo(blowupFactor)
  let coefficientSize = 1
  while (coefficientSize < coefficients.length) coefficientSize <<= 1
  const evaluationSize = coefficientSize * blowupFactor
  const padded = new Array<FieldElement>(evaluationSize).fill(0n)
  for (let i = 0; i < coefficients.length; i++) {
    padded[i] = F.normalize(coefficients[i])
  }
  return fft(padded)
}

export function cosetLowDegreeExtend (
  coefficients: FieldElement[],
  blowupFactor: number,
  cosetOffset: FieldElement
): FieldElement[] {
  assertPowerOfTwo(blowupFactor)
  let coefficientSize = 1
  while (coefficientSize < coefficients.length) coefficientSize <<= 1
  return evaluatePolynomialOnCoset(
    coefficients,
    coefficientSize * blowupFactor,
    cosetOffset
  )
}

export function evaluatePolynomialOnCoset (
  coefficients: FieldElement[],
  evaluationSize: number,
  cosetOffset: FieldElement
): FieldElement[] {
  assertPowerOfTwo(evaluationSize)
  cosetOffset = F.normalize(cosetOffset)
  if (cosetOffset === 0n) {
    throw new Error('Coset offset must be non-zero')
  }
  if (coefficients.length > evaluationSize) {
    throw new Error('Polynomial degree exceeds evaluation domain')
  }
  const padded = new Array<FieldElement>(evaluationSize).fill(0n)
  let scale = 1n
  for (let i = 0; i < coefficients.length; i++) {
    padded[i] = F.mul(F.normalize(coefficients[i]), scale)
    scale = F.mul(scale, cosetOffset)
  }
  return fft(padded)
}

export function evaluatePolynomialOnDomain (
  coefficients: FieldElement[],
  domain: FieldElement[]
): FieldElement[] {
  if (domain.length === 0) {
    throw new Error('Evaluation domain must not be empty')
  }
  return domain.map(point => evaluatePolynomial(coefficients, point))
}

export function getCosetEvaluationDomain (
  size: number,
  cosetOffset: FieldElement
): FieldElement[] {
  return getPowerOfTwoCosetDomain(size, cosetOffset)
}

export function applyVanishingMask (
  coefficients: FieldElement[],
  traceDomainSize: number,
  maskCoefficients: FieldElement[]
): FieldElement[] {
  assertPowerOfTwo(traceDomainSize)
  if (maskCoefficients.length === 0) {
    return coefficients.slice()
  }

  const size = Math.max(
    coefficients.length,
    traceDomainSize + maskCoefficients.length
  )
  const masked = new Array<FieldElement>(size).fill(0n)
  for (let i = 0; i < coefficients.length; i++) {
    masked[i] = F.add(masked[i], F.normalize(coefficients[i]))
  }

  // Add r(x) * (x^n - 1). This preserves evaluations on the n-point
  // trace domain while randomizing evaluations on the larger coset domain.
  for (let i = 0; i < maskCoefficients.length; i++) {
    const mask = F.normalize(maskCoefficients[i])
    masked[i] = F.sub(masked[i], mask)
    masked[i + traceDomainSize] = F.add(masked[i + traceDomainSize], mask)
  }

  return trimPolynomial(masked)
}

export function interpolateEvaluations (
  evaluations: FieldElement[]
): FieldElement[] {
  return ifft(evaluations)
}

export function serializeFieldElements (
  values: FieldElement[]
): number[] {
  const out = new Array<number>(values.length * 8)
  for (let i = 0; i < values.length; i++) {
    writeFieldElementBytesLE(out, i * 8, values[i])
  }
  return out
}

export function writeFieldElementBytesLE (
  out: number[],
  offset: number,
  value: FieldElement
): void {
  let v = F.normalize(value)
  for (let i = 0; i < 8; i++) {
    out[offset + i] = Number(v & 0xffn)
    v >>= 8n
  }
}
