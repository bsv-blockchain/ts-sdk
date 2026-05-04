import { AirDefinition } from './Air.js'
import { FieldElement } from './Field.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from './Stark.js'
import {
  TypedFieldTrace,
  typedFieldAdd,
  typedFieldColumn,
  typedFieldElement,
  typedFieldSub,
  typedFieldTraceToRows
} from './TypedField.js'
import { buildTypedTraceMerkleTree } from './TypedMerkle.js'
import {
  typedEvaluatePolynomialOnCoset,
  typedInterpolateEvaluations
} from './TypedPolynomial.js'
import { MerkleTree } from './Merkle.js'

export interface TypedStarkBackendBenchmarkOptions {
  traceLength: number
  traceWidth: number
  blowupFactor: number
  cosetOffset: FieldElement
  numQueries: number
  maxRemainderSize: number
  sampleColumns?: number
  maxSampleTraceLength?: number
  now?: () => number
}

export interface TypedStarkBackendBenchmarkMetrics {
  backend: 'typed-array-synthetic'
  traceLength: number
  traceWidth: number
  blowupFactor: number
  ldeRows: number
  ldeCells: number
  sampleTraceLength: number
  sampleColumns: number
  measuredLdeRows: number
  measuredLdeCells: number
  measuredMs: number
  scaledMs: number
  estimatedProofBytes: number
}

export interface TypedTraceCommitment {
  traceLength: number
  traceWidth: number
  ldeSize: number
  blowupFactor: number
  cosetOffset: FieldElement
  columnCoefficients: TypedFieldTrace['columns']
  ldeTrace: TypedFieldTrace
  tree: MerkleTree
}

export function proveTypedStark (
  air: AirDefinition,
  trace: TypedFieldTrace,
  options: StarkProverOptions = {}
): StarkProof {
  return proveStark(air, typedFieldTraceToRows(trace), options)
}

export function verifyTypedStark (
  air: AirDefinition,
  proof: StarkProof,
  options: StarkVerifierOptions = {}
): boolean {
  return verifyStark(air, proof, options)
}

export function typedStarkProofBytes (proof: StarkProof): number {
  return serializeStarkProof(proof).length
}

export function commitTypedTraceLde (
  trace: TypedFieldTrace,
  options: {
    blowupFactor: number
    cosetOffset: FieldElement
    maskCoefficients?: FieldElement[][]
  }
): TypedTraceCommitment {
  if (trace.columns.length !== trace.width) {
    throw new Error('Typed STARK trace width mismatch')
  }
  if (trace.length < 2 || (trace.length & (trace.length - 1)) !== 0) {
    throw new Error('Typed STARK trace length must be a power of two')
  }
  if (options.blowupFactor < 1 || (options.blowupFactor & (options.blowupFactor - 1)) !== 0) {
    throw new Error('Typed STARK blowup factor must be a power of two')
  }
  const ldeSize = trace.length * options.blowupFactor
  const columnCoefficients = trace.columns.map(column =>
    typedInterpolateEvaluations(column)
  )
  const ldeColumns = columnCoefficients.map((coefficients, column) => {
    const mask = options.maskCoefficients?.[column]
    return typedEvaluatePolynomialOnCoset(
      mask === undefined
        ? coefficients
        : typedApplyVanishingMask(coefficients, trace.length, mask),
      ldeSize,
      options.cosetOffset
    )
  })
  const ldeTrace = {
    length: ldeSize,
    width: trace.width,
    columns: ldeColumns
  }
  return {
    traceLength: trace.length,
    traceWidth: trace.width,
    ldeSize,
    blowupFactor: options.blowupFactor,
    cosetOffset: options.cosetOffset,
    columnCoefficients,
    ldeTrace,
    tree: buildTypedTraceMerkleTree(ldeTrace)
  }
}

export function benchmarkTypedStarkBackendShape (
  options: TypedStarkBackendBenchmarkOptions
): TypedStarkBackendBenchmarkMetrics {
  const now = options.now ?? (() => Date.now())
  const sampleColumns = Math.max(1, Math.min(
    options.traceWidth,
    options.sampleColumns ?? 4
  ))
  const sampleTraceLength = samplePowerOfTwo(
    options.traceLength,
    options.maxSampleTraceLength ?? 4096
  )
  const measuredLdeRows = sampleTraceLength * options.blowupFactor
  const measuredLdeCells = measuredLdeRows * sampleColumns

  const sampleTrace: TypedFieldTrace = {
    length: sampleTraceLength,
    width: sampleColumns,
    columns: Array.from({ length: sampleColumns }, (_, column) =>
      typedFieldColumn(deterministicColumn(sampleTraceLength, column))
    )
  }
  const start = now()
  commitTypedTraceLde(sampleTrace, {
    blowupFactor: options.blowupFactor,
    cosetOffset: options.cosetOffset
  })
  const measuredMs = now() - start

  const ldeRows = options.traceLength * options.blowupFactor
  const ldeCells = ldeRows * options.traceWidth
  const scale = measuredLdeCells === 0 ? 0 : ldeCells / measuredLdeCells

  return {
    backend: 'typed-array-synthetic',
    traceLength: options.traceLength,
    traceWidth: options.traceWidth,
    blowupFactor: options.blowupFactor,
    ldeRows,
    ldeCells,
    sampleTraceLength,
    sampleColumns,
    measuredLdeRows,
    measuredLdeCells,
    measuredMs,
    scaledMs: measuredMs * scale,
    estimatedProofBytes: estimateStarkProofBytes({
      traceLength: options.traceLength,
      traceWidth: options.traceWidth,
      blowupFactor: options.blowupFactor,
      numQueries: options.numQueries,
      maxRemainderSize: options.maxRemainderSize
    })
  }
}

export function estimateStarkProofBytes (input: {
  traceLength: number
  traceWidth: number
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
}): number {
  const ldeSize = input.traceLength * input.blowupFactor
  const merkleHeight = Math.log2(ldeSize)
  const traceOpening = openingBytes(input.traceWidth, merkleHeight, ldeSize)
  const compositionOpening = openingBytes(1, merkleHeight, ldeSize)
  const openings =
    varIntBytes(input.numQueries * 2) +
    input.numQueries * 2 * traceOpening +
    varIntBytes(input.numQueries) +
    input.numQueries * traceOpening +
    varIntBytes(input.numQueries) +
    input.numQueries * traceOpening +
    varIntBytes(input.numQueries) +
    input.numQueries * compositionOpening
  return 128 +
    openings +
    varIntBytes(ldeSize) +
    friProofBytes(ldeSize, input.numQueries, input.maxRemainderSize) * 2
}

function friProofBytes (
  domainSize: number,
  numQueries: number,
  maxRemainderSize: number
): number {
  let current = domainSize
  let layers = 0
  while (current > maxRemainderSize) {
    layers++
    current >>= 1
  }
  const merklePath = (height: number): number => {
    return varIntBytes(height) + height * 33
  }
  let queryLayerBytes = 0
  for (let layer = 0; layer < layers; layer++) {
    const height = Math.log2(domainSize >> layer)
    queryLayerBytes +=
      varIntBytes(domainSize) * 2 +
      16 +
      merklePath(height) * 2
  }
  return 64 +
    layers * 32 +
    current * 8 +
    varIntBytes(numQueries) +
    numQueries * (
      varIntBytes(domainSize) * 2 +
      varIntBytes(layers) +
      queryLayerBytes
    )
}

function openingBytes (
  rowWidth: number,
  merkleHeight: number,
  maxIndex: number
): number {
  return varIntBytes(maxIndex) +
    varIntBytes(rowWidth) +
    rowWidth * 8 +
    varIntBytes(merkleHeight) +
    merkleHeight * 33
}

function deterministicColumn (
  length: number,
  column: number
): FieldElement[] {
  const out = new Array<FieldElement>(length)
  for (let row = 0; row < length; row++) {
    out[row] = BigInt((row + 1) * (column + 17))
  }
  return out
}

function typedApplyVanishingMask (
  coefficients: TypedTraceCommitment['columnCoefficients'][number],
  traceDomainSize: number,
  maskCoefficients: FieldElement[]
): TypedTraceCommitment['columnCoefficients'][number] {
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
  for (let i = 0; i < maskCoefficients.length; i++) {
    const mask = typedFieldElement(maskCoefficients[i])
    const low = typedFieldSub({ lo: out.lo[i], hi: out.hi[i] }, mask)
    out.lo[i] = low.lo
    out.hi[i] = low.hi
    const highIndex = i + traceDomainSize
    const high = typedFieldAdd({
      lo: out.lo[highIndex],
      hi: out.hi[highIndex]
    }, mask)
    out.lo[highIndex] = high.lo
    out.hi[highIndex] = high.hi
  }
  return out
}

function samplePowerOfTwo (
  requested: number,
  cap: number
): number {
  let out = 1
  const target = Math.max(1, Math.min(requested, cap))
  while (out * 2 <= target) out *= 2
  return out
}

function varIntBytes (value: number): number {
  if (value < 0xfd) return 1
  if (value <= 0xffff) return 3
  if (value <= 0xffffffff) return 5
  return 9
}
