import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from '../stark/Air.js'
import { FieldElement } from '../stark/Field.js'
import {
  StarkProof,
  StarkProverOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import {
  METHOD2_SHA256_BLOCK_LAYOUT,
  Method2Sha256BlockLayout,
  buildMethod2Sha256BlockAir,
  buildMethod2Sha256BlockTrace,
  method2Sha256CompressBlockReference
} from './Method2Sha256.js'

export const METHOD2_SHA256_BLOCK_PROOF_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_SHA256_BLOCK_PROOF_V1'
export const METHOD2_SHA256_BLOCK_PROOF_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_SHA256_BLOCK_PUBLIC_INPUT_V1'

export const METHOD2_SHA256_BLOCK_PROOF_STARK_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 16,
  maskDegree: 1,
  cosetOffset: 3n,
  transcriptDomain: METHOD2_SHA256_BLOCK_PROOF_TRANSCRIPT_DOMAIN
} as const

export interface Method2Sha256CompressionBlockProofTrace {
  initialState: number[]
  block: number[]
  expectedOutputState: number[]
  outputState: number[]
  traceRows: FieldElement[][]
  layout: Method2Sha256BlockLayout
}

export interface Method2Sha256CompressionBlockMetrics {
  traceLength: number
  traceWidth: number
  activeRows: number
  roundRows: number
  committedCells: number
  proofBytes?: number
}

export function buildMethod2Sha256CompressionBlockProofTrace (
  initialState: number[],
  block: number[],
  expectedOutputState?: number[]
): Method2Sha256CompressionBlockProofTrace {
  validateSha256State(initialState)
  validateSha256Block(block)
  const outputState = method2Sha256CompressBlockReference(initialState, block)
  const expected = expectedOutputState === undefined
    ? outputState
    : expectedOutputState.slice()
  validateSha256State(expected)
  if (!u32ArraysEqual(expected, outputState)) {
    throw new Error('SHA-256 compression output does not match expected state')
  }
  const trace = buildMethod2Sha256BlockTrace(initialState, block)
  if (!u32ArraysEqual(trace.outputState, outputState)) {
    throw new Error('SHA-256 compression trace output mismatch')
  }
  return {
    initialState: initialState.slice(),
    block: block.slice(),
    expectedOutputState: expected,
    outputState,
    traceRows: trace.traceRows,
    layout: trace.layout
  }
}

export function buildMethod2Sha256CompressionBlockProofAir (
  trace: Method2Sha256CompressionBlockProofTrace
): AirDefinition {
  validateMethod2Sha256CompressionBlockProofTrace(trace)
  const air = buildMethod2Sha256BlockAir(
    trace.initialState,
    trace.block,
    trace.expectedOutputState
  )
  return {
    ...air,
    publicInputDigest: method2Sha256CompressionBlockPublicInputDigest(trace)
  }
}

export function proveMethod2Sha256CompressionBlock (
  trace: Method2Sha256CompressionBlockProofTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildMethod2Sha256CompressionBlockProofAir(trace)
  return proveStark(air, trace.traceRows, {
    ...METHOD2_SHA256_BLOCK_PROOF_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: METHOD2_SHA256_BLOCK_PROOF_TRANSCRIPT_DOMAIN
  })
}

export function verifyMethod2Sha256CompressionBlock (
  trace: Method2Sha256CompressionBlockProofTrace,
  proof: StarkProof
): boolean {
  try {
    const air = buildMethod2Sha256CompressionBlockProofAir(trace)
    return verifyStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset,
      traceDegreeBound: proof.traceDegreeBound,
      compositionDegreeBound: proof.compositionDegreeBound,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: METHOD2_SHA256_BLOCK_PROOF_TRANSCRIPT_DOMAIN
    })
  } catch {
    return false
  }
}

export function method2Sha256CompressionBlockMetrics (
  trace: Method2Sha256CompressionBlockProofTrace,
  proof?: StarkProof
): Method2Sha256CompressionBlockMetrics {
  return {
    traceLength: trace.traceRows.length,
    traceWidth: trace.layout.width,
    activeRows: 65,
    roundRows: 64,
    committedCells: trace.traceRows.length * trace.layout.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2Sha256CompressionBlockPublicInputDigest (
  trace: Method2Sha256CompressionBlockProofTrace
): number[] {
  validateMethod2Sha256CompressionBlockProofTrace(trace)
  const writer = new Writer()
  writer.write(toArray(METHOD2_SHA256_BLOCK_PROOF_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(trace.initialState.length)
  for (const word of trace.initialState) writer.writeUInt32BE(word >>> 0)
  writer.writeVarIntNum(trace.block.length)
  writer.write(trace.block)
  writer.writeVarIntNum(trace.expectedOutputState.length)
  for (const word of trace.expectedOutputState) writer.writeUInt32BE(word >>> 0)
  writer.writeVarIntNum(METHOD2_SHA256_BLOCK_LAYOUT.width)
  return sha256(writer.toArray())
}

export function validateMethod2Sha256CompressionBlockProofTrace (
  trace: Method2Sha256CompressionBlockProofTrace
): void {
  validateSha256State(trace.initialState)
  validateSha256Block(trace.block)
  validateSha256State(trace.expectedOutputState)
  validateSha256State(trace.outputState)
  if (!u32ArraysEqual(trace.outputState, trace.expectedOutputState)) {
    throw new Error('SHA-256 compression trace expected output mismatch')
  }
  if (!u32ArraysEqual(
    trace.outputState,
    method2Sha256CompressBlockReference(trace.initialState, trace.block)
  )) {
    throw new Error('SHA-256 compression trace output is invalid')
  }
  if (trace.layout.width !== METHOD2_SHA256_BLOCK_LAYOUT.width) {
    throw new Error('SHA-256 compression trace layout mismatch')
  }
  if (trace.traceRows.length !== 128) {
    throw new Error('SHA-256 compression trace length mismatch')
  }
  for (const row of trace.traceRows) {
    if (row.length !== trace.layout.width) {
      throw new Error('SHA-256 compression trace row width mismatch')
    }
  }
}

function validateSha256Block (block: number[]): void {
  if (block.length !== 64) throw new Error('SHA-256 block must be 64 bytes')
  for (const byte of block) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid SHA-256 block byte')
    }
  }
}

function validateSha256State (state: number[]): void {
  if (state.length !== 8) throw new Error('SHA-256 state must contain 8 words')
  for (const word of state) {
    if (!Number.isInteger(word) || word < 0 || word > 0xffffffff) {
      throw new Error('SHA-256 word must be uint32')
    }
  }
}

function u32ArraysEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => (value >>> 0) === (right[index] >>> 0))
}
