import {
  compressPoint,
  isOnCurve
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  DualBaseAccumulationMetrics,
  DualBaseAccumulationProofBundle,
  DualBaseAccumulationTrace,
  buildDualBaseAccumulationTrace,
  dualBaseAccumulationMetrics,
  proveDualBaseAccumulation,
  validateDualBaseAccumulationTrace,
  verifyDualBaseAccumulation
} from './DualBaseAccumulation.js'
import {
  DualBaseLookupMetrics,
  DualBaseLookupPrototype,
  dualBaseLookupMetrics,
  proveDualBaseLookupPrototype,
  verifyDualBaseLookupPrototypeProof
} from './DualBaseLookup.js'
import { StarkProof, StarkProverOptions } from './Stark.js'

export const DUAL_BASE_EC_COMPRESSED_POINT_BYTES = 33
export const DUAL_BASE_EC_COMPRESSED_POINT_NIBBLES =
  DUAL_BASE_EC_COMPRESSED_POINT_BYTES * 2

export interface DualBaseCompressedPointWitness {
  point: SecpPoint
  bytes: number[]
  prefix: number
  xBytes: number[]
  nibbles: number[]
}

export interface DualBaseEcIntegratedRow {
  window: number
  tableIndex: number
  sign: 0 | 1
  magnitude: number
  selectedG: SecpPoint
  selectedB: SecpPoint
  accGBefore: SecpPoint
  accGAfter: SecpPoint
  accBBefore: SecpPoint
  accBAfter: SecpPoint
  gBranch: string
  bBranch: string
  gBranchSelectors: DualBaseEcBranchSelectors
  bBranchSelectors: DualBaseEcBranchSelectors
}

export interface DualBaseEcBranchSelectors {
  selectedInfinity: 0 | 1
  accumulatorInfinity: 0 | 1
  distinctAdd: 0 | 1
  oppositeAdd: 0 | 1
}

export interface DualBaseEcIntegratedTrace {
  lookup: DualBaseLookupPrototype
  accumulation: DualBaseAccumulationTrace
  rows: DualBaseEcIntegratedRow[]
  publicA: SecpPoint
  privateS: SecpPoint
  compressedS: DualBaseCompressedPointWitness
}

export interface DualBaseEcIntegratedProof {
  lookupProof: StarkProof
  accumulationProof: DualBaseAccumulationProofBundle
}

export interface DualBaseEcIntegratedMetrics {
  rows: number
  committedEcRows: number
  compressedSBytes: number
  compressedSNibbles: number
  branchSelectorColumns: number
  lookup: DualBaseLookupMetrics
  accumulation: DualBaseAccumulationMetrics
  totalProofBytes?: number
}

export function buildDualBaseEcIntegratedTrace (
  lookup: DualBaseLookupPrototype
): DualBaseEcIntegratedTrace {
  const accumulation = buildDualBaseAccumulationTrace(lookup)
  const rows = accumulation.steps.map(step => ({
    window: step.window,
    tableIndex: step.tableIndex,
    sign: step.sign,
    magnitude: step.magnitude,
    selectedG: step.g.selected,
    selectedB: step.b.selected,
    accGBefore: step.g.before,
    accGAfter: step.g.after,
    accBBefore: step.b.before,
    accBAfter: step.b.after,
    gBranch: step.g.branch,
    bBranch: step.b.branch,
    gBranchSelectors: branchSelectors(step.g.branch),
    bBranchSelectors: branchSelectors(step.b.branch)
  }))
  const trace = {
    lookup,
    accumulation,
    rows,
    publicA: accumulation.finalG,
    privateS: accumulation.finalB,
    compressedS: buildDualBaseCompressedPointWitness(accumulation.finalB)
  }
  validateDualBaseEcIntegratedTrace(trace)
  return trace
}

export function validateDualBaseEcIntegratedTrace (
  trace: DualBaseEcIntegratedTrace
): void {
  validateDualBaseAccumulationTrace(trace.accumulation)
  if (trace.rows.length !== trace.accumulation.steps.length) {
    throw new Error('Dual-base EC integrated row count mismatch')
  }
  for (let i = 0; i < trace.rows.length; i++) {
    const row = trace.rows[i]
    const step = trace.accumulation.steps[i]
    if (
      row.window !== step.window ||
      row.tableIndex !== step.tableIndex ||
      row.sign !== step.sign ||
      row.magnitude !== step.magnitude ||
      row.gBranch !== step.g.branch ||
      row.bBranch !== step.b.branch ||
      !branchSelectorsMatch(row.gBranchSelectors, step.g.branch) ||
      !branchSelectorsMatch(row.bBranchSelectors, step.b.branch) ||
      !pointsEqual(row.selectedG, step.g.selected) ||
      !pointsEqual(row.selectedB, step.b.selected) ||
      !pointsEqual(row.accGBefore, step.g.before) ||
      !pointsEqual(row.accGAfter, step.g.after) ||
      !pointsEqual(row.accBBefore, step.b.before) ||
      !pointsEqual(row.accBAfter, step.b.after)
    ) {
      throw new Error('Dual-base EC integrated row mismatch')
    }
  }
  if (!pointsEqual(trace.publicA, trace.accumulation.finalG)) {
    throw new Error('Dual-base EC public A mismatch')
  }
  if (!pointsEqual(trace.privateS, trace.accumulation.finalB)) {
    throw new Error('Dual-base EC private S mismatch')
  }
  validateDualBaseCompressedPointWitness(trace.compressedS, trace.privateS)
}

export function proveDualBaseEcIntegrated (
  trace: DualBaseEcIntegratedTrace,
  options: StarkProverOptions = {}
): DualBaseEcIntegratedProof {
  validateDualBaseEcIntegratedTrace(trace)
  return {
    lookupProof: proveDualBaseLookupPrototype(trace.lookup, options),
    accumulationProof: proveDualBaseAccumulation(trace.accumulation, options)
  }
}

export function verifyDualBaseEcIntegrated (
  trace: DualBaseEcIntegratedTrace,
  proof: DualBaseEcIntegratedProof
): boolean {
  try {
    validateDualBaseEcIntegratedTrace(trace)
    return verifyDualBaseLookupPrototypeProof(trace.lookup, proof.lookupProof) &&
      verifyDualBaseAccumulation(trace.accumulation, proof.accumulationProof)
  } catch {
    return false
  }
}

export function dualBaseEcIntegratedMetrics (
  trace: DualBaseEcIntegratedTrace,
  proof?: DualBaseEcIntegratedProof
): DualBaseEcIntegratedMetrics {
  const lookup = dualBaseLookupMetrics(trace.lookup, proof?.lookupProof)
  const accumulation = dualBaseAccumulationMetrics(
    trace.accumulation,
    proof?.accumulationProof
  )
  return {
    rows: trace.rows.length,
    committedEcRows: trace.rows.length,
    compressedSBytes: DUAL_BASE_EC_COMPRESSED_POINT_BYTES,
    compressedSNibbles: DUAL_BASE_EC_COMPRESSED_POINT_NIBBLES,
    branchSelectorColumns: 8,
    lookup,
    accumulation,
    totalProofBytes: proof === undefined
      ? undefined
      : (lookup.proofBytes ?? 0) + (accumulation.totalProofBytes ?? 0)
  }
}

export function buildDualBaseCompressedPointWitness (
  point: SecpPoint
): DualBaseCompressedPointWitness {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('Dual-base EC compressed point witness requires a valid point')
  }
  const bytes = compressPoint(point)
  if (bytes.length !== DUAL_BASE_EC_COMPRESSED_POINT_BYTES) {
    throw new Error('Unexpected compressed point length')
  }
  return {
    point,
    bytes,
    prefix: bytes[0],
    xBytes: bytes.slice(1),
    nibbles: bytesToNibbles(bytes)
  }
}

export function validateDualBaseCompressedPointWitness (
  witness: DualBaseCompressedPointWitness,
  expectedPoint: SecpPoint
): void {
  if (!pointsEqual(witness.point, expectedPoint)) {
    throw new Error('Compressed point witness point mismatch')
  }
  const expected = compressPoint(expectedPoint)
  if (!bytesEqual(witness.bytes, expected)) {
    throw new Error('Compressed point witness bytes mismatch')
  }
  if (witness.prefix !== expected[0]) {
    throw new Error('Compressed point witness prefix mismatch')
  }
  if (!bytesEqual(witness.xBytes, expected.slice(1))) {
    throw new Error('Compressed point witness x bytes mismatch')
  }
  if (!bytesEqual(nibblesToBytes(witness.nibbles), expected)) {
    throw new Error('Compressed point witness nibbles mismatch')
  }
}

export function dualBaseCompressedSForHmac (
  trace: DualBaseEcIntegratedTrace
): number[] {
  validateDualBaseEcIntegratedTrace(trace)
  return trace.compressedS.bytes.slice()
}

export function bytesToNibbles (bytes: number[]): number[] {
  const out: number[] = []
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Byte is outside range')
    }
    out.push(byte & 0x0f)
    out.push(byte >>> 4)
  }
  return out
}

export function nibblesToBytes (nibbles: number[]): number[] {
  if (nibbles.length % 2 !== 0) {
    throw new Error('Nibble length must be even')
  }
  const out: number[] = []
  for (let i = 0; i < nibbles.length; i += 2) {
    const low = nibbles[i]
    const high = nibbles[i + 1]
    if (
      !Number.isInteger(low) ||
      !Number.isInteger(high) ||
      low < 0 ||
      low > 15 ||
      high < 0 ||
      high > 15
    ) {
      throw new Error('Nibble is outside range16')
    }
    out.push(low | (high << 4))
  }
  return out
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

function branchSelectors (branch: string): DualBaseEcBranchSelectors {
  return {
    selectedInfinity: branch === 'selected-infinity' ? 1 : 0,
    accumulatorInfinity: branch === 'accumulator-infinity' ? 1 : 0,
    distinctAdd: branch === 'distinct-add' ? 1 : 0,
    oppositeAdd: branch === 'opposite-add' ? 1 : 0
  }
}

function branchSelectorsMatch (
  selectors: DualBaseEcBranchSelectors,
  branch: string
): boolean {
  const expected = branchSelectors(branch)
  return selectors.selectedInfinity === expected.selectedInfinity &&
    selectors.accumulatorInfinity === expected.accumulatorInfinity &&
    selectors.distinctAdd === expected.distinctAdd &&
    selectors.oppositeAdd === expected.oppositeAdd &&
    selectors.selectedInfinity +
      selectors.accumulatorInfinity +
      selectors.distinctAdd +
      selectors.oppositeAdd === 1
}
