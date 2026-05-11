import {
  SECP256K1_N,
  SECP256K1_P,
  compressPoint,
  isOnCurve,
  pointAdd,
  scalarMultiply
} from '../circuit/Secp256k1.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  DUAL_BASE_NEGATIVE_SIGN,
  DUAL_BASE_POSITIVE_SIGN
} from './DualBaseLookup.js'
import {
  BRC69_RADIX11_WINDOW_COUNT,
  BRC69_RADIX11_WINDOW_BITS,
  ProductionRadix11LookupPrototype,
  ProductionRadix11PointPairRow
} from './DualBaseRadix11Metrics.js'
import {
  Secp256k1AffineAddProofBundle,
  Secp256k1AffineAddTraceBundle,
  buildSecp256k1AffineAddTraceBundle,
  proveSecp256k1AffineAdd,
  secp256k1AffineAddMetrics,
  verifySecp256k1AffineAdd
} from './Secp256k1AffineAdd.js'
import { StarkProverOptions, StarkVerifierOptions } from './Stark.js'

export type ProductionRadix11EcLane = 'G' | 'B'
export type ProductionRadix11EcBranch =
  'selected-infinity' |
  'accumulator-infinity' |
  'distinct-add' |
  'doubling' |
  'opposite-add'

export interface ProductionRadix11EcLaneRow {
  lane: ProductionRadix11EcLane
  branch: ProductionRadix11EcBranch
  before: SecpPoint
  tablePoint: SecpPoint
  selected: SecpPoint
  after: SecpPoint
}

export interface ProductionRadix11EcStep {
  window: number
  tableIndex: number
  digit: bigint
  sign: 0 | 1
  magnitude: number
  isZero: 0 | 1
  tableRow: ProductionRadix11PointPairRow
  g: ProductionRadix11EcLaneRow
  b: ProductionRadix11EcLaneRow
}

export interface ProductionRadix11EcTrace {
  lookup: ProductionRadix11LookupPrototype
  steps: ProductionRadix11EcStep[]
  publicA: SecpPoint
  privateS: SecpPoint
  compressedS: number[]
}

export interface ProductionRadix11EcAddProof {
  lane: ProductionRadix11EcLane
  step: number
  trace: Secp256k1AffineAddTraceBundle
  proof: Secp256k1AffineAddProofBundle
}

export interface ProductionRadix11EcProofBundle {
  addProofs: ProductionRadix11EcAddProof[]
}

export interface ProductionRadix11EcMetrics {
  steps: number
  laneRows: number
  selectedRows: number
  zeroDigits: number
  negativeDigits: number
  signedPointNegations: number
  selectedInfinityBranches: number
  accumulatorInfinityBranches: number
  distinctAddBranches: number
  doublingBranches: number
  oppositeBranches: number
  fieldLinearOps: number
  fieldMulOps: number
  fieldLinearRows: number
  fieldMulRows: number
  affineAddProofs: number
  totalFieldLinearProofs: number
  totalFieldMulProofs: number
  totalProofBytes?: number
  activeRows: number
  paddedRows: number
  committedWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
}

export const PRODUCTION_RADIX11_EC_COMMITTED_WIDTH = 64
export const PRODUCTION_RADIX11_EC_LINEAR_ROWS_PER_OP = 5
export const PRODUCTION_RADIX11_EC_MUL_ROWS_PER_OP = 20
export const PRODUCTION_RADIX11_EC_LINEAR_OPS_PER_DISTINCT_ADD = 6
export const PRODUCTION_RADIX11_EC_MUL_OPS_PER_DISTINCT_ADD = 4

export function buildProductionRadix11EcTrace (
  lookup: ProductionRadix11LookupPrototype,
  publicA: SecpPoint = scalarMultiply(lookup.scalar)
): ProductionRadix11EcTrace {
  validateProductionRadix11LookupShape(lookup)
  assertProductionRadix11ExceptionalBranchesUnreachable(lookup)
  const steps: ProductionRadix11EcStep[] = []
  let accG = infinityPoint()
  let accB = infinityPoint()

  for (let i = 0; i < lookup.digits.length; i++) {
    const digit = lookup.digits[i]
    const tableIndex = lookup.selectedIndexes[i]
    const tableRow = lookup.table[tableIndex]
    if (tableRow === undefined) {
      throw new Error('Production radix-11 EC selected table row is missing')
    }
    validateSelectedRow(digit.window, digit.magnitude, tableIndex, tableRow)
    const selectedG = applyDigitSign(tableRow.g, digit.sign, digit.magnitude)
    const selectedB = applyDigitSign(tableRow.b, digit.sign, digit.magnitude)
    const g = accumulateLane('G', accG, tableRow.g, selectedG)
    const b = accumulateLane('B', accB, tableRow.b, selectedB)
    steps.push({
      window: digit.window,
      tableIndex,
      digit: digit.digit,
      sign: digit.sign,
      magnitude: digit.magnitude,
      isZero: tableRow.isZero,
      tableRow,
      g,
      b
    })
    accG = g.after
    accB = b.after
  }

  if (accB.infinity === true) {
    throw new Error('Production radix-11 EC private S must be non-infinity')
  }
  const trace = {
    lookup,
    steps,
    publicA,
    privateS: accB,
    compressedS: compressPoint(accB)
  }
  validateProductionRadix11EcTrace(trace)
  return trace
}

export function validateProductionRadix11EcTrace (
  trace: ProductionRadix11EcTrace
): void {
  validateProductionRadix11LookupShape(trace.lookup)
  assertProductionRadix11ExceptionalBranchesUnreachable(trace.lookup)
  if (trace.steps.length !== trace.lookup.digits.length) {
    throw new Error('Production radix-11 EC step count mismatch')
  }
  let accG = infinityPoint()
  let accB = infinityPoint()
  for (let i = 0; i < trace.steps.length; i++) {
    const step = trace.steps[i]
    const digit = trace.lookup.digits[i]
    const tableIndex = trace.lookup.selectedIndexes[i]
    const tableRow = trace.lookup.table[tableIndex]
    if (
      tableRow === undefined ||
      step.tableRow !== tableRow ||
      step.window !== digit.window ||
      step.tableIndex !== tableIndex ||
      step.digit !== digit.digit ||
      step.sign !== digit.sign ||
      step.magnitude !== digit.magnitude ||
      step.isZero !== tableRow.isZero
    ) {
      throw new Error('Production radix-11 EC step metadata mismatch')
    }
    validateSelectedRow(step.window, step.magnitude, step.tableIndex, tableRow)
    validateLaneRow(
      step.g,
      'G',
      accG,
      tableRow.g,
      applyDigitSign(tableRow.g, step.sign, step.magnitude)
    )
    validateLaneRow(
      step.b,
      'B',
      accB,
      tableRow.b,
      applyDigitSign(tableRow.b, step.sign, step.magnitude)
    )
    accG = step.g.after
    accB = step.b.after
  }

  const expectedA = scalarMultiply(trace.lookup.scalar)
  const expectedS = scalarMultiply(trace.lookup.scalar, trace.lookup.baseB)
  if (!pointsEqual(accG, expectedA) || !pointsEqual(trace.publicA, expectedA)) {
    throw new Error('Production radix-11 EC public A mismatch')
  }
  if (!pointsEqual(accB, expectedS) || !pointsEqual(trace.privateS, expectedS)) {
    throw new Error('Production radix-11 EC private S mismatch')
  }
  if (trace.privateS.infinity === true || !isOnCurve(trace.privateS)) {
    throw new Error('Production radix-11 EC private S is invalid')
  }
  if (!bytesEqual(trace.compressedS, compressPoint(trace.privateS))) {
    throw new Error('Production radix-11 EC compressed S mismatch')
  }
}

export function proveProductionRadix11Ec (
  trace: ProductionRadix11EcTrace,
  options: StarkProverOptions = {}
): ProductionRadix11EcProofBundle {
  validateProductionRadix11EcTrace(trace)
  const addProofs: ProductionRadix11EcAddProof[] = []
  for (const item of distinctAddLanes(trace)) {
    const addTrace = buildSecp256k1AffineAddTraceBundle(
      item.lane.before,
      item.lane.selected
    )
    addProofs.push({
      lane: item.lane.lane,
      step: item.step,
      trace: addTrace,
      proof: proveSecp256k1AffineAdd(addTrace, options)
    })
  }
  return { addProofs }
}

export function verifyProductionRadix11Ec (
  trace: ProductionRadix11EcTrace,
  proof: ProductionRadix11EcProofBundle,
  options: StarkVerifierOptions = {}
): boolean {
  try {
    validateProductionRadix11EcTrace(trace)
    const expected = distinctAddLanes(trace)
    if (expected.length !== proof.addProofs.length) return false
    for (let i = 0; i < expected.length; i++) {
      const item = proof.addProofs[i]
      const lane = expected[i]
      if (item.step !== lane.step || item.lane !== lane.lane.lane) return false
      if (!pointsEqual(item.trace.witness.left, lane.lane.before)) return false
      if (!pointsEqual(item.trace.witness.right, lane.lane.selected)) return false
      if (!pointsEqual(item.trace.witness.result, lane.lane.after)) return false
      if (!verifySecp256k1AffineAdd(item.trace, item.proof, options)) return false
    }
    return true
  } catch {
    return false
  }
}

export function productionRadix11EcMetrics (
  trace: ProductionRadix11EcTrace,
  blowupFactor: number = 16,
  proof?: ProductionRadix11EcProofBundle
): ProductionRadix11EcMetrics {
  validateProductionRadix11EcTrace(trace)
  let zeroDigits = 0
  let negativeDigits = 0
  let selectedInfinityBranches = 0
  let accumulatorInfinityBranches = 0
  let distinctAddBranches = 0
  let doublingBranches = 0
  let oppositeBranches = 0

  for (const step of trace.steps) {
    if (step.magnitude === 0) zeroDigits++
    if (step.sign === DUAL_BASE_NEGATIVE_SIGN) negativeDigits++
    for (const lane of [step.g, step.b]) {
      if (lane.branch === 'selected-infinity') selectedInfinityBranches++
      else if (lane.branch === 'accumulator-infinity') accumulatorInfinityBranches++
      else if (lane.branch === 'distinct-add') distinctAddBranches++
      else if (lane.branch === 'doubling') doublingBranches++
      else if (lane.branch === 'opposite-add') oppositeBranches++
    }
  }

  const fieldLinearOps =
    distinctAddBranches * PRODUCTION_RADIX11_EC_LINEAR_OPS_PER_DISTINCT_ADD
  const fieldMulOps =
    distinctAddBranches * PRODUCTION_RADIX11_EC_MUL_OPS_PER_DISTINCT_ADD
  const affineAddProofs = proof?.addProofs.length ?? distinctAddBranches
  const fieldLinearRows =
    fieldLinearOps * PRODUCTION_RADIX11_EC_LINEAR_ROWS_PER_OP
  const fieldMulRows = fieldMulOps * PRODUCTION_RADIX11_EC_MUL_ROWS_PER_OP
  const laneRows = trace.steps.length * 2
  const activeRows = laneRows + fieldLinearRows + fieldMulRows
  const paddedRows = nextPowerOfTwo(Math.max(2, activeRows + 1))
  const committedWidth = PRODUCTION_RADIX11_EC_COMMITTED_WIDTH
  return {
    steps: trace.steps.length,
    laneRows,
    selectedRows: trace.steps.length,
    zeroDigits,
    negativeDigits,
    signedPointNegations: negativeDigits * 2,
    selectedInfinityBranches,
    accumulatorInfinityBranches,
    distinctAddBranches,
    doublingBranches,
    oppositeBranches,
    fieldLinearOps,
    fieldMulOps,
    fieldLinearRows,
    fieldMulRows,
    affineAddProofs,
    totalFieldLinearProofs: affineAddProofs *
      PRODUCTION_RADIX11_EC_LINEAR_OPS_PER_DISTINCT_ADD,
    totalFieldMulProofs: affineAddProofs *
      PRODUCTION_RADIX11_EC_MUL_OPS_PER_DISTINCT_ADD,
    totalProofBytes: proof === undefined
      ? undefined
      : proof.addProofs.reduce((total, item) => {
        return total + (secp256k1AffineAddMetrics(item.proof).totalProofBytes ?? 0)
      }, 0),
    activeRows,
    paddedRows,
    committedWidth,
    committedCells: paddedRows * committedWidth,
    ldeRows: paddedRows * blowupFactor,
    ldeCells: paddedRows * blowupFactor * committedWidth
  }
}

export function assertProductionRadix11ExceptionalBranchesUnreachable (
  lookup: ProductionRadix11LookupPrototype
): void {
  const radix = 1n << BigInt(BRC69_RADIX11_WINDOW_BITS)
  let prefix = 0n
  let weight = 1n

  for (const digit of lookup.digits) {
    if (digit.window < 0 || digit.window >= BRC69_RADIX11_WINDOW_COUNT) {
      throw new Error('Production radix-11 digit window is invalid')
    }
    const selected = digit.digit * weight
    if (selected !== 0n) {
      if (sameScalarMultiple(prefix, selected)) {
        throw new Error(
          'Production radix-11 scalar bounds allow an EC doubling branch'
        )
      }
      if (sameScalarMultiple(prefix, -selected)) {
        throw new Error(
          'Production radix-11 scalar bounds allow an EC opposite branch'
        )
      }
    }
    prefix += selected
    weight *= radix
  }

  if (prefix !== lookup.scalar) {
    throw new Error('Production radix-11 scalar reconstruction mismatch')
  }
  if (prefix <= 0n || prefix >= SECP256K1_N) {
    throw new Error('Production radix-11 scalar is outside secp256k1 range')
  }
}

function validateProductionRadix11LookupShape (
  lookup: ProductionRadix11LookupPrototype
): void {
  if (
    lookup.digits.length !== BRC69_RADIX11_WINDOW_COUNT ||
    lookup.selectedIndexes.length !== BRC69_RADIX11_WINDOW_COUNT
  ) {
    throw new Error('Production radix-11 EC lookup window count mismatch')
  }
  for (let i = 0; i < lookup.digits.length; i++) {
    if (lookup.digits[i].window !== i) {
      throw new Error('Production radix-11 EC digits must be in window order')
    }
  }
}

function validateSelectedRow (
  window: number,
  magnitude: number,
  tableIndex: number,
  row: ProductionRadix11PointPairRow
): void {
  if (
    row.index !== tableIndex ||
    row.window !== window ||
    row.magnitude !== magnitude ||
    row.isZero !== (magnitude === 0 ? 1 : 0)
  ) {
    throw new Error('Production radix-11 EC selected row mismatch')
  }
}

function validateLaneRow (
  row: ProductionRadix11EcLaneRow,
  lane: ProductionRadix11EcLane,
  before: SecpPoint,
  tablePoint: SecpPoint,
  selected: SecpPoint
): void {
  if (
    row.lane !== lane ||
    !pointsEqual(row.before, before) ||
    !pointsEqual(row.tablePoint, tablePoint) ||
    !pointsEqual(row.selected, selected) ||
    !pointsEqual(row.after, pointAdd(before, selected)) ||
    row.branch !== branchFor(before, selected)
  ) {
    throw new Error('Production radix-11 EC lane mismatch')
  }
}

function accumulateLane (
  lane: ProductionRadix11EcLane,
  before: SecpPoint,
  tablePoint: SecpPoint,
  selected: SecpPoint
): ProductionRadix11EcLaneRow {
  return {
    lane,
    branch: branchFor(before, selected),
    before,
    tablePoint,
    selected,
    after: pointAdd(before, selected)
  }
}

function branchFor (
  before: SecpPoint,
  selected: SecpPoint
): ProductionRadix11EcBranch {
  if (selected.infinity === true) return 'selected-infinity'
  if (before.infinity === true) return 'accumulator-infinity'
  if (before.x === selected.x) {
    return before.y === selected.y ? 'doubling' : 'opposite-add'
  }
  return 'distinct-add'
}

function applyDigitSign (
  point: SecpPoint,
  sign: 0 | 1,
  magnitude: number
): SecpPoint {
  if (magnitude === 0) {
    if (sign !== DUAL_BASE_POSITIVE_SIGN || point.infinity !== true) {
      throw new Error('Production radix-11 zero digit must be canonical')
    }
    return infinityPoint()
  }
  if (point.infinity === true) {
    throw new Error('Production radix-11 nonzero selected point is infinity')
  }
  if (sign === DUAL_BASE_POSITIVE_SIGN) return point
  if (sign === DUAL_BASE_NEGATIVE_SIGN) return negatePoint(point)
  throw new Error('Production radix-11 digit sign is invalid')
}

function negatePoint (point: SecpPoint): SecpPoint {
  if (point.infinity === true) return infinityPoint()
  return {
    x: point.x,
    y: point.y === 0n ? 0n : SECP256K1_P - point.y
  }
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function sameScalarMultiple (left: bigint, right: bigint): boolean {
  return modN(left - right) === 0n
}

function modN (value: bigint): bigint {
  const out = value % SECP256K1_N
  return out < 0n ? out + SECP256K1_N : out
}

function distinctAddLanes (
  trace: ProductionRadix11EcTrace
): Array<{ step: number, lane: ProductionRadix11EcLaneRow }> {
  const out: Array<{ step: number, lane: ProductionRadix11EcLaneRow }> = []
  for (let step = 0; step < trace.steps.length; step++) {
    const row = trace.steps[step]
    if (row.g.branch === 'distinct-add') out.push({ step, lane: row.g })
    if (row.b.branch === 'distinct-add') out.push({ step, lane: row.b })
  }
  return out
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}
