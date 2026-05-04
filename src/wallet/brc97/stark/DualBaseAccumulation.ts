import {
  pointAdd,
  scalarMultiply
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  DualBaseLookupPrototype,
  DualBasePointPairTableRow,
  selectedDualBasePointPairs,
  validateDualBaseLookupPrototype
} from './DualBaseLookup.js'
import {
  Secp256k1AffineAddProofBundle,
  Secp256k1AffineAddTraceBundle,
  buildSecp256k1AffineAddTraceBundle,
  proveSecp256k1AffineAdd,
  secp256k1AffineAddMetrics,
  verifySecp256k1AffineAdd
} from './Secp256k1AffineAdd.js'
import { StarkProverOptions } from './Stark.js'

export type DualBaseAccumulationLane = 'G' | 'B'
export type DualBaseAccumulationBranch =
  'selected-infinity' |
  'accumulator-infinity' |
  'distinct-add' |
  'opposite-add'

export interface DualBaseAccumulationLaneRow {
  lane: DualBaseAccumulationLane
  branch: DualBaseAccumulationBranch
  before: SecpPoint
  selected: SecpPoint
  after: SecpPoint
}

export interface DualBaseAccumulationStep {
  window: number
  tableIndex: number
  digit: bigint
  sign: 0 | 1
  magnitude: number
  g: DualBaseAccumulationLaneRow
  b: DualBaseAccumulationLaneRow
}

export interface DualBaseAccumulationTrace {
  lookup: DualBaseLookupPrototype
  selectedRows: DualBasePointPairTableRow[]
  steps: DualBaseAccumulationStep[]
  finalG: SecpPoint
  finalB: SecpPoint
}

export interface DualBaseAccumulationAddProof {
  lane: DualBaseAccumulationLane
  step: number
  trace: Secp256k1AffineAddTraceBundle
  proof: Secp256k1AffineAddProofBundle
}

export interface DualBaseAccumulationProofBundle {
  addProofs: DualBaseAccumulationAddProof[]
}

export interface DualBaseAccumulationMetrics {
  steps: number
  selectedRows: number
  gDistinctAdds: number
  bDistinctAdds: number
  selectedInfinityBranches: number
  accumulatorInfinityBranches: number
  oppositeBranches: number
  affineAddProofs: number
  totalFieldLinearProofs: number
  totalFieldMulProofs: number
  totalProofBytes?: number
}

export function buildDualBaseAccumulationTrace (
  lookup: DualBaseLookupPrototype
): DualBaseAccumulationTrace {
  validateDualBaseLookupPrototype(lookup)
  const selectedRows = selectedDualBasePointPairs(lookup)
  const steps: DualBaseAccumulationStep[] = []
  let accG = infinityPoint()
  let accB = infinityPoint()

  for (let i = 0; i < selectedRows.length; i++) {
    const selected = selectedRows[i]
    const digit = lookup.digits[i]
    const g = accumulateLane('G', accG, selected.g)
    const b = accumulateLane('B', accB, selected.b)
    steps.push({
      window: digit.window,
      tableIndex: selected.index,
      digit: digit.digit,
      sign: digit.sign,
      magnitude: digit.magnitude,
      g,
      b
    })
    accG = g.after
    accB = b.after
  }

  const trace = {
    lookup,
    selectedRows,
    steps,
    finalG: accG,
    finalB: accB
  }
  validateDualBaseAccumulationTrace(trace)
  return trace
}

export function validateDualBaseAccumulationTrace (
  trace: DualBaseAccumulationTrace
): void {
  if (trace.steps.length !== trace.lookup.digits.length) {
    throw new Error('Dual-base accumulation step count mismatch')
  }
  let accG = infinityPoint()
  let accB = infinityPoint()
  for (let i = 0; i < trace.steps.length; i++) {
    const step = trace.steps[i]
    const selected = trace.selectedRows[i]
    const digit = trace.lookup.digits[i]
    if (
      step.window !== digit.window ||
      step.tableIndex !== selected.index ||
      step.sign !== digit.sign ||
      step.magnitude !== digit.magnitude
    ) {
      throw new Error('Dual-base accumulation step metadata mismatch')
    }
    validateLaneRow(step.g, accG, selected.g)
    validateLaneRow(step.b, accB, selected.b)
    accG = step.g.after
    accB = step.b.after
  }
  const expectedG = scalarMultiply(trace.lookup.scalar, trace.lookup.baseG)
  const expectedB = scalarMultiply(trace.lookup.scalar, trace.lookup.baseB)
  if (!pointsEqual(accG, expectedG) || !pointsEqual(trace.finalG, expectedG)) {
    throw new Error('Dual-base accumulation G result mismatch')
  }
  if (!pointsEqual(accB, expectedB) || !pointsEqual(trace.finalB, expectedB)) {
    throw new Error('Dual-base accumulation B result mismatch')
  }
}

export function proveDualBaseAccumulation (
  trace: DualBaseAccumulationTrace,
  options: StarkProverOptions = {}
): DualBaseAccumulationProofBundle {
  validateDualBaseAccumulationTrace(trace)
  const addProofs: DualBaseAccumulationAddProof[] = []
  for (let step = 0; step < trace.steps.length; step++) {
    const row = trace.steps[step]
    for (const lane of [row.g, row.b]) {
      if (lane.branch !== 'distinct-add') continue
      const addTrace = buildSecp256k1AffineAddTraceBundle(
        lane.before,
        lane.selected
      )
      addProofs.push({
        lane: lane.lane,
        step,
        trace: addTrace,
        proof: proveSecp256k1AffineAdd(addTrace, options)
      })
    }
  }
  return { addProofs }
}

export function verifyDualBaseAccumulation (
  trace: DualBaseAccumulationTrace,
  proof: DualBaseAccumulationProofBundle
): boolean {
  try {
    validateDualBaseAccumulationTrace(trace)
    const expected = distinctAddLanes(trace)
    if (expected.length !== proof.addProofs.length) return false
    for (let i = 0; i < expected.length; i++) {
      const item = proof.addProofs[i]
      const lane = expected[i]
      if (item.step !== lane.step || item.lane !== lane.lane.lane) return false
      if (!pointsEqual(item.trace.witness.left, lane.lane.before)) return false
      if (!pointsEqual(item.trace.witness.right, lane.lane.selected)) return false
      if (!pointsEqual(item.trace.witness.result, lane.lane.after)) return false
      if (!verifySecp256k1AffineAdd(item.trace, item.proof)) return false
    }
    return true
  } catch {
    return false
  }
}

export function dualBaseAccumulationMetrics (
  trace: DualBaseAccumulationTrace,
  proof?: DualBaseAccumulationProofBundle
): DualBaseAccumulationMetrics {
  let gDistinctAdds = 0
  let bDistinctAdds = 0
  let selectedInfinityBranches = 0
  let accumulatorInfinityBranches = 0
  let oppositeBranches = 0
  for (const step of trace.steps) {
    for (const lane of [step.g, step.b]) {
      if (lane.branch === 'distinct-add') {
        if (lane.lane === 'G') gDistinctAdds++
        else bDistinctAdds++
      } else if (lane.branch === 'selected-infinity') {
        selectedInfinityBranches++
      } else if (lane.branch === 'accumulator-infinity') {
        accumulatorInfinityBranches++
      } else if (lane.branch === 'opposite-add') {
        oppositeBranches++
      }
    }
  }
  return {
    steps: trace.steps.length,
    selectedRows: trace.selectedRows.length,
    gDistinctAdds,
    bDistinctAdds,
    selectedInfinityBranches,
    accumulatorInfinityBranches,
    oppositeBranches,
    affineAddProofs: proof?.addProofs.length ?? gDistinctAdds + bDistinctAdds,
    totalFieldLinearProofs: (proof?.addProofs.length ?? gDistinctAdds + bDistinctAdds) * 6,
    totalFieldMulProofs: (proof?.addProofs.length ?? gDistinctAdds + bDistinctAdds) * 4,
    totalProofBytes: proof === undefined
      ? undefined
      : proof.addProofs.reduce((total, item) => {
        return total + (secp256k1AffineAddMetrics(item.proof).totalProofBytes ?? 0)
      }, 0)
  }
}

function accumulateLane (
  lane: DualBaseAccumulationLane,
  before: SecpPoint,
  selected: SecpPoint
): DualBaseAccumulationLaneRow {
  if (selected.infinity === true) {
    return {
      lane,
      branch: 'selected-infinity',
      before,
      selected,
      after: before
    }
  }
  if (before.infinity === true) {
    return {
      lane,
      branch: 'accumulator-infinity',
      before,
      selected,
      after: selected
    }
  }
  const after = pointAdd(before, selected)
  return {
    lane,
    branch: after.infinity === true ? 'opposite-add' : 'distinct-add',
    before,
    selected,
    after
  }
}

function validateLaneRow (
  row: DualBaseAccumulationLaneRow,
  before: SecpPoint,
  selected: SecpPoint
): void {
  if (!pointsEqual(row.before, before) || !pointsEqual(row.selected, selected)) {
    throw new Error('Dual-base accumulation lane input mismatch')
  }
  if (!pointsEqual(row.after, pointAdd(before, selected))) {
    throw new Error('Dual-base accumulation lane output mismatch')
  }
  if (selected.infinity === true && row.branch !== 'selected-infinity') {
    throw new Error('Dual-base accumulation selected-infinity branch mismatch')
  }
  if (
    selected.infinity !== true &&
    before.infinity === true &&
    row.branch !== 'accumulator-infinity'
  ) {
    throw new Error('Dual-base accumulation accumulator-infinity branch mismatch')
  }
  if (
    selected.infinity !== true &&
    before.infinity !== true &&
    row.after.infinity !== true &&
    row.branch !== 'distinct-add'
  ) {
    throw new Error('Dual-base accumulation distinct-add branch mismatch')
  }
  if (
    selected.infinity !== true &&
    before.infinity !== true &&
    row.after.infinity === true &&
    row.branch !== 'opposite-add'
  ) {
    throw new Error('Dual-base accumulation opposite-add branch mismatch')
  }
}

function distinctAddLanes (
  trace: DualBaseAccumulationTrace
): Array<{ step: number, lane: DualBaseAccumulationLaneRow }> {
  const out: Array<{ step: number, lane: DualBaseAccumulationLaneRow }> = []
  for (let step = 0; step < trace.steps.length; step++) {
    const row = trace.steps[step]
    if (row.g.branch === 'distinct-add') out.push({ step, lane: row.g })
    if (row.b.branch === 'distinct-add') out.push({ step, lane: row.b })
  }
  return out
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}
