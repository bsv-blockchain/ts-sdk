import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { SECP256K1_P } from '../circuit/Secp256k1.js'
import { SecpPoint } from '../circuit/Types.js'
import { AirDefinition } from './Air.js'
import { F, FieldElement } from './Field.js'
import {
  ProductionRadix11EcLane,
  ProductionRadix11EcLaneRow,
  ProductionRadix11EcTrace,
  validateProductionRadix11EcTrace
} from './ProductionRadix11Ec.js'
import {
  Secp256k1AffineAddWitness,
  Secp256k1AffineAddTraceBundle,
  buildSecp256k1AffineAddTraceBundle
} from './Secp256k1AffineAdd.js'
import {
  SECP256K1_FIELD_LIMB_BITS,
  SECP256K1_FIELD_LIMBS,
  SECP256K1_FIELD_LINEAR_ADD,
  SECP256K1_FIELD_LINEAR_CARRY_BITS,
  SECP256K1_FIELD_LINEAR_SUB,
  SECP256K1_FIELD_MUL_CARRY_BITS,
  SECP256K1_FIELD_MUL_LIMB_BITS,
  SECP256K1_FIELD_MUL_LIMBS,
  SECP256K1_FIELD_MUL_PRODUCT_LIMBS,
  Secp256k1FieldLinearTrace,
  Secp256k1FieldMulTrace,
  buildSecp256k1FieldAddTrace,
  buildSecp256k1FieldMulTrace,
  buildSecp256k1FieldSubTrace,
  secp256k1FieldFromLimbs52,
  secp256k1FieldToLimbs26,
  secp256k1FieldToLimbs52
} from './Secp256k1FieldOps.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from './Stark.js'

export const PRODUCTION_EC_TRANSCRIPT_DOMAIN =
  'BRC69_PRODUCTION_EC_AIR_V1'
export const PRODUCTION_EC_PUBLIC_INPUT_ID =
  'BRC69_PRODUCTION_EC_PUBLIC_INPUT_V1'

export const PRODUCTION_EC_ROW_KIND_INACTIVE = 0n
export const PRODUCTION_EC_ROW_KIND_LINEAR = 1n
export const PRODUCTION_EC_ROW_KIND_MUL = 2n

const FIELD_RADIX = 1n << BigInt(SECP256K1_FIELD_LIMB_BITS)
const MUL_RADIX = 1n << BigInt(SECP256K1_FIELD_MUL_LIMB_BITS)
const INV_TWO = F.div(1n, 2n)
const LINEAR_CARRY_BIAS = 1n << BigInt(SECP256K1_FIELD_LINEAR_CARRY_BITS - 1)
const MUL_CARRY_BIAS = 1n << BigInt(SECP256K1_FIELD_MUL_CARRY_BITS - 1)
const PRODUCTION_EC_RANGE_BITS = SECP256K1_FIELD_LIMB_BITS * 3
const PRODUCTION_EC_LINEAR_RANGE_A = 0
const PRODUCTION_EC_LINEAR_RANGE_B =
  PRODUCTION_EC_LINEAR_RANGE_A + SECP256K1_FIELD_LIMB_BITS
const PRODUCTION_EC_LINEAR_RANGE_C =
  PRODUCTION_EC_LINEAR_RANGE_B + SECP256K1_FIELD_LIMB_BITS
const PRODUCTION_EC_MUL_RANGE_A = 0
const PRODUCTION_EC_MUL_RANGE_B =
  PRODUCTION_EC_MUL_RANGE_A + SECP256K1_FIELD_MUL_LIMB_BITS
const PRODUCTION_EC_MUL_RANGE_C =
  PRODUCTION_EC_MUL_RANGE_B + SECP256K1_FIELD_MUL_LIMB_BITS
const PRODUCTION_EC_MUL_RANGE_Q =
  PRODUCTION_EC_MUL_RANGE_C + SECP256K1_FIELD_MUL_LIMB_BITS
const PRODUCTION_EC_CANONICAL_VALUES = 4
const PRODUCTION_EC_CANONICAL_BITS = SECP256K1_FIELD_LIMB_BITS * 3
const P_52 = bigintToLimbs(SECP256K1_P, SECP256K1_FIELD_LIMBS, FIELD_RADIX)
const P_26 = bigintToLimbs(SECP256K1_P, SECP256K1_FIELD_MUL_LIMBS, MUL_RADIX)
const P_MINUS_ONE_52 = bigintToLimbs(
  SECP256K1_P - 1n,
  SECP256K1_FIELD_LIMBS,
  FIELD_RADIX
)
const P_MINUS_ONE_26 = bigintToLimbs(
  SECP256K1_P - 1n,
  SECP256K1_FIELD_MUL_LIMBS,
  MUL_RADIX
)

export interface ProductionEcLayout {
  kind: number
  active: number
  sameOpNext: number
  limb: number
  limbSelectors: number
  linearOp: number
  a26: number
  b26: number
  c26: number
  q26: number
  a52: number
  b52: number
  c52: number
  qLinear: number
  carryIn: number
  carryOut: number
  opCode: number
  metadataSameNext: number
  accumulatorLinkNext: number
  branchSelectedInfinity: number
  branchAccumulatorInfinity: number
  branchDistinctAdd: number
  branchDoubling: number
  branchOpposite: number
  beforeInfinity: number
  selectedInfinity: number
  afterInfinity: number
  beforeX: number
  beforeY: number
  selectedX: number
  selectedY: number
  afterX: number
  afterY: number
  dx: number
  dy: number
  inverseDx: number
  slope: number
  slopeSquared: number
  xAfterFirstSub: number
  xDiff: number
  ySum: number
  carryBits: number
  rangeBits: number
  canonicalBorrowIn: number
  canonicalBorrowOut: number
  canonicalBits: number
  opSelectors: number
  width: number
}

export interface ProductionEcOperationSchedule {
  row: number
  rows: number
  step: number
  lane: ProductionRadix11EcLane
  op: ProductionEcOperation
  kind: 'linear' | 'mul'
  metadataSameNext: FieldElement
  accumulatorLinkNext: FieldElement
  laneRow: ProductionRadix11EcLaneRow
}

export type ProductionEcOperation =
  'dx' |
  'dy' |
  'inverse' |
  'slope' |
  'slopeSquared' |
  'xFirstSub' |
  'xSecondSub' |
  'xDiff' |
  'ySum' |
  'yRelation'

export interface ProductionEcPublicInput {
  publicA: SecpPoint
  baseB: SecpPoint
  radixWindowCount: number
  scheduledAdditions: number
  activeRows: number
  paddedRows: number
  schedule: Array<{
    row: number
    rows: number
    step: number
    lane: ProductionRadix11EcLane
    op: ProductionEcOperation
    kind: 'linear' | 'mul'
    metadataSameNext: FieldElement
    accumulatorLinkNext: FieldElement
  }>
}

export interface ProductionEcTrace {
  source: ProductionRadix11EcTrace
  rows: FieldElement[][]
  layout: ProductionEcLayout
  publicInput: ProductionEcPublicInput
}

export interface ProductionEcMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  scheduledAdditions: number
  distinctAddBranches: number
  linearOps: number
  mulOps: number
  proofBytes?: number
}

interface ProductionEcAffineWitnessLimbs {
  dx: FieldElement[]
  dy: FieldElement[]
  inverseDx: FieldElement[]
  slope: FieldElement[]
  slopeSquared: FieldElement[]
  xAfterFirstSub: FieldElement[]
  xDiff: FieldElement[]
  ySum: FieldElement[]
}

interface ProductionEcCanonicalWitness {
  borrowIn: bigint[]
  borrowOut: bigint[]
  diff: bigint[]
}

export const PRODUCTION_EC_LAYOUT: ProductionEcLayout = {
  kind: 0,
  active: 1,
  sameOpNext: 2,
  limb: 3,
  limbSelectors: 4,
  linearOp: 4 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS,
  a26: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS,
  b26: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS,
  c26: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 2,
  q26: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 3,
  a52: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4,
  b52: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS,
  c52: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 2,
  qLinear: 5 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  carryIn: 6 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  carryOut: 7 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  opCode: 8 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  metadataSameNext: 9 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  accumulatorLinkNext: 10 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  branchSelectedInfinity: 11 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  branchAccumulatorInfinity: 12 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  branchDistinctAdd: 13 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  branchDoubling: 14 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  branchOpposite: 15 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  beforeInfinity: 16 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  selectedInfinity: 17 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  afterInfinity: 18 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  beforeX: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  beforeY: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS,
  selectedX: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 2,
  selectedY: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 3,
  afterX: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 4,
  afterY: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 5,
  dx: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 6,
  dy: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 7,
  inverseDx: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 8,
  slope: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 9,
  slopeSquared: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 10,
  xAfterFirstSub: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 11,
  xDiff: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 12,
  ySum: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 13,
  carryBits: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14,
  rangeBits: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS,
  canonicalBorrowIn: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS + PRODUCTION_EC_RANGE_BITS,
  canonicalBorrowOut: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS + PRODUCTION_EC_RANGE_BITS + PRODUCTION_EC_CANONICAL_VALUES,
  canonicalBits: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS + PRODUCTION_EC_RANGE_BITS + PRODUCTION_EC_CANONICAL_VALUES * 2,
  opSelectors: 19 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS + PRODUCTION_EC_RANGE_BITS + PRODUCTION_EC_CANONICAL_VALUES * 2 + PRODUCTION_EC_CANONICAL_BITS,
  width: 29 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3 + SECP256K1_FIELD_LIMBS * 14 + SECP256K1_FIELD_MUL_CARRY_BITS + PRODUCTION_EC_RANGE_BITS + PRODUCTION_EC_CANONICAL_VALUES * 2 + PRODUCTION_EC_CANONICAL_BITS
}

export function buildProductionEcTrace (
  source: ProductionRadix11EcTrace,
  options: { minTraceLength?: number } = {}
): ProductionEcTrace {
  validateProductionRadix11EcTrace(source)
  assertProductionEcSupportedBranches(source)
  const layout = PRODUCTION_EC_LAYOUT
  const operations = productionEcOperations(source)
  const activeRows = operations.reduce((total, item) => total + item.rows, 0)
  const paddedRows = nextPowerOfTwo(Math.max(
    2,
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  const rows = emptyRows(paddedRows, layout.width)
  const schedule: ProductionEcOperationSchedule[] = []
  let row = 0
  for (const item of operations) {
    schedule.push({ ...item, row })
    if (item.kind === 'linear') {
      writeLinearRows(rows, row, item.trace as Secp256k1FieldLinearTrace, layout)
    } else {
      writeMulRows(rows, row, item.trace as Secp256k1FieldMulTrace, layout)
    }
    writeAccumulatorMetadataRows(rows, row, item.rows, item, layout)
    row += item.rows
  }
  return {
    source,
    rows,
    layout,
    publicInput: {
      publicA: source.publicA,
      baseB: source.lookup.baseB,
      radixWindowCount: source.lookup.digits.length,
      scheduledAdditions: operations.length / 10,
      activeRows,
      paddedRows,
      schedule: schedule.map(item => ({
        row: item.row,
        rows: item.rows,
        step: item.step,
        lane: item.lane,
        op: item.op,
        kind: item.kind,
        metadataSameNext: item.metadataSameNext,
        accumulatorLinkNext: item.accumulatorLinkNext
      }))
    }
  }
}

export function buildProductionEcAir (
  input: ProductionEcTrace | ProductionEcPublicInput,
  publicInputDigest = productionEcPublicInputDigest(
    'rows' in input ? input.publicInput : input
  )
): AirDefinition {
  const publicInput = 'rows' in input ? input.publicInput : input
  const layout = PRODUCTION_EC_LAYOUT
  return {
    traceWidth: layout.width,
    transitionDegree: 5,
    publicInputDigest,
    boundaryConstraints: productionEcBoundaryConstraints(publicInput, layout),
    fullBoundaryColumns: productionEcScheduleColumns(publicInput, layout),
    evaluateTransition: (current, next) =>
      evaluateProductionEcTransition(current, next, layout)
  }
}

export function proveProductionEc (
  trace: ProductionEcTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildProductionEcAir(trace)
  return proveStark(air, trace.rows, {
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: PRODUCTION_EC_TRANSCRIPT_DOMAIN
  })
}

export function verifyProductionEc (
  publicInput: ProductionEcPublicInput,
  proof: StarkProof
): boolean {
  const publicInputDigest = productionEcPublicInputDigest(publicInput)
  if (!bytesEqual(proof.publicInputDigest, publicInputDigest)) return false
  const air = buildProductionEcAir(publicInput, publicInputDigest)
  return verifyStark(air, proof, starkVerifierOptions(proof))
}

export function productionEcTracePublicA (
  trace: ProductionEcTrace
): SecpPoint {
  return productionEcTraceFinalLanePoint(trace, 'G')
}

export function productionEcTracePrivateS (
  trace: ProductionEcTrace
): SecpPoint {
  return productionEcTraceFinalLanePoint(trace, 'B')
}

export function productionEcTraceSelectedPoint (
  trace: ProductionEcTrace,
  lane: ProductionRadix11EcLane,
  step: number
): SecpPoint {
  const operation = trace.publicInput.schedule.find(item =>
    item.lane === lane && item.step === step
  )
  if (operation === undefined) {
    throw new Error(`production EC ${lane} step ${step} selected row is missing`)
  }
  const row = trace.rows[operation.row]
  if (row === undefined) {
    throw new Error(`production EC ${lane} step ${step} row is missing`)
  }
  return pointFromTraceRow(
    row,
    trace.layout.selectedInfinity,
    trace.layout.selectedX,
    trace.layout.selectedY
  )
}

export function productionEcMetrics (
  trace: ProductionEcTrace,
  proof?: StarkProof,
  blowupFactor: number = 16
): ProductionEcMetrics {
  return {
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.paddedRows,
    traceWidth: trace.layout.width,
    committedCells: trace.publicInput.paddedRows * trace.layout.width,
    ldeRows: trace.publicInput.paddedRows * blowupFactor,
    ldeCells: trace.publicInput.paddedRows * trace.layout.width * blowupFactor,
    scheduledAdditions: trace.publicInput.scheduledAdditions,
    distinctAddBranches: countDistinctAddBranches(trace.source),
    linearOps: trace.publicInput.scheduledAdditions * 6,
    mulOps: trace.publicInput.scheduledAdditions * 4,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function evaluateProductionEcTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout = PRODUCTION_EC_LAYOUT
): FieldElement[] {
  const kind = current[layout.kind]
  const active = current[layout.active]
  const isLinear = F.mul(kind, F.sub(PRODUCTION_EC_ROW_KIND_MUL, kind))
  const isMul = F.mul(
    F.mul(kind, F.sub(kind, PRODUCTION_EC_ROW_KIND_LINEAR)),
    INV_TWO
  )
  const constraints = [
    F.mul(
      kind,
      F.mul(
        F.sub(kind, PRODUCTION_EC_ROW_KIND_LINEAR),
        F.sub(kind, PRODUCTION_EC_ROW_KIND_MUL)
      )
    ),
    F.sub(active, F.add(isLinear, isMul)),
    F.sub(selectorSum(current, layout), active),
    F.mul(current[layout.sameOpNext], F.sub(current[layout.sameOpNext], 1n))
  ]
  constraints.push(...gateConstraints(
    evaluateLinearRow(current, layout),
    isLinear
  ))
  constraints.push(...gateConstraints(
    evaluateMulRow(current, layout),
    isMul
  ))
  constraints.push(...gateConstraints(
    linearContinuity(current, next, layout),
    F.mul(isLinear, current[layout.sameOpNext])
  ))
  constraints.push(...gateConstraints(
    mulContinuity(current, next, layout),
    F.mul(isMul, current[layout.sameOpNext])
  ))
  constraints.push(...evaluateAccumulatorMetadataTransition(current, next, layout))
  return constraints
}

function evaluateAccumulatorMetadataTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout
): FieldElement[] {
  const active = current[layout.active]
  const selectedInfinity = current[layout.branchSelectedInfinity]
  const accumulatorInfinity = current[layout.branchAccumulatorInfinity]
  const distinctAdd = current[layout.branchDistinctAdd]
  const doubling = current[layout.branchDoubling]
  const opposite = current[layout.branchOpposite]
  const branchSum = F.add(
    F.add(selectedInfinity, accumulatorInfinity),
    F.add(distinctAdd, F.add(doubling, opposite))
  )
  const constraints: FieldElement[] = [
    F.sub(branchSum, active),
    boolConstraint(selectedInfinity),
    boolConstraint(accumulatorInfinity),
    boolConstraint(distinctAdd),
    boolConstraint(doubling),
    boolConstraint(opposite),
    boolConstraint(current[layout.beforeInfinity]),
    boolConstraint(current[layout.selectedInfinity]),
    boolConstraint(current[layout.afterInfinity]),
    doubling,
    opposite,
    F.mul(selectedInfinity, F.sub(current[layout.selectedInfinity], 1n)),
    F.mul(accumulatorInfinity, F.sub(current[layout.beforeInfinity], 1n)),
    F.mul(accumulatorInfinity, current[layout.selectedInfinity]),
    F.mul(accumulatorInfinity, current[layout.afterInfinity]),
    F.mul(distinctAdd, current[layout.beforeInfinity]),
    F.mul(distinctAdd, current[layout.selectedInfinity]),
    F.mul(distinctAdd, current[layout.afterInfinity])
  ]
  constraints.push(...gatedLimbEquality(
    current,
    layout.afterX,
    layout.beforeX,
    selectedInfinity
  ))
  constraints.push(...gatedLimbEquality(
    current,
    layout.afterY,
    layout.beforeY,
    selectedInfinity
  ))
  constraints.push(F.mul(
    selectedInfinity,
    F.sub(current[layout.afterInfinity], current[layout.beforeInfinity])
  ))
  constraints.push(...gatedLimbEquality(
    current,
    layout.afterX,
    layout.selectedX,
    accumulatorInfinity
  ))
  constraints.push(...gatedLimbEquality(
    current,
    layout.afterY,
    layout.selectedY,
    accumulatorInfinity
  ))
  constraints.push(...distinctAddFieldBindings(current, layout, distinctAdd))
  constraints.push(...gatedMetadataContinuity(
    current,
    next,
    layout,
    current[layout.metadataSameNext]
  ))
  constraints.push(...gatedAccumulatorLink(
    current,
    next,
    layout,
    current[layout.accumulatorLinkNext]
  ))
  return constraints
}

function productionEcOperations (
  source: ProductionRadix11EcTrace
): Array<{
    step: number
    lane: ProductionRadix11EcLane
    op: ProductionEcOperation
    kind: 'linear' | 'mul'
    rows: number
    trace: Secp256k1FieldLinearTrace | Secp256k1FieldMulTrace
    metadataSameNext: FieldElement
    accumulatorLinkNext: FieldElement
    laneRow: ProductionRadix11EcLaneRow
    witness: Secp256k1AffineAddWitness
  }> {
  const out: ReturnType<typeof productionEcOperations> = []
  for (const laneName of ['G', 'B'] as ProductionRadix11EcLane[]) {
    for (let step = 0; step < source.steps.length; step++) {
      const lane = laneName === 'G' ? source.steps[step].g : source.steps[step].b
      const bundle = lane.branch === 'distinct-add'
        ? buildSecp256k1AffineAddTraceBundle(lane.before, lane.selected)
        : dummyAffineAddTraceBundle()
      const group: ReturnType<typeof productionEcOperations> = []
      pushBundleOps(group, step, lane.lane, lane, bundle)
      for (let i = 0; i < group.length; i++) {
        out.push({
          ...group[i],
          metadataSameNext: i + 1 < group.length ? 1n : 0n,
          accumulatorLinkNext:
            i + 1 === group.length && step + 1 < source.steps.length ? 1n : 0n
        })
      }
    }
  }
  return out
}

function pushBundleOps (
  out: ReturnType<typeof productionEcOperations>,
  step: number,
  lane: ProductionRadix11EcLane,
  laneRow: ProductionRadix11EcLaneRow,
  bundle: Secp256k1AffineAddTraceBundle
): void {
  for (const [op, trace] of [
    ['dx', bundle.linear.dx],
    ['dy', bundle.linear.dy],
    ['xFirstSub', bundle.linear.xFirstSub],
    ['xSecondSub', bundle.linear.xSecondSub],
    ['xDiff', bundle.linear.xDiff],
    ['ySum', bundle.linear.ySum]
  ] as Array<[ProductionEcOperation, Secp256k1FieldLinearTrace]>) {
    out.push({
      step,
      lane,
      op,
      kind: 'linear',
      rows: trace.activeRows,
      trace,
      metadataSameNext: 0n,
      accumulatorLinkNext: 0n,
      laneRow,
      witness: bundle.witness
    })
  }
  for (const [op, trace] of [
    ['inverse', bundle.mul.inverse],
    ['slope', bundle.mul.slope],
    ['slopeSquared', bundle.mul.slopeSquared],
    ['yRelation', bundle.mul.yRelation]
  ] as Array<[ProductionEcOperation, Secp256k1FieldMulTrace]>) {
    out.push({
      step,
      lane,
      op,
      kind: 'mul',
      rows: trace.activeRows,
      trace,
      metadataSameNext: 0n,
      accumulatorLinkNext: 0n,
      laneRow,
      witness: bundle.witness
    })
  }
}

function writeLinearRows (
  rows: FieldElement[][],
  offset: number,
  trace: Secp256k1FieldLinearTrace,
  layout: ProductionEcLayout
): void {
  const a = secp256k1FieldToLimbs52(trace.a)
  const b = secp256k1FieldToLimbs52(trace.b)
  const c = secp256k1FieldToLimbs52(trace.c)
  const canonical = [a, b, c].map(limbs =>
    canonicalWitness(limbs, P_MINUS_ONE_52, FIELD_RADIX)
  )
  let carry = 0n
  for (let limb = 0; limb < trace.activeRows; limb++) {
    const row = rows[offset + limb]
    row[layout.kind] = PRODUCTION_EC_ROW_KIND_LINEAR
    row[layout.active] = 1n
    row[layout.sameOpNext] = limb + 1 < trace.activeRows ? 1n : 0n
    row[layout.limb] = BigInt(limb)
    row[layout.limbSelectors + limb] = 1n
    row[layout.linearOp] = trace.op
    writeLimbs(row, layout.a52, a)
    writeLimbs(row, layout.b52, b)
    writeLimbs(row, layout.c52, c)
    row[layout.qLinear] = F.normalize(trace.q)
    row[layout.carryIn] = F.normalize(carry)
    const carryOut = linearCarryOut(trace.op, a, b, c, trace.q, limb, carry)
    row[layout.carryOut] = F.normalize(carryOut)
    writeSignedBits(
      row,
      layout.carryBits,
      carryOut,
      LINEAR_CARRY_BIAS,
      SECP256K1_FIELD_LINEAR_CARRY_BITS
    )
    writeUnsignedBits(
      row,
      layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_A,
      a[limb],
      SECP256K1_FIELD_LIMB_BITS
    )
    writeUnsignedBits(
      row,
      layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_B,
      b[limb],
      SECP256K1_FIELD_LIMB_BITS
    )
    writeUnsignedBits(
      row,
      layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_C,
      c[limb],
      SECP256K1_FIELD_LIMB_BITS
    )
    writeCanonicalWitness(
      row,
      layout,
      canonical,
      limb,
      SECP256K1_FIELD_LIMB_BITS
    )
    carry = carryOut
  }
  if (carry !== 0n) throw new Error('production EC linear final carry is nonzero')
}

function writeMulRows (
  rows: FieldElement[][],
  offset: number,
  trace: Secp256k1FieldMulTrace,
  layout: ProductionEcLayout
): void {
  const a26 = secp256k1FieldToLimbs26(trace.a)
  const b26 = secp256k1FieldToLimbs26(trace.b)
  const c26 = secp256k1FieldToLimbs26(trace.c)
  const q26 = secp256k1FieldToLimbs26(trace.q)
  const a52 = secp256k1FieldToLimbs52(trace.a)
  const b52 = secp256k1FieldToLimbs52(trace.b)
  const c52 = secp256k1FieldToLimbs52(trace.c)
  const canonical = [a26, b26, c26, q26].map(limbs =>
    canonicalWitness(limbs, P_MINUS_ONE_26, MUL_RADIX)
  )
  let carry = 0n
  for (let limb = 0; limb < trace.activeRows; limb++) {
    const row = rows[offset + limb]
    row[layout.kind] = PRODUCTION_EC_ROW_KIND_MUL
    row[layout.active] = 1n
    row[layout.sameOpNext] = limb + 1 < trace.activeRows ? 1n : 0n
    row[layout.limb] = BigInt(limb)
    row[layout.limbSelectors + limb] = 1n
    writeLimbs(row, layout.a26, a26)
    writeLimbs(row, layout.b26, b26)
    writeLimbs(row, layout.c26, c26)
    writeLimbs(row, layout.q26, q26)
    writeLimbs(row, layout.a52, a52)
    writeLimbs(row, layout.b52, b52)
    writeLimbs(row, layout.c52, c52)
    row[layout.carryIn] = F.normalize(carry)
    const carryOut = mulCarryOut(a26, b26, c26, q26, limb, carry)
    row[layout.carryOut] = F.normalize(carryOut)
    writeSignedBits(
      row,
      layout.carryBits,
      carryOut,
      MUL_CARRY_BIAS,
      SECP256K1_FIELD_MUL_CARRY_BITS
    )
    if (limb < SECP256K1_FIELD_MUL_LIMBS) {
      writeUnsignedBits(
        row,
        layout.rangeBits + PRODUCTION_EC_MUL_RANGE_A,
        a26[limb],
        SECP256K1_FIELD_MUL_LIMB_BITS
      )
      writeUnsignedBits(
        row,
        layout.rangeBits + PRODUCTION_EC_MUL_RANGE_B,
        b26[limb],
        SECP256K1_FIELD_MUL_LIMB_BITS
      )
      writeUnsignedBits(
        row,
        layout.rangeBits + PRODUCTION_EC_MUL_RANGE_C,
        c26[limb],
        SECP256K1_FIELD_MUL_LIMB_BITS
      )
      writeUnsignedBits(
        row,
        layout.rangeBits + PRODUCTION_EC_MUL_RANGE_Q,
        q26[limb],
        SECP256K1_FIELD_MUL_LIMB_BITS
      )
    }
    writeCanonicalWitness(
      row,
      layout,
      canonical,
      limb,
      SECP256K1_FIELD_MUL_LIMB_BITS
    )
    carry = carryOut
  }
  if (carry !== 0n) throw new Error('production EC mul final carry is nonzero')
}

function writeAccumulatorMetadataRows (
  rows: FieldElement[][],
  offset: number,
  count: number,
  operation: {
    op: ProductionEcOperation
    metadataSameNext: FieldElement
    accumulatorLinkNext: FieldElement
    laneRow: ProductionRadix11EcLaneRow
    witness: Secp256k1AffineAddWitness
  },
  layout: ProductionEcLayout
): void {
  const branch = productionEcBranchSelectors(operation.laneRow.branch)
  const before = pointLimbsOrZero(operation.laneRow.before)
  const selected = pointLimbsOrZero(operation.laneRow.selected)
  const after = pointLimbsOrZero(operation.laneRow.after)
  const witness = affineWitnessLimbs(operation.witness)
  for (let i = 0; i < count; i++) {
    const row = rows[offset + i]
    const opCode = productionEcOpCode(operation.op)
    row[layout.opCode] = opCode
    row[layout.opSelectors + Number(opCode - 1n)] = 1n
    row[layout.metadataSameNext] =
      i + 1 < count ? 1n : operation.metadataSameNext
    row[layout.accumulatorLinkNext] =
      i + 1 < count ? 0n : operation.accumulatorLinkNext
    row[layout.branchSelectedInfinity] = branch.selectedInfinity
    row[layout.branchAccumulatorInfinity] = branch.accumulatorInfinity
    row[layout.branchDistinctAdd] = branch.distinctAdd
    row[layout.branchDoubling] = branch.doubling
    row[layout.branchOpposite] = branch.opposite
    row[layout.beforeInfinity] = operation.laneRow.before.infinity === true ? 1n : 0n
    row[layout.selectedInfinity] = operation.laneRow.selected.infinity === true ? 1n : 0n
    row[layout.afterInfinity] = operation.laneRow.after.infinity === true ? 1n : 0n
    writeLimbs(row, layout.beforeX, before.x)
    writeLimbs(row, layout.beforeY, before.y)
    writeLimbs(row, layout.selectedX, selected.x)
    writeLimbs(row, layout.selectedY, selected.y)
    writeLimbs(row, layout.afterX, after.x)
    writeLimbs(row, layout.afterY, after.y)
    writeLimbs(row, layout.dx, witness.dx)
    writeLimbs(row, layout.dy, witness.dy)
    writeLimbs(row, layout.inverseDx, witness.inverseDx)
    writeLimbs(row, layout.slope, witness.slope)
    writeLimbs(row, layout.slopeSquared, witness.slopeSquared)
    writeLimbs(row, layout.xAfterFirstSub, witness.xAfterFirstSub)
    writeLimbs(row, layout.xDiff, witness.xDiff)
    writeLimbs(row, layout.ySum, witness.ySum)
  }
}

function productionEcBoundaryConstraints (
  publicInput: ProductionEcPublicInput,
  layout: ProductionEcLayout
): NonNullable<AirDefinition['boundaryConstraints']> {
  const constraints: NonNullable<AirDefinition['boundaryConstraints']> = []
  for (const op of publicInput.schedule) {
    constraints.push({ column: layout.carryIn, row: op.row, value: 0n })
    constraints.push({ column: layout.carryOut, row: op.row + op.rows - 1, value: 0n })
    const canonicalValues = op.kind === 'linear'
      ? 3
      : PRODUCTION_EC_CANONICAL_VALUES
    for (let i = 0; i < canonicalValues; i++) {
      constraints.push({
        column: layout.canonicalBorrowIn + i,
        row: op.row,
        value: 0n
      })
      constraints.push({
        column: layout.canonicalBorrowOut + i,
        row: op.row + op.rows - 1,
        value: 0n
      })
    }
  }
  const firstG = firstLaneOperation(publicInput, 'G')
  const firstB = firstLaneOperation(publicInput, 'B')
  for (const op of [firstG, firstB]) {
    constraints.push({ column: layout.beforeInfinity, row: op.row, value: 1n })
    for (const column of [...limbColumns(layout.beforeX), ...limbColumns(layout.beforeY)]) {
      constraints.push({ column, row: op.row, value: 0n })
    }
  }
  const finalG = finalLaneOperation(publicInput, 'G')
  const finalGRow = finalG.row + finalG.rows - 1
  constraints.push({
    column: layout.afterInfinity,
    row: finalGRow,
    value: publicInput.publicA.infinity === true ? 1n : 0n
  })
  const publicALimbs = pointLimbsOrZero(publicInput.publicA)
  for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
    constraints.push({
      column: layout.afterX + i,
      row: finalGRow,
      value: publicALimbs.x[i]
    })
    constraints.push({
      column: layout.afterY + i,
      row: finalGRow,
      value: publicALimbs.y[i]
    })
  }
  const finalB = finalLaneOperation(publicInput, 'B')
  constraints.push({
    column: layout.afterInfinity,
    row: finalB.row + finalB.rows - 1,
    value: 0n
  })
  return constraints
}

function firstLaneOperation (
  publicInput: ProductionEcPublicInput,
  lane: ProductionRadix11EcLane
): ProductionEcPublicInput['schedule'][number] {
  const operation = publicInput.schedule.find(item => item.lane === lane)
  if (operation === undefined) {
    throw new Error(`production EC ${lane} lane has no scheduled operation`)
  }
  return operation
}

function finalLaneOperation (
  publicInput: ProductionEcPublicInput,
  lane: ProductionRadix11EcLane
): ProductionEcPublicInput['schedule'][number] {
  for (let i = publicInput.schedule.length - 1; i >= 0; i--) {
    const operation = publicInput.schedule[i]
    if (operation.lane === lane) return operation
  }
  throw new Error(`production EC ${lane} lane has no scheduled operation`)
}

function productionEcTraceFinalLanePoint (
  trace: ProductionEcTrace,
  lane: ProductionRadix11EcLane
): SecpPoint {
  const operation = finalLaneOperation(trace.publicInput, lane)
  const row = trace.rows[operation.row + operation.rows - 1]
  if (row === undefined) {
    throw new Error(`production EC ${lane} final row is missing`)
  }
  return pointFromTraceRow(
    row,
    trace.layout.afterInfinity,
    trace.layout.afterX,
    trace.layout.afterY
  )
}

function pointFromTraceRow (
  row: FieldElement[],
  infinityColumn: number,
  xOffset: number,
  yOffset: number
): SecpPoint {
  const infinity = row[infinityColumn]
  if (infinity === 1n) return { x: 0n, y: 0n, infinity: true }
  if (infinity !== 0n) {
    throw new Error('production EC point infinity flag is not boolean')
  }
  return {
    x: secp256k1FieldFromLimbs52(
      row.slice(xOffset, xOffset + SECP256K1_FIELD_LIMBS)
    ),
    y: secp256k1FieldFromLimbs52(
      row.slice(yOffset, yOffset + SECP256K1_FIELD_LIMBS)
    )
  }
}

function productionEcScheduleColumns (
  publicInput: ProductionEcPublicInput,
  layout: ProductionEcLayout
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const values = Array.from({ length: layout.width }, () =>
    new Array<FieldElement>(publicInput.paddedRows).fill(0n)
  )
  for (const op of publicInput.schedule) {
    for (let i = 0; i < op.rows; i++) {
      const row = op.row + i
      values[layout.kind][row] = op.kind === 'linear'
        ? PRODUCTION_EC_ROW_KIND_LINEAR
        : PRODUCTION_EC_ROW_KIND_MUL
      values[layout.active][row] = 1n
      values[layout.sameOpNext][row] = i + 1 < op.rows ? 1n : 0n
      values[layout.limb][row] = BigInt(i)
      values[layout.limbSelectors + i][row] = 1n
      values[layout.linearOp][row] = linearScheduleOp(op.op)
      const opCode = productionEcOpCode(op.op)
      values[layout.opCode][row] = opCode
      values[layout.opSelectors + Number(opCode - 1n)][row] = 1n
      values[layout.metadataSameNext][row] =
        i + 1 < op.rows ? 1n : op.metadataSameNext
      values[layout.accumulatorLinkNext][row] =
        i + 1 < op.rows ? 0n : op.accumulatorLinkNext
    }
  }
  const columns = [
    layout.kind,
    layout.active,
    layout.sameOpNext,
    layout.limb,
    layout.linearOp,
    layout.opCode,
    layout.metadataSameNext,
    layout.accumulatorLinkNext,
    ...Array.from({ length: SECP256K1_FIELD_MUL_PRODUCT_LIMBS }, (_, i) =>
      layout.limbSelectors + i
    ),
    ...Array.from({ length: 10 }, (_, i) =>
      layout.opSelectors + i
    )
  ]
  return columns.map(column => ({ column, values: values[column] }))
}

function productionEcOpCode (op: ProductionEcOperation): FieldElement {
  if (op === 'dx') return 1n
  if (op === 'dy') return 2n
  if (op === 'inverse') return 3n
  if (op === 'slope') return 4n
  if (op === 'slopeSquared') return 5n
  if (op === 'xFirstSub') return 6n
  if (op === 'xSecondSub') return 7n
  if (op === 'xDiff') return 8n
  if (op === 'ySum') return 9n
  if (op === 'yRelation') return 10n
  return 0n
}

function linearScheduleOp (op: ProductionEcOperation): FieldElement {
  if (op === 'ySum') return SECP256K1_FIELD_LINEAR_ADD
  if (
    op === 'dx' ||
    op === 'dy' ||
    op === 'xFirstSub' ||
    op === 'xSecondSub' ||
    op === 'xDiff'
  ) {
    return SECP256K1_FIELD_LINEAR_SUB
  }
  return 0n
}

function evaluateLinearRow (
  row: FieldElement[],
  layout: ProductionEcLayout
): FieldElement[] {
  const op = row[layout.linearOp]
  const add = F.sub(SECP256K1_FIELD_LINEAR_SUB, op)
  const sub = F.sub(op, SECP256K1_FIELD_LINEAR_ADD)
  const q = row[layout.qLinear]
  let selectedEquation = 0n
  for (let limb = 0; limb < SECP256K1_FIELD_LIMBS; limb++) {
    const selector = row[layout.limbSelectors + limb]
    const signedB = F.sub(
      F.mul(add, row[layout.b52 + limb]),
      F.mul(sub, row[layout.b52 + limb])
    )
    const equation = F.sub(
      F.add(
        F.sub(
          F.sub(
            F.add(row[layout.a52 + limb], signedB),
            row[layout.c52 + limb]
          ),
          F.mul(q, P_52[limb])
        ),
        row[layout.carryIn]
      ),
      F.mul(row[layout.carryOut], FIELD_RADIX)
    )
    selectedEquation = F.add(selectedEquation, F.mul(selector, equation))
  }
  const constraints = [
    F.mul(F.sub(op, SECP256K1_FIELD_LINEAR_ADD), F.sub(op, SECP256K1_FIELD_LINEAR_SUB)),
    selectedEquation,
    F.mul(add, F.mul(q, F.sub(q, 1n))),
    F.mul(sub, F.mul(q, F.add(q, 1n)))
  ]
  constraints.push(...signedBitsConstraint(
    row,
    layout.carryBits,
    row[layout.carryOut],
    LINEAR_CARRY_BIAS,
    SECP256K1_FIELD_LINEAR_CARRY_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_A,
    selectedLimb(row, layout, layout.a52, SECP256K1_FIELD_LIMBS),
    SECP256K1_FIELD_LIMB_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_B,
    selectedLimb(row, layout, layout.b52, SECP256K1_FIELD_LIMBS),
    SECP256K1_FIELD_LIMB_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_LINEAR_RANGE_C,
    selectedLimb(row, layout, layout.c52, SECP256K1_FIELD_LIMBS),
    SECP256K1_FIELD_LIMB_BITS
  ))
  constraints.push(...canonicalConstraints(
    row,
    layout,
    [
      [layout.a52, PRODUCTION_EC_LINEAR_RANGE_A],
      [layout.b52, PRODUCTION_EC_LINEAR_RANGE_B],
      [layout.c52, PRODUCTION_EC_LINEAR_RANGE_C]
    ],
    P_MINUS_ONE_52,
    FIELD_RADIX,
    SECP256K1_FIELD_LIMB_BITS,
    SECP256K1_FIELD_LIMBS
  ))
  return constraints
}

function evaluateMulRow (
  row: FieldElement[],
  layout: ProductionEcLayout
): FieldElement[] {
  let selectedEquation = 0n
  for (let limb = 0; limb < SECP256K1_FIELD_MUL_PRODUCT_LIMBS; limb++) {
    const selector = row[layout.limbSelectors + limb]
    const prod = convolutionFromRow(row, layout.a26, layout.b26, limb)
    const qp = quotientProductFromRow(row, layout.q26, limb)
    const c = limb < SECP256K1_FIELD_MUL_LIMBS
      ? row[layout.c26 + limb]
      : 0n
    const equation = F.sub(
      F.sub(F.add(prod, row[layout.carryIn]), F.add(c, qp)),
      F.mul(row[layout.carryOut], MUL_RADIX)
    )
    selectedEquation = F.add(selectedEquation, F.mul(selector, equation))
  }
  const constraints = [selectedEquation]
  for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
    constraints.push(F.sub(
      row[layout.a52 + i],
      F.add(row[layout.a26 + i * 2], F.mul(row[layout.a26 + i * 2 + 1], MUL_RADIX))
    ))
    constraints.push(F.sub(
      row[layout.b52 + i],
      F.add(row[layout.b26 + i * 2], F.mul(row[layout.b26 + i * 2 + 1], MUL_RADIX))
    ))
    constraints.push(F.sub(
      row[layout.c52 + i],
      F.add(row[layout.c26 + i * 2], F.mul(row[layout.c26 + i * 2 + 1], MUL_RADIX))
    ))
  }
  constraints.push(...signedBitsConstraint(
    row,
    layout.carryBits,
    row[layout.carryOut],
    MUL_CARRY_BIAS,
    SECP256K1_FIELD_MUL_CARRY_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_MUL_RANGE_A,
    selectedLimb(row, layout, layout.a26, SECP256K1_FIELD_MUL_LIMBS),
    SECP256K1_FIELD_MUL_LIMB_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_MUL_RANGE_B,
    selectedLimb(row, layout, layout.b26, SECP256K1_FIELD_MUL_LIMBS),
    SECP256K1_FIELD_MUL_LIMB_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_MUL_RANGE_C,
    selectedLimb(row, layout, layout.c26, SECP256K1_FIELD_MUL_LIMBS),
    SECP256K1_FIELD_MUL_LIMB_BITS
  ))
  constraints.push(...unsignedBitsConstraint(
    row,
    layout.rangeBits + PRODUCTION_EC_MUL_RANGE_Q,
    selectedLimb(row, layout, layout.q26, SECP256K1_FIELD_MUL_LIMBS),
    SECP256K1_FIELD_MUL_LIMB_BITS
  ))
  constraints.push(...canonicalConstraints(
    row,
    layout,
    [
      [layout.a26, PRODUCTION_EC_MUL_RANGE_A],
      [layout.b26, PRODUCTION_EC_MUL_RANGE_B],
      [layout.c26, PRODUCTION_EC_MUL_RANGE_C],
      [layout.q26, PRODUCTION_EC_MUL_RANGE_Q]
    ],
    P_MINUS_ONE_26,
    MUL_RADIX,
    SECP256K1_FIELD_MUL_LIMB_BITS,
    SECP256K1_FIELD_MUL_LIMBS
  ))
  return constraints
}

function linearContinuity (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout
): FieldElement[] {
  const constraints = [
    F.sub(next[layout.carryIn], current[layout.carryOut]),
    F.sub(next[layout.linearOp], current[layout.linearOp]),
    F.sub(next[layout.qLinear], current[layout.qLinear])
  ]
  for (const offset of [layout.a52, layout.b52, layout.c52]) {
    for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
      constraints.push(F.sub(next[offset + i], current[offset + i]))
    }
  }
  for (let i = 0; i < 3; i++) {
    constraints.push(F.sub(
      next[layout.canonicalBorrowIn + i],
      current[layout.canonicalBorrowOut + i]
    ))
  }
  return constraints
}

function mulContinuity (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout
): FieldElement[] {
  const constraints = [
    F.sub(next[layout.carryIn], current[layout.carryOut])
  ]
  for (const [offset, count] of [
    [layout.a26, SECP256K1_FIELD_MUL_LIMBS],
    [layout.b26, SECP256K1_FIELD_MUL_LIMBS],
    [layout.c26, SECP256K1_FIELD_MUL_LIMBS],
    [layout.q26, SECP256K1_FIELD_MUL_LIMBS],
    [layout.a52, SECP256K1_FIELD_LIMBS],
    [layout.b52, SECP256K1_FIELD_LIMBS],
    [layout.c52, SECP256K1_FIELD_LIMBS]
  ] as Array<[number, number]>) {
    for (let i = 0; i < count; i++) {
      constraints.push(F.sub(next[offset + i], current[offset + i]))
    }
  }
  for (let i = 0; i < PRODUCTION_EC_CANONICAL_VALUES; i++) {
    constraints.push(F.sub(
      next[layout.canonicalBorrowIn + i],
      current[layout.canonicalBorrowOut + i]
    ))
  }
  return constraints
}

function productionEcPublicInputDigest (
  input: ProductionEcPublicInput
): number[] {
  const writer = new Writer()
  writer.write(toArray(PRODUCTION_EC_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(input.radixWindowCount)
  writer.writeVarIntNum(input.scheduledAdditions)
  writer.writeVarIntNum(input.activeRows)
  writer.writeVarIntNum(input.paddedRows)
  writePoint(writer, input.publicA)
  writePoint(writer, input.baseB)
  writer.writeVarIntNum(input.schedule.length)
  for (const row of input.schedule) {
    writer.writeVarIntNum(row.row)
    writer.writeVarIntNum(row.rows)
    writer.writeVarIntNum(row.step)
    writer.writeUInt8(row.lane === 'G' ? 1 : 2)
    writer.write(toArray(row.op, 'utf8'))
    writer.writeUInt8(row.kind === 'linear' ? 1 : 2)
    writer.writeUInt8(Number(row.metadataSameNext))
    writer.writeUInt8(Number(row.accumulatorLinkNext))
  }
  return sha256(writer.toArray())
}

function countDistinctAddBranches (source: ProductionRadix11EcTrace): number {
  let count = 0
  for (const step of source.steps) {
    if (step.g.branch === 'distinct-add') count++
    if (step.b.branch === 'distinct-add') count++
  }
  return count
}

function assertProductionEcSupportedBranches (
  source: ProductionRadix11EcTrace
): void {
  for (const step of source.steps) {
    for (const lane of [step.g, step.b]) {
      if (lane.branch === 'doubling' || lane.branch === 'opposite-add') {
        throw new Error(
          'production EC AIR does not support doubling/opposite accumulator branches'
        )
      }
    }
  }
}

function dummyAffineAddTraceBundle (): Secp256k1AffineAddTraceBundle {
  const zero = 0n
  return {
    witness: {
      left: { x: zero, y: zero },
      right: { x: zero, y: zero },
      result: { x: zero, y: zero },
      dx: zero,
      dy: zero,
      inverseDx: zero,
      slope: zero,
      slopeSquared: zero,
      xAfterFirstSub: zero,
      xDiff: zero,
      ySum: zero
    },
    linear: {
      dx: buildSecp256k1FieldSubTrace(zero, zero, zero),
      dy: buildSecp256k1FieldSubTrace(zero, zero, zero),
      xFirstSub: buildSecp256k1FieldSubTrace(zero, zero, zero),
      xSecondSub: buildSecp256k1FieldSubTrace(zero, zero, zero),
      xDiff: buildSecp256k1FieldSubTrace(zero, zero, zero),
      ySum: buildSecp256k1FieldAddTrace(zero, zero, zero)
    },
    mul: {
      inverse: buildSecp256k1FieldMulTrace(zero, zero, zero),
      slope: buildSecp256k1FieldMulTrace(zero, zero, zero),
      slopeSquared: buildSecp256k1FieldMulTrace(zero, zero, zero),
      yRelation: buildSecp256k1FieldMulTrace(zero, zero, zero)
    }
  }
}

function productionEcBranchSelectors (
  branch: ProductionRadix11EcLaneRow['branch']
): {
    selectedInfinity: FieldElement
    accumulatorInfinity: FieldElement
    distinctAdd: FieldElement
    doubling: FieldElement
    opposite: FieldElement
  } {
  return {
    selectedInfinity: branch === 'selected-infinity' ? 1n : 0n,
    accumulatorInfinity: branch === 'accumulator-infinity' ? 1n : 0n,
    distinctAdd: branch === 'distinct-add' ? 1n : 0n,
    doubling: branch === 'doubling' ? 1n : 0n,
    opposite: branch === 'opposite-add' ? 1n : 0n
  }
}

function pointLimbsOrZero (
  point: SecpPoint
): { x: FieldElement[], y: FieldElement[] } {
  if (point.infinity === true) {
    return {
      x: new Array<FieldElement>(SECP256K1_FIELD_LIMBS).fill(0n),
      y: new Array<FieldElement>(SECP256K1_FIELD_LIMBS).fill(0n)
    }
  }
  return {
    x: secp256k1FieldToLimbs52(point.x),
    y: secp256k1FieldToLimbs52(point.y)
  }
}

function affineWitnessLimbs (
  witness: Secp256k1AffineAddWitness
): ProductionEcAffineWitnessLimbs {
  return {
    dx: secp256k1FieldToLimbs52(witness.dx),
    dy: secp256k1FieldToLimbs52(witness.dy),
    inverseDx: secp256k1FieldToLimbs52(witness.inverseDx),
    slope: secp256k1FieldToLimbs52(witness.slope),
    slopeSquared: secp256k1FieldToLimbs52(witness.slopeSquared),
    xAfterFirstSub: secp256k1FieldToLimbs52(witness.xAfterFirstSub),
    xDiff: secp256k1FieldToLimbs52(witness.xDiff),
    ySum: secp256k1FieldToLimbs52(witness.ySum)
  }
}

function starkVerifierOptions (proof: StarkProof): StarkVerifierOptions {
  return {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain: PRODUCTION_EC_TRANSCRIPT_DOMAIN
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}

function selectorSum (
  row: FieldElement[],
  layout: ProductionEcLayout
): FieldElement {
  let sum = 0n
  for (let i = 0; i < SECP256K1_FIELD_MUL_PRODUCT_LIMBS; i++) {
    sum = F.add(sum, row[layout.limbSelectors + i])
  }
  return sum
}

function linearCarryOut (
  op: FieldElement,
  a: bigint[],
  b: bigint[],
  c: bigint[],
  q: bigint,
  limb: number,
  carryIn: bigint
): bigint {
  const signedB = op === SECP256K1_FIELD_LINEAR_ADD ? b[limb] : -b[limb]
  const value = a[limb] + signedB - c[limb] - q * P_52[limb] + carryIn
  if (value % FIELD_RADIX !== 0n) {
    throw new Error('production EC linear carry is not integral')
  }
  return value / FIELD_RADIX
}

function mulCarryOut (
  a: bigint[],
  b: bigint[],
  c: bigint[],
  q: bigint[],
  limb: number,
  carryIn: bigint
): bigint {
  const value = convolution(a, b, limb) + carryIn -
    (c[limb] ?? 0n) -
    quotientProduct(q, limb)
  if (value % MUL_RADIX !== 0n) {
    throw new Error('production EC mul carry is not integral')
  }
  return value / MUL_RADIX
}

function convolutionFromRow (
  row: FieldElement[],
  leftOffset: number,
  rightOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < SECP256K1_FIELD_MUL_LIMBS; i++) {
    const j = limb - i
    if (j >= 0 && j < SECP256K1_FIELD_MUL_LIMBS) {
      sum = F.add(sum, F.mul(row[leftOffset + i], row[rightOffset + j]))
    }
  }
  return sum
}

function quotientProductFromRow (
  row: FieldElement[],
  qOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < SECP256K1_FIELD_MUL_LIMBS; i++) {
    const j = limb - i
    if (j >= 0 && j < P_26.length) {
      sum = F.add(sum, F.mul(row[qOffset + i], P_26[j]))
    }
  }
  return sum
}

function convolution (left: bigint[], right: bigint[], limb: number): bigint {
  let sum = 0n
  for (let i = 0; i < left.length; i++) {
    const j = limb - i
    if (j >= 0 && j < right.length) sum += left[i] * right[j]
  }
  return sum
}

function quotientProduct (q: bigint[], limb: number): bigint {
  let sum = 0n
  for (let i = 0; i < q.length; i++) {
    const j = limb - i
    if (j >= 0 && j < P_26.length) sum += q[i] * P_26[j]
  }
  return sum
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function boolConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function signedBitsConstraint (
  row: FieldElement[],
  offset: number,
  signedValue: FieldElement,
  bias: bigint,
  bits: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  let value = 0n
  for (let bit = 0; bit < bits; bit++) {
    const bitValue = row[offset + bit]
    constraints.push(boolConstraint(bitValue))
    value = F.add(value, F.mul(bitValue, 1n << BigInt(bit)))
  }
  constraints.push(F.sub(F.add(signedValue, bias), value))
  return constraints
}

function unsignedBitsConstraint (
  row: FieldElement[],
  offset: number,
  value: FieldElement,
  bits: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  let recomposed = 0n
  for (let bit = 0; bit < bits; bit++) {
    const bitValue = row[offset + bit]
    constraints.push(boolConstraint(bitValue))
    recomposed = F.add(recomposed, F.mul(bitValue, 1n << BigInt(bit)))
  }
  constraints.push(F.sub(value, recomposed))
  return constraints
}

function canonicalConstraints (
  row: FieldElement[],
  layout: ProductionEcLayout,
  values: Array<[number, number]>,
  bound: bigint[],
  radix: bigint,
  bits: number,
  count: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let valueIndex = 0; valueIndex < values.length; valueIndex++) {
    const [valueOffset, bitOffset] = values[valueIndex]
    const borrowIn = row[layout.canonicalBorrowIn + valueIndex]
    const borrowOut = row[layout.canonicalBorrowOut + valueIndex]
    let diff = 0n
    for (let bit = 0; bit < bits; bit++) {
      const bitValue = row[layout.canonicalBits + bitOffset + bit]
      constraints.push(boolConstraint(bitValue))
      diff = F.add(diff, F.mul(bitValue, 1n << BigInt(bit)))
    }
    constraints.push(boolConstraint(borrowIn))
    constraints.push(boolConstraint(borrowOut))
    constraints.push(F.add(
      F.sub(
        F.sub(
          F.sub(selectedConstantLimb(row, layout, bound, count), selectedLimb(
            row,
            layout,
            valueOffset,
            count
          )),
          borrowIn
        ),
        diff
      ),
      F.mul(borrowOut, radix)
    ))
  }
  return constraints
}

function selectedLimb (
  row: FieldElement[],
  layout: ProductionEcLayout,
  offset: number,
  count: number
): FieldElement {
  let selected = 0n
  for (let i = 0; i < count; i++) {
    selected = F.add(
      selected,
      F.mul(row[layout.limbSelectors + i], row[offset + i])
    )
  }
  return selected
}

function selectedConstantLimb (
  row: FieldElement[],
  layout: ProductionEcLayout,
  limbs: bigint[],
  count: number
): FieldElement {
  let selected = 0n
  for (let i = 0; i < count; i++) {
    selected = F.add(
      selected,
      F.mul(row[layout.limbSelectors + i], limbs[i])
    )
  }
  return selected
}

function distinctAddFieldBindings (
  row: FieldElement[],
  layout: ProductionEcLayout,
  distinctAdd: FieldElement
): FieldElement[] {
  const constraints: FieldElement[] = []
  const one = [1n, 0n, 0n, 0n, 0n]
  bindFieldOp(constraints, row, layout, distinctAdd, 1n, {
    a: layout.selectedX,
    b: layout.beforeX,
    c: layout.dx
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 2n, {
    a: layout.selectedY,
    b: layout.beforeY,
    c: layout.dy
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 3n, {
    a: layout.dx,
    b: layout.inverseDx,
    cValues: one
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 4n, {
    a: layout.dy,
    b: layout.inverseDx,
    c: layout.slope
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 5n, {
    a: layout.slope,
    b: layout.slope,
    c: layout.slopeSquared
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 6n, {
    a: layout.slopeSquared,
    b: layout.beforeX,
    c: layout.xAfterFirstSub
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 7n, {
    a: layout.xAfterFirstSub,
    b: layout.selectedX,
    c: layout.afterX
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 8n, {
    a: layout.beforeX,
    b: layout.afterX,
    c: layout.xDiff
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 9n, {
    a: layout.afterY,
    b: layout.beforeY,
    c: layout.ySum
  })
  bindFieldOp(constraints, row, layout, distinctAdd, 10n, {
    a: layout.slope,
    b: layout.xDiff,
    c: layout.ySum
  })
  return constraints
}

function bindFieldOp (
  constraints: FieldElement[],
  row: FieldElement[],
  layout: ProductionEcLayout,
  distinctAdd: FieldElement,
  opCode: FieldElement,
  bindings: {
    a: number
    b: number
    c?: number
    cValues?: FieldElement[]
  }
): void {
  const selector = F.mul(distinctAdd, row[layout.opSelectors + Number(opCode - 1n)])
  constraints.push(...gatedLimbEquality(row, layout.a52, bindings.a, selector))
  constraints.push(...gatedLimbEquality(row, layout.b52, bindings.b, selector))
  if (bindings.c !== undefined) {
    constraints.push(...gatedLimbEquality(row, layout.c52, bindings.c, selector))
  } else if (bindings.cValues !== undefined) {
    for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
      constraints.push(F.mul(
        selector,
        F.sub(row[layout.c52 + i], bindings.cValues[i])
      ))
    }
  }
}

function gatedLimbEquality (
  row: FieldElement[],
  leftOffset: number,
  rightOffset: number,
  selector: FieldElement
): FieldElement[] {
  return Array.from({ length: SECP256K1_FIELD_LIMBS }, (_, i) =>
    F.mul(selector, F.sub(row[leftOffset + i], row[rightOffset + i]))
  )
}

function gatedMetadataContinuity (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout,
  selector: FieldElement
): FieldElement[] {
  const columns = [
    layout.branchSelectedInfinity,
    layout.branchAccumulatorInfinity,
    layout.branchDistinctAdd,
    layout.branchDoubling,
    layout.branchOpposite,
    layout.beforeInfinity,
    layout.selectedInfinity,
    layout.afterInfinity,
    ...limbColumns(layout.beforeX),
    ...limbColumns(layout.beforeY),
    ...limbColumns(layout.selectedX),
    ...limbColumns(layout.selectedY),
    ...limbColumns(layout.afterX),
    ...limbColumns(layout.afterY),
    ...limbColumns(layout.dx),
    ...limbColumns(layout.dy),
    ...limbColumns(layout.inverseDx),
    ...limbColumns(layout.slope),
    ...limbColumns(layout.slopeSquared),
    ...limbColumns(layout.xAfterFirstSub),
    ...limbColumns(layout.xDiff),
    ...limbColumns(layout.ySum)
  ]
  return columns.map(column =>
    F.mul(selector, F.sub(next[column], current[column]))
  )
}

function gatedAccumulatorLink (
  current: FieldElement[],
  next: FieldElement[],
  layout: ProductionEcLayout,
  selector: FieldElement
): FieldElement[] {
  const constraints = [
    F.mul(selector, F.sub(next[layout.beforeInfinity], current[layout.afterInfinity]))
  ]
  for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
    constraints.push(F.mul(
      selector,
      F.sub(next[layout.beforeX + i], current[layout.afterX + i])
    ))
    constraints.push(F.mul(
      selector,
      F.sub(next[layout.beforeY + i], current[layout.afterY + i])
    ))
  }
  return constraints
}

function limbColumns (offset: number): number[] {
  return Array.from({ length: SECP256K1_FIELD_LIMBS }, (_, i) => offset + i)
}

function writeLimbs (
  row: FieldElement[],
  offset: number,
  limbs: bigint[]
): void {
  for (let i = 0; i < limbs.length; i++) {
    row[offset + i] = F.normalize(limbs[i])
  }
}

function writeSignedBits (
  row: FieldElement[],
  offset: number,
  signedValue: bigint,
  bias: bigint,
  bits: number
): void {
  assertSignedBitRange(signedValue, bias, bits)
  let value = signedValue + bias
  for (let bit = 0; bit < bits; bit++) {
    row[offset + bit] = value & 1n
    value >>= 1n
  }
}

function writeUnsignedBits (
  row: FieldElement[],
  offset: number,
  value: bigint,
  bits: number
): void {
  if (value < 0n || value >= (1n << BigInt(bits))) {
    throw new Error('production EC field limb exceeds configured range')
  }
  let current = value
  for (let bit = 0; bit < bits; bit++) {
    row[offset + bit] = current & 1n
    current >>= 1n
  }
}

function writeCanonicalWitness (
  row: FieldElement[],
  layout: ProductionEcLayout,
  witnesses: ProductionEcCanonicalWitness[],
  limb: number,
  bits: number
): void {
  for (let valueIndex = 0; valueIndex < witnesses.length; valueIndex++) {
    const witness = witnesses[valueIndex]
    row[layout.canonicalBorrowIn + valueIndex] = witness.borrowIn[limb] ?? 0n
    row[layout.canonicalBorrowOut + valueIndex] = witness.borrowOut[limb] ?? 0n
    writeUnsignedBits(
      row,
      layout.canonicalBits + valueIndex * bits,
      witness.diff[limb] ?? 0n,
      bits
    )
  }
}

function canonicalWitness (
  limbs: bigint[],
  bound: bigint[],
  radix: bigint
): ProductionEcCanonicalWitness {
  const borrowIn = new Array<bigint>(limbs.length)
  const borrowOut = new Array<bigint>(limbs.length)
  const diff = new Array<bigint>(limbs.length)
  let borrow = 0n
  for (let limb = 0; limb < limbs.length; limb++) {
    borrowIn[limb] = borrow
    let value = bound[limb] - limbs[limb] - borrow
    if (value < 0n) {
      value += radix
      borrow = 1n
    } else {
      borrow = 0n
    }
    diff[limb] = value
    borrowOut[limb] = borrow
  }
  if (borrow !== 0n) {
    throw new Error('production EC field element is non-canonical')
  }
  return { borrowIn, borrowOut, diff }
}

function assertSignedBitRange (
  signedValue: bigint,
  bias: bigint,
  bits: number
): void {
  const value = signedValue + bias
  if (value < 0n || value >= (1n << BigInt(bits))) {
    throw new Error('production EC field carry exceeds configured range')
  }
}

function writePoint (writer: Writer, point: SecpPoint): void {
  writer.writeUInt8(point.infinity === true ? 1 : 0)
  writeBigIntBytes(writer, point.x, 32)
  writeBigIntBytes(writer, point.y, 32)
}

function writeBigIntBytes (
  writer: Writer,
  value: bigint,
  size: number
): void {
  const bytes = new Array<number>(size).fill(0)
  let current = value
  for (let i = size - 1; i >= 0; i--) {
    bytes[i] = Number(current & 0xffn)
    current >>= 8n
  }
  if (current !== 0n) throw new Error('production EC digest value overflow')
  writer.write(bytes)
}

function bigintToLimbs (
  value: bigint,
  count: number,
  radix: bigint
): bigint[] {
  const out: bigint[] = []
  let current = value
  for (let i = 0; i < count; i++) {
    out.push(current % radix)
    current /= radix
  }
  return out
}

function emptyRows (height: number, width: number): FieldElement[][] {
  return new Array<FieldElement[]>(height)
    .fill([])
    .map(() => new Array<FieldElement>(width).fill(0n))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
