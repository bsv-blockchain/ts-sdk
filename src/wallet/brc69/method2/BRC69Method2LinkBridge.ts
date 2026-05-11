import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { SECP256K1_P } from '../circuit/index.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  BRC69_RADIX11_POINT_LIMBS,
  BRC69_RADIX11_WINDOW_COUNT,
  ProductionRadix11LookupPrototype
} from '../stark/DualBaseRadix11Metrics.js'
import { LOOKUP_BUS_TUPLE_ARITY } from '../stark/LookupBus.js'
import { ProductionRadix11EcTrace } from '../stark/ProductionRadix11Ec.js'
import { secp256k1FieldToLimbs52 } from '../stark/Secp256k1FieldOps.js'

export const BRC69_METHOD2_LINK_BRIDGE_TRANSCRIPT_DOMAIN =
  'BRC69_METHOD2_LINK_BRIDGE_AIR_V1'
export const BRC69_METHOD2_LINK_BRIDGE_PUBLIC_INPUT_ID =
  'BRC69_METHOD2_LINK_BRIDGE_PUBLIC_INPUT_V1'

const LIMB_RADIX = 1n << 52n
const P_LIMBS = bigintToLimbs52(SECP256K1_P)
export interface BRC69Method2LinkBridgeLayout {
  active: number
  window: number
  magnitude: number
  isZero: number
  sign: number
  tableTuple: number
  selectedGInfinity: number
  selectedGX: number
  selectedGY: number
  selectedBInfinity: number
  selectedBX: number
  selectedBY: number
  gNegationCarries: number
  bNegationCarries: number
  width: number
}

export interface BRC69Method2LinkBridgePublicInput {
  activeRows: number
  traceLength: number
  scheduleRows: Array<{
    active: FieldElement
    window: FieldElement
  }>
}

export interface BRC69Method2LinkBridgeTrace {
  rows: FieldElement[][]
  layout: BRC69Method2LinkBridgeLayout
  publicInput: BRC69Method2LinkBridgePublicInput
}

export const BRC69_METHOD2_LINK_BRIDGE_LAYOUT:
BRC69Method2LinkBridgeLayout = (() => {
  const layout = {
    active: 0,
    window: 1,
    magnitude: 2,
    isZero: 3,
    sign: 4,
    tableTuple: 5,
    selectedGInfinity: 5 + LOOKUP_BUS_TUPLE_ARITY,
    selectedGX: 6 + LOOKUP_BUS_TUPLE_ARITY,
    selectedGY: 6 + LOOKUP_BUS_TUPLE_ARITY + BRC69_RADIX11_POINT_LIMBS,
    selectedBInfinity: 6 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 2,
    selectedBX: 7 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 2,
    selectedBY: 7 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 3,
    gNegationCarries: 7 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 4,
    bNegationCarries: 7 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 4 +
      BRC69_RADIX11_POINT_LIMBS + 1,
    width: 7 + LOOKUP_BUS_TUPLE_ARITY +
      BRC69_RADIX11_POINT_LIMBS * 4 +
      (BRC69_RADIX11_POINT_LIMBS + 1) * 2
  }
  return layout
})()

export function buildBRC69Method2LinkBridgeTrace (
  lookup: ProductionRadix11LookupPrototype,
  ec: ProductionRadix11EcTrace,
  options: { minTraceLength?: number } = {}
): BRC69Method2LinkBridgeTrace {
  if (ec.lookup !== lookup) {
    throw new Error('BRC69 link bridge lookup/EC mismatch')
  }
  const layout = BRC69_METHOD2_LINK_BRIDGE_LAYOUT
  const activeRows = BRC69_RADIX11_WINDOW_COUNT
  const traceLength = nextPowerOfTwo(Math.max(
    2,
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  const rows = new Array<FieldElement[]>(traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const scheduleRows = linkBridgeScheduleRows(traceLength)

  for (let rowIndex = 0; rowIndex < activeRows; rowIndex++) {
    const digit = lookup.digits[rowIndex]
    const step = ec.steps[rowIndex]
    if (digit === undefined || step === undefined) {
      throw new Error('BRC69 link bridge step is missing')
    }
    const row = rows[rowIndex]
    row[layout.active] = 1n
    row[layout.window] = BigInt(rowIndex)
    row[layout.magnitude] = BigInt(digit.magnitude)
    row[layout.isZero] = digit.magnitude === 0 ? 1n : 0n
    row[layout.sign] = BigInt(digit.sign)
    writeVector(row, layout.tableTuple, step.tableRow.values)
    writeSelectedPoint(row, layout.selectedGInfinity, layout.selectedGX, layout.selectedGY, step.g.selected)
    writeSelectedPoint(row, layout.selectedBInfinity, layout.selectedBX, layout.selectedBY, step.b.selected)
    writeNegationCarries(
      row,
      layout.gNegationCarries,
      step.tableRow.values.slice(8, 13),
      row.slice(layout.selectedGY, layout.selectedGY + BRC69_RADIX11_POINT_LIMBS),
      digit.sign,
      digit.magnitude === 0
    )
    writeNegationCarries(
      row,
      layout.bNegationCarries,
      step.tableRow.values.slice(18, 23),
      row.slice(layout.selectedBY, layout.selectedBY + BRC69_RADIX11_POINT_LIMBS),
      digit.sign,
      digit.magnitude === 0
    )
  }

  return {
    rows,
    layout,
    publicInput: {
      activeRows,
      traceLength,
      scheduleRows
    }
  }
}

export function buildBRC69Method2LinkBridgeAir (
  input: BRC69Method2LinkBridgeTrace | BRC69Method2LinkBridgePublicInput,
  publicInputDigest = brc69Method2LinkBridgePublicInputDigest(
    'rows' in input ? input.publicInput : input
  )
): AirDefinition {
  const publicInput = 'rows' in input ? input.publicInput : input
  const layout = BRC69_METHOD2_LINK_BRIDGE_LAYOUT
  return {
    traceWidth: layout.width,
    transitionDegree: 6,
    publicInputDigest,
    boundaryConstraints: [],
    fullBoundaryColumns: [
      {
        column: layout.active,
        values: publicInput.scheduleRows.map(row => row.active)
      },
      {
        column: layout.window,
        values: publicInput.scheduleRows.map(row => row.window)
      }
    ],
    evaluateTransition: current =>
      evaluateBRC69Method2LinkBridgeRow(current, layout)
  }
}

export function brc69Method2LinkBridgePublicInputDigest (
  publicInput: BRC69Method2LinkBridgePublicInput
): number[] {
  validateBRC69Method2LinkBridgePublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(BRC69_METHOD2_LINK_BRIDGE_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  for (const row of publicInput.scheduleRows) {
    writer.write(F.toBytesLE(row.active))
    writer.write(F.toBytesLE(row.window))
  }
  return sha256(writer.toArray())
}

export function validateBRC69Method2LinkBridgePublicInput (
  publicInput: BRC69Method2LinkBridgePublicInput
): void {
  if (
    publicInput.activeRows !== BRC69_RADIX11_WINDOW_COUNT ||
    !isPowerOfTwo(publicInput.traceLength) ||
    publicInput.traceLength < publicInput.activeRows + 1 ||
    publicInput.scheduleRows.length !== publicInput.traceLength
  ) {
    throw new Error('BRC69 link bridge public input shape mismatch')
  }
  const expected = linkBridgeScheduleRows(publicInput.traceLength)
  for (let i = 0; i < expected.length; i++) {
    if (
      publicInput.scheduleRows[i].active !== expected[i].active ||
      publicInput.scheduleRows[i].window !== expected[i].window
    ) {
      throw new Error('BRC69 link bridge schedule mismatch')
    }
  }
}

function evaluateBRC69Method2LinkBridgeRow (
  row: FieldElement[],
  layout: BRC69Method2LinkBridgeLayout
): FieldElement[] {
  const active = row[layout.active]
  const sign = row[layout.sign]
  const isZero = row[layout.isZero]
  const nonZero = F.sub(1n, isZero)
  const constraints: FieldElement[] = [
    F.mul(active, booleanConstraint(sign)),
    F.mul(active, booleanConstraint(isZero)),
    F.mul(active, F.mul(isZero, sign)),
    F.mul(active, F.sub(row[layout.tableTuple], row[layout.window])),
    F.mul(active, F.sub(row[layout.tableTuple + 1], row[layout.magnitude])),
    F.mul(active, F.sub(row[layout.tableTuple + 2], isZero))
  ]
  constraints.push(...laneConstraints(
    row,
    active,
    sign,
    nonZero,
    layout.selectedGInfinity,
    layout.selectedGX,
    layout.selectedGY,
    layout.tableTuple + 3,
    layout.tableTuple + 8,
    layout.gNegationCarries
  ))
  constraints.push(...laneConstraints(
    row,
    active,
    sign,
    nonZero,
    layout.selectedBInfinity,
    layout.selectedBX,
    layout.selectedBY,
    layout.tableTuple + 13,
    layout.tableTuple + 18,
    layout.bNegationCarries
  ))
  return constraints
}

function laneConstraints (
  row: FieldElement[],
  active: FieldElement,
  sign: FieldElement,
  nonZero: FieldElement,
  selectedInfinity: number,
  selectedX: number,
  selectedY: number,
  tableX: number,
  tableY: number,
  carries: number
): FieldElement[] {
  const positive = F.sub(1n, sign)
  const constraints: FieldElement[] = [
    F.mul(active, F.sub(row[selectedInfinity], F.sub(1n, nonZero)))
  ]
  for (let i = 0; i < BRC69_RADIX11_POINT_LIMBS; i++) {
    constraints.push(F.mul(active, F.mul(nonZero, F.sub(
      row[selectedX + i],
      row[tableX + i]
    ))))
    constraints.push(F.mul(active, F.mul(positive, F.mul(nonZero, F.sub(
      row[selectedY + i],
      row[tableY + i]
    )))))
  }
  constraints.push(F.mul(active, F.mul(sign, row[carries])))
  constraints.push(F.mul(active, F.mul(sign, row[carries + BRC69_RADIX11_POINT_LIMBS])))
  for (let i = 0; i < BRC69_RADIX11_POINT_LIMBS + 1; i++) {
    constraints.push(F.mul(active, F.mul(sign, booleanConstraint(row[carries + i]))))
    constraints.push(F.mul(active, F.mul(positive, row[carries + i])))
  }
  for (let i = 0; i < BRC69_RADIX11_POINT_LIMBS; i++) {
    const relation = F.sub(
      F.add(
        F.add(row[selectedY + i], row[tableY + i]),
        row[carries + i]
      ),
      F.add(P_LIMBS[i], F.mul(row[carries + i + 1], LIMB_RADIX))
    )
    constraints.push(F.mul(active, F.mul(sign, F.mul(nonZero, relation))))
  }
  return constraints
}

function writeSelectedPoint (
  row: FieldElement[],
  infinityColumn: number,
  xColumn: number,
  yColumn: number,
  point: { x: bigint, y: bigint, infinity?: boolean }
): void {
  row[infinityColumn] = point.infinity === true ? 1n : 0n
  if (point.infinity === true) return
  writeVector(row, xColumn, secp256k1FieldToLimbs52(point.x))
  writeVector(row, yColumn, secp256k1FieldToLimbs52(point.y))
}

function writeNegationCarries (
  row: FieldElement[],
  offset: number,
  tableY: FieldElement[],
  selectedY: FieldElement[],
  sign: number,
  isZero: boolean
): void {
  if (sign === 0 || isZero) return
  let carry = 0n
  row[offset] = carry
  for (let i = 0; i < BRC69_RADIX11_POINT_LIMBS; i++) {
    const total = selectedY[i] + tableY[i] + carry - P_LIMBS[i]
    const nextCarry = total / LIMB_RADIX
    if (total !== nextCarry * LIMB_RADIX) {
      throw new Error('BRC69 link bridge y-negation carry mismatch')
    }
    if (nextCarry !== 0n && nextCarry !== 1n) {
      throw new Error('BRC69 link bridge y-negation carry is out of range')
    }
    row[offset + i + 1] = nextCarry
    carry = nextCarry
  }
  if (carry !== 0n) {
    throw new Error('BRC69 link bridge y-negation final carry mismatch')
  }
}

function linkBridgeScheduleRows (
  traceLength: number
): BRC69Method2LinkBridgePublicInput['scheduleRows'] {
  return Array.from({ length: traceLength }, (_, row) => ({
    active: row < BRC69_RADIX11_WINDOW_COUNT ? 1n : 0n,
    window: row < BRC69_RADIX11_WINDOW_COUNT ? BigInt(row) : 0n
  }))
}

function writeVector (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < values.length; i++) row[offset + i] = F.normalize(values[i])
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function isPowerOfTwo (value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0
}

function bigintToLimbs52 (value: bigint): bigint[] {
  const limbs: bigint[] = []
  let remaining = value
  for (let i = 0; i < BRC69_RADIX11_POINT_LIMBS; i++) {
    limbs.push(remaining % LIMB_RADIX)
    remaining /= LIMB_RADIX
  }
  if (remaining !== 0n) {
    throw new Error('BRC69 link bridge limb decomposition overflow')
  }
  return limbs
}
