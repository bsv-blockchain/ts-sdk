import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import {
  compressPoint,
  isOnCurve
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import { secp256k1FieldToLimbs52 } from '../stark/Secp256k1FieldOps.js'
import {
  ProductionRadix11EcTrace,
  validateProductionRadix11EcTrace
} from '../stark/ProductionRadix11Ec.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import { METHOD2_HMAC_KEY_SIZE } from './Method2Hmac.js'

export const BRC97_PRODUCTION_COMPRESSION_TRANSCRIPT_DOMAIN =
  'BRC97_PRODUCTION_COMPRESSION_AIR_V1'
export const BRC97_PRODUCTION_COMPRESSION_PUBLIC_INPUT_ID =
  'BRC97_PRODUCTION_COMPRESSION_PUBLIC_INPUT_V1'
export const BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: BRC97_PRODUCTION_COMPRESSION_TRANSCRIPT_DOMAIN
} as const

const X_BITS = 256
const BYTE_BITS = 8
const X_BYTES = 32
const POINT_LIMBS_52 = 5
const LIMB_BITS = 52
const PREFIX_ROW = X_BITS
const Y_HALF_BITS = 51

export interface BRC97ProductionCompressionLayout {
  kind: number
  byteIndex: number
  bitInByte: number
  lastBitInByte: number
  byteWeight: number
  limbWeights: number
  xBit: number
  byte: number
  byteAccumulator: number
  xLimbs: number
  xLimbAccumulators: number
  yLimb0: number
  yParity: number
  yHalf: number
  prefix: number
  yHalfBits: number
  width: number
}

export interface BRC97ProductionCompressionScheduleRow {
  kind: FieldElement
  byteIndex: FieldElement
  bitInByte: FieldElement
  lastBitInByte: FieldElement
  byteWeight: FieldElement
  limbWeights: FieldElement[]
}

export interface BRC97ProductionCompressionPublicInput {
  activeRows: number
  traceLength: number
  scheduleRows: BRC97ProductionCompressionScheduleRow[]
}

export interface BRC97ProductionCompressionTrace {
  point: SecpPoint
  compressedBytes: number[]
  rows: FieldElement[][]
  layout: BRC97ProductionCompressionLayout
  publicInput: BRC97ProductionCompressionPublicInput
  pointTuple: bigint[]
  byteTuples: bigint[][]
}

export interface BRC97ProductionCompressionMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  compressedBytes: number
  xBitRows: number
  proofBytes?: number
}

export const BRC97_PRODUCTION_COMPRESSION_LAYOUT:
BRC97ProductionCompressionLayout = (() => {
  const layout = {
    kind: 0,
    byteIndex: 1,
    bitInByte: 2,
    lastBitInByte: 3,
    byteWeight: 4,
    limbWeights: 5,
    xBit: 5 + POINT_LIMBS_52,
    byte: 6 + POINT_LIMBS_52,
    byteAccumulator: 7 + POINT_LIMBS_52,
    xLimbs: 8 + POINT_LIMBS_52,
    xLimbAccumulators: 8 + POINT_LIMBS_52 + POINT_LIMBS_52,
    yLimb0: 8 + POINT_LIMBS_52 * 3,
    yParity: 9 + POINT_LIMBS_52 * 3,
    yHalf: 10 + POINT_LIMBS_52 * 3,
    prefix: 11 + POINT_LIMBS_52 * 3,
    yHalfBits: 12 + POINT_LIMBS_52 * 3,
    width: 12 + POINT_LIMBS_52 * 3 + Y_HALF_BITS
  }
  return layout
})()

export function buildBRC97ProductionCompressionTrace (
  input: ProductionRadix11EcTrace | SecpPoint,
  options: { minTraceLength?: number } = {}
): BRC97ProductionCompressionTrace {
  const point = 'privateS' in input ? input.privateS : input
  if ('privateS' in input) validateProductionRadix11EcTrace(input)
  validateCompressionPoint(point)
  const compressedBytes = compressPoint(point)
  const layout = BRC97_PRODUCTION_COMPRESSION_LAYOUT
  const activeRows = PREFIX_ROW + 1
  const traceLength = nextPowerOfTwo(Math.max(
    2,
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  const rows = new Array<FieldElement[]>(traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const scheduleRows = compressionScheduleRows(traceLength)
  const xLimbs = secp256k1FieldToLimbs52(point.x)
  const yLimbs = secp256k1FieldToLimbs52(point.y)
  const yParity = point.y & 1n
  const yHalf = (yLimbs[0] - yParity) / 2n
  let byteAccumulator = 0n
  const limbAccumulators = new Array<bigint>(POINT_LIMBS_52).fill(0n)

  for (let bitIndex = 0; bitIndex < X_BITS; bitIndex++) {
    const row = rows[bitIndex]
    const schedule = scheduleRows[bitIndex]
    const xBit = (point.x >> BigInt(bitIndex)) & 1n
    const byteIndex = Number(schedule.byteIndex)
    const byte = compressedBytes[byteIndex]
    if (byte === undefined) {
      throw new Error('BRC97 production compression byte is missing')
    }
    row[layout.kind] = schedule.kind
    row[layout.byteIndex] = schedule.byteIndex
    row[layout.bitInByte] = schedule.bitInByte
    row[layout.lastBitInByte] = schedule.lastBitInByte
    row[layout.byteWeight] = schedule.byteWeight
    writeVector(row, layout.limbWeights, schedule.limbWeights)
    row[layout.xBit] = xBit
    row[layout.byte] = BigInt(byte)
    row[layout.byteAccumulator] = byteAccumulator
    writeVector(row, layout.xLimbs, xLimbs)
    writeVector(row, layout.xLimbAccumulators, limbAccumulators)
    row[layout.yLimb0] = yLimbs[0]
    row[layout.yParity] = yParity

    const bitWeight = 1n << BigInt(Number(schedule.bitInByte))
    byteAccumulator += xBit * bitWeight
    for (let limb = 0; limb < POINT_LIMBS_52; limb++) {
      limbAccumulators[limb] += xBit * schedule.limbWeights[limb]
    }
    if (schedule.lastBitInByte === 1n) {
      if (byteAccumulator !== BigInt(byte)) {
        throw new Error('BRC97 production compression byte reconstruction mismatch')
      }
      byteAccumulator = 0n
    }
  }

  const prefix = compressedBytes[0]
  const prefixRow = rows[PREFIX_ROW]
  const prefixSchedule = scheduleRows[PREFIX_ROW]
  prefixRow[layout.kind] = prefixSchedule.kind
  prefixRow[layout.byteIndex] = prefixSchedule.byteIndex
  prefixRow[layout.bitInByte] = prefixSchedule.bitInByte
  prefixRow[layout.lastBitInByte] = prefixSchedule.lastBitInByte
  prefixRow[layout.byteWeight] = prefixSchedule.byteWeight
  writeVector(prefixRow, layout.limbWeights, prefixSchedule.limbWeights)
  prefixRow[layout.byte] = BigInt(prefix)
  prefixRow[layout.byteAccumulator] = 0n
  writeVector(prefixRow, layout.xLimbs, xLimbs)
  writeVector(prefixRow, layout.xLimbAccumulators, limbAccumulators)
  prefixRow[layout.yLimb0] = yLimbs[0]
  prefixRow[layout.yParity] = yParity
  prefixRow[layout.yHalf] = yHalf
  prefixRow[layout.prefix] = BigInt(prefix)
  writeBits(prefixRow, layout.yHalfBits, yHalf, Y_HALF_BITS)

  if (prefix !== 2 + Number(yParity)) {
    throw new Error('BRC97 production compression prefix mismatch')
  }
  if (!vectorsEqual(limbAccumulators, xLimbs)) {
    throw new Error('BRC97 production compression x-limb mismatch')
  }

  return {
    point: { ...point },
    compressedBytes,
    rows,
    layout,
    publicInput: {
      activeRows,
      traceLength,
      scheduleRows
    },
    pointTuple: pointTuple(point),
    byteTuples: compressedBytes.map((byte, index) => byteTuple(index, byte))
  }
}

export function buildBRC97ProductionCompressionAir (
  input: BRC97ProductionCompressionTrace | BRC97ProductionCompressionPublicInput,
  publicInputDigest = brc97ProductionCompressionPublicInputDigest(
    'rows' in input ? input.publicInput : input
  )
): AirDefinition {
  const publicInput = 'rows' in input ? input.publicInput : input
  const layout = BRC97_PRODUCTION_COMPRESSION_LAYOUT
  return {
    traceWidth: layout.width,
    transitionDegree: 5,
    publicInputDigest,
    boundaryConstraints: [
      { column: layout.byteAccumulator, row: 0, value: 0n },
      ...Array.from({ length: POINT_LIMBS_52 }, (_, limb) => ({
        column: layout.xLimbAccumulators + limb,
        row: 0,
        value: 0n
      }))
    ],
    fullBoundaryColumns: [
      {
        column: layout.kind,
        values: publicInput.scheduleRows.map(row => row.kind)
      },
      {
        column: layout.byteIndex,
        values: publicInput.scheduleRows.map(row => row.byteIndex)
      },
      {
        column: layout.bitInByte,
        values: publicInput.scheduleRows.map(row => row.bitInByte)
      },
      {
        column: layout.lastBitInByte,
        values: publicInput.scheduleRows.map(row => row.lastBitInByte)
      },
      {
        column: layout.byteWeight,
        values: publicInput.scheduleRows.map(row => row.byteWeight)
      },
      ...Array.from({ length: POINT_LIMBS_52 }, (_, limb) => ({
        column: layout.limbWeights + limb,
        values: publicInput.scheduleRows.map(row => row.limbWeights[limb])
      }))
    ],
    evaluateTransition: (current, next) =>
      evaluateBRC97ProductionCompressionTransition(current, next, layout)
  }
}

export function proveBRC97ProductionCompression (
  trace: BRC97ProductionCompressionTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildBRC97ProductionCompressionAir(trace)
  return proveStark(air, trace.rows, {
    ...BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: BRC97_PRODUCTION_COMPRESSION_TRANSCRIPT_DOMAIN
  })
}

export function verifyBRC97ProductionCompression (
  publicInput: BRC97ProductionCompressionPublicInput,
  proof: StarkProof
): boolean {
  if (!proofMeetsProductionProfile(proof)) return false
  const air = buildBRC97ProductionCompressionAir(
    publicInput,
    proof.publicInputDigest
  )
  return verifyStark(air, proof, starkVerifierOptions(proof))
}

export function brc97ProductionCompressionMetrics (
  trace: BRC97ProductionCompressionTrace,
  proof?: StarkProof,
  blowupFactor: number = 16
): BRC97ProductionCompressionMetrics {
  return {
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    ldeRows: trace.publicInput.traceLength * blowupFactor,
    ldeCells: trace.publicInput.traceLength * trace.layout.width * blowupFactor,
    compressedBytes: METHOD2_HMAC_KEY_SIZE,
    xBitRows: X_BITS,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function brc97ProductionCompressionPointTuple (
  trace: BRC97ProductionCompressionTrace
): bigint[] {
  return trace.pointTuple.slice()
}

export function brc97ProductionCompressionByteTuple (
  trace: BRC97ProductionCompressionTrace,
  index: number
): bigint[] {
  const tuple = trace.byteTuples[index]
  if (tuple === undefined) {
    throw new Error('BRC97 production compression byte tuple is missing')
  }
  return tuple.slice()
}

export function brc97ProductionCompressionBytes (
  trace: BRC97ProductionCompressionTrace
): number[] {
  return trace.compressedBytes.slice()
}

export function brc97ProductionCompressionPublicInputDigest (
  publicInput: BRC97ProductionCompressionPublicInput
): number[] {
  validatePublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(BRC97_PRODUCTION_COMPRESSION_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.scheduleRows.length)
  for (const row of publicInput.scheduleRows) {
    writeField(writer, row.kind)
    writeField(writer, row.byteIndex)
    writeField(writer, row.bitInByte)
    writeField(writer, row.lastBitInByte)
    writeField(writer, row.byteWeight)
    for (const weight of row.limbWeights) writeField(writer, weight)
  }
  return sha256(writer.toArray())
}

export function evaluateBRC97ProductionCompressionTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: BRC97ProductionCompressionLayout =
  BRC97_PRODUCTION_COMPRESSION_LAYOUT
): FieldElement[] {
  const kind = current[layout.kind]
  const xRow = kindSelector(kind, 1n)
  const prefixRow = kindSelector(kind, 2n)
  const inactive = kindSelector(kind, 0n)
  const lastBit = current[layout.lastBitInByte]
  const xBit = current[layout.xBit]
  const byteWeight = current[layout.byteWeight]
  const byteNext = F.add(
    current[layout.byteAccumulator],
    F.mul(xBit, byteWeight)
  )
  const constraints: FieldElement[] = [
    F.mul(kind, F.mul(F.sub(kind, 1n), F.sub(kind, 2n))),
    F.mul(xRow, F.sub(xBit, F.mul(xBit, xBit))),
    F.mul(xRow, F.sub(lastBit, F.mul(lastBit, lastBit))),
    F.mul(xRow, F.mul(F.sub(1n, lastBit), F.sub(
      next[layout.byteAccumulator],
      byteNext
    ))),
    F.mul(xRow, F.mul(lastBit, next[layout.byteAccumulator])),
    F.mul(xRow, F.mul(lastBit, F.sub(byteNext, current[layout.byte]))),
    F.mul(xRow, F.mul(F.sub(1n, lastBit), F.sub(
      next[layout.byte],
      current[layout.byte]
    ))),
    F.mul(prefixRow, F.sub(
      current[layout.prefix],
      F.add(2n, current[layout.yParity])
    )),
    F.mul(prefixRow, F.sub(current[layout.byte], current[layout.prefix])),
    F.mul(prefixRow, F.sub(
      current[layout.yParity],
      F.mul(current[layout.yParity], current[layout.yParity])
    )),
    F.mul(prefixRow, F.sub(
      current[layout.yHalf],
      bitsToValue(readVector(current, layout.yHalfBits, Y_HALF_BITS))
    )),
    F.mul(prefixRow, F.sub(
      current[layout.yLimb0],
      F.add(current[layout.yParity], F.mul(2n, current[layout.yHalf]))
    ))
  ]

  for (let limb = 0; limb < POINT_LIMBS_52; limb++) {
    const expectedNext = F.add(
      current[layout.xLimbAccumulators + limb],
      F.mul(xBit, current[layout.limbWeights + limb])
    )
    constraints.push(F.mul(xRow, F.sub(
      next[layout.xLimbAccumulators + limb],
      expectedNext
    )))
    constraints.push(F.mul(xRow, F.sub(
      next[layout.xLimbs + limb],
      current[layout.xLimbs + limb]
    )))
    constraints.push(F.mul(prefixRow, F.sub(
      current[layout.xLimbAccumulators + limb],
      current[layout.xLimbs + limb]
    )))
    constraints.push(F.mul(inactive, current[layout.xLimbAccumulators + limb]))
  }
  for (const bit of readVector(current, layout.yHalfBits, Y_HALF_BITS)) {
    constraints.push(F.mul(prefixRow, F.sub(bit, F.mul(bit, bit))))
  }
  constraints.push(F.mul(inactive, current[layout.byteAccumulator]))
  return constraints
}

function compressionScheduleRows (
  traceLength: number
): BRC97ProductionCompressionScheduleRow[] {
  const rows: BRC97ProductionCompressionScheduleRow[] = []
  for (let row = 0; row < traceLength; row++) {
    if (row < X_BITS) {
      const byteLeIndex = Math.floor(row / BYTE_BITS)
      const bitInByte = row % BYTE_BITS
      const limb = Math.floor(row / LIMB_BITS)
      const limbOffset = row - limb * LIMB_BITS
      const weights = new Array<FieldElement>(POINT_LIMBS_52).fill(0n)
      weights[limb] = 1n << BigInt(limbOffset)
      rows.push({
        kind: 1n,
        byteIndex: BigInt(X_BYTES - byteLeIndex),
        bitInByte: BigInt(bitInByte),
        lastBitInByte: bitInByte === BYTE_BITS - 1 ? 1n : 0n,
        byteWeight: 1n << BigInt(bitInByte),
        limbWeights: weights
      })
    } else if (row === PREFIX_ROW) {
      rows.push({
        kind: 2n,
        byteIndex: 0n,
        bitInByte: 0n,
        lastBitInByte: 0n,
        byteWeight: 0n,
        limbWeights: new Array<FieldElement>(POINT_LIMBS_52).fill(0n)
      })
    } else {
      rows.push({
        kind: 0n,
        byteIndex: 0n,
        bitInByte: 0n,
        lastBitInByte: 0n,
        byteWeight: 0n,
        limbWeights: new Array<FieldElement>(POINT_LIMBS_52).fill(0n)
      })
    }
  }
  return rows
}

function validatePublicInput (
  publicInput: BRC97ProductionCompressionPublicInput
): void {
  if (
    publicInput.activeRows !== PREFIX_ROW + 1 ||
    publicInput.scheduleRows.length !== publicInput.traceLength
  ) {
    throw new Error('BRC97 production compression public input shape mismatch')
  }
  const expected = compressionScheduleRows(publicInput.traceLength)
  for (let i = 0; i < expected.length; i++) {
    const row = publicInput.scheduleRows[i]
    const expectedRow = expected[i]
    if (
      row.kind !== expectedRow.kind ||
      row.byteIndex !== expectedRow.byteIndex ||
      row.bitInByte !== expectedRow.bitInByte ||
      row.lastBitInByte !== expectedRow.lastBitInByte ||
      row.byteWeight !== expectedRow.byteWeight ||
      !vectorsEqual(row.limbWeights, expectedRow.limbWeights)
    ) {
      throw new Error('BRC97 production compression schedule mismatch')
    }
  }
}

function validateCompressionPoint (point: SecpPoint): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('BRC97 production compression requires non-infinity S')
  }
}

function pointTuple (point: SecpPoint): bigint[] {
  validateCompressionPoint(point)
  return [
    0n,
    ...secp256k1FieldToLimbs52(point.x),
    ...secp256k1FieldToLimbs52(point.y)
  ]
}

function byteTuple (index: number, value: number): bigint[] {
  if (!Number.isSafeInteger(value) || value < 0 || value > 255) {
    throw new Error('BRC97 production compression byte is invalid')
  }
  return [BigInt(index), BigInt(value)]
}

function writeVector (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < values.length; i++) row[offset + i] = values[i]
}

function readVector (
  row: FieldElement[],
  offset: number,
  length: number
): FieldElement[] {
  return row.slice(offset, offset + length)
}

function writeBits (
  row: FieldElement[],
  offset: number,
  value: bigint,
  bits: number
): void {
  if (value < 0n || value >= (1n << BigInt(bits))) {
    throw new Error('BRC97 production compression bit value is out of range')
  }
  for (let bit = 0; bit < bits; bit++) {
    row[offset + bit] = (value >> BigInt(bit)) & 1n
  }
}

function bitsToValue (bits: FieldElement[]): FieldElement {
  let value = 0n
  let weight = 1n
  for (const bit of bits) {
    value = F.add(value, F.mul(bit, weight))
    weight *= 2n
  }
  return value
}

function kindSelector (kind: FieldElement, value: FieldElement): FieldElement {
  if (value === 0n) return F.mul(F.sub(kind, 1n), F.sub(kind, 2n))
  if (value === 1n) return F.neg(F.mul(kind, F.sub(kind, 2n)))
  return F.div(F.mul(kind, F.sub(kind, 1n)), 2n)
}

function proofMeetsProductionProfile (proof: StarkProof): boolean {
  return proof.blowupFactor ===
    BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS.blowupFactor &&
    proof.numQueries === BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize ===
      BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree === BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset === BRC97_PRODUCTION_COMPRESSION_STARK_OPTIONS.cosetOffset
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
    transcriptDomain: BRC97_PRODUCTION_COMPRESSION_TRANSCRIPT_DOMAIN
  }
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}

function vectorsEqual (left: bigint[], right: bigint[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
