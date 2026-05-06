import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { SECP256K1_N } from '../circuit/index.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  DUAL_BASE_NEGATIVE_SIGN,
  DUAL_BASE_POSITIVE_SIGN
} from '../stark/DualBaseLookup.js'
import {
  BRC69_RADIX11_FINAL_MAX_MAGNITUDE,
  BRC69_RADIX11_MAX_MAGNITUDE,
  BRC69_RADIX11_WINDOW_BITS,
  BRC69_RADIX11_WINDOW_COUNT,
  ProductionRadix11LookupPrototype
} from '../stark/DualBaseRadix11Metrics.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  serializeStarkProof,
  proveStark,
  verifyStark
} from '../stark/Stark.js'

export const BRC69_PRODUCTION_SCALAR_TRANSCRIPT_DOMAIN =
  'BRC69_PRODUCTION_SCALAR_AIR_V1'
export const BRC69_PRODUCTION_SCALAR_PUBLIC_INPUT_ID =
  'BRC69_PRODUCTION_SCALAR_PUBLIC_INPUT_V1'
export const BRC69_PRODUCTION_SCALAR_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: BRC69_PRODUCTION_SCALAR_TRANSCRIPT_DOMAIN
} as const

const RADIX = 1n << BigInt(BRC69_RADIX11_WINDOW_BITS)
const DIGIT_BITS = BRC69_RADIX11_WINDOW_BITS
const N_MINUS_ONE_LIMBS = bigintToRadixLimbs(
  SECP256K1_N - 1n,
  BRC69_RADIX11_WINDOW_COUNT
)

export interface BRC69ProductionScalarLayout {
  active: number
  window: number
  finalWindow: number
  nMinusOneLimb: number
  sign: number
  magnitude: number
  isZero: number
  magnitudeNonZeroInv: number
  unsignedLimb: number
  complementLimb: number
  carryNeg: number
  nextCarryNeg: number
  borrow: number
  nextBorrow: number
  limbSum: number
  limbSumInv: number
  magnitudeBits: number
  unsignedBits: number
  complementBits: number
  width: number
}

export interface BRC69ProductionScalarScheduleRow {
  active: FieldElement
  window: FieldElement
  finalWindow: FieldElement
  nMinusOneLimb: FieldElement
}

export interface BRC69ProductionScalarPublicInput {
  windowBits: number
  windowCount: number
  activeRows: number
  traceLength: number
  scheduleRows: BRC69ProductionScalarScheduleRow[]
}

export interface BRC69ProductionScalarTrace {
  lookup: ProductionRadix11LookupPrototype
  rows: FieldElement[][]
  layout: BRC69ProductionScalarLayout
  publicInput: BRC69ProductionScalarPublicInput
  digitTuples: bigint[][]
}

export interface BRC69ProductionScalarMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  digitRows: number
  bitRows: number
  proofBytes?: number
}

export const BRC69_PRODUCTION_SCALAR_LAYOUT:
BRC69ProductionScalarLayout = (() => {
  const layout = {
    active: 0,
    window: 1,
    finalWindow: 2,
    nMinusOneLimb: 3,
    sign: 4,
    magnitude: 5,
    isZero: 6,
    magnitudeNonZeroInv: 7,
    unsignedLimb: 8,
    complementLimb: 9,
    carryNeg: 10,
    nextCarryNeg: 11,
    borrow: 12,
    nextBorrow: 13,
    limbSum: 14,
    limbSumInv: 15,
    magnitudeBits: 16,
    unsignedBits: 16 + DIGIT_BITS,
    complementBits: 16 + DIGIT_BITS * 2,
    width: 16 + DIGIT_BITS * 3
  }
  return layout
})()

export function buildBRC69ProductionScalarTrace (
  lookup: ProductionRadix11LookupPrototype,
  options: { minTraceLength?: number } = {}
): BRC69ProductionScalarTrace {
  validateLookupShape(lookup)
  const layout = BRC69_PRODUCTION_SCALAR_LAYOUT
  const activeRows = BRC69_RADIX11_WINDOW_COUNT
  const traceLength = nextPowerOfTwo(Math.max(
    2,
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  const rows = new Array<FieldElement[]>(traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const scheduleRows = scalarScheduleRows(traceLength)
  const unsignedLimbs = bigintToRadixLimbs(
    lookup.scalar,
    BRC69_RADIX11_WINDOW_COUNT
  )
  const complementLimbs = bigintToRadixLimbs(
    SECP256K1_N - 1n - lookup.scalar,
    BRC69_RADIX11_WINDOW_COUNT
  )
  const digitTuples: bigint[][] = []
  let carryNeg = 0n
  let borrow = 0n
  let limbSum = 0n

  for (let rowIndex = 0; rowIndex < activeRows; rowIndex++) {
    const digit = lookup.digits[rowIndex]
    if (digit === undefined) {
      throw new Error('BRC69 production scalar digit is missing')
    }
    const magnitude = BigInt(digit.magnitude)
    const sign = BigInt(digit.sign)
    const isZero = digit.magnitude === 0 ? 1n : 0n
    const signedDigit = digit.sign === DUAL_BASE_NEGATIVE_SIGN
      ? -magnitude
      : magnitude
    const unsignedLimb = positiveMod(signedDigit - carryNeg, RADIX)
    const nextCarry = (signedDigit - carryNeg - unsignedLimb) / RADIX
    const nextCarryNeg = -nextCarry
    if (unsignedLimb !== unsignedLimbs[rowIndex]) {
      throw new Error('BRC69 production scalar unsigned limb mismatch')
    }
    if (nextCarryNeg !== 0n && nextCarryNeg !== 1n) {
      throw new Error('BRC69 production scalar carry is out of range')
    }
    const nMinusOneLimb = N_MINUS_ONE_LIMBS[rowIndex]
    const diff = nMinusOneLimb - borrow - unsignedLimb
    const complementLimb = diff < 0n ? diff + RADIX : diff
    const nextBorrow = diff < 0n ? 1n : 0n
    if (complementLimb !== complementLimbs[rowIndex]) {
      throw new Error('BRC69 production scalar complement limb mismatch')
    }

    const row = rows[rowIndex]
    row[layout.active] = 1n
    row[layout.window] = BigInt(rowIndex)
    row[layout.finalWindow] = rowIndex === activeRows - 1 ? 1n : 0n
    row[layout.nMinusOneLimb] = nMinusOneLimb
    row[layout.sign] = sign
    row[layout.magnitude] = magnitude
    row[layout.isZero] = isZero
    row[layout.magnitudeNonZeroInv] = magnitude === 0n ? 0n : F.inv(magnitude)
    row[layout.unsignedLimb] = unsignedLimb
    row[layout.complementLimb] = complementLimb
    row[layout.carryNeg] = carryNeg
    row[layout.nextCarryNeg] = nextCarryNeg
    row[layout.borrow] = borrow
    row[layout.nextBorrow] = nextBorrow
    row[layout.limbSum] = limbSum
    writeBits(row, layout.magnitudeBits, magnitude)
    writeBits(row, layout.unsignedBits, unsignedLimb)
    writeBits(row, layout.complementBits, complementLimb)

    digitTuples.push([
      BigInt(digit.window),
      magnitude,
      isZero,
      sign
    ])
    carryNeg = nextCarryNeg
    borrow = nextBorrow
    limbSum += unsignedLimb
  }

  if (carryNeg !== 0n) {
    throw new Error('BRC69 production scalar final carry is non-zero')
  }
  if (borrow !== 0n) {
    throw new Error('BRC69 production scalar is outside the secp256k1 range')
  }
  if (limbSum === 0n) {
    throw new Error('BRC69 production scalar must be non-zero')
  }
  for (let rowIndex = activeRows; rowIndex < traceLength; rowIndex++) {
    rows[rowIndex][layout.limbSum] = F.normalize(limbSum)
    rows[rowIndex][layout.limbSumInv] = F.inv(F.normalize(limbSum))
  }

  return {
    lookup,
    rows,
    layout,
    publicInput: {
      windowBits: BRC69_RADIX11_WINDOW_BITS,
      windowCount: BRC69_RADIX11_WINDOW_COUNT,
      activeRows,
      traceLength,
      scheduleRows
    },
    digitTuples
  }
}

export function buildBRC69ProductionScalarAir (
  input: BRC69ProductionScalarTrace | BRC69ProductionScalarPublicInput,
  publicInputDigest = brc69ProductionScalarPublicInputDigest(
    'rows' in input ? input.publicInput : input
  )
): AirDefinition {
  const publicInput = 'rows' in input ? input.publicInput : input
  const layout = BRC69_PRODUCTION_SCALAR_LAYOUT
  const firstInactive = publicInput.activeRows
  return {
    traceWidth: layout.width,
    transitionDegree: 4,
    publicInputDigest,
    boundaryConstraints: [
      { column: layout.carryNeg, row: 0, value: 0n },
      { column: layout.borrow, row: 0, value: 0n },
      { column: layout.limbSum, row: 0, value: 0n },
      { column: layout.carryNeg, row: firstInactive, value: 0n },
      { column: layout.borrow, row: firstInactive, value: 0n }
    ],
    fullBoundaryColumns: [
      {
        column: layout.active,
        values: publicInput.scheduleRows.map(row => row.active)
      },
      {
        column: layout.window,
        values: publicInput.scheduleRows.map(row => row.window)
      },
      {
        column: layout.finalWindow,
        values: publicInput.scheduleRows.map(row => row.finalWindow)
      },
      {
        column: layout.nMinusOneLimb,
        values: publicInput.scheduleRows.map(row => row.nMinusOneLimb)
      }
    ],
    evaluateTransition: (current, next) =>
      evaluateBRC69ProductionScalarTransition(current, next, layout)
  }
}

export function proveBRC69ProductionScalar (
  trace: BRC69ProductionScalarTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildBRC69ProductionScalarAir(trace)
  return proveStark(air, trace.rows, {
    ...BRC69_PRODUCTION_SCALAR_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: BRC69_PRODUCTION_SCALAR_TRANSCRIPT_DOMAIN
  })
}

export function verifyBRC69ProductionScalar (
  publicInput: BRC69ProductionScalarPublicInput,
  proof: StarkProof
): boolean {
  if (!proofMeetsProductionProfile(proof)) return false
  const air = buildBRC69ProductionScalarAir(publicInput, proof.publicInputDigest)
  return verifyStark(air, proof, starkVerifierOptions(proof))
}

export function brc69ProductionScalarMetrics (
  trace: BRC69ProductionScalarTrace,
  proof?: StarkProof,
  blowupFactor: number = 16
): BRC69ProductionScalarMetrics {
  return {
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    ldeRows: trace.publicInput.traceLength * blowupFactor,
    ldeCells: trace.publicInput.traceLength * trace.layout.width * blowupFactor,
    digitRows: trace.publicInput.activeRows,
    bitRows: trace.publicInput.activeRows * DIGIT_BITS * 3,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function brc69ProductionScalarDigitTuple (
  trace: BRC69ProductionScalarTrace,
  index: number
): bigint[] {
  const tuple = trace.digitTuples[index]
  if (tuple === undefined) {
    throw new Error('BRC69 production scalar digit tuple is missing')
  }
  return tuple.slice()
}

export function brc69ProductionScalarPublicInputDigest (
  publicInput: BRC69ProductionScalarPublicInput
): number[] {
  validatePublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(BRC69_PRODUCTION_SCALAR_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.windowBits)
  writer.writeVarIntNum(publicInput.windowCount)
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.scheduleRows.length)
  for (const row of publicInput.scheduleRows) {
    writeField(writer, row.active)
    writeField(writer, row.window)
    writeField(writer, row.finalWindow)
    writeField(writer, row.nMinusOneLimb)
  }
  return sha256(writer.toArray())
}

export function evaluateBRC69ProductionScalarTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: BRC69ProductionScalarLayout = BRC69_PRODUCTION_SCALAR_LAYOUT
): FieldElement[] {
  const active = current[layout.active]
  const nextActive = next[layout.active]
  const sign = current[layout.sign]
  const magnitude = current[layout.magnitude]
  const isZero = current[layout.isZero]
  const magnitudeInv = current[layout.magnitudeNonZeroInv]
  const unsignedLimb = current[layout.unsignedLimb]
  const complementLimb = current[layout.complementLimb]
  const carryNeg = current[layout.carryNeg]
  const nextCarryNeg = current[layout.nextCarryNeg]
  const borrow = current[layout.borrow]
  const nextBorrow = current[layout.nextBorrow]
  const finalWindow = current[layout.finalWindow]
  const magnitudeBits = readBits(current, layout.magnitudeBits)
  const unsignedBits = readBits(current, layout.unsignedBits)
  const complementBits = readBits(current, layout.complementBits)
  const magnitudeFromBits = bitsToValue(magnitudeBits)
  const unsignedFromBits = bitsToValue(unsignedBits)
  const complementFromBits = bitsToValue(complementBits)
  const signedDigit = F.sub(
    magnitude,
    F.mul(2n, F.mul(sign, magnitude))
  )
  const constraints: FieldElement[] = [
    F.mul(active, F.sub(sign, F.mul(sign, sign))),
    F.mul(active, F.sub(isZero, F.mul(isZero, isZero))),
    F.mul(active, F.sub(carryNeg, F.mul(carryNeg, carryNeg))),
    F.mul(active, F.sub(nextCarryNeg, F.mul(nextCarryNeg, nextCarryNeg))),
    F.mul(active, F.sub(borrow, F.mul(borrow, borrow))),
    F.mul(active, F.sub(nextBorrow, F.mul(nextBorrow, nextBorrow))),
    F.mul(active, F.sub(magnitude, magnitudeFromBits)),
    F.mul(active, F.sub(unsignedLimb, unsignedFromBits)),
    F.mul(active, F.sub(complementLimb, complementFromBits)),
    F.mul(active, F.mul(isZero, magnitude)),
    F.mul(active, F.mul(F.sub(1n, isZero), F.sub(F.mul(magnitude, magnitudeInv), 1n))),
    F.mul(active, F.mul(isZero, magnitudeInv)),
    F.mul(active, F.mul(isZero, sign)),
    F.mul(active, F.sub(
      F.add(F.sub(F.sub(signedDigit, carryNeg), unsignedLimb), F.mul(RADIX, nextCarryNeg)),
      0n
    )),
    F.mul(active, F.add(
      F.sub(F.sub(F.sub(current[layout.nMinusOneLimb], borrow), unsignedLimb), complementLimb),
      F.mul(RADIX, nextBorrow)
    )),
    F.mul(active, F.sub(next[layout.carryNeg], nextCarryNeg)),
    F.mul(active, F.sub(next[layout.borrow], nextBorrow)),
    F.sub(
      next[layout.limbSum],
      F.add(current[layout.limbSum], F.mul(active, unsignedLimb))
    ),
    F.mul(active, F.mul(F.sub(1n, nextActive), F.sub(
      F.mul(next[layout.limbSum], next[layout.limbSumInv]),
      1n
    )))
  ]

  for (const bit of magnitudeBits) {
    constraints.push(F.mul(active, F.sub(bit, F.mul(bit, bit))))
  }
  for (const bit of unsignedBits) {
    constraints.push(F.mul(active, F.sub(bit, F.mul(bit, bit))))
  }
  for (const bit of complementBits) {
    constraints.push(F.mul(active, F.sub(bit, F.mul(bit, bit))))
  }
  const highMagnitudeBit = magnitudeBits[DIGIT_BITS - 1]
  for (let bit = 0; bit < DIGIT_BITS - 1; bit++) {
    constraints.push(F.mul(active, F.mul(highMagnitudeBit, magnitudeBits[bit])))
  }
  constraints.push(F.mul(active, F.mul(highMagnitudeBit, F.sub(1n, sign))))
  for (let bit = 4; bit < DIGIT_BITS; bit++) {
    constraints.push(F.mul(active, F.mul(finalWindow, magnitudeBits[bit])))
  }
  for (let bit = 0; bit < 3; bit++) {
    constraints.push(F.mul(
      active,
      F.mul(finalWindow, F.mul(magnitudeBits[3], magnitudeBits[bit]))
    ))
  }
  return constraints
}

function validateLookupShape (lookup: ProductionRadix11LookupPrototype): void {
  if (lookup.scalar <= 0n || lookup.scalar >= SECP256K1_N) {
    throw new Error('BRC69 production scalar is outside the secp256k1 range')
  }
  if (
    lookup.digits.length !== BRC69_RADIX11_WINDOW_COUNT ||
    lookup.selectedIndexes.length !== BRC69_RADIX11_WINDOW_COUNT
  ) {
    throw new Error('BRC69 production scalar window count mismatch')
  }
  for (let i = 0; i < lookup.digits.length; i++) {
    const digit = lookup.digits[i]
    if (digit.window !== i) {
      throw new Error('BRC69 production scalar windows must be ordered')
    }
    if (
      digit.sign !== DUAL_BASE_POSITIVE_SIGN &&
      digit.sign !== DUAL_BASE_NEGATIVE_SIGN
    ) {
      throw new Error('BRC69 production scalar digit sign is invalid')
    }
    if (digit.magnitude < 0 || digit.magnitude > BRC69_RADIX11_MAX_MAGNITUDE) {
      throw new Error('BRC69 production scalar digit magnitude is invalid')
    }
    if (i === BRC69_RADIX11_WINDOW_COUNT - 1 &&
      digit.magnitude > BRC69_RADIX11_FINAL_MAX_MAGNITUDE) {
      throw new Error('BRC69 production scalar final digit is out of range')
    }
    if (digit.magnitude === 0 && digit.sign !== DUAL_BASE_POSITIVE_SIGN) {
      throw new Error('BRC69 production scalar zero digit is non-canonical')
    }
  }
}

function validatePublicInput (
  publicInput: BRC69ProductionScalarPublicInput
): void {
  if (
    publicInput.windowBits !== BRC69_RADIX11_WINDOW_BITS ||
    publicInput.windowCount !== BRC69_RADIX11_WINDOW_COUNT ||
    publicInput.activeRows !== BRC69_RADIX11_WINDOW_COUNT ||
    publicInput.scheduleRows.length !== publicInput.traceLength
  ) {
    throw new Error('BRC69 production scalar public input shape mismatch')
  }
  for (let i = 0; i < publicInput.scheduleRows.length; i++) {
    const expectedActive = i < BRC69_RADIX11_WINDOW_COUNT ? 1n : 0n
    const expectedWindow = i < BRC69_RADIX11_WINDOW_COUNT ? BigInt(i) : 0n
    const expectedFinal = i === BRC69_RADIX11_WINDOW_COUNT - 1 ? 1n : 0n
    const expectedN = i < BRC69_RADIX11_WINDOW_COUNT
      ? N_MINUS_ONE_LIMBS[i]
      : 0n
    const row = publicInput.scheduleRows[i]
    if (
      row.active !== expectedActive ||
      row.window !== expectedWindow ||
      row.finalWindow !== expectedFinal ||
      row.nMinusOneLimb !== expectedN
    ) {
      throw new Error('BRC69 production scalar schedule mismatch')
    }
  }
}

function scalarScheduleRows (
  traceLength: number
): BRC69ProductionScalarScheduleRow[] {
  const rows: BRC69ProductionScalarScheduleRow[] = []
  for (let row = 0; row < traceLength; row++) {
    rows.push({
      active: row < BRC69_RADIX11_WINDOW_COUNT ? 1n : 0n,
      window: row < BRC69_RADIX11_WINDOW_COUNT ? BigInt(row) : 0n,
      finalWindow: row === BRC69_RADIX11_WINDOW_COUNT - 1 ? 1n : 0n,
      nMinusOneLimb: row < BRC69_RADIX11_WINDOW_COUNT
        ? N_MINUS_ONE_LIMBS[row]
        : 0n
    })
  }
  return rows
}

function writeBits (
  row: FieldElement[],
  offset: number,
  value: bigint
): void {
  if (value < 0n || value >= RADIX) {
    throw new Error('BRC69 production scalar bit value is out of range')
  }
  for (let bit = 0; bit < DIGIT_BITS; bit++) {
    row[offset + bit] = (value >> BigInt(bit)) & 1n
  }
}

function readBits (row: FieldElement[], offset: number): FieldElement[] {
  return row.slice(offset, offset + DIGIT_BITS)
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

function bigintToRadixLimbs (value: bigint, count: number): bigint[] {
  if (value < 0n) {
    throw new Error('BRC69 production scalar limb value is negative')
  }
  const limbs: bigint[] = []
  let remaining = value
  for (let i = 0; i < count; i++) {
    limbs.push(remaining % RADIX)
    remaining /= RADIX
  }
  if (remaining !== 0n) {
    throw new Error('BRC69 production scalar does not fit in radix limbs')
  }
  return limbs
}

function positiveMod (value: bigint, modulus: bigint): bigint {
  let out = value % modulus
  if (out < 0n) out += modulus
  return out
}

function proofMeetsProductionProfile (proof: StarkProof): boolean {
  return proof.blowupFactor === BRC69_PRODUCTION_SCALAR_STARK_OPTIONS.blowupFactor &&
    proof.numQueries === BRC69_PRODUCTION_SCALAR_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize === BRC69_PRODUCTION_SCALAR_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree === BRC69_PRODUCTION_SCALAR_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset === BRC69_PRODUCTION_SCALAR_STARK_OPTIONS.cosetOffset
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
    transcriptDomain: BRC69_PRODUCTION_SCALAR_TRANSCRIPT_DOMAIN
  }
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
