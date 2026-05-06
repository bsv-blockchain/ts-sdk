import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { SECP256K1_P, modP } from '../circuit/Secp256k1.js'
import { AirDefinition } from './Air.js'
import { F, FieldElement } from './Field.js'
import {
  StarkProof,
  StarkProverOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from './Stark.js'

export const SECP256K1_FIELD_OPS_TRANSCRIPT_DOMAIN =
  'BRC69_SECP256K1_FIELD_OPS_PROTOTYPE_V1'
export const SECP256K1_FIELD_LINEAR_DIGEST_ID =
  'BRC69_SECP256K1_FIELD_LINEAR_PUBLIC_INPUT_V1'
export const SECP256K1_FIELD_MUL_DIGEST_ID =
  'BRC69_SECP256K1_FIELD_MUL_PUBLIC_INPUT_V1'

export const SECP256K1_FIELD_LIMB_BITS = 52
export const SECP256K1_FIELD_LIMBS = 5
export const SECP256K1_FIELD_MUL_LIMB_BITS = 26
export const SECP256K1_FIELD_MUL_LIMBS = 10
export const SECP256K1_FIELD_MUL_PRODUCT_LIMBS = 20
export const SECP256K1_FIELD_LINEAR_CARRY_BITS = 8
export const SECP256K1_FIELD_MUL_CARRY_BITS = 44
export const SECP256K1_FIELD_LINEAR_ADD = 1n
export const SECP256K1_FIELD_LINEAR_SUB = 2n

const FIELD_RADIX = 1n << BigInt(SECP256K1_FIELD_LIMB_BITS)
const MUL_RADIX = 1n << BigInt(SECP256K1_FIELD_MUL_LIMB_BITS)
const LINEAR_CARRY_BIAS = 1n << BigInt(SECP256K1_FIELD_LINEAR_CARRY_BITS - 1)
const MUL_CARRY_BIAS = 1n << BigInt(SECP256K1_FIELD_MUL_CARRY_BITS - 1)
const P_52 = bigintToLimbs(SECP256K1_P, SECP256K1_FIELD_LIMBS, FIELD_RADIX)
const P_26 = bigintToLimbs(SECP256K1_P, SECP256K1_FIELD_MUL_LIMBS, MUL_RADIX)

export interface Secp256k1FieldLinearLayout {
  active: number
  limb: number
  limbSelectors: number
  op: number
  a: number
  b: number
  c: number
  q: number
  carryIn: number
  carryOut: number
  carryBits: number
  width: number
}

export interface Secp256k1FieldMulLayout {
  active: number
  limb: number
  limbSelectors: number
  a26: number
  b26: number
  c26: number
  q26: number
  a52: number
  b52: number
  c52: number
  carryIn: number
  carryOut: number
  carryBits: number
  width: number
}

export interface Secp256k1FieldLinearTrace {
  rows: FieldElement[][]
  activeRows: number
  paddedRows: number
  layout: Secp256k1FieldLinearLayout
  op: FieldElement
  a: bigint
  b: bigint
  c: bigint
  q: bigint
}

export interface Secp256k1FieldMulTrace {
  rows: FieldElement[][]
  activeRows: number
  paddedRows: number
  layout: Secp256k1FieldMulLayout
  a: bigint
  b: bigint
  c: bigint
  q: bigint
}

export interface Secp256k1FieldOpMetrics {
  limbBits: number
  limbCount: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  proofBytes?: number
}

export const SECP256K1_FIELD_LINEAR_LAYOUT: Secp256k1FieldLinearLayout = {
  active: 0,
  limb: 1,
  limbSelectors: 2,
  op: 2 + SECP256K1_FIELD_LIMBS,
  a: 3 + SECP256K1_FIELD_LIMBS,
  b: 3 + SECP256K1_FIELD_LIMBS * 2,
  c: 3 + SECP256K1_FIELD_LIMBS * 3,
  q: 3 + SECP256K1_FIELD_LIMBS * 4,
  carryIn: 4 + SECP256K1_FIELD_LIMBS * 4,
  carryOut: 5 + SECP256K1_FIELD_LIMBS * 4,
  carryBits: 6 + SECP256K1_FIELD_LIMBS * 4,
  width: 6 + SECP256K1_FIELD_LIMBS * 4 + SECP256K1_FIELD_LINEAR_CARRY_BITS
}

export const SECP256K1_FIELD_MUL_LAYOUT: Secp256k1FieldMulLayout = {
  active: 0,
  limb: 1,
  limbSelectors: 2,
  a26: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS,
  b26: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS,
  c26: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 2,
  q26: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 3,
  a52: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4,
  b52: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS,
  c52: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 2,
  carryIn: 2 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  carryOut: 3 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  carryBits: 4 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS + SECP256K1_FIELD_MUL_LIMBS * 4 + SECP256K1_FIELD_LIMBS * 3,
  width: 4 + SECP256K1_FIELD_MUL_PRODUCT_LIMBS +
    SECP256K1_FIELD_MUL_LIMBS * 4 +
    SECP256K1_FIELD_LIMBS * 3 +
    SECP256K1_FIELD_MUL_CARRY_BITS
}

export function buildSecp256k1FieldAddTrace (
  a: bigint,
  b: bigint,
  c = modP(a + b)
): Secp256k1FieldLinearTrace {
  return buildSecp256k1FieldLinearTrace(SECP256K1_FIELD_LINEAR_ADD, a, b, c)
}

export function buildSecp256k1FieldSubTrace (
  a: bigint,
  b: bigint,
  c = modP(a - b)
): Secp256k1FieldLinearTrace {
  return buildSecp256k1FieldLinearTrace(SECP256K1_FIELD_LINEAR_SUB, a, b, c)
}

export function buildSecp256k1FieldLinearTrace (
  op: FieldElement,
  a: bigint,
  b: bigint,
  c: bigint
): Secp256k1FieldLinearTrace {
  validateFieldElement(a, 'a')
  validateFieldElement(b, 'b')
  validateFieldElement(c, 'c')
  if (op !== SECP256K1_FIELD_LINEAR_ADD && op !== SECP256K1_FIELD_LINEAR_SUB) {
    throw new Error('Unsupported secp256k1 linear field operation')
  }
  const signedNumerator = op === SECP256K1_FIELD_LINEAR_ADD
    ? a + b - c
    : a - b - c
  if (signedNumerator % SECP256K1_P !== 0n) {
    throw new Error('secp256k1 linear field operation is not congruent')
  }
  const q = signedNumerator / SECP256K1_P
  if (op === SECP256K1_FIELD_LINEAR_ADD && q !== 0n && q !== 1n) {
    throw new Error('secp256k1 field add quotient is invalid')
  }
  if (op === SECP256K1_FIELD_LINEAR_SUB && q !== 0n && q !== -1n) {
    throw new Error('secp256k1 field sub quotient is invalid')
  }

  const layout = SECP256K1_FIELD_LINEAR_LAYOUT
  const activeRows = SECP256K1_FIELD_LIMBS
  const paddedRows = 8
  const rows = emptyRows(paddedRows, layout.width)
  const aLimbs = secp256k1FieldToLimbs52(a)
  const bLimbs = secp256k1FieldToLimbs52(b)
  const cLimbs = secp256k1FieldToLimbs52(c)
  let carry = 0n
  for (let limb = 0; limb < activeRows; limb++) {
    const row = rows[limb]
    row[layout.active] = 1n
    row[layout.limb] = BigInt(limb)
    row[layout.limbSelectors + limb] = 1n
    row[layout.op] = op
    writeLimbs(row, layout.a, aLimbs)
    writeLimbs(row, layout.b, bLimbs)
    writeLimbs(row, layout.c, cLimbs)
    row[layout.q] = F.normalize(q)
    row[layout.carryIn] = F.normalize(carry)
    const carryOut = linearCarryOut(
      op,
      aLimbs,
      bLimbs,
      cLimbs,
      q,
      limb,
      carry
    )
    row[layout.carryOut] = F.normalize(carryOut)
    writeSignedBits(row, layout.carryBits, carryOut, LINEAR_CARRY_BIAS, SECP256K1_FIELD_LINEAR_CARRY_BITS)
    carry = carryOut
  }
  if (carry !== 0n) throw new Error('secp256k1 field linear final carry is nonzero')
  return {
    rows,
    activeRows,
    paddedRows,
    layout,
    op,
    a,
    b,
    c,
    q
  }
}

export function buildSecp256k1FieldMulTrace (
  a: bigint,
  b: bigint,
  c = modP(a * b)
): Secp256k1FieldMulTrace {
  validateFieldElement(a, 'a')
  validateFieldElement(b, 'b')
  validateFieldElement(c, 'c')
  const numerator = a * b - c
  if (numerator % SECP256K1_P !== 0n) {
    throw new Error('secp256k1 field mul result is not congruent')
  }
  const q = numerator / SECP256K1_P
  validateFieldElement(q, 'q')

  const layout = SECP256K1_FIELD_MUL_LAYOUT
  const activeRows = SECP256K1_FIELD_MUL_PRODUCT_LIMBS
  const paddedRows = 32
  const rows = emptyRows(paddedRows, layout.width)
  const a26 = secp256k1FieldToLimbs26(a)
  const b26 = secp256k1FieldToLimbs26(b)
  const c26 = secp256k1FieldToLimbs26(c)
  const q26 = secp256k1FieldToLimbs26(q)
  const a52 = secp256k1FieldToLimbs52(a)
  const b52 = secp256k1FieldToLimbs52(b)
  const c52 = secp256k1FieldToLimbs52(c)
  let carry = 0n
  for (let limb = 0; limb < activeRows; limb++) {
    const row = rows[limb]
    row[layout.active] = 1n
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
    writeSignedBits(row, layout.carryBits, carryOut, MUL_CARRY_BIAS, SECP256K1_FIELD_MUL_CARRY_BITS)
    carry = carryOut
  }
  if (carry !== 0n) throw new Error('secp256k1 field mul final carry is nonzero')
  return {
    rows,
    activeRows,
    paddedRows,
    layout,
    a,
    b,
    c,
    q
  }
}

export function buildSecp256k1FieldLinearAir (
  trace: Secp256k1FieldLinearTrace,
  publicInputDigest = secp256k1FieldLinearDigest(trace)
): AirDefinition {
  const layout = trace.layout
  return {
    traceWidth: layout.width,
    transitionDegree: 5,
    publicInputDigest,
    boundaryConstraints: [
      { column: layout.carryIn, row: 0, value: 0n },
      { column: layout.carryOut, row: trace.activeRows - 1, value: 0n },
      ...limbBoundary(layout.a, secp256k1FieldToLimbs52(trace.a)),
      ...limbBoundary(layout.b, secp256k1FieldToLimbs52(trace.b)),
      ...limbBoundary(layout.c, secp256k1FieldToLimbs52(trace.c)),
      { column: layout.op, row: 0, value: trace.op },
      { column: layout.q, row: 0, value: F.normalize(trace.q) }
    ],
    fullBoundaryColumns: linearFullBoundaryColumns(trace),
    evaluateTransition: (current, next) =>
      evaluateSecp256k1FieldLinearTransition(current, next, layout)
  }
}

export function buildSecp256k1FieldMulAir (
  trace: Secp256k1FieldMulTrace,
  publicInputDigest = secp256k1FieldMulDigest(trace)
): AirDefinition {
  const layout = trace.layout
  return {
    traceWidth: layout.width,
    transitionDegree: 5,
    publicInputDigest,
    boundaryConstraints: [
      { column: layout.carryIn, row: 0, value: 0n },
      { column: layout.carryOut, row: trace.activeRows - 1, value: 0n },
      ...limbBoundary(layout.a52, secp256k1FieldToLimbs52(trace.a)),
      ...limbBoundary(layout.b52, secp256k1FieldToLimbs52(trace.b)),
      ...limbBoundary(layout.c52, secp256k1FieldToLimbs52(trace.c))
    ],
    fullBoundaryColumns: mulFullBoundaryColumns(trace),
    evaluateTransition: (current, next) =>
      evaluateSecp256k1FieldMulTransition(current, next, layout)
  }
}

export function evaluateSecp256k1FieldLinearTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Secp256k1FieldLinearLayout = SECP256K1_FIELD_LINEAR_LAYOUT
): FieldElement[] {
  const active = current[layout.active]
  const constraints = [
    booleanConstraint(active),
    ...gateConstraints(evaluateActiveLinearRow(current, layout), active),
    ...gateConstraints(
      linearContinuityConstraints(current, next, layout),
      F.mul(active, next[layout.active])
    )
  ]
  return constraints
}

export function evaluateSecp256k1FieldMulTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Secp256k1FieldMulLayout = SECP256K1_FIELD_MUL_LAYOUT
): FieldElement[] {
  const active = current[layout.active]
  const constraints = [
    booleanConstraint(active),
    ...gateConstraints(evaluateActiveMulRow(current, layout), active),
    ...gateConstraints(
      mulContinuityConstraints(current, next, layout),
      F.mul(active, next[layout.active])
    )
  ]
  return constraints
}

export function proveSecp256k1FieldLinear (
  trace: Secp256k1FieldLinearTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildSecp256k1FieldLinearAir(trace)
  return proveStark(air, trace.rows, {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 8,
    maskDegree: 1,
    cosetOffset: 3n,
    ...options,
    transcriptDomain: `${SECP256K1_FIELD_OPS_TRANSCRIPT_DOMAIN}:linear`,
    publicInputDigest: air.publicInputDigest
  })
}

export function proveSecp256k1FieldMul (
  trace: Secp256k1FieldMulTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildSecp256k1FieldMulAir(trace)
  return proveStark(air, trace.rows, {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 16,
    maskDegree: 1,
    cosetOffset: 3n,
    ...options,
    transcriptDomain: `${SECP256K1_FIELD_OPS_TRANSCRIPT_DOMAIN}:mul`,
    publicInputDigest: air.publicInputDigest
  })
}

export function verifySecp256k1FieldLinear (
  trace: Secp256k1FieldLinearTrace,
  proof: StarkProof
): boolean {
  const air = buildSecp256k1FieldLinearAir(trace, proof.publicInputDigest)
  return verifyStark(air, proof, starkVerifierOptions(proof, `${SECP256K1_FIELD_OPS_TRANSCRIPT_DOMAIN}:linear`))
}

export function verifySecp256k1FieldMul (
  trace: Secp256k1FieldMulTrace,
  proof: StarkProof
): boolean {
  const air = buildSecp256k1FieldMulAir(trace, proof.publicInputDigest)
  return verifyStark(air, proof, starkVerifierOptions(proof, `${SECP256K1_FIELD_OPS_TRANSCRIPT_DOMAIN}:mul`))
}

export function secp256k1FieldLinearMetrics (
  proof?: StarkProof
): Secp256k1FieldOpMetrics {
  return {
    limbBits: SECP256K1_FIELD_LIMB_BITS,
    limbCount: SECP256K1_FIELD_LIMBS,
    activeRows: SECP256K1_FIELD_LIMBS,
    paddedRows: 8,
    traceWidth: SECP256K1_FIELD_LINEAR_LAYOUT.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function secp256k1FieldMulMetrics (
  proof?: StarkProof
): Secp256k1FieldOpMetrics {
  return {
    limbBits: SECP256K1_FIELD_LIMB_BITS,
    limbCount: SECP256K1_FIELD_LIMBS,
    activeRows: SECP256K1_FIELD_MUL_PRODUCT_LIMBS,
    paddedRows: 32,
    traceWidth: SECP256K1_FIELD_MUL_LAYOUT.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function secp256k1FieldToLimbs52 (value: bigint): bigint[] {
  validateFieldElement(value, 'field element')
  return bigintToLimbs(value, SECP256K1_FIELD_LIMBS, FIELD_RADIX)
}

export function secp256k1FieldFromLimbs52 (limbs: FieldElement[]): bigint {
  return limbsToBigint(limbs, SECP256K1_FIELD_LIMBS, FIELD_RADIX)
}

export function secp256k1FieldToLimbs26 (value: bigint): bigint[] {
  validateFieldElement(value, 'field element')
  return bigintToLimbs(value, SECP256K1_FIELD_MUL_LIMBS, MUL_RADIX)
}

export function secp256k1FieldLinearDigest (
  trace: Secp256k1FieldLinearTrace
): number[] {
  const writer = new Writer()
  writer.write(toArray(SECP256K1_FIELD_LINEAR_DIGEST_ID, 'utf8'))
  writer.writeVarIntNum(trace.activeRows)
  writer.writeVarIntNum(trace.layout.width)
  writer.writeUInt8(Number(trace.op))
  writeFieldBytes(writer, trace.a)
  writeFieldBytes(writer, trace.b)
  writeFieldBytes(writer, trace.c)
  return sha256(writer.toArray())
}

export function secp256k1FieldMulDigest (
  trace: Secp256k1FieldMulTrace
): number[] {
  const writer = new Writer()
  writer.write(toArray(SECP256K1_FIELD_MUL_DIGEST_ID, 'utf8'))
  writer.writeVarIntNum(trace.activeRows)
  writer.writeVarIntNum(trace.layout.width)
  writeFieldBytes(writer, trace.a)
  writeFieldBytes(writer, trace.b)
  writeFieldBytes(writer, trace.c)
  return sha256(writer.toArray())
}

function evaluateActiveLinearRow (
  row: FieldElement[],
  layout: Secp256k1FieldLinearLayout
): FieldElement[] {
  const op = row[layout.op]
  const add = F.sub(SECP256K1_FIELD_LINEAR_SUB, op)
  const sub = F.sub(op, SECP256K1_FIELD_LINEAR_ADD)
  const q = row[layout.q]
  let selectorSum = 0n
  let selectedEquation = 0n
  for (let limb = 0; limb < SECP256K1_FIELD_LIMBS; limb++) {
    const selector = row[layout.limbSelectors + limb]
    selectorSum = F.add(selectorSum, selector)
    const signedB = F.sub(
      F.mul(add, row[layout.b + limb]),
      F.mul(sub, row[layout.b + limb])
    )
    const equation = F.sub(
      F.add(
        F.sub(
          F.sub(
            F.add(row[layout.a + limb], signedB),
            row[layout.c + limb]
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
    F.sub(selectorSum, 1n),
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
  return constraints
}

function evaluateActiveMulRow (
  row: FieldElement[],
  layout: Secp256k1FieldMulLayout
): FieldElement[] {
  let selectorSum = 0n
  let selectedEquation = 0n
  for (let limb = 0; limb < SECP256K1_FIELD_MUL_PRODUCT_LIMBS; limb++) {
    const selector = row[layout.limbSelectors + limb]
    selectorSum = F.add(selectorSum, selector)
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
  const constraints = [
    F.sub(selectorSum, 1n),
    selectedEquation
  ]
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
  return constraints
}

function linearContinuityConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Secp256k1FieldLinearLayout
): FieldElement[] {
  const constraints = [
    F.sub(next[layout.carryIn], current[layout.carryOut]),
    F.sub(next[layout.op], current[layout.op]),
    F.sub(next[layout.q], current[layout.q])
  ]
  for (const offset of [layout.a, layout.b, layout.c]) {
    for (let i = 0; i < SECP256K1_FIELD_LIMBS; i++) {
      constraints.push(F.sub(next[offset + i], current[offset + i]))
    }
  }
  return constraints
}

function mulContinuityConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Secp256k1FieldMulLayout
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
  return constraints
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
    throw new Error('secp256k1 field linear carry is not integral')
  }
  const carryOut = value / FIELD_RADIX
  assertSignedBitRange(carryOut, LINEAR_CARRY_BIAS, SECP256K1_FIELD_LINEAR_CARRY_BITS)
  return carryOut
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
    throw new Error('secp256k1 field mul carry is not integral')
  }
  const carryOut = value / MUL_RADIX
  assertSignedBitRange(carryOut, MUL_CARRY_BIAS, SECP256K1_FIELD_MUL_CARRY_BITS)
  return carryOut
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

function linearFullBoundaryColumns (
  trace: Secp256k1FieldLinearTrace
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const layout = trace.layout
  return [
    {
      column: layout.active,
      values: trace.rows.map((_, row) => row < trace.activeRows ? 1n : 0n)
    },
    {
      column: layout.limb,
      values: trace.rows.map((_, row) => row < trace.activeRows ? BigInt(row) : 0n)
    },
    ...Array.from({ length: SECP256K1_FIELD_LIMBS }, (_, limb) => ({
      column: layout.limbSelectors + limb,
      values: trace.rows.map((_, row) => row === limb ? 1n : 0n)
    }))
  ]
}

function mulFullBoundaryColumns (
  trace: Secp256k1FieldMulTrace
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const layout = trace.layout
  return [
    {
      column: layout.active,
      values: trace.rows.map((_, row) => row < trace.activeRows ? 1n : 0n)
    },
    {
      column: layout.limb,
      values: trace.rows.map((_, row) => row < trace.activeRows ? BigInt(row) : 0n)
    },
    ...Array.from({ length: SECP256K1_FIELD_MUL_PRODUCT_LIMBS }, (_, limb) => ({
      column: layout.limbSelectors + limb,
      values: trace.rows.map((_, row) => row === limb ? 1n : 0n)
    }))
  ]
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
    constraints.push(booleanConstraint(bitValue))
    value = F.add(value, F.mul(bitValue, 1n << BigInt(bit)))
  }
  constraints.push(F.sub(F.add(signedValue, bias), value))
  return constraints
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

function assertSignedBitRange (
  signedValue: bigint,
  bias: bigint,
  bits: number
): void {
  const value = signedValue + bias
  if (value < 0n || value >= (1n << BigInt(bits))) {
    throw new Error('secp256k1 field carry exceeds configured range')
  }
}

function limbBoundary (
  offset: number,
  limbs: bigint[]
): Array<{ column: number, row: number, value: FieldElement }> {
  return limbs.map((limb, index) => ({
    column: offset + index,
    row: 0,
    value: limb
  }))
}

function bigintToLimbs (
  value: bigint,
  limbCount: number,
  radix: bigint
): bigint[] {
  if (value < 0n || value >= radix ** BigInt(limbCount)) {
    throw new Error('secp256k1 field value exceeds limb width')
  }
  const limbs = new Array<bigint>(limbCount)
  let current = value
  const mask = radix - 1n
  for (let i = 0; i < limbCount; i++) {
    limbs[i] = current & mask
    current >>= bitLength(radix)
  }
  if (current !== 0n) throw new Error('secp256k1 field limb overflow')
  return limbs
}

function limbsToBigint (
  limbs: FieldElement[],
  limbCount: number,
  radix: bigint
): bigint {
  if (limbs.length !== limbCount) {
    throw new Error('secp256k1 field limb count mismatch')
  }
  let value = 0n
  for (let i = limbs.length - 1; i >= 0; i--) {
    if (limbs[i] < 0n || limbs[i] >= radix) {
      throw new Error('secp256k1 field limb is outside range')
    }
    value = value * radix + limbs[i]
  }
  if (value >= SECP256K1_P) {
    throw new Error('secp256k1 field limbs are non-canonical')
  }
  return value
}

function bitLength (radix: bigint): bigint {
  let bits = 0n
  let value = radix
  while (value > 1n) {
    bits++
    value >>= 1n
  }
  return bits
}

function writeLimbs (row: FieldElement[], offset: number, limbs: bigint[]): void {
  for (let i = 0; i < limbs.length; i++) row[offset + i] = limbs[i]
}

function writeFieldBytes (writer: Writer, value: bigint): void {
  const bytes = new Array<number>(32)
  let current = value
  for (let i = bytes.length - 1; i >= 0; i--) {
    bytes[i] = Number(current & 0xffn)
    current >>= 8n
  }
  if (current !== 0n) throw new Error('secp256k1 field digest overflow')
  writer.write(bytes)
}

function emptyRows (height: number, width: number): FieldElement[][] {
  return new Array<FieldElement[]>(height)
    .fill([])
    .map(() => new Array<FieldElement>(width).fill(0n))
}

function validateFieldElement (value: bigint, label: string): void {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error(`secp256k1 field ${label} is out of range`)
  }
}

function starkVerifierOptions (proof: StarkProof, transcriptDomain: string): {
  blowupFactor: number
  numQueries: number
  maxRemainderSize: number
  maskDegree: number
  cosetOffset: FieldElement
  traceDegreeBound: number
  compositionDegreeBound: number
  publicInputDigest: number[]
  transcriptDomain: string
} {
  return {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain
  }
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}
