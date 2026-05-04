import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import {
  AirDefinition,
  F,
  FieldElement,
  StarkProof,
  StarkProverOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/index.js'
import { SECP256K1_P, modP } from '../circuit/index.js'
import {
  METHOD2_V2_FIELD_LIMB_BITS,
  METHOD2_V2_FIELD_LIMB_COUNT
} from './Method2V2MixedAdd.js'

export const BRC69_METHOD2_V2_FIELD_MUL_TRANSCRIPT_DOMAIN =
  'BRC69_METHOD2_V2_FIELD_MUL_AIR_V1'
export const METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS =
  METHOD2_V2_FIELD_LIMB_COUNT * 2
export const METHOD2_V2_FIELD_MUL_CARRY_BITS = 37
export const METHOD2_V2_FIELD_MUL_CARRY_BIAS =
  1n << BigInt(METHOD2_V2_FIELD_MUL_CARRY_BITS - 1)
export const METHOD2_V2_FIELD_MUL_TRANSITION_DEGREE = 5

const LIMB_RADIX = 1n << BigInt(METHOD2_V2_FIELD_LIMB_BITS)
const P_LIMBS = bigintToLimbs(SECP256K1_P, METHOD2_V2_FIELD_LIMB_COUNT)

export interface Method2V2FieldMulLayout {
  active: number
  limb: number
  limbSelectors: number
  a: number
  b: number
  c: number
  q: number
  carryIn: number
  carryOut: number
  carryBits: number
  width: number
}

export interface Method2V2FieldMulTrace {
  rows: FieldElement[][]
  activeRows: number
  paddedRows: number
  layout: Method2V2FieldMulLayout
  a: bigint
  b: bigint
  c: bigint
  q: bigint
}

export interface Method2V2FieldMulMetrics {
  limbBits: number
  limbCount: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  carryBits: number
  multiplicationTermsPerRowMax: number
  proofBytes?: number
  verifies?: boolean
}

export const METHOD2_V2_FIELD_MUL_LAYOUT: Method2V2FieldMulLayout = {
  active: 0,
  limb: 1,
  limbSelectors: 2,
  a: 2 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS,
  b: 2 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT,
  c: 2 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT * 2,
  q: 2 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT * 3,
  carryIn: 2 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT * 4,
  carryOut: 3 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT * 4,
  carryBits: 4 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS + METHOD2_V2_FIELD_LIMB_COUNT * 4,
  width: 4 + METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS +
    METHOD2_V2_FIELD_LIMB_COUNT * 4 +
    METHOD2_V2_FIELD_MUL_CARRY_BITS
}

export function buildMethod2V2FieldMulTrace (
  a: bigint,
  b: bigint,
  c = modP(a * b)
): Method2V2FieldMulTrace {
  validateFieldElement(a, 'a')
  validateFieldElement(b, 'b')
  validateFieldElement(c, 'c')
  const numerator = a * b - c
  if (numerator % SECP256K1_P !== 0n) {
    throw new Error('Method 2 V2 field mul result is not congruent')
  }
  const q = numerator / SECP256K1_P
  validateFieldElement(q, 'q')

  const layout = METHOD2_V2_FIELD_MUL_LAYOUT
  const activeRows = METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS
  const paddedRows = 32
  const rows = new Array<FieldElement[]>(paddedRows)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  const aLimbs = bigintToLimbs(a, METHOD2_V2_FIELD_LIMB_COUNT)
  const bLimbs = bigintToLimbs(b, METHOD2_V2_FIELD_LIMB_COUNT)
  const cLimbs = bigintToLimbs(c, METHOD2_V2_FIELD_LIMB_COUNT)
  const qLimbs = bigintToLimbs(q, METHOD2_V2_FIELD_LIMB_COUNT)
  let carry = 0n
  for (let limb = 0; limb < activeRows; limb++) {
    const row = rows[limb]
    row[layout.active] = 1n
    row[layout.limb] = BigInt(limb)
    row[layout.limbSelectors + limb] = 1n
    writeLimbs(row, layout.a, aLimbs)
    writeLimbs(row, layout.b, bLimbs)
    writeLimbs(row, layout.c, cLimbs)
    writeLimbs(row, layout.q, qLimbs)
    row[layout.carryIn] = F.normalize(carry)
    const carryOut = carryOutForLimb(
      aLimbs,
      bLimbs,
      cLimbs,
      qLimbs,
      limb,
      carry
    )
    row[layout.carryOut] = F.normalize(carryOut)
    writeCarryBits(row, layout.carryBits, carryOut)
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 V2 field mul final carry is nonzero')
  }
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

export function buildMethod2V2FieldMulAir (
  trace: Method2V2FieldMulTrace,
  publicInputDigest: number[] = method2V2FieldMulDigest(trace)
): AirDefinition {
  const layout = trace.layout
  const aLimbs = bigintToLimbs(trace.a, METHOD2_V2_FIELD_LIMB_COUNT)
  const bLimbs = bigintToLimbs(trace.b, METHOD2_V2_FIELD_LIMB_COUNT)
  const cLimbs = bigintToLimbs(trace.c, METHOD2_V2_FIELD_LIMB_COUNT)
  return {
    traceWidth: layout.width,
    transitionDegree: METHOD2_V2_FIELD_MUL_TRANSITION_DEGREE,
    publicInputDigest,
    boundaryConstraints: [
      { column: layout.carryIn, row: 0, value: 0n },
      { column: layout.carryOut, row: trace.activeRows - 1, value: 0n },
      ...limbBoundaryConstraints(layout.a, aLimbs),
      ...limbBoundaryConstraints(layout.b, bLimbs),
      ...limbBoundaryConstraints(layout.c, cLimbs)
    ],
    fullBoundaryColumns: [
      {
        column: layout.active,
        values: trace.rows.map((_, row) => row < trace.activeRows ? 1n : 0n)
      },
      {
        column: layout.limb,
        values: trace.rows.map((_, row) => row < trace.activeRows ? BigInt(row) : 0n)
      },
      ...Array.from({ length: METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS }, (_, limb) => ({
        column: layout.limbSelectors + limb,
        values: trace.rows.map((_, row) => row === limb ? 1n : 0n)
      }))
    ],
    evaluateTransition: (current, next) =>
      evaluateMethod2V2FieldMulTransition(current, next, layout)
  }
}

export function evaluateMethod2V2FieldMulTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2FieldMulLayout = METHOD2_V2_FIELD_MUL_LAYOUT
): FieldElement[] {
  const constraints: FieldElement[] = [
    booleanConstraint(current[layout.active])
  ]
  constraints.push(...gateConstraints(
    evaluateActiveFieldMulRow(current, layout),
    current[layout.active]
  ))
  constraints.push(...gateConstraints(
    activeContinuityConstraints(current, next, layout),
    F.mul(current[layout.active], next[layout.active])
  ))
  return constraints
}

export function proveMethod2V2FieldMul (
  trace: Method2V2FieldMulTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildMethod2V2FieldMulAir(
    trace,
    options.publicInputDigest ?? method2V2FieldMulDigest(trace)
  )
  return proveStark(air, trace.rows, {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 16,
    maskDegree: 1,
    cosetOffset: 3n,
    transcriptDomain: BRC69_METHOD2_V2_FIELD_MUL_TRANSCRIPT_DOMAIN,
    ...options,
    publicInputDigest: air.publicInputDigest
  })
}

export function verifyMethod2V2FieldMul (
  trace: Method2V2FieldMulTrace,
  proof: StarkProof
): boolean {
  const air = buildMethod2V2FieldMulAir(trace, proof.publicInputDigest)
  return verifyStark(air, proof, {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain: BRC69_METHOD2_V2_FIELD_MUL_TRANSCRIPT_DOMAIN
  })
}

export function method2V2FieldMulMetrics (
  proof?: StarkProof
): Method2V2FieldMulMetrics {
  return {
    limbBits: METHOD2_V2_FIELD_LIMB_BITS,
    limbCount: METHOD2_V2_FIELD_LIMB_COUNT,
    activeRows: METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS,
    paddedRows: 32,
    traceWidth: METHOD2_V2_FIELD_MUL_LAYOUT.width,
    carryBits: METHOD2_V2_FIELD_MUL_CARRY_BITS,
    multiplicationTermsPerRowMax: METHOD2_V2_FIELD_LIMB_COUNT,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length,
    verifies: undefined
  }
}

export function method2V2FieldMulDigest (
  trace: Method2V2FieldMulTrace
): number[] {
  const writer = new Writer()
  writer.write(toArray(BRC69_METHOD2_V2_FIELD_MUL_TRANSCRIPT_DOMAIN, 'utf8'))
  writer.writeVarIntNum(trace.activeRows)
  writer.writeVarIntNum(trace.layout.width)
  writeField(writer, trace.a)
  writeField(writer, trace.b)
  writeField(writer, trace.c)
  return sha256(writer.toArray())
}

function evaluateActiveFieldMulRow (
  row: FieldElement[],
  layout: Method2V2FieldMulLayout
): FieldElement[] {
  const carryIn = row[layout.carryIn]
  const carryOut = row[layout.carryOut]
  const constraints: FieldElement[] = []
  let selectorSum = 0n
  let selectedEquation = 0n
  for (let limb = 0; limb < METHOD2_V2_FIELD_MUL_PRODUCT_LIMBS; limb++) {
    const selector = row[layout.limbSelectors + limb]
    selectorSum = F.add(selectorSum, selector)
    const prod = convolutionLimbFromRow(row, layout.a, layout.b, limb)
    const qp = quotientProductLimbFromRow(row, layout.q, limb)
    const c = limb < METHOD2_V2_FIELD_LIMB_COUNT
      ? row[layout.c + limb]
      : 0n
    const equation = F.sub(
      F.sub(F.add(prod, carryIn), F.add(c, qp)),
      F.mul(carryOut, LIMB_RADIX)
    )
    selectedEquation = F.add(selectedEquation, F.mul(selector, equation))
  }
  constraints.push(F.sub(selectorSum, 1n))
  constraints.push(selectedEquation)
  let carryBitsValue = 0n
  for (let bit = 0; bit < METHOD2_V2_FIELD_MUL_CARRY_BITS; bit++) {
    const bitValue = row[layout.carryBits + bit]
    constraints.push(booleanConstraint(bitValue))
    carryBitsValue = F.add(
      carryBitsValue,
      F.mul(bitValue, 1n << BigInt(bit))
    )
  }
  constraints.push(F.sub(
    F.add(carryOut, METHOD2_V2_FIELD_MUL_CARRY_BIAS),
    carryBitsValue
  ))
  return constraints
}

function activeContinuityConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2FieldMulLayout
): FieldElement[] {
  const constraints = [
    F.sub(next[layout.carryIn], current[layout.carryOut])
  ]
  for (const offset of [layout.a, layout.b, layout.c, layout.q]) {
    for (let limb = 0; limb < METHOD2_V2_FIELD_LIMB_COUNT; limb++) {
      constraints.push(F.sub(next[offset + limb], current[offset + limb]))
    }
  }
  return constraints
}

function carryOutForLimb (
  a: bigint[],
  b: bigint[],
  c: bigint[],
  q: bigint[],
  limb: number,
  carryIn: bigint
): bigint {
  const value = convolutionLimb(a, b, limb) +
    carryIn -
    (c[limb] ?? 0n) -
    quotientProductLimb(q, limb)
  if (value % LIMB_RADIX !== 0n) {
    throw new Error('Method 2 V2 field mul carry is not integral')
  }
  const carryOut = value / LIMB_RADIX
  const biased = carryOut + METHOD2_V2_FIELD_MUL_CARRY_BIAS
  if (
    biased < 0n ||
    biased >= (1n << BigInt(METHOD2_V2_FIELD_MUL_CARRY_BITS))
  ) {
    throw new Error('Method 2 V2 field mul carry exceeds range')
  }
  return carryOut
}

function convolutionLimbFromRow (
  row: FieldElement[],
  leftOffset: number,
  rightOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < METHOD2_V2_FIELD_LIMB_COUNT; i++) {
    const j = limb - i
    if (j >= 0 && j < METHOD2_V2_FIELD_LIMB_COUNT) {
      sum = F.add(sum, F.mul(row[leftOffset + i], row[rightOffset + j]))
    }
  }
  return sum
}

function quotientProductLimbFromRow (
  row: FieldElement[],
  qOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < METHOD2_V2_FIELD_LIMB_COUNT; i++) {
    const j = limb - i
    if (j >= 0 && j < METHOD2_V2_FIELD_LIMB_COUNT) {
      sum = F.add(sum, F.mul(row[qOffset + i], P_LIMBS[j]))
    }
  }
  return sum
}

function convolutionLimb (
  left: bigint[],
  right: bigint[],
  limb: number
): bigint {
  let sum = 0n
  for (let i = 0; i < left.length; i++) {
    const j = limb - i
    if (j >= 0 && j < right.length) sum += left[i] * right[j]
  }
  return sum
}

function quotientProductLimb (q: bigint[], limb: number): bigint {
  let sum = 0n
  for (let i = 0; i < q.length; i++) {
    const j = limb - i
    if (j >= 0 && j < P_LIMBS.length) sum += q[i] * P_LIMBS[j]
  }
  return sum
}

function writeCarryBits (
  row: FieldElement[],
  offset: number,
  carry: bigint
): void {
  let value = carry + METHOD2_V2_FIELD_MUL_CARRY_BIAS
  for (let bit = 0; bit < METHOD2_V2_FIELD_MUL_CARRY_BITS; bit++) {
    row[offset + bit] = value & 1n
    value >>= 1n
  }
  if (value !== 0n) {
    throw new Error('Method 2 V2 field mul carry bits overflow')
  }
}

function limbBoundaryConstraints (
  offset: number,
  limbs: bigint[]
): Array<{ column: number, row: number, value: FieldElement }> {
  return limbs.map((limb, index) => ({
    column: offset + index,
    row: 0,
    value: limb
  }))
}

function bigintToLimbs (value: bigint, limbCount: number): bigint[] {
  if (value < 0n || value >= (1n << BigInt(limbCount * METHOD2_V2_FIELD_LIMB_BITS))) {
    throw new Error('Method 2 V2 field mul value exceeds limb width')
  }
  const limbs = new Array<bigint>(limbCount)
  let current = value
  const mask = LIMB_RADIX - 1n
  for (let i = 0; i < limbCount; i++) {
    limbs[i] = current & mask
    current >>= BigInt(METHOD2_V2_FIELD_LIMB_BITS)
  }
  if (current !== 0n) throw new Error('Method 2 V2 field mul limb overflow')
  return limbs
}

function writeLimbs (
  row: FieldElement[],
  offset: number,
  limbs: bigint[]
): void {
  for (let i = 0; i < limbs.length; i++) row[offset + i] = limbs[i]
}

function writeField (writer: Writer, value: bigint): void {
  const bytes = new Array<number>(32)
  let current = value
  for (let i = bytes.length - 1; i >= 0; i--) {
    bytes[i] = Number(current & 0xffn)
    current >>= 8n
  }
  if (current !== 0n) throw new Error('Method 2 V2 field mul digest overflow')
  writer.write(bytes)
}

function validateFieldElement (value: bigint, label: string): void {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error(`Method 2 V2 field mul ${label} is out of range`)
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
