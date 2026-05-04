import {
  SECP256K1_P,
  isOnCurve,
  modP,
  pointAdd
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import { FieldElement } from '../stark/index.js'
import { METHOD2_V2_LIMB_BITS } from './Method2V2.js'

export const METHOD2_V2_FIELD_LIMB_BITS = METHOD2_V2_LIMB_BITS
export const METHOD2_V2_FIELD_LIMB_COUNT = 9
export const METHOD2_V2_MIXED_ADD_TRANSITION_DEGREE_ESTIMATE = 2

export interface Method2V2JacobianPoint {
  x: bigint
  y: bigint
  z: bigint
}

export interface Method2V2MixedAddLayout {
  x1: number
  y1: number
  z1: number
  x2: number
  y2: number
  x3: number
  y3: number
  z3: number
  z1z1: number
  u2: number
  z1z1z1: number
  s2: number
  h: number
  hh: number
  i: number
  j: number
  r: number
  v: number
  r2: number
  twoV: number
  vMinusX3: number
  rTimesVMinusX3: number
  y1j: number
  twoY1J: number
  z1PlusH: number
  z1PlusHSquared: number
  width: number
}

export interface Method2V2MixedAddWitness {
  row: FieldElement[]
  output: Method2V2JacobianPoint
  affineOutput: SecpPoint
  layout: Method2V2MixedAddLayout
}

export interface Method2V2MixedAddMetrics {
  limbBits: number
  limbCount: number
  fieldElements: number
  oneRowWidth: number
  transitionDegreeEstimate: number
  mixedAddCountForMethod2: number
  naiveFullWidthColumnsFor86Adds: number
}

export const METHOD2_V2_MIXED_ADD_LAYOUT: Method2V2MixedAddLayout = (() => {
  let offset = 0
  const next = (): number => {
    const current = offset
    offset += METHOD2_V2_FIELD_LIMB_COUNT
    return current
  }
  const layout = {
    x1: next(),
    y1: next(),
    z1: next(),
    x2: next(),
    y2: next(),
    x3: next(),
    y3: next(),
    z3: next(),
    z1z1: next(),
    u2: next(),
    z1z1z1: next(),
    s2: next(),
    h: next(),
    hh: next(),
    i: next(),
    j: next(),
    r: next(),
    v: next(),
    r2: next(),
    twoV: next(),
    vMinusX3: next(),
    rTimesVMinusX3: next(),
    y1j: next(),
    twoY1J: next(),
    z1PlusH: next(),
    z1PlusHSquared: next(),
    width: offset
  }
  return layout
})()

export function writeMethod2V2MixedAddWitness (
  accumulator: Method2V2JacobianPoint,
  affine: SecpPoint
): Method2V2MixedAddWitness {
  validateJacobianInput(accumulator)
  validateAffineInput(affine)
  const layout = METHOD2_V2_MIXED_ADD_LAYOUT
  const row = new Array<FieldElement>(layout.width).fill(0n)

  const z1z1 = fieldSquare(accumulator.z)
  const u2 = fieldMul(affine.x, z1z1)
  const z1z1z1 = fieldMul(z1z1, accumulator.z)
  const s2 = fieldMul(affine.y, z1z1z1)
  const h = fieldSub(u2, accumulator.x)
  if (h === 0n) {
    throw new Error('Method 2 V2 mixed add prototype excludes H = 0')
  }
  const hh = fieldSquare(h)
  const i = fieldMul(4n, hh)
  const j = fieldMul(h, i)
  const r = fieldMul(2n, fieldSub(s2, accumulator.y))
  const v = fieldMul(accumulator.x, i)
  const r2 = fieldSquare(r)
  const twoV = fieldMul(2n, v)
  const x3 = fieldSub(fieldSub(r2, j), twoV)
  const vMinusX3 = fieldSub(v, x3)
  const rTimesVMinusX3 = fieldMul(r, vMinusX3)
  const y1j = fieldMul(accumulator.y, j)
  const twoY1J = fieldMul(2n, y1j)
  const y3 = fieldSub(rTimesVMinusX3, twoY1J)
  const z1PlusH = fieldAdd(accumulator.z, h)
  const z1PlusHSquared = fieldSquare(z1PlusH)
  const z3 = fieldSub(fieldSub(z1PlusHSquared, z1z1), hh)
  const output = { x: x3, y: y3, z: z3 }
  const affineOutput = jacobianToAffine(output)
  const expectedOutput = pointAdd(jacobianToAffine(accumulator), affine)
  if (!pointsEqual(affineOutput, expectedOutput)) {
    throw new Error('Method 2 V2 mixed add witness does not match point addition')
  }

  writeField(row, layout.x1, accumulator.x)
  writeField(row, layout.y1, accumulator.y)
  writeField(row, layout.z1, accumulator.z)
  writeField(row, layout.x2, affine.x)
  writeField(row, layout.y2, affine.y)
  writeField(row, layout.x3, x3)
  writeField(row, layout.y3, y3)
  writeField(row, layout.z3, z3)
  writeField(row, layout.z1z1, z1z1)
  writeField(row, layout.u2, u2)
  writeField(row, layout.z1z1z1, z1z1z1)
  writeField(row, layout.s2, s2)
  writeField(row, layout.h, h)
  writeField(row, layout.hh, hh)
  writeField(row, layout.i, i)
  writeField(row, layout.j, j)
  writeField(row, layout.r, r)
  writeField(row, layout.v, v)
  writeField(row, layout.r2, r2)
  writeField(row, layout.twoV, twoV)
  writeField(row, layout.vMinusX3, vMinusX3)
  writeField(row, layout.rTimesVMinusX3, rTimesVMinusX3)
  writeField(row, layout.y1j, y1j)
  writeField(row, layout.twoY1J, twoY1J)
  writeField(row, layout.z1PlusH, z1PlusH)
  writeField(row, layout.z1PlusHSquared, z1PlusHSquared)

  return {
    row,
    output,
    affineOutput,
    layout
  }
}

export function evaluateMethod2V2MixedAddConstraints (
  row: FieldElement[],
  layout: Method2V2MixedAddLayout = METHOD2_V2_MIXED_ADD_LAYOUT
): bigint[] {
  const x1 = readField(row, layout.x1)
  const y1 = readField(row, layout.y1)
  const z1 = readField(row, layout.z1)
  const x2 = readField(row, layout.x2)
  const y2 = readField(row, layout.y2)
  const x3 = readField(row, layout.x3)
  const y3 = readField(row, layout.y3)
  const z3 = readField(row, layout.z3)
  const z1z1 = readField(row, layout.z1z1)
  const u2 = readField(row, layout.u2)
  const z1z1z1 = readField(row, layout.z1z1z1)
  const s2 = readField(row, layout.s2)
  const h = readField(row, layout.h)
  const hh = readField(row, layout.hh)
  const i = readField(row, layout.i)
  const j = readField(row, layout.j)
  const r = readField(row, layout.r)
  const v = readField(row, layout.v)
  const r2 = readField(row, layout.r2)
  const twoV = readField(row, layout.twoV)
  const vMinusX3 = readField(row, layout.vMinusX3)
  const rTimesVMinusX3 = readField(row, layout.rTimesVMinusX3)
  const y1j = readField(row, layout.y1j)
  const twoY1J = readField(row, layout.twoY1J)
  const z1PlusH = readField(row, layout.z1PlusH)
  const z1PlusHSquared = readField(row, layout.z1PlusHSquared)

  const constraints = [
    fieldSub(z1z1, fieldSquare(z1)),
    fieldSub(u2, fieldMul(x2, z1z1)),
    fieldSub(z1z1z1, fieldMul(z1z1, z1)),
    fieldSub(s2, fieldMul(y2, z1z1z1)),
    fieldSub(h, fieldSub(u2, x1)),
    fieldSub(hh, fieldSquare(h)),
    fieldSub(i, fieldMul(4n, hh)),
    fieldSub(j, fieldMul(h, i)),
    fieldSub(r, fieldMul(2n, fieldSub(s2, y1))),
    fieldSub(v, fieldMul(x1, i)),
    fieldSub(r2, fieldSquare(r)),
    fieldSub(twoV, fieldMul(2n, v)),
    fieldSub(x3, fieldSub(fieldSub(r2, j), twoV)),
    fieldSub(vMinusX3, fieldSub(v, x3)),
    fieldSub(rTimesVMinusX3, fieldMul(r, vMinusX3)),
    fieldSub(y1j, fieldMul(y1, j)),
    fieldSub(twoY1J, fieldMul(2n, y1j)),
    fieldSub(y3, fieldSub(rTimesVMinusX3, twoY1J)),
    fieldSub(z1PlusH, fieldAdd(z1, h)),
    fieldSub(z1PlusHSquared, fieldSquare(z1PlusH)),
    fieldSub(z3, fieldSub(fieldSub(z1PlusHSquared, z1z1), hh)),
    h === 0n ? 1n : 0n
  ]
  return constraints
}

export function method2V2MixedAddMetrics (): Method2V2MixedAddMetrics {
  const fieldElements = METHOD2_V2_MIXED_ADD_LAYOUT.width /
    METHOD2_V2_FIELD_LIMB_COUNT
  return {
    limbBits: METHOD2_V2_FIELD_LIMB_BITS,
    limbCount: METHOD2_V2_FIELD_LIMB_COUNT,
    fieldElements,
    oneRowWidth: METHOD2_V2_MIXED_ADD_LAYOUT.width,
    transitionDegreeEstimate: METHOD2_V2_MIXED_ADD_TRANSITION_DEGREE_ESTIMATE,
    mixedAddCountForMethod2: 86,
    naiveFullWidthColumnsFor86Adds: METHOD2_V2_MIXED_ADD_LAYOUT.width
  }
}

export function affineToJacobian (point: SecpPoint): Method2V2JacobianPoint {
  validateAffineInput(point)
  return { x: point.x, y: point.y, z: 1n }
}

export function jacobianToAffine (point: Method2V2JacobianPoint): SecpPoint {
  validateJacobianInput(point)
  const zInv = modInv(point.z)
  const zInv2 = fieldSquare(zInv)
  const zInv3 = fieldMul(zInv2, zInv)
  return {
    x: fieldMul(point.x, zInv2),
    y: fieldMul(point.y, zInv3)
  }
}

function writeField (row: FieldElement[], offset: number, value: bigint): void {
  const limbs = bigintToLimbs(value)
  for (let i = 0; i < limbs.length; i++) {
    row[offset + i] = limbs[i]
  }
}

function readField (row: FieldElement[], offset: number): bigint {
  let value = 0n
  for (let i = METHOD2_V2_FIELD_LIMB_COUNT - 1; i >= 0; i--) {
    const limb = row[offset + i]
    const max = 1n << BigInt(METHOD2_V2_FIELD_LIMB_BITS)
    if (limb < 0n || limb >= max) {
      throw new Error('Method 2 V2 mixed add limb out of range')
    }
    value = (value << BigInt(METHOD2_V2_FIELD_LIMB_BITS)) + limb
  }
  if (value >= SECP256K1_P) {
    throw new Error('Method 2 V2 mixed add field element is non-canonical')
  }
  return value
}

function bigintToLimbs (value: bigint): bigint[] {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Method 2 V2 mixed add field element out of range')
  }
  const limbs = new Array<bigint>(METHOD2_V2_FIELD_LIMB_COUNT)
  let current = value
  const mask = (1n << BigInt(METHOD2_V2_FIELD_LIMB_BITS)) - 1n
  for (let i = 0; i < METHOD2_V2_FIELD_LIMB_COUNT; i++) {
    limbs[i] = current & mask
    current >>= BigInt(METHOD2_V2_FIELD_LIMB_BITS)
  }
  if (current !== 0n) throw new Error('Method 2 V2 mixed add limb overflow')
  return limbs
}

function validateJacobianInput (point: Method2V2JacobianPoint): void {
  if (point.z === 0n) throw new Error('Method 2 V2 mixed add requires nonzero Z')
  jacobianToAffineUnchecked(point)
}

function validateAffineInput (point: SecpPoint): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('Method 2 V2 mixed add requires a valid affine point')
  }
}

function jacobianToAffineUnchecked (point: Method2V2JacobianPoint): SecpPoint {
  const zInv = modInv(point.z)
  const zInv2 = fieldSquare(zInv)
  const zInv3 = fieldMul(zInv2, zInv)
  const affine = {
    x: fieldMul(point.x, zInv2),
    y: fieldMul(point.y, zInv3)
  }
  if (!isOnCurve(affine)) {
    throw new Error('Method 2 V2 mixed add requires an on-curve accumulator')
  }
  return affine
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  return left.infinity === true
    ? right.infinity === true
    : right.infinity !== true && left.x === right.x && left.y === right.y
}

function fieldAdd (left: bigint, right: bigint): bigint {
  return modP(left + right)
}

function fieldSub (left: bigint, right: bigint): bigint {
  return modP(left - right)
}

function fieldMul (left: bigint, right: bigint): bigint {
  return modP(left * right)
}

function fieldSquare (value: bigint): bigint {
  return fieldMul(value, value)
}

function modInv (value: bigint): bigint {
  value = modP(value)
  if (value === 0n) throw new Error('Cannot invert zero')
  let low = value
  let high = SECP256K1_P
  let lm = 1n
  let hm = 0n
  while (low > 1n) {
    const ratio = high / low
    ;[lm, hm] = [hm - lm * ratio, lm]
    ;[low, high] = [high - low * ratio, low]
  }
  return modP(lm)
}
