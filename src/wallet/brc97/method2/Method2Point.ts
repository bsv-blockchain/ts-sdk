import { SecpPoint } from '../circuit/Types.js'
import {
  SECP256K1_P,
  isOnCurve,
  modP
} from '../circuit/index.js'
import {
  F,
  FieldElement
} from '../stark/index.js'
import {
  METHOD2_FIELD_LAYOUT,
  METHOD2_FIELD_MUL_LAYOUT,
  METHOD2_FIELD_ADD_SMALL_LAYOUT,
  evaluateMethod2FieldAddSmallConstraints,
  evaluateMethod2FieldElementConstraints,
  evaluateMethod2FieldMulConstraints,
  fieldLimb,
  writeMethod2FieldAddSmallWitness,
  writeMethod2FieldElement,
  writeMethod2FieldMulWitness
} from './Method2Field.js'

export interface Method2PointLayout {
  x: number
  y: number
  x2: number
  x3: number
  y2: number
  xSquareMul: number
  xCubeMul: number
  ySquareMul: number
  curveAdd: number
  width: number
}

export const METHOD2_POINT_LAYOUT: Method2PointLayout = {
  x: 0,
  y: METHOD2_FIELD_LAYOUT.width,
  x2: METHOD2_FIELD_LAYOUT.width * 2,
  x3: METHOD2_FIELD_LAYOUT.width * 3,
  y2: METHOD2_FIELD_LAYOUT.width * 4,
  xSquareMul: METHOD2_FIELD_LAYOUT.width * 5,
  xCubeMul: METHOD2_FIELD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width,
  ySquareMul: METHOD2_FIELD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 2,
  curveAdd: METHOD2_FIELD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  width: METHOD2_FIELD_LAYOUT.width * 5 +
    METHOD2_FIELD_MUL_LAYOUT.width * 3 +
    METHOD2_FIELD_ADD_SMALL_LAYOUT.width
}

export function writeMethod2PointWitness (
  row: FieldElement[],
  offset: number,
  point: SecpPoint
): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('Method 2 point witness must be a valid affine secp256k1 point')
  }
  const x2 = modP(point.x * point.x)
  const x3 = modP(x2 * point.x)
  const y2 = modP(point.y * point.y)
  if (y2 !== modP(x3 + 7n)) {
    throw new Error('Method 2 point witness is not on curve')
  }

  writeMethod2FieldElement(row, offset + METHOD2_POINT_LAYOUT.x, point.x)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_LAYOUT.y, point.y)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_LAYOUT.x2, x2)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_LAYOUT.x3, x3)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_LAYOUT.y2, y2)
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_LAYOUT.xSquareMul,
    point.x,
    point.x,
    x2
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_LAYOUT.xCubeMul,
    x2,
    point.x,
    x3
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_LAYOUT.ySquareMul,
    point.y,
    point.y,
    y2
  )
  writeMethod2FieldAddSmallWitness(
    row,
    offset + METHOD2_POINT_LAYOUT.curveAdd,
    x3,
    7,
    y2
  )
}

export function evaluateMethod2PointConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return [
    ...evaluateMethod2FieldElementConstraints(row, offset + METHOD2_POINT_LAYOUT.x),
    ...evaluateMethod2FieldElementConstraints(row, offset + METHOD2_POINT_LAYOUT.y),
    ...evaluateMethod2FieldElementConstraints(row, offset + METHOD2_POINT_LAYOUT.x2),
    ...evaluateMethod2FieldElementConstraints(row, offset + METHOD2_POINT_LAYOUT.x3),
    ...evaluateMethod2FieldElementConstraints(row, offset + METHOD2_POINT_LAYOUT.y2),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_LAYOUT.xSquareMul,
      offset + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_LAYOUT.x2
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_LAYOUT.xCubeMul,
      offset + METHOD2_POINT_LAYOUT.x2,
      offset + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_LAYOUT.x3
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_LAYOUT.ySquareMul,
      offset + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_LAYOUT.y2
    ),
    ...evaluateMethod2FieldAddSmallConstraints(
      row,
      offset + METHOD2_POINT_LAYOUT.curveAdd,
      offset + METHOD2_POINT_LAYOUT.x3,
      7,
      offset + METHOD2_POINT_LAYOUT.y2
    )
  ]
}

export function evaluateMethod2CompressedPointConstraints (
  row: FieldElement[],
  pointOffset: number,
  compressedOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  const yParity = row[
    pointOffset + METHOD2_POINT_LAYOUT.y + METHOD2_FIELD_LAYOUT.bits
  ]
  constraints.push(F.sub(
    row[compressedOffset],
    F.add(2n, yParity)
  ))
  for (let limb = 0; limb < 16; limb++) {
    const lowByte = row[compressedOffset + 1 + 31 - limb * 2]
    const highByte = row[compressedOffset + 1 + 30 - limb * 2]
    constraints.push(F.sub(
      fieldLimb(row, pointOffset + METHOD2_POINT_LAYOUT.x, limb),
      F.add(lowByte, F.mul(highByte, 256n))
    ))
  }
  return constraints
}

export function pointCoordinateValue (
  point: SecpPoint,
  coordinate: 'x' | 'y'
): bigint {
  const value = point[coordinate]
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Point coordinate out of secp256k1 field')
  }
  return value
}
