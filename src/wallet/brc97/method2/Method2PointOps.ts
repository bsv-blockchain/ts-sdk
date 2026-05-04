import { SecpPoint } from '../circuit/Types.js'
import {
  bigintToU16LimbsLE,
  isOnCurve,
  modInvP,
  modP,
  pointAdd,
  pointDouble
} from '../circuit/index.js'
import {
  F,
  FieldElement
} from '../stark/index.js'
import {
  METHOD2_FIELD_ADD_LAYOUT,
  METHOD2_FIELD_LAYOUT,
  METHOD2_FIELD_LIMB_COUNT,
  METHOD2_FIELD_MUL_LAYOUT,
  evaluateMethod2FieldAddConstraints,
  evaluateMethod2FieldElementConstraints,
  evaluateMethod2FieldMulConstraints,
  fieldLimb,
  writeMethod2FieldAddWitness,
  writeMethod2FieldElement,
  writeMethod2FieldMulWitness
} from './Method2Field.js'
import {
  METHOD2_POINT_LAYOUT,
  evaluateMethod2PointConstraints,
  writeMethod2PointWitness
} from './Method2Point.js'

export interface Method2PointDoubleLayout {
  input: number
  output: number
  one: number
  twoY: number
  twoYInverse: number
  twoX2: number
  threeX2: number
  slope: number
  slopeSquared: number
  twoX: number
  inputXMinusOutputX: number
  lambdaDiff: number
  twoYAdd: number
  twoYInverseMul: number
  twoX2Add: number
  threeX2Add: number
  slopeNumeratorMul: number
  slopeSquareMul: number
  twoXAdd: number
  outputXAdd: number
  inputXMinusOutputXAdd: number
  lambdaDiffMul: number
  outputYAdd: number
  width: number
}

export interface Method2PointAddDistinctLayout {
  left: number
  right: number
  output: number
  one: number
  diffX: number
  diffY: number
  diffXInverse: number
  slope: number
  slopeSquared: number
  sumX: number
  leftXMinusOutputX: number
  lambdaDiff: number
  diffXAdd: number
  diffYAdd: number
  diffXInverseMul: number
  slopeMul: number
  slopeSquareMul: number
  sumXAdd: number
  outputXAdd: number
  leftXMinusOutputXAdd: number
  lambdaDiffMul: number
  outputYAdd: number
  width: number
}

const DOUBLE_FIELD_START = METHOD2_POINT_LAYOUT.width * 2
const DOUBLE_RELATION_START = DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 10

export const METHOD2_POINT_DOUBLE_LAYOUT: Method2PointDoubleLayout = {
  input: 0,
  output: METHOD2_POINT_LAYOUT.width,
  one: DOUBLE_FIELD_START,
  twoY: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width,
  twoYInverse: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 2,
  twoX2: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 3,
  threeX2: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 4,
  slope: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 5,
  slopeSquared: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 6,
  twoX: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 7,
  inputXMinusOutputX: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 8,
  lambdaDiff: DOUBLE_FIELD_START + METHOD2_FIELD_LAYOUT.width * 9,
  twoYAdd: DOUBLE_RELATION_START,
  twoYInverseMul: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width,
  twoX2Add: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width + METHOD2_FIELD_MUL_LAYOUT.width,
  threeX2Add: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeNumeratorMul: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeSquareMul: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 2,
  twoXAdd: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputXAdd: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 4 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  inputXMinusOutputXAdd: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  lambdaDiffMul: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputYAdd: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 4,
  width: DOUBLE_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 7 + METHOD2_FIELD_MUL_LAYOUT.width * 4
}

const ADD_FIELD_START = METHOD2_POINT_LAYOUT.width * 3
const ADD_RELATION_START = ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 9

export const METHOD2_POINT_ADD_DISTINCT_LAYOUT: Method2PointAddDistinctLayout = {
  left: 0,
  right: METHOD2_POINT_LAYOUT.width,
  output: METHOD2_POINT_LAYOUT.width * 2,
  one: ADD_FIELD_START,
  diffX: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width,
  diffY: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 2,
  diffXInverse: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 3,
  slope: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 4,
  slopeSquared: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 5,
  sumX: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 6,
  leftXMinusOutputX: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 7,
  lambdaDiff: ADD_FIELD_START + METHOD2_FIELD_LAYOUT.width * 8,
  diffXAdd: ADD_RELATION_START,
  diffYAdd: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width,
  diffXInverseMul: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2,
  slopeMul: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeSquareMul: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width * 2,
  sumXAdd: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputXAdd: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  leftXMinusOutputXAdd: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 4 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  lambdaDiffMul: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputYAdd: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 4,
  width: ADD_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 4
}

export function writeMethod2PointDoubleWitness (
  row: FieldElement[],
  offset: number,
  input: SecpPoint
): SecpPoint {
  if (input.infinity === true || !isOnCurve(input)) {
    throw new Error('Method 2 point double input must be a valid affine point')
  }
  const twoY = modP(input.y + input.y)
  if (twoY === 0n) {
    throw new Error('Method 2 point double input must have nonzero 2y')
  }
  const output = pointDouble(input)
  if (output.infinity === true || !isOnCurve(output)) {
    throw new Error('Method 2 point double output must be affine')
  }

  const twoYInverse = modInvP(twoY)
  const x2 = modP(input.x * input.x)
  const twoX2 = modP(x2 + x2)
  const threeX2 = modP(twoX2 + x2)
  const slope = modP(threeX2 * twoYInverse)
  const slopeSquared = modP(slope * slope)
  const twoX = modP(input.x + input.x)
  const inputXMinusOutputX = modP(input.x - output.x)
  const lambdaDiff = modP(slope * inputXMinusOutputX)

  writeMethod2PointWitness(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.input, input)
  writeMethod2PointWitness(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.output, output)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.one, 1n)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.twoY, twoY)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYInverse, twoYInverse)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2, twoX2)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2, threeX2)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.slope, slope)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquared, slopeSquared)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX, twoX)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputX, inputXMinusOutputX)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiff, lambdaDiff)
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYAdd,
    input.y,
    input.y,
    twoY
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYInverseMul,
    twoY,
    twoYInverse,
    1n
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2Add,
    x2,
    x2,
    twoX2
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2Add,
    twoX2,
    x2,
    threeX2
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeNumeratorMul,
    slope,
    twoY,
    threeX2
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquareMul,
    slope,
    slope,
    slopeSquared
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.twoXAdd,
    input.x,
    input.x,
    twoX
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.outputXAdd,
    output.x,
    twoX,
    slopeSquared
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputXAdd,
    output.x,
    inputXMinusOutputX,
    input.x
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiffMul,
    slope,
    inputXMinusOutputX,
    lambdaDiff
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_DOUBLE_LAYOUT.outputYAdd,
    output.y,
    input.y,
    lambdaDiff
  )
  return output
}

export function evaluateMethod2PointDoubleConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return [
    ...evaluateMethod2PointConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input
    ),
    ...evaluateMethod2PointConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.output
    ),
    ...evaluateFieldValueConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.one,
      1n
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoY
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYInverse
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slope
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputX
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYAdd,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoY
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYInverseMul,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoY,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoYInverse,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.one
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2Add,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x2,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x2,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2Add,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX2,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x2,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeNumeratorMul,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slope,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoY,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.threeX2
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquareMul,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slope,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slope,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoXAdd,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.outputXAdd,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.output + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.twoX,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputXAdd,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.output + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputX,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiffMul,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.slope,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.inputXMinusOutputX,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.outputYAdd,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.output + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.input + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_DOUBLE_LAYOUT.lambdaDiff
    )
  ]
}

export function writeMethod2PointAddDistinctWitness (
  row: FieldElement[],
  offset: number,
  left: SecpPoint,
  right: SecpPoint
): SecpPoint {
  if (left.infinity === true || right.infinity === true) {
    throw new Error('Method 2 point add inputs must be affine')
  }
  if (!isOnCurve(left) || !isOnCurve(right)) {
    throw new Error('Method 2 point add inputs must be valid curve points')
  }
  const diffX = modP(right.x - left.x)
  if (diffX === 0n) {
    throw new Error('Method 2 distinct point add requires different x coordinates')
  }
  const output = pointAdd(left, right)
  if (output.infinity === true || !isOnCurve(output)) {
    throw new Error('Method 2 point add output must be affine')
  }

  const diffY = modP(right.y - left.y)
  const diffXInverse = modInvP(diffX)
  const slope = modP(diffY * diffXInverse)
  const slopeSquared = modP(slope * slope)
  const sumX = modP(left.x + right.x)
  const leftXMinusOutputX = modP(left.x - output.x)
  const lambdaDiff = modP(slope * leftXMinusOutputX)

  writeMethod2PointWitness(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left, left)
  writeMethod2PointWitness(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.right, right)
  writeMethod2PointWitness(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.output, output)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.one, 1n)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffX, diffX)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffY, diffY)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverse, diffXInverse)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope, slope)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquared, slopeSquared)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumX, sumX)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputX, leftXMinusOutputX)
  writeMethod2FieldElement(row, offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiff, lambdaDiff)
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXAdd,
    left.x,
    diffX,
    right.x
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffYAdd,
    left.y,
    diffY,
    right.y
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverseMul,
    diffX,
    diffXInverse,
    1n
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeMul,
    diffX,
    slope,
    diffY
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquareMul,
    slope,
    slope,
    slopeSquared
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumXAdd,
    left.x,
    right.x,
    sumX
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.outputXAdd,
    output.x,
    sumX,
    slopeSquared
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputXAdd,
    output.x,
    leftXMinusOutputX,
    left.x
  )
  writeMethod2FieldMulWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiffMul,
    slope,
    leftXMinusOutputX,
    lambdaDiff
  )
  writeMethod2FieldAddWitness(
    row,
    offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.outputYAdd,
    output.y,
    left.y,
    lambdaDiff
  )
  return output
}

export function evaluateMethod2PointAddDistinctConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return [
    ...evaluateMethod2PointConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left
    ),
    ...evaluateMethod2PointConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.right
    ),
    ...evaluateMethod2PointConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.output
    ),
    ...evaluateFieldValueConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.one,
      1n
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffX
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffY
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverse
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumX
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputX
    ),
    ...evaluateMethod2FieldElementConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.right + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffYAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffY,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.right + METHOD2_POINT_LAYOUT.y
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverseMul,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffXInverse,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.one
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeMul,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.diffY
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquareMul,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumXAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.right + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumX
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.outputXAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.output + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.sumX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputXAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.output + METHOD2_POINT_LAYOUT.x,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiffMul,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.slope,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.leftXMinusOutputX,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.outputYAdd,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.output + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.left + METHOD2_POINT_LAYOUT.y,
      offset + METHOD2_POINT_ADD_DISTINCT_LAYOUT.lambdaDiff
    )
  ]
}

function evaluateFieldValueConstraints (
  row: FieldElement[],
  offset: number,
  expected: bigint
): FieldElement[] {
  const constraints = evaluateMethod2FieldElementConstraints(row, offset)
  const limbs = bigintToU16LimbsLE(expected, METHOD2_FIELD_LIMB_COUNT)
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    constraints.push(F.sub(
      fieldLimb(row, offset, limb),
      BigInt(limbs[limb])
    ))
  }
  return constraints
}
