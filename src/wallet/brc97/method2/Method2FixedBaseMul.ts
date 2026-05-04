import { AirDefinition, FieldElement, F } from '../stark/index.js'
import {
  SECP256K1_G,
  SECP256K1_P,
  isOnCurve,
  modInvP,
  modP,
  pointAdd,
  pointDouble,
  scalarMultiply,
  validateScalar
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  METHOD2_SCALAR_LAYOUT,
  evaluateMethod2ScalarConstraints,
  writeMethod2ScalarWitness
} from './Method2Scalar.js'
import {
  METHOD2_FIELD_ADD_LAYOUT,
  METHOD2_FIELD_LAYOUT,
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

export const METHOD2_FIXED_BASE_MUL_BITS = 256

interface Method2PointAddRelationLayout {
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

interface Method2PointDoubleRelationLayout {
  one: number
  twoY: number
  twoYInverse: number
  twoX2: number
  threeX2: number
  slope: number
  slopeSquared: number
  twoX: number
  leftXMinusOutputX: number
  lambdaDiff: number
  twoYAdd: number
  twoYInverseMul: number
  twoX2Add: number
  threeX2Add: number
  slopeNumeratorMul: number
  slopeSquareMul: number
  twoXAdd: number
  outputXAdd: number
  leftXMinusOutputXAdd: number
  lambdaDiffMul: number
  outputYAdd: number
  width: number
}

export interface Method2FixedBaseMulLayout {
  activeBits: number
  scalar: number
  bitSelectors: number
  scalarBit: number
  decrementedBit: number
  borrowIn: number
  borrowOut: number
  addSelector: number
  doubleSelector: number
  left: number
  right: number
  output: number
  relation: number
  width: number
}

const ADD_RELATION_FIELD_START = 0
const ADD_RELATION_RELATION_START = METHOD2_FIELD_LAYOUT.width * 9

const ADD_RELATION_LAYOUT: Method2PointAddRelationLayout = {
  one: ADD_RELATION_FIELD_START,
  diffX: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width,
  diffY: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 2,
  diffXInverse: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 3,
  slope: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 4,
  slopeSquared: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 5,
  sumX: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 6,
  leftXMinusOutputX: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 7,
  lambdaDiff: ADD_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 8,
  diffXAdd: ADD_RELATION_RELATION_START,
  diffYAdd: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width,
  diffXInverseMul: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2,
  slopeMul: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeSquareMul: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width * 2,
  sumXAdd: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputXAdd: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  leftXMinusOutputXAdd: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 4 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  lambdaDiffMul: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputYAdd: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 4,
  width: ADD_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 4
}

const DOUBLE_RELATION_FIELD_START = 0
const DOUBLE_RELATION_RELATION_START = METHOD2_FIELD_LAYOUT.width * 10

const DOUBLE_RELATION_LAYOUT: Method2PointDoubleRelationLayout = {
  one: DOUBLE_RELATION_FIELD_START,
  twoY: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width,
  twoYInverse: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 2,
  twoX2: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 3,
  threeX2: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 4,
  slope: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 5,
  slopeSquared: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 6,
  twoX: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 7,
  leftXMinusOutputX: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 8,
  lambdaDiff: DOUBLE_RELATION_FIELD_START + METHOD2_FIELD_LAYOUT.width * 9,
  twoYAdd: DOUBLE_RELATION_RELATION_START,
  twoYInverseMul: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width,
  twoX2Add: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width + METHOD2_FIELD_MUL_LAYOUT.width,
  threeX2Add: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 2 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeNumeratorMul: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width,
  slopeSquareMul: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 2,
  twoXAdd: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 3 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputXAdd: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 4 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  leftXMinusOutputXAdd: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 5 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  lambdaDiffMul: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 3,
  outputYAdd: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 6 + METHOD2_FIELD_MUL_LAYOUT.width * 4,
  width: DOUBLE_RELATION_RELATION_START + METHOD2_FIELD_ADD_LAYOUT.width * 7 + METHOD2_FIELD_MUL_LAYOUT.width * 4
}

const RELATION_WIDTH = Math.max(
  ADD_RELATION_LAYOUT.width,
  DOUBLE_RELATION_LAYOUT.width
)

export const METHOD2_FIXED_BASE_MUL_LAYOUT =
  method2FixedBaseMulLayout(METHOD2_FIXED_BASE_MUL_BITS)

export interface Method2FixedBaseMulTrace {
  traceRows: FieldElement[][]
  output: SecpPoint
  activeBits: number
  layout: Method2FixedBaseMulLayout
}

export function method2FixedBaseMulLayout (
  activeBits = METHOD2_FIXED_BASE_MUL_BITS
): Method2FixedBaseMulLayout {
  if (!Number.isInteger(activeBits) || activeBits < 1 || activeBits > 256) {
    throw new Error('Fixed-base scalar multiplication bit count is invalid')
  }
  const scalarBit = METHOD2_SCALAR_LAYOUT.width + activeBits
  return {
    activeBits,
    scalar: 0,
    bitSelectors: METHOD2_SCALAR_LAYOUT.width,
    scalarBit,
    decrementedBit: scalarBit + 1,
    borrowIn: scalarBit + 2,
    borrowOut: scalarBit + 3,
    addSelector: scalarBit + 4,
    doubleSelector: scalarBit + 5,
    left: scalarBit + 6,
    right: scalarBit + 6 + METHOD2_POINT_LAYOUT.width,
    output: scalarBit + 6 + METHOD2_POINT_LAYOUT.width * 2,
    relation: scalarBit + 6 + METHOD2_POINT_LAYOUT.width * 3,
    width: scalarBit + 6 + METHOD2_POINT_LAYOUT.width * 3 + RELATION_WIDTH
  }
}

export function buildMethod2FixedBaseMulTrace (
  scalar: bigint,
  activeBits = METHOD2_FIXED_BASE_MUL_BITS
): Method2FixedBaseMulTrace {
  return buildMethod2BaseMulTrace(scalar, SECP256K1_G, activeBits)
}

export function buildMethod2BaseMulTrace (
  scalar: bigint,
  basePoint: SecpPoint,
  activeBits = METHOD2_FIXED_BASE_MUL_BITS
): Method2FixedBaseMulTrace {
  validateFixedBaseMulInputs(scalar, activeBits)
  validateBasePoint(basePoint)
  const layout = method2FixedBaseMulLayout(activeBits)
  const traceLength = nextPowerOfTwo(activeBits + 1)
  const traceRows = new Array<FieldElement[]>(traceLength)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  let accumulator = basePoint
  let base = basePoint
  let borrowIn = 1n
  const decremented = scalar - 1n

  for (let bit = 0; bit < activeBits; bit++) {
    const row = traceRows[bit]
    const scalarBit = (scalar >> BigInt(bit)) & 1n
    const decrementedBit = (decremented >> BigInt(bit)) & 1n
    const borrowOut = (decrementedBit + borrowIn - scalarBit) / 2n
    if (scalarBit - borrowIn - decrementedBit + borrowOut * 2n !== 0n) {
      throw new Error('Invalid fixed-base scalar decrement witness')
    }

    row[layout.bitSelectors + bit] = 1n
    row[layout.scalarBit] = scalarBit
    row[layout.decrementedBit] = decrementedBit
    row[layout.borrowIn] = borrowIn
    row[layout.borrowOut] = borrowOut
    writeMethod2ScalarWitness(row, layout.scalar, scalar)
    writeMethod2PointWitness(row, layout.left, accumulator)
    writeMethod2PointWitness(row, layout.right, base)

    if (decrementedBit === 0n) {
      writeMethod2PointWitness(row, layout.output, accumulator)
    } else if (pointsEqual(accumulator, base)) {
      row[layout.doubleSelector] = 1n
      accumulator = pointDouble(accumulator)
      writeMethod2PointWitness(row, layout.output, accumulator)
      writeDoubleRelation(row, layout.relation, base)
    } else {
      row[layout.addSelector] = 1n
      const previous = accumulator
      accumulator = pointAdd(accumulator, base)
      if (accumulator.infinity === true || !isOnCurve(accumulator)) {
        throw new Error('Fixed-base scalar multiplication produced infinity')
      }
      writeMethod2PointWitness(row, layout.output, accumulator)
      writeAddRelation(row, layout.relation, previous, base, accumulator)
    }

    borrowIn = borrowOut
    base = pointDouble(base)
    if (base.infinity === true || !isOnCurve(base)) {
      throw new Error('Fixed-base scalar multiplication base reached infinity')
    }
  }

  if (!pointsEqual(accumulator, scalarMultiply(scalar, basePoint))) {
    throw new Error('Fixed-base scalar multiplication witness mismatch')
  }

  return {
    traceRows,
    output: accumulator,
    activeBits,
    layout
  }
}

export function buildMethod2FixedBaseMulAir (
  expectedOutput: SecpPoint,
  activeBits = METHOD2_FIXED_BASE_MUL_BITS
): AirDefinition {
  return buildMethod2BaseMulAir(SECP256K1_G, expectedOutput, activeBits)
}

export function buildMethod2BaseMulAir (
  basePoint: SecpPoint,
  expectedOutput: SecpPoint | undefined,
  activeBits = METHOD2_FIXED_BASE_MUL_BITS
): AirDefinition {
  validateBasePoint(basePoint)
  if (
    expectedOutput !== undefined &&
    (expectedOutput.infinity === true || !isOnCurve(expectedOutput))
  ) {
    throw new Error('Fixed-base scalar multiplication output must be affine')
  }
  const layout = method2FixedBaseMulLayout(activeBits)
  const boundaryConstraints = [
    ...method2BaseMulPointBoundaryConstraints(0, layout.left, basePoint),
    { column: layout.bitSelectors, row: 0, value: 1n },
    { column: layout.borrowIn, row: 0, value: 1n },
    { column: layout.borrowOut, row: activeBits - 1, value: 0n },
    ...method2BaseMulZeroBoundaryConstraints(
      0,
      layout.bitSelectors + 1,
      activeBits - 1
    ),
    ...method2BaseMulZeroBoundaryConstraints(
      0,
      layout.scalar + METHOD2_SCALAR_LAYOUT.bits + activeBits,
      256 - activeBits
    ),
    ...baseBoundaryConstraints(layout, basePoint)
  ]
  if (expectedOutput !== undefined) {
    boundaryConstraints.push(...method2BaseMulPointBoundaryConstraints(
      activeBits - 1,
      layout.output,
      expectedOutput
    ))
  }
  return {
    traceWidth: layout.width,
    transitionDegree: 6,
    boundaryConstraints,
    evaluateTransition: (current, next) => evaluateMethod2BaseMulTransition(
      current,
      next,
      layout
    )
  }
}

export function evaluateMethod2BaseMulTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2FixedBaseMulLayout
): FieldElement[] {
  const active = selectorSum(current, layout)
  const nextActive = selectorSum(next, layout)
  const decrementedBit = current[layout.decrementedBit]
  const copySelector = F.sub(active, decrementedBit)
  const addSelector = current[layout.addSelector]
  const doubleSelector = current[layout.doubleSelector]
  const resetSelector = F.mul(
    current[layout.bitSelectors + layout.activeBits - 1],
    next[layout.bitSelectors]
  )
  const continueSelector = F.sub(nextActive, resetSelector)
  const constraints: FieldElement[] = []

  constraints.push(...evaluateSelectorConstraints(current, next, layout))
  constraints.push(booleanConstraint(current[layout.scalarBit]))
  constraints.push(booleanConstraint(decrementedBit))
  constraints.push(booleanConstraint(current[layout.borrowIn]))
  constraints.push(booleanConstraint(current[layout.borrowOut]))
  constraints.push(booleanConstraint(addSelector))
  constraints.push(booleanConstraint(doubleSelector))
  constraints.push(F.sub(
    current[layout.scalarBit],
    selectedScalarBit(current, layout)
  ))
  constraints.push(F.add(
    F.sub(F.sub(current[layout.scalarBit], current[layout.borrowIn]), decrementedBit),
    F.mul(2n, current[layout.borrowOut])
  ))
  constraints.push(F.sub(decrementedBit, F.add(addSelector, doubleSelector)))
  constraints.push(F.mul(
    F.sub(1n, resetSelector),
    F.sub(current[layout.borrowOut], next[layout.borrowIn])
  ))

  constraints.push(...gateConstraints(
    evaluateMethod2ScalarConstraints(current, layout.scalar),
    active
  ))
  constraints.push(...gateConstraints(
    evaluateMethod2PointConstraints(current, layout.left),
    active
  ))
  constraints.push(...gateConstraints(
    evaluateMethod2PointConstraints(current, layout.right),
    active
  ))
  constraints.push(...gateConstraints(
    evaluateMethod2PointConstraints(current, layout.output),
    active
  ))
  constraints.push(...gateConstraints(
    evaluateAddRelationConstraints(current, layout.relation, layout),
    addSelector
  ))
  constraints.push(...gateConstraints(
    evaluateDoubleRelationConstraints(current, layout.relation, layout),
    doubleSelector
  ))
  constraints.push(...gateConstraints(
    pointEqualityConstraints(current, layout.left, current, layout.output),
    copySelector
  ))
  constraints.push(...gateConstraints(
    pointEqualityConstraints(current, layout.left, current, layout.right),
    doubleSelector
  ))
  constraints.push(...gateConstraints(
    pointEqualityConstraints(current, layout.output, next, layout.left),
    continueSelector
  ))
  constraints.push(...gateConstraints(
    copyRangeConstraints(
      current,
      layout.scalar,
      next,
      layout.scalar,
      METHOD2_SCALAR_LAYOUT.width
    ),
    nextActive
  ))
  return constraints
}

function evaluateSelectorConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2FixedBaseMulLayout
): FieldElement[] {
  const constraints: FieldElement[] = []
  const active = selectorSum(current, layout)
  const lastSelector = current[layout.bitSelectors + layout.activeBits - 1]
  constraints.push(booleanConstraint(active))
  constraints.push(F.mul(
    next[layout.bitSelectors],
    F.sub(next[layout.bitSelectors], lastSelector)
  ))
  for (let bit = 0; bit < layout.activeBits; bit++) {
    const selector = current[layout.bitSelectors + bit]
    constraints.push(booleanConstraint(selector))
    if (bit > 0) {
      constraints.push(F.mul(lastSelector, next[layout.bitSelectors + bit]))
    }
    if (bit < layout.activeBits - 1) {
      constraints.push(F.sub(
        next[layout.bitSelectors + bit + 1],
        selector
      ))
    }
  }
  return constraints
}

function writeAddRelation (
  row: FieldElement[],
  offset: number,
  left: SecpPoint,
  right: SecpPoint,
  output: SecpPoint
): void {
  const diffX = modP(right.x - left.x)
  if (diffX === 0n) {
    throw new Error('Fixed-base add relation requires distinct x coordinates')
  }
  const diffY = modP(right.y - left.y)
  const diffXInverse = modInvP(diffX)
  const slope = modP(diffY * diffXInverse)
  const slopeSquared = modP(slope * slope)
  const sumX = modP(left.x + right.x)
  const leftXMinusOutputX = modP(left.x - output.x)
  const lambdaDiff = modP(slope * leftXMinusOutputX)

  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.one, 1n)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.diffX, diffX)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.diffY, diffY)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.diffXInverse, diffXInverse)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.slope, slope)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.slopeSquared, slopeSquared)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.sumX, sumX)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.leftXMinusOutputX, leftXMinusOutputX)
  writeMethod2FieldElement(row, offset + ADD_RELATION_LAYOUT.lambdaDiff, lambdaDiff)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.diffXAdd, left.x, diffX, right.x)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.diffYAdd, left.y, diffY, right.y)
  writeMethod2FieldMulWitness(row, offset + ADD_RELATION_LAYOUT.diffXInverseMul, diffX, diffXInverse, 1n)
  writeMethod2FieldMulWitness(row, offset + ADD_RELATION_LAYOUT.slopeMul, diffX, slope, diffY)
  writeMethod2FieldMulWitness(row, offset + ADD_RELATION_LAYOUT.slopeSquareMul, slope, slope, slopeSquared)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.sumXAdd, left.x, right.x, sumX)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.outputXAdd, output.x, sumX, slopeSquared)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.leftXMinusOutputXAdd, output.x, leftXMinusOutputX, left.x)
  writeMethod2FieldMulWitness(row, offset + ADD_RELATION_LAYOUT.lambdaDiffMul, slope, leftXMinusOutputX, lambdaDiff)
  writeMethod2FieldAddWitness(row, offset + ADD_RELATION_LAYOUT.outputYAdd, output.y, left.y, lambdaDiff)
}

function evaluateAddRelationConstraints (
  row: FieldElement[],
  offset: number,
  layout: Method2FixedBaseMulLayout
): FieldElement[] {
  return [
    ...evaluateFieldOneConstraints(row, offset + ADD_RELATION_LAYOUT.one),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.diffX),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.diffY),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.diffXInverse),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.slope),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.slopeSquared),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.sumX),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.leftXMinusOutputX),
    ...evaluateMethod2FieldElementConstraints(row, offset + ADD_RELATION_LAYOUT.lambdaDiff),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.diffXAdd,
      layout.left + METHOD2_POINT_LAYOUT.x,
      offset + ADD_RELATION_LAYOUT.diffX,
      layout.right + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.diffYAdd,
      layout.left + METHOD2_POINT_LAYOUT.y,
      offset + ADD_RELATION_LAYOUT.diffY,
      layout.right + METHOD2_POINT_LAYOUT.y
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.diffXInverseMul,
      offset + ADD_RELATION_LAYOUT.diffX,
      offset + ADD_RELATION_LAYOUT.diffXInverse,
      offset + ADD_RELATION_LAYOUT.one
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.slopeMul,
      offset + ADD_RELATION_LAYOUT.diffX,
      offset + ADD_RELATION_LAYOUT.slope,
      offset + ADD_RELATION_LAYOUT.diffY
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.slopeSquareMul,
      offset + ADD_RELATION_LAYOUT.slope,
      offset + ADD_RELATION_LAYOUT.slope,
      offset + ADD_RELATION_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.sumXAdd,
      layout.left + METHOD2_POINT_LAYOUT.x,
      layout.right + METHOD2_POINT_LAYOUT.x,
      offset + ADD_RELATION_LAYOUT.sumX
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.outputXAdd,
      layout.output + METHOD2_POINT_LAYOUT.x,
      offset + ADD_RELATION_LAYOUT.sumX,
      offset + ADD_RELATION_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.leftXMinusOutputXAdd,
      layout.output + METHOD2_POINT_LAYOUT.x,
      offset + ADD_RELATION_LAYOUT.leftXMinusOutputX,
      layout.left + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.lambdaDiffMul,
      offset + ADD_RELATION_LAYOUT.slope,
      offset + ADD_RELATION_LAYOUT.leftXMinusOutputX,
      offset + ADD_RELATION_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + ADD_RELATION_LAYOUT.outputYAdd,
      layout.output + METHOD2_POINT_LAYOUT.y,
      layout.left + METHOD2_POINT_LAYOUT.y,
      offset + ADD_RELATION_LAYOUT.lambdaDiff
    )
  ]
}

function writeDoubleRelation (
  row: FieldElement[],
  offset: number,
  input: SecpPoint
): void {
  const output = pointDouble(input)
  if (output.infinity === true || !isOnCurve(output)) {
    throw new Error('Fixed-base double relation output must be affine')
  }
  const twoY = modP(input.y + input.y)
  const twoYInverse = modInvP(twoY)
  const x2 = modP(input.x * input.x)
  const twoX2 = modP(x2 + x2)
  const threeX2 = modP(twoX2 + x2)
  const slope = modP(threeX2 * twoYInverse)
  const slopeSquared = modP(slope * slope)
  const twoX = modP(input.x + input.x)
  const leftXMinusOutputX = modP(input.x - output.x)
  const lambdaDiff = modP(slope * leftXMinusOutputX)

  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.one, 1n)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.twoY, twoY)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.twoYInverse, twoYInverse)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.twoX2, twoX2)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.threeX2, threeX2)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.slope, slope)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.slopeSquared, slopeSquared)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.twoX, twoX)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputX, leftXMinusOutputX)
  writeMethod2FieldElement(row, offset + DOUBLE_RELATION_LAYOUT.lambdaDiff, lambdaDiff)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.twoYAdd, input.y, input.y, twoY)
  writeMethod2FieldMulWitness(row, offset + DOUBLE_RELATION_LAYOUT.twoYInverseMul, twoY, twoYInverse, 1n)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.twoX2Add, x2, x2, twoX2)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.threeX2Add, twoX2, x2, threeX2)
  writeMethod2FieldMulWitness(row, offset + DOUBLE_RELATION_LAYOUT.slopeNumeratorMul, slope, twoY, threeX2)
  writeMethod2FieldMulWitness(row, offset + DOUBLE_RELATION_LAYOUT.slopeSquareMul, slope, slope, slopeSquared)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.twoXAdd, input.x, input.x, twoX)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.outputXAdd, output.x, twoX, slopeSquared)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputXAdd, output.x, leftXMinusOutputX, input.x)
  writeMethod2FieldMulWitness(row, offset + DOUBLE_RELATION_LAYOUT.lambdaDiffMul, slope, leftXMinusOutputX, lambdaDiff)
  writeMethod2FieldAddWitness(row, offset + DOUBLE_RELATION_LAYOUT.outputYAdd, output.y, input.y, lambdaDiff)
}

function evaluateDoubleRelationConstraints (
  row: FieldElement[],
  offset: number,
  layout: Method2FixedBaseMulLayout
): FieldElement[] {
  return [
    ...evaluateFieldOneConstraints(row, offset + DOUBLE_RELATION_LAYOUT.one),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.twoY),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.twoYInverse),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.twoX2),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.threeX2),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.slope),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.slopeSquared),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.twoX),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputX),
    ...evaluateMethod2FieldElementConstraints(row, offset + DOUBLE_RELATION_LAYOUT.lambdaDiff),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.twoYAdd,
      layout.left + METHOD2_POINT_LAYOUT.y,
      layout.left + METHOD2_POINT_LAYOUT.y,
      offset + DOUBLE_RELATION_LAYOUT.twoY
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.twoYInverseMul,
      offset + DOUBLE_RELATION_LAYOUT.twoY,
      offset + DOUBLE_RELATION_LAYOUT.twoYInverse,
      offset + DOUBLE_RELATION_LAYOUT.one
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.twoX2Add,
      layout.left + METHOD2_POINT_LAYOUT.x2,
      layout.left + METHOD2_POINT_LAYOUT.x2,
      offset + DOUBLE_RELATION_LAYOUT.twoX2
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.threeX2Add,
      offset + DOUBLE_RELATION_LAYOUT.twoX2,
      layout.left + METHOD2_POINT_LAYOUT.x2,
      offset + DOUBLE_RELATION_LAYOUT.threeX2
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.slopeNumeratorMul,
      offset + DOUBLE_RELATION_LAYOUT.slope,
      offset + DOUBLE_RELATION_LAYOUT.twoY,
      offset + DOUBLE_RELATION_LAYOUT.threeX2
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.slopeSquareMul,
      offset + DOUBLE_RELATION_LAYOUT.slope,
      offset + DOUBLE_RELATION_LAYOUT.slope,
      offset + DOUBLE_RELATION_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.twoXAdd,
      layout.left + METHOD2_POINT_LAYOUT.x,
      layout.left + METHOD2_POINT_LAYOUT.x,
      offset + DOUBLE_RELATION_LAYOUT.twoX
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.outputXAdd,
      layout.output + METHOD2_POINT_LAYOUT.x,
      offset + DOUBLE_RELATION_LAYOUT.twoX,
      offset + DOUBLE_RELATION_LAYOUT.slopeSquared
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputXAdd,
      layout.output + METHOD2_POINT_LAYOUT.x,
      offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputX,
      layout.left + METHOD2_POINT_LAYOUT.x
    ),
    ...evaluateMethod2FieldMulConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.lambdaDiffMul,
      offset + DOUBLE_RELATION_LAYOUT.slope,
      offset + DOUBLE_RELATION_LAYOUT.leftXMinusOutputX,
      offset + DOUBLE_RELATION_LAYOUT.lambdaDiff
    ),
    ...evaluateMethod2FieldAddConstraints(
      row,
      offset + DOUBLE_RELATION_LAYOUT.outputYAdd,
      layout.output + METHOD2_POINT_LAYOUT.y,
      layout.left + METHOD2_POINT_LAYOUT.y,
      offset + DOUBLE_RELATION_LAYOUT.lambdaDiff
    )
  ]
}

function selectedScalarBit (
  row: FieldElement[],
  layout: Method2FixedBaseMulLayout
): FieldElement {
  let selected = 0n
  for (let bit = 0; bit < layout.activeBits; bit++) {
    selected = F.add(
      selected,
      F.mul(
        row[layout.bitSelectors + bit],
        row[layout.scalar + METHOD2_SCALAR_LAYOUT.bits + bit]
      )
    )
  }
  return selected
}

function selectorSum (
  row: FieldElement[],
  layout: Method2FixedBaseMulLayout
): FieldElement {
  let sum = 0n
  for (let bit = 0; bit < layout.activeBits; bit++) {
    sum = F.add(sum, row[layout.bitSelectors + bit])
  }
  return sum
}

function validateFixedBaseMulInputs (
  scalar: bigint,
  activeBits: number
): void {
  validateScalar(scalar)
  if (!Number.isInteger(activeBits) || activeBits < 1 || activeBits > 256) {
    throw new Error('Fixed-base scalar multiplication bit count is invalid')
  }
  if (activeBits < 256 && scalar >= (1n << BigInt(activeBits))) {
    throw new Error('Scalar does not fit in the requested active bit count')
  }
}

function validateBasePoint (point: SecpPoint): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('Base scalar multiplication point must be affine')
  }
}

function baseBoundaryConstraints (
  layout: Method2FixedBaseMulLayout,
  basePoint: SecpPoint
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  let base = basePoint
  for (let bit = 0; bit < layout.activeBits; bit++) {
    constraints.push(...method2BaseMulPointBoundaryConstraints(
      bit,
      layout.right,
      base
    ))
    base = pointDouble(base)
    if (base.infinity === true || !isOnCurve(base)) {
      throw new Error('Fixed-base boundary base reached infinity')
    }
  }
  return constraints
}

export function method2BaseMulPointBoundaryConstraints (
  row: number,
  offset: number,
  point: SecpPoint
): Array<{ column: number, row: number, value: FieldElement }> {
  return [
    ...fieldBoundaryConstraints(row, offset + METHOD2_POINT_LAYOUT.x, point.x),
    ...fieldBoundaryConstraints(row, offset + METHOD2_POINT_LAYOUT.y, point.y)
  ]
}

function fieldBoundaryConstraints (
  row: number,
  offset: number,
  value: bigint
): Array<{ column: number, row: number, value: FieldElement }> {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Fixed-base boundary field value out of range')
  }
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  for (let limb = 0; limb < 16; limb++) {
    constraints.push({
      column: offset + METHOD2_FIELD_LAYOUT.limbs + limb,
      row,
      value: fieldLimbFromBigint(value, limb)
    })
  }
  return constraints
}

export function method2BaseMulZeroBoundaryConstraints (
  row: number,
  offset: number,
  count: number
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  for (let i = 0; i < count; i++) {
    constraints.push({
      column: offset + i,
      row,
      value: 0n
    })
  }
  return constraints
}

function fieldLimbFromBigint (
  value: bigint,
  limb: number
): FieldElement {
  return (value >> BigInt(limb * 16)) & 0xffffn
}

function pointEqualityConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number
): FieldElement[] {
  return [
    ...fieldEqualityConstraints(
      leftRow,
      leftOffset + METHOD2_POINT_LAYOUT.x,
      rightRow,
      rightOffset + METHOD2_POINT_LAYOUT.x
    ),
    ...fieldEqualityConstraints(
      leftRow,
      leftOffset + METHOD2_POINT_LAYOUT.y,
      rightRow,
      rightOffset + METHOD2_POINT_LAYOUT.y
    )
  ]
}

function fieldEqualityConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let limb = 0; limb < 16; limb++) {
    constraints.push(F.sub(
      fieldLimb(leftRow, leftOffset, limb),
      fieldLimb(rightRow, rightOffset, limb)
    ))
  }
  return constraints
}

function copyRangeConstraints (
  leftRow: FieldElement[],
  leftOffset: number,
  rightRow: FieldElement[],
  rightOffset: number,
  width: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let i = 0; i < width; i++) {
    constraints.push(F.sub(leftRow[leftOffset + i], rightRow[rightOffset + i]))
  }
  return constraints
}

function evaluateFieldOneConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  const constraints = evaluateMethod2FieldElementConstraints(row, offset)
  constraints.push(F.sub(fieldLimb(row, offset, 0), 1n))
  for (let limb = 1; limb < 16; limb++) {
    constraints.push(fieldLimb(row, offset, limb))
  }
  return constraints
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

function pointsEqual (
  left: SecpPoint,
  right: SecpPoint
): boolean {
  return left.infinity === right.infinity &&
    left.x === right.x &&
    left.y === right.y
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
