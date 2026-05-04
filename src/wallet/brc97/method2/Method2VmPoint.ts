import { SecpPoint } from '../circuit/Types.js'
import {
  bigintToU16LimbsLE,
  compressPoint,
  isOnCurve,
  modInvP,
  modP,
  pointAdd,
  pointDouble
} from '../circuit/index.js'
import { Method2VmBuilder } from './Method2Vm.js'
import {
  appendMethod2VmFieldAdd,
  appendMethod2VmFieldElementWithLinkedLimbs,
  appendMethod2VmFieldMul,
  appendMethod2VmFieldSub
} from './Method2VmField.js'

export interface Method2VmPointWitness {
  point: SecpPoint
  compressed: number[]
}

export function appendMethod2VmPoint (
  builder: Method2VmBuilder,
  point: SecpPoint
): Method2VmPointWitness {
  return appendMethod2VmPointWithLinkedLimbs(builder, point)
}

export function appendMethod2VmPointWithLinkedLimbs (
  builder: Method2VmBuilder,
  point: SecpPoint,
  linkLimb?: (limb: number, value: number, destination: 'a' | 'b' | 'c') => void
): Method2VmPointWitness {
  assertAffinePoint(point, 'Method 2 VM point')
  const x2 = modP(point.x * point.x)
  const x3 = modP(x2 * point.x)
  const y2 = modP(point.y * point.y)

  appendMethod2VmFieldElementWithLinkedLimbs(
    builder,
    point.x,
    (limb, value) => linkLimb?.(limb, value, 'a')
  )
  appendMethod2VmFieldElementWithLinkedLimbs(
    builder,
    point.y,
    (limb, value) => linkLimb?.(16 + limb, value, 'a')
  )
  appendMethod2VmFieldMul(builder, point.x, point.x, x2)
  appendMethod2VmFieldMul(builder, x2, point.x, x3)
  appendMethod2VmFieldMul(builder, point.y, point.y, y2)
  appendMethod2VmFieldAdd(builder, x3, 7n, y2)

  return {
    point,
    compressed: compressPoint(point)
  }
}

export function appendMethod2VmCompressedPoint (
  builder: Method2VmBuilder,
  point: SecpPoint
): number[] {
  return appendMethod2VmCompressedPointWithLinkedLimbs(builder, point)
}

export function appendMethod2VmCompressedPointWithLinkedLimbs (
  builder: Method2VmBuilder,
  point: SecpPoint,
  linkLimb?: (limb: number, value: number, destination: 'a' | 'b' | 'c') => void,
  linkByte?: (byteIndex: number, value: number) => void
): number[] {
  appendMethod2VmPointWithLinkedLimbs(builder, point, linkLimb)
  const compressed = compressPoint(point)
  const xLimbs = bigintToU16LimbsLE(point.x, 16)
  const yLimbs = bigintToU16LimbsLE(point.y, 16)
  const yParity = Number(point.y & 1n)
  const yHalf = (yLimbs[0] - yParity) / 2
  const twoYHalf = yHalf * 2

  builder.assertByte(compressed[0])
  builder.assertBool(yParity as 0 | 1)
  builder.assertU16(yHalf)
  builder.assertMul(yHalf, 2, twoYHalf)
  linkLimb?.(16, yLimbs[0], 'c')
  builder.assertAdd(yParity, twoYHalf, yLimbs[0])
  if (linkByte !== undefined) {
    builder.assertAddLinked(2, yParity, compressed[0], 'a')
    linkByte(0, compressed[0])
  } else {
    builder.assertAdd(2, yParity, compressed[0])
  }
  for (let limb = xLimbs.length - 1; limb >= 0; limb--) {
    const lowByte = compressed[1 + 31 - limb * 2]
    const highByte = compressed[1 + 30 - limb * 2]
    const highShifted = highByte * 256
    builder.assertByte(lowByte)
    builder.assertByte(highByte)
    if (linkByte !== undefined) {
      builder.assertEqLinked(highByte, highByte, 'a')
      linkByte(1 + 30 - limb * 2, highByte)
      builder.assertEqLinked(lowByte, lowByte, 'a')
      linkByte(1 + 31 - limb * 2, lowByte)
    }
    builder.assertMul(highByte, 256, highShifted)
    linkLimb?.(limb, xLimbs[limb], 'c')
    builder.assertAdd(lowByte, highShifted, xLimbs[limb])
  }

  return compressed
}

export function appendMethod2VmPointDouble (
  builder: Method2VmBuilder,
  input: SecpPoint
): SecpPoint {
  assertAffinePoint(input, 'Method 2 VM point double input')
  const twoY = modP(input.y + input.y)
  if (twoY === 0n) {
    throw new Error('Method 2 VM point double input must have nonzero 2y')
  }
  const output = pointDouble(input)
  assertAffinePoint(output, 'Method 2 VM point double output')

  const twoYInverse = modInvP(twoY)
  const x2 = modP(input.x * input.x)
  const twoX2 = modP(x2 + x2)
  const threeX2 = modP(twoX2 + x2)
  const slope = modP(threeX2 * twoYInverse)
  const slopeSquared = modP(slope * slope)
  const twoX = modP(input.x + input.x)
  const inputXMinusOutputX = modP(input.x - output.x)
  const lambdaDiff = modP(slope * inputXMinusOutputX)

  appendMethod2VmPoint(builder, input)
  appendMethod2VmPoint(builder, output)
  appendMethod2VmFieldAdd(builder, input.y, input.y, twoY)
  appendMethod2VmFieldMul(builder, twoY, twoYInverse, 1n)
  appendMethod2VmFieldMul(builder, input.x, input.x, x2)
  appendMethod2VmFieldAdd(builder, x2, x2, twoX2)
  appendMethod2VmFieldAdd(builder, twoX2, x2, threeX2)
  appendMethod2VmFieldMul(builder, slope, twoY, threeX2)
  appendMethod2VmFieldMul(builder, slope, slope, slopeSquared)
  appendMethod2VmFieldAdd(builder, input.x, input.x, twoX)
  appendMethod2VmFieldAdd(builder, output.x, twoX, slopeSquared)
  appendMethod2VmFieldSub(builder, input.x, output.x, inputXMinusOutputX)
  appendMethod2VmFieldMul(builder, slope, inputXMinusOutputX, lambdaDiff)
  appendMethod2VmFieldAdd(builder, output.y, input.y, lambdaDiff)

  return output
}

export function appendMethod2VmPointAddDistinct (
  builder: Method2VmBuilder,
  left: SecpPoint,
  right: SecpPoint
): SecpPoint {
  assertAffinePoint(left, 'Method 2 VM point add left input')
  assertAffinePoint(right, 'Method 2 VM point add right input')
  if (left.x === right.x) {
    throw new Error('Method 2 VM distinct point add requires different x coordinates')
  }
  const output = pointAdd(left, right)
  assertAffinePoint(output, 'Method 2 VM point add output')

  const diffX = modP(right.x - left.x)
  const diffY = modP(right.y - left.y)
  const diffXInverse = modInvP(diffX)
  const slope = modP(diffY * diffXInverse)
  const slopeSquared = modP(slope * slope)
  const sumX = modP(left.x + right.x)
  const leftXMinusOutputX = modP(left.x - output.x)
  const lambdaDiff = modP(slope * leftXMinusOutputX)

  appendMethod2VmPoint(builder, left)
  appendMethod2VmPoint(builder, right)
  appendMethod2VmPoint(builder, output)
  appendMethod2VmFieldSub(builder, right.x, left.x, diffX)
  appendMethod2VmFieldSub(builder, right.y, left.y, diffY)
  appendMethod2VmFieldMul(builder, diffX, diffXInverse, 1n)
  appendMethod2VmFieldMul(builder, slope, diffX, diffY)
  appendMethod2VmFieldMul(builder, slope, slope, slopeSquared)
  appendMethod2VmFieldAdd(builder, left.x, right.x, sumX)
  appendMethod2VmFieldAdd(builder, output.x, sumX, slopeSquared)
  appendMethod2VmFieldSub(builder, left.x, output.x, leftXMinusOutputX)
  appendMethod2VmFieldMul(builder, slope, leftXMinusOutputX, lambdaDiff)
  appendMethod2VmFieldAdd(builder, output.y, left.y, lambdaDiff)

  return output
}

export function appendMethod2VmPointEquality (
  builder: Method2VmBuilder,
  left: SecpPoint,
  right: SecpPoint
): void {
  assertAffinePoint(left, 'Method 2 VM point equality left input')
  assertAffinePoint(right, 'Method 2 VM point equality right input')
  appendMethod2VmPoint(builder, left)
  appendMethod2VmPoint(builder, right)

  const leftX = bigintToU16LimbsLE(left.x, 16)
  const leftY = bigintToU16LimbsLE(left.y, 16)
  const rightX = bigintToU16LimbsLE(right.x, 16)
  const rightY = bigintToU16LimbsLE(right.y, 16)
  for (let limb = 0; limb < 16; limb++) {
    builder.assertEq(leftX[limb], rightX[limb])
    builder.assertEq(leftY[limb], rightY[limb])
  }
}

function assertAffinePoint (
  point: SecpPoint,
  label: string
): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error(`${label} must be a valid affine secp256k1 point`)
  }
}
