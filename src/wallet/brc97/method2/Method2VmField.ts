import {
  SECP256K1_P,
  U16_RADIX,
  bigintToU16LimbsLE,
  modP
} from '../circuit/index.js'
import { Method2VmBuilder } from './Method2Vm.js'

export const METHOD2_VM_FIELD_LIMBS = 16
export const METHOD2_VM_FIELD_PRODUCT_LIMBS = 32
export const METHOD2_VM_FIELD_MUL_CARRY_OFFSET = 1n << 47n

const P_LIMBS = bigintToU16LimbsLE(SECP256K1_P, METHOD2_VM_FIELD_LIMBS)
const P_MINUS_ONE_LIMBS = bigintToU16LimbsLE(
  SECP256K1_P - 1n,
  METHOD2_VM_FIELD_LIMBS
)
const U16_RADIX_BIGINT = BigInt(U16_RADIX)

export interface Method2VmFieldWitness {
  value: bigint
  limbs: number[]
}

export interface Method2VmFieldMulWitness {
  result: bigint
  quotient: bigint
  quotientLimbs: number[]
}

export function appendMethod2VmFieldElement (
  builder: Method2VmBuilder,
  value: bigint
): Method2VmFieldWitness {
  return appendMethod2VmFieldElementWithLinkedLimbs(builder, value)
}

export function appendMethod2VmFieldElementWithLinkedLimbs (
  builder: Method2VmBuilder,
  value: bigint,
  linkLimb?: (limb: number, value: number) => void
): Method2VmFieldWitness {
  assertField(value)
  const limbs = bigintToU16LimbsLE(value, METHOD2_VM_FIELD_LIMBS)
  const diffLimbs = bigintToU16LimbsLE(
    SECP256K1_P - 1n - value,
    METHOD2_VM_FIELD_LIMBS
  )
  for (let i = 0; i < METHOD2_VM_FIELD_LIMBS; i++) {
    linkLimb?.(i, limbs[i])
    builder.assertU16(limbs[i])
    builder.assertU16(diffLimbs[i])
  }

  let carry = 0n
  for (let i = 0; i < METHOD2_VM_FIELD_LIMBS; i++) {
    const carryOut = checkedDivRadix(
      BigInt(limbs[i]) +
        BigInt(diffLimbs[i]) +
        carry -
        BigInt(P_MINUS_ONE_LIMBS[i])
    )
    builder.assertFieldAddLimb(
      limbs[i],
      diffLimbs[i],
      P_MINUS_ONE_LIMBS[i],
      0,
      0,
      carry,
      carryOut
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM field canonical carry mismatch')
  }

  return { value, limbs }
}

export function appendMethod2VmFieldAdd (
  builder: Method2VmBuilder,
  left: bigint,
  right: bigint,
  result: bigint = modP(left + right)
): Method2VmFieldWitness {
  const leftWitness = appendMethod2VmFieldElement(builder, left)
  const rightWitness = appendMethod2VmFieldElement(builder, right)
  const resultWitness = appendMethod2VmFieldElement(builder, result)
  const wrap = left + right >= SECP256K1_P ? 1 : 0
  let carry = 0n
  for (let i = 0; i < METHOD2_VM_FIELD_LIMBS; i++) {
    const carryOut = checkedDivRadix(
      BigInt(leftWitness.limbs[i]) +
        BigInt(rightWitness.limbs[i]) +
        carry -
        BigInt(resultWitness.limbs[i]) -
        BigInt(wrap * P_LIMBS[i])
    )
    builder.assertFieldAddLimb(
      leftWitness.limbs[i],
      rightWitness.limbs[i],
      resultWitness.limbs[i],
      P_LIMBS[i],
      wrap,
      carry,
      carryOut
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM field addition carry mismatch')
  }
  return resultWitness
}

export function appendMethod2VmFieldSub (
  builder: Method2VmBuilder,
  left: bigint,
  right: bigint,
  result: bigint = modP(left - right)
): Method2VmFieldWitness {
  const leftWitness = appendMethod2VmFieldElement(builder, left)
  const rightWitness = appendMethod2VmFieldElement(builder, right)
  const resultWitness = appendMethod2VmFieldElement(builder, result)
  const wrap = left < right ? 1 : 0
  let carry = 0n
  for (let i = 0; i < METHOD2_VM_FIELD_LIMBS; i++) {
    const carryOut = checkedDivRadix(
      BigInt(leftWitness.limbs[i]) -
        BigInt(rightWitness.limbs[i]) +
        BigInt(wrap * P_LIMBS[i]) +
        carry -
        BigInt(resultWitness.limbs[i])
    )
    builder.assertFieldSubLimb(
      leftWitness.limbs[i],
      rightWitness.limbs[i],
      resultWitness.limbs[i],
      P_LIMBS[i],
      wrap,
      carry,
      carryOut
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM field subtraction carry mismatch')
  }
  return resultWitness
}

export function appendMethod2VmFieldMul (
  builder: Method2VmBuilder,
  left: bigint,
  right: bigint,
  result: bigint = modP(left * right)
): Method2VmFieldMulWitness {
  const leftWitness = appendMethod2VmFieldElement(builder, left)
  const rightWitness = appendMethod2VmFieldElement(builder, right)
  const resultWitness = appendMethod2VmFieldElement(builder, result)
  const quotient = (left * right - result) / SECP256K1_P
  if (left * right !== result + quotient * SECP256K1_P) {
    throw new Error('Method 2 VM field multiplication quotient mismatch')
  }
  const quotientWitness = appendMethod2VmFieldElement(builder, quotient)
  const product = convolution(leftWitness.limbs, rightWitness.limbs)
  const quotientProduct = convolution(quotientWitness.limbs, P_LIMBS)

  let carry = 0n
  for (let i = 0; i < METHOD2_VM_FIELD_PRODUCT_LIMBS; i++) {
    const resultLimb = BigInt(resultWitness.limbs[i] ?? 0)
    const carryOut = checkedDivRadix(
      resultLimb + quotientProduct[i] + carry - product[i]
    )
    const carryInStored = storeSignedCarry(carry)
    const carryOutStored = storeSignedCarry(carryOut)
    builder.assertU48(carryInStored)
    builder.assertU48(carryOutStored)
    builder.assertFieldMulLimb(
      product[i],
      resultLimb,
      quotientProduct[i],
      carryInStored,
      carryOutStored
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM field multiplication carry mismatch')
  }

  return {
    result,
    quotient,
    quotientLimbs: quotientWitness.limbs
  }
}

function assertField (value: bigint): void {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Method 2 VM field value must satisfy 0 <= x < p')
  }
}

function convolution (left: number[], right: number[]): bigint[] {
  const out = new Array<bigint>(METHOD2_VM_FIELD_PRODUCT_LIMBS).fill(0n)
  for (let i = 0; i < left.length; i++) {
    for (let j = 0; j < right.length; j++) {
      out[i + j] += BigInt(left[i]) * BigInt(right[j])
    }
  }
  return out
}

function checkedDivRadix (value: bigint): bigint {
  if (value % U16_RADIX_BIGINT !== 0n) {
    throw new Error('Method 2 VM field carry is not integral')
  }
  return value / U16_RADIX_BIGINT
}

function storeSignedCarry (carry: bigint): bigint {
  const stored = carry + METHOD2_VM_FIELD_MUL_CARRY_OFFSET
  if (stored < 0n || stored >= (1n << 48n)) {
    throw new Error('Method 2 VM field multiplication carry out of range')
  }
  return stored
}
