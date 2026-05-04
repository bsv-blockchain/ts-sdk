import {
  F,
  FieldElement
} from '../stark/index.js'
import {
  SECP256K1_P,
  U16_RADIX,
  bigintToU16LimbsLE,
  toBitsLE
} from '../circuit/index.js'

export const METHOD2_FIELD_LIMB_COUNT = 16
export const METHOD2_FIELD_BIT_COUNT = 256
const CARRY_LIMB_COUNT = 3
const MUL_LIMB_COUNT = METHOD2_FIELD_LIMB_COUNT * 2
const SIGNED_CARRY_OFFSET = 1 << 20

export interface Method2FieldLayout {
  limbs: number
  bits: number
  diffLimbs: number
  diffBits: number
  carries: number
  width: number
}

export interface Method2FieldMulLayout {
  quotient: number
  carryLimbs: number
  carryBits: number
  width: number
}

export interface Method2FieldAddSmallLayout {
  wrap: number
  carryLimbs: number
  carryBits: number
  width: number
}

export interface Method2FieldAddLayout {
  wrap: number
  carryLimbs: number
  carryBits: number
  width: number
}

export const METHOD2_FIELD_LAYOUT: Method2FieldLayout = {
  limbs: 0,
  bits: METHOD2_FIELD_LIMB_COUNT,
  diffLimbs: METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT,
  diffBits: METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT + METHOD2_FIELD_LIMB_COUNT,
  carries: METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT + METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT,
  width: METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT + METHOD2_FIELD_LIMB_COUNT + METHOD2_FIELD_BIT_COUNT + METHOD2_FIELD_LIMB_COUNT
}

export const METHOD2_FIELD_MUL_LAYOUT: Method2FieldMulLayout = {
  quotient: 0,
  carryLimbs: METHOD2_FIELD_LAYOUT.width,
  carryBits: METHOD2_FIELD_LAYOUT.width + MUL_LIMB_COUNT * CARRY_LIMB_COUNT,
  width: METHOD2_FIELD_LAYOUT.width + MUL_LIMB_COUNT * CARRY_LIMB_COUNT + MUL_LIMB_COUNT * CARRY_LIMB_COUNT * 16
}

export const METHOD2_FIELD_ADD_SMALL_LAYOUT: Method2FieldAddSmallLayout = {
  wrap: 0,
  carryLimbs: 1,
  carryBits: 1 + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT,
  width: 1 + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT * 16
}

export const METHOD2_FIELD_ADD_LAYOUT: Method2FieldAddLayout = {
  wrap: 0,
  carryLimbs: 1,
  carryBits: 1 + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT,
  width: 1 + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT + METHOD2_FIELD_LIMB_COUNT * CARRY_LIMB_COUNT * 16
}

const P_LIMBS = bigintToU16LimbsLE(
  SECP256K1_P,
  METHOD2_FIELD_LIMB_COUNT
)

export function writeMethod2FieldElement (
  row: FieldElement[],
  offset: number,
  value: bigint
): void {
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Method 2 field witness must satisfy 0 <= x < p')
  }
  const limbs = bigintToU16LimbsLE(value, METHOD2_FIELD_LIMB_COUNT)
  const bits = toBitsLE(value, METHOD2_FIELD_BIT_COUNT)
  const diff = SECP256K1_P - 1n - value
  const diffLimbs = bigintToU16LimbsLE(diff, METHOD2_FIELD_LIMB_COUNT)
  const diffBits = toBitsLE(diff, METHOD2_FIELD_BIT_COUNT)
  const carries = rangeCarries(limbs, diffLimbs)

  writeNumbers(row, offset + METHOD2_FIELD_LAYOUT.limbs, limbs)
  writeNumbers(row, offset + METHOD2_FIELD_LAYOUT.bits, bits)
  writeNumbers(row, offset + METHOD2_FIELD_LAYOUT.diffLimbs, diffLimbs)
  writeNumbers(row, offset + METHOD2_FIELD_LAYOUT.diffBits, diffBits)
  writeNumbers(row, offset + METHOD2_FIELD_LAYOUT.carries, carries)
}

export function evaluateMethod2FieldElementConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    let valueFromBits = 0n
    let diffFromBits = 0n
    for (let bit = 0; bit < 16; bit++) {
      const valueBit = row[offset + METHOD2_FIELD_LAYOUT.bits + limb * 16 + bit]
      const diffBit = row[offset + METHOD2_FIELD_LAYOUT.diffBits + limb * 16 + bit]
      constraints.push(booleanConstraint(valueBit))
      constraints.push(booleanConstraint(diffBit))
      valueFromBits = F.add(
        valueFromBits,
        F.mul(valueBit, BigInt(1 << bit))
      )
      diffFromBits = F.add(
        diffFromBits,
        F.mul(diffBit, BigInt(1 << bit))
      )
    }
    const valueLimb = fieldLimb(row, offset, limb)
    const diffLimb = row[offset + METHOD2_FIELD_LAYOUT.diffLimbs + limb]
    constraints.push(F.sub(valueLimb, valueFromBits))
    constraints.push(F.sub(diffLimb, diffFromBits))

    const carry = row[offset + METHOD2_FIELD_LAYOUT.carries + limb]
    constraints.push(booleanConstraint(carry))
    const carryIn = limb === 0
      ? 1n
      : row[offset + METHOD2_FIELD_LAYOUT.carries + limb - 1]
    constraints.push(F.sub(
      F.add(F.add(valueLimb, diffLimb), carryIn),
      F.add(
        BigInt(P_LIMBS[limb]),
        F.mul(carry, BigInt(U16_RADIX))
      )
    ))
  }
  constraints.push(row[
    offset + METHOD2_FIELD_LAYOUT.carries + METHOD2_FIELD_LIMB_COUNT - 1
  ])
  return constraints
}

export function writeMethod2FieldMulWitness (
  row: FieldElement[],
  offset: number,
  left: bigint,
  right: bigint,
  result: bigint
): void {
  const quotient = (left * right - result) / SECP256K1_P
  if (quotient < 0n || quotient >= SECP256K1_P) {
    throw new Error('Method 2 field multiplication quotient out of range')
  }
  if (left * right !== result + quotient * SECP256K1_P) {
    throw new Error('Invalid Method 2 field multiplication witness')
  }
  writeMethod2FieldElement(
    row,
    offset + METHOD2_FIELD_MUL_LAYOUT.quotient,
    quotient
  )

  const product = convolutionLimbs(
    bigintToU16LimbsLE(left, METHOD2_FIELD_LIMB_COUNT),
    bigintToU16LimbsLE(right, METHOD2_FIELD_LIMB_COUNT)
  )
  const quotientProduct = convolutionLimbs(
    bigintToU16LimbsLE(quotient, METHOD2_FIELD_LIMB_COUNT),
    P_LIMBS
  )
  const resultLimbs = bigintToU16LimbsLE(result, METHOD2_FIELD_LIMB_COUNT)
  let carry = 0n
  for (let limb = 0; limb < MUL_LIMB_COUNT; limb++) {
    const sum = BigInt(resultLimbs[limb] ?? 0) +
      quotientProduct[limb] +
      carry
    const carryOut = (sum - product[limb]) / BigInt(U16_RADIX)
    if (sum - product[limb] !== carryOut * BigInt(U16_RADIX)) {
      throw new Error('Invalid Method 2 multiplication carry witness')
    }
    const stored = carryOut + BigInt(SIGNED_CARRY_OFFSET)
    if (stored < 0n || stored >= (1n << 48n)) {
      throw new Error('Method 2 multiplication carry out of range')
    }
    writeCarry(
      row,
      offset + METHOD2_FIELD_MUL_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_MUL_LAYOUT.carryBits,
      limb,
      stored
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Invalid final Method 2 multiplication carry')
  }
}

export function evaluateMethod2FieldMulConstraints (
  row: FieldElement[],
  offset: number,
  leftOffset: number,
  rightOffset: number,
  resultOffset: number
): FieldElement[] {
  const constraints = evaluateMethod2FieldElementConstraints(
    row,
    offset + METHOD2_FIELD_MUL_LAYOUT.quotient
  )
  for (let limb = 0; limb < MUL_LIMB_COUNT; limb++) {
    constraints.push(...carryConstraints(
      row,
      offset + METHOD2_FIELD_MUL_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_MUL_LAYOUT.carryBits,
      limb
    ))
    const carryIn = limb === 0
      ? 0n
      : signedCarryValue(
        row,
        offset + METHOD2_FIELD_MUL_LAYOUT.carryLimbs,
        limb - 1
      )
    const carryOut = signedCarryValue(
      row,
      offset + METHOD2_FIELD_MUL_LAYOUT.carryLimbs,
      limb
    )
    constraints.push(F.sub(
      F.add(
        F.add(
          fieldLimb(row, resultOffset, limb),
          quotientProductLimb(
            row,
            offset + METHOD2_FIELD_MUL_LAYOUT.quotient,
            limb
          )
        ),
        carryIn
      ),
      F.add(
        productLimb(row, leftOffset, rightOffset, limb),
        F.mul(carryOut, BigInt(U16_RADIX))
      )
    ))
  }
  constraints.push(signedCarryValue(
    row,
    offset + METHOD2_FIELD_MUL_LAYOUT.carryLimbs,
    MUL_LIMB_COUNT - 1
  ))
  return constraints
}

export function writeMethod2FieldAddWitness (
  row: FieldElement[],
  offset: number,
  left: bigint,
  right: bigint,
  result: bigint
): void {
  const wrapped = left + right >= SECP256K1_P ? 1n : 0n
  if ((left + right) % SECP256K1_P !== result) {
    throw new Error('Invalid Method 2 field addition witness')
  }
  row[offset + METHOD2_FIELD_ADD_LAYOUT.wrap] = wrapped
  const leftLimbs = bigintToU16LimbsLE(left, METHOD2_FIELD_LIMB_COUNT)
  const rightLimbs = bigintToU16LimbsLE(right, METHOD2_FIELD_LIMB_COUNT)
  const resultLimbs = bigintToU16LimbsLE(result, METHOD2_FIELD_LIMB_COUNT)
  let carry = 0n
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    const sum = BigInt(leftLimbs[limb]) +
      BigInt(rightLimbs[limb]) +
      carry
    const target = BigInt(resultLimbs[limb]) +
      wrapped * BigInt(P_LIMBS[limb])
    const carryOut = (sum - target) / BigInt(U16_RADIX)
    if (sum - target !== carryOut * BigInt(U16_RADIX)) {
      throw new Error('Invalid Method 2 addition carry witness')
    }
    const stored = carryOut + BigInt(SIGNED_CARRY_OFFSET)
    if (stored < 0n || stored >= (1n << 48n)) {
      throw new Error('Method 2 addition carry out of range')
    }
    writeCarry(
      row,
      offset + METHOD2_FIELD_ADD_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_ADD_LAYOUT.carryBits,
      limb,
      stored
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Invalid final Method 2 addition carry')
  }
}

export function evaluateMethod2FieldAddConstraints (
  row: FieldElement[],
  offset: number,
  leftOffset: number,
  rightOffset: number,
  resultOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  const wrap = row[offset + METHOD2_FIELD_ADD_LAYOUT.wrap]
  constraints.push(booleanConstraint(wrap))
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    constraints.push(...carryConstraints(
      row,
      offset + METHOD2_FIELD_ADD_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_ADD_LAYOUT.carryBits,
      limb
    ))
    const carryIn = limb === 0
      ? 0n
      : signedCarryValue(
        row,
        offset + METHOD2_FIELD_ADD_LAYOUT.carryLimbs,
        limb - 1
      )
    const carryOut = signedCarryValue(
      row,
      offset + METHOD2_FIELD_ADD_LAYOUT.carryLimbs,
      limb
    )
    const left = F.add(
      F.add(fieldLimb(row, leftOffset, limb), fieldLimb(row, rightOffset, limb)),
      carryIn
    )
    const right = F.add(
      F.add(
        fieldLimb(row, resultOffset, limb),
        F.mul(wrap, BigInt(P_LIMBS[limb]))
      ),
      F.mul(carryOut, BigInt(U16_RADIX))
    )
    constraints.push(F.sub(left, right))
  }
  constraints.push(signedCarryValue(
    row,
    offset + METHOD2_FIELD_ADD_LAYOUT.carryLimbs,
    METHOD2_FIELD_LIMB_COUNT - 1
  ))
  return constraints
}

export function writeMethod2FieldAddSmallWitness (
  row: FieldElement[],
  offset: number,
  value: bigint,
  addend: number,
  result: bigint
): void {
  const wrapped = value + BigInt(addend) >= SECP256K1_P ? 1n : 0n
  if ((value + BigInt(addend)) % SECP256K1_P !== result) {
    throw new Error('Invalid Method 2 field add-small witness')
  }
  row[offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.wrap] = wrapped
  const valueLimbs = bigintToU16LimbsLE(value, METHOD2_FIELD_LIMB_COUNT)
  const resultLimbs = bigintToU16LimbsLE(result, METHOD2_FIELD_LIMB_COUNT)
  let carry = 0n
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    const left = BigInt(valueLimbs[limb]) +
      (limb === 0 ? BigInt(addend) : 0n) +
      carry
    const right = BigInt(resultLimbs[limb]) +
      wrapped * BigInt(P_LIMBS[limb])
    const carryOut = (left - right) / BigInt(U16_RADIX)
    if (left - right !== carryOut * BigInt(U16_RADIX)) {
      throw new Error('Invalid Method 2 add-small carry witness')
    }
    const stored = carryOut + BigInt(SIGNED_CARRY_OFFSET)
    if (stored < 0n || stored >= (1n << 48n)) {
      throw new Error('Method 2 add-small carry out of range')
    }
    writeCarry(
      row,
      offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryBits,
      limb,
      stored
    )
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Invalid final Method 2 add-small carry')
  }
}

export function evaluateMethod2FieldAddSmallConstraints (
  row: FieldElement[],
  offset: number,
  valueOffset: number,
  addend: number,
  resultOffset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  const wrap = row[offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.wrap]
  constraints.push(booleanConstraint(wrap))
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    constraints.push(...carryConstraints(
      row,
      offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryLimbs,
      offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryBits,
      limb
    ))
    const carryIn = limb === 0
      ? 0n
      : signedCarryValue(
        row,
        offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryLimbs,
        limb - 1
      )
    const carryOut = signedCarryValue(
      row,
      offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryLimbs,
      limb
    )
    constraints.push(F.sub(
      F.add(
        F.add(
          fieldLimb(row, valueOffset, limb),
          limb === 0 ? BigInt(addend) : 0n
        ),
        carryIn
      ),
      F.add(
        F.add(
          fieldLimb(row, resultOffset, limb),
          F.mul(wrap, BigInt(P_LIMBS[limb]))
        ),
        F.mul(carryOut, BigInt(U16_RADIX))
      )
    ))
  }
  constraints.push(signedCarryValue(
    row,
    offset + METHOD2_FIELD_ADD_SMALL_LAYOUT.carryLimbs,
    METHOD2_FIELD_LIMB_COUNT - 1
  ))
  return constraints
}

export function fieldLimb (
  row: FieldElement[],
  offset: number,
  limb: number
): FieldElement {
  if (limb >= METHOD2_FIELD_LIMB_COUNT) return 0n
  return row[offset + METHOD2_FIELD_LAYOUT.limbs + limb]
}

function rangeCarries (
  valueLimbs: number[],
  diffLimbs: number[]
): number[] {
  const carries: number[] = []
  let carry = 1
  for (let limb = 0; limb < METHOD2_FIELD_LIMB_COUNT; limb++) {
    const sum = valueLimbs[limb] + diffLimbs[limb] + carry
    carry = sum >= U16_RADIX ? 1 : 0
    carries.push(carry)
  }
  if (carry !== 0) {
    throw new Error('Invalid Method 2 field range carry witness')
  }
  return carries
}

function productLimb (
  row: FieldElement[],
  leftOffset: number,
  rightOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < METHOD2_FIELD_LIMB_COUNT; i++) {
    const j = limb - i
    if (j >= 0 && j < METHOD2_FIELD_LIMB_COUNT) {
      sum = F.add(
        sum,
        F.mul(fieldLimb(row, leftOffset, i), fieldLimb(row, rightOffset, j))
      )
    }
  }
  return sum
}

function quotientProductLimb (
  row: FieldElement[],
  quotientOffset: number,
  limb: number
): FieldElement {
  let sum = 0n
  for (let i = 0; i < METHOD2_FIELD_LIMB_COUNT; i++) {
    const j = limb - i
    if (j >= 0 && j < METHOD2_FIELD_LIMB_COUNT) {
      sum = F.add(
        sum,
        F.mul(fieldLimb(row, quotientOffset, i), BigInt(P_LIMBS[j]))
      )
    }
  }
  return sum
}

function convolutionLimbs (
  left: number[],
  right: number[]
): bigint[] {
  const out = new Array<bigint>(MUL_LIMB_COUNT).fill(0n)
  for (let i = 0; i < left.length; i++) {
    for (let j = 0; j < right.length; j++) {
      out[i + j] += BigInt(left[i]) * BigInt(right[j])
    }
  }
  return out
}

function writeCarry (
  row: FieldElement[],
  carryLimbOffset: number,
  carryBitOffset: number,
  carry: number,
  value: bigint
): void {
  const limbs = bigintToU16LimbsLE(value, CARRY_LIMB_COUNT)
  const bits = toBitsLE(value, CARRY_LIMB_COUNT * 16)
  const limbOffset = carryLimbOffset + carry * CARRY_LIMB_COUNT
  writeNumbers(row, limbOffset, limbs)
  const bitOffset = carryBitOffset + carry * CARRY_LIMB_COUNT * 16
  writeNumbers(row, bitOffset, bits)
}

function carryConstraints (
  row: FieldElement[],
  carryLimbOffset: number,
  carryBitOffset: number,
  carry: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let carryLimb = 0; carryLimb < CARRY_LIMB_COUNT; carryLimb++) {
    let limbFromBits = 0n
    for (let bit = 0; bit < 16; bit++) {
      const bitValue = row[
        carryBitOffset + carry * CARRY_LIMB_COUNT * 16 + carryLimb * 16 + bit
      ]
      constraints.push(booleanConstraint(bitValue))
      limbFromBits = F.add(
        limbFromBits,
        F.mul(bitValue, BigInt(1 << bit))
      )
    }
    constraints.push(F.sub(
      row[carryLimbOffset + carry * CARRY_LIMB_COUNT + carryLimb],
      limbFromBits
    ))
  }
  return constraints
}

function carryValue (
  row: FieldElement[],
  offset: number,
  carry: number
): FieldElement {
  let value = 0n
  for (let limb = CARRY_LIMB_COUNT - 1; limb >= 0; limb--) {
    value = F.add(
      F.mul(value, BigInt(U16_RADIX)),
      row[offset + carry * CARRY_LIMB_COUNT + limb]
    )
  }
  return value
}

function signedCarryValue (
  row: FieldElement[],
  offset: number,
  carry: number
): FieldElement {
  return F.sub(carryValue(row, offset, carry), BigInt(SIGNED_CARRY_OFFSET))
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function writeNumbers (
  row: FieldElement[],
  offset: number,
  values: number[]
): void {
  for (let i = 0; i < values.length; i++) {
    row[offset + i] = BigInt(values[i])
  }
}
