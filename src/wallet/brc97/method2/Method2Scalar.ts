import {
  F,
  FieldElement
} from '../stark/index.js'
import {
  SECP256K1_N,
  U16_RADIX,
  bigintToU16LimbsLE,
  toBitsLE
} from '../circuit/index.js'

export const METHOD2_SCALAR_LIMB_COUNT = 16
export const METHOD2_SCALAR_BIT_COUNT = 256

export interface Method2ScalarLayout {
  limbs: number
  bits: number
  diffLimbs: number
  diffBits: number
  carries: number
  nonZeroInverse: number
  width: number
}

export const METHOD2_SCALAR_LAYOUT: Method2ScalarLayout = {
  limbs: 0,
  bits: METHOD2_SCALAR_LIMB_COUNT,
  diffLimbs: METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT,
  diffBits: METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT,
  carries: METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT,
  nonZeroInverse: METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT,
  width: METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT + METHOD2_SCALAR_BIT_COUNT + METHOD2_SCALAR_LIMB_COUNT + 1
}

const SCALAR_N_LIMBS = bigintToU16LimbsLE(
  SECP256K1_N,
  METHOD2_SCALAR_LIMB_COUNT
)

export function writeMethod2ScalarWitness (
  row: FieldElement[],
  offset: number,
  scalar: bigint
): void {
  if (scalar <= 0n || scalar >= SECP256K1_N) {
    throw new Error('Method 2 scalar witness must satisfy 0 < a < n')
  }
  const scalarLimbs = bigintToU16LimbsLE(
    scalar,
    METHOD2_SCALAR_LIMB_COUNT
  )
  const scalarBits = toBitsLE(scalar, METHOD2_SCALAR_BIT_COUNT)
  const diff = SECP256K1_N - 1n - scalar
  const diffLimbs = bigintToU16LimbsLE(diff, METHOD2_SCALAR_LIMB_COUNT)
  const diffBits = toBitsLE(diff, METHOD2_SCALAR_BIT_COUNT)
  const carries = scalarRangeCarries(scalarLimbs, diffLimbs)
  const bitSum = scalarBits.reduce((sum, bit) => sum + bit, 0)

  writeNumbers(row, offset + METHOD2_SCALAR_LAYOUT.limbs, scalarLimbs)
  writeNumbers(row, offset + METHOD2_SCALAR_LAYOUT.bits, scalarBits)
  writeNumbers(row, offset + METHOD2_SCALAR_LAYOUT.diffLimbs, diffLimbs)
  writeNumbers(row, offset + METHOD2_SCALAR_LAYOUT.diffBits, diffBits)
  writeNumbers(row, offset + METHOD2_SCALAR_LAYOUT.carries, carries)
  row[offset + METHOD2_SCALAR_LAYOUT.nonZeroInverse] = F.inv(BigInt(bitSum))
}

export function evaluateMethod2ScalarConstraints (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  let scalarBitSum = 0n

  for (let limb = 0; limb < METHOD2_SCALAR_LIMB_COUNT; limb++) {
    let scalarLimbFromBits = 0n
    let diffLimbFromBits = 0n
    for (let bit = 0; bit < 16; bit++) {
      const scalarBit = row[
        offset + METHOD2_SCALAR_LAYOUT.bits + limb * 16 + bit
      ]
      const diffBit = row[
        offset + METHOD2_SCALAR_LAYOUT.diffBits + limb * 16 + bit
      ]
      constraints.push(booleanConstraint(scalarBit))
      constraints.push(booleanConstraint(diffBit))
      scalarLimbFromBits = F.add(
        scalarLimbFromBits,
        F.mul(scalarBit, BigInt(1 << bit))
      )
      diffLimbFromBits = F.add(
        diffLimbFromBits,
        F.mul(diffBit, BigInt(1 << bit))
      )
      scalarBitSum = F.add(scalarBitSum, scalarBit)
    }

    const scalarLimb = row[offset + METHOD2_SCALAR_LAYOUT.limbs + limb]
    const diffLimb = row[offset + METHOD2_SCALAR_LAYOUT.diffLimbs + limb]
    constraints.push(F.sub(scalarLimb, scalarLimbFromBits))
    constraints.push(F.sub(diffLimb, diffLimbFromBits))

    const carry = row[offset + METHOD2_SCALAR_LAYOUT.carries + limb]
    constraints.push(booleanConstraint(carry))
    const carryIn = limb === 0
      ? 1n
      : row[offset + METHOD2_SCALAR_LAYOUT.carries + limb - 1]
    constraints.push(F.sub(
      F.add(F.add(scalarLimb, diffLimb), carryIn),
      F.add(
        BigInt(SCALAR_N_LIMBS[limb]),
        F.mul(carry, BigInt(U16_RADIX))
      )
    ))
  }

  constraints.push(row[
    offset + METHOD2_SCALAR_LAYOUT.carries + METHOD2_SCALAR_LIMB_COUNT - 1
  ])
  constraints.push(F.sub(
    F.mul(
      scalarBitSum,
      row[offset + METHOD2_SCALAR_LAYOUT.nonZeroInverse]
    ),
    1n
  ))
  return constraints
}

function scalarRangeCarries (
  scalarLimbs: number[],
  diffLimbs: number[]
): number[] {
  const carries: number[] = []
  let carry = 1
  for (let limb = 0; limb < METHOD2_SCALAR_LIMB_COUNT; limb++) {
    const sum = scalarLimbs[limb] + diffLimbs[limb] + carry
    carry = sum >= U16_RADIX ? 1 : 0
    carries.push(carry)
  }
  if (carry !== 0) {
    throw new Error('Invalid scalar range carry witness')
  }
  return carries
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
