import { SecpPoint } from '../circuit/Types.js'
import {
  SECP256K1_G,
  SECP256K1_N,
  bigintToU16LimbsLE,
  isOnCurve,
  pointDouble,
  scalarMultiply,
  toBitsLE,
  validateScalar
} from '../circuit/index.js'
import {
  METHOD2_VM_LAYOUT,
  Method2VmBuilder,
  Method2VmFixedCell,
  Method2VmLinkDestination,
  Method2VmProgram
} from './Method2Vm.js'
import {
  appendMethod2VmCompressedPointWithLinkedLimbs,
  appendMethod2VmPoint,
  appendMethod2VmPointAddDistinct,
  appendMethod2VmPointDouble,
  appendMethod2VmPointEquality
} from './Method2VmPoint.js'
import { Method2VmRegisterProgramBuilder } from './Method2VmRegister.js'
import {
  Method2VmHmacInputBuilder,
  Method2VmHmacInputWitness
} from './Method2VmHmac.js'

export const METHOD2_VM_SCALAR_BITS = 256
export const METHOD2_VM_SCALAR_LIMBS = 16

const N_LIMBS = bigintToU16LimbsLE(
  SECP256K1_N,
  METHOD2_VM_SCALAR_LIMBS
)

export interface Method2VmScalarWitness {
  scalar: bigint
  bits: number[]
  decrementedBits: number[]
  limbs: number[]
  rangeDiffLimbs: number[]
  minusOneLimbs: number[]
  borrowIns: number[]
  borrowOuts: number[]
  addSelectors: number[]
  doubleSelectors: number[]
}

export interface Method2VmScalarMulWitness {
  scalar: Method2VmScalarWitness
  base: SecpPoint
  output: SecpPoint
  activeBits: number
  additions: number
  doublings: number
}

export interface Method2VmRegisterizedScalarMulWitness
  extends Method2VmScalarMulWitness {
  stateCheckpoints: number
  stateCarries: number
  branchMuxes: number
  scalarSteps: number
  candidateAdditions: number
  candidateDoublings: number
  baseCheckpointStart: number
  publicOutputBindings: number
  compressedOutputBindings: number
}

export interface Method2VmScalarMulProgram {
  program: Method2VmProgram
  witness: Method2VmRegisterizedScalarMulWitness
}

export interface Method2VmScalarMulCompressedWitness {
  scalarMul: Method2VmRegisterizedScalarMulWitness
  compressed: number[]
}

export interface Method2VmScalarMulHmacInputWitness
  extends Method2VmScalarMulCompressedWitness {
  hmac: Method2VmHmacInputWitness
}

export function appendMethod2VmScalar (
  builder: Method2VmBuilder,
  scalar: bigint,
  activeBits = METHOD2_VM_SCALAR_BITS
): Method2VmScalarWitness {
  validateScalarInputs(scalar, activeBits)
  const bits = toBitsLE(scalar, METHOD2_VM_SCALAR_BITS)
  const decrementedBits = toBitsLE(scalar - 1n, METHOD2_VM_SCALAR_BITS)
  const limbs = bigintToU16LimbsLE(scalar, METHOD2_VM_SCALAR_LIMBS)
  const rangeDiff = SECP256K1_N - 1n - scalar
  const rangeDiffLimbs = bigintToU16LimbsLE(
    rangeDiff,
    METHOD2_VM_SCALAR_LIMBS
  )
  const minusOneLimbs = bigintToU16LimbsLE(
    scalar - 1n,
    METHOD2_VM_SCALAR_LIMBS
  )
  const bitWitness = appendScalarBitMaterializationRows(
    builder,
    bits,
    decrementedBits,
    limbs,
    minusOneLimbs,
    activeBits
  )

  for (let limb = 0; limb < METHOD2_VM_SCALAR_LIMBS; limb++) {
    builder.assertU16(limbs[limb])
    builder.assertU16(rangeDiffLimbs[limb])
    builder.assertU16(minusOneLimbs[limb])
  }

  appendScalarRangeRows(builder, limbs, rangeDiffLimbs)
  appendScalarMinusOneRows(builder, limbs, minusOneLimbs)

  return {
    scalar,
    bits,
    decrementedBits,
    limbs,
    rangeDiffLimbs,
    minusOneLimbs,
    borrowIns: bitWitness.borrowIns,
    borrowOuts: bitWitness.borrowOuts,
    addSelectors: bitWitness.addSelectors,
    doubleSelectors: bitWitness.doubleSelectors
  }
}

export function appendMethod2VmFixedBaseScalarMul (
  builder: Method2VmBuilder,
  scalar: bigint,
  activeBits = METHOD2_VM_SCALAR_BITS
): Method2VmScalarMulWitness {
  return appendMethod2VmScalarMul(builder, scalar, SECP256K1_G, activeBits)
}

export function appendMethod2VmScalarMul (
  builder: Method2VmBuilder,
  scalar: bigint,
  basePoint: SecpPoint,
  activeBits = METHOD2_VM_SCALAR_BITS
): Method2VmScalarMulWitness {
  validateBasePoint(basePoint)
  const scalarWitness = appendMethod2VmScalar(builder, scalar, activeBits)
  appendMethod2VmPoint(builder, basePoint)

  let accumulator = basePoint
  let base = basePoint
  let borrowIn = 1n
  let additions = 0
  let doublings = 0

  for (let bit = 0; bit < activeBits; bit++) {
    const scalarBit = BigInt(scalarWitness.bits[bit])
    const decrementedBit = BigInt(scalarWitness.decrementedBits[bit])
    const borrowOut = (decrementedBit + borrowIn - scalarBit) / 2n
    appendBorrowRows(builder, scalarBit, decrementedBit, borrowIn, borrowOut)

    if (decrementedBit === 0n) {
      appendMethod2VmPointEquality(builder, accumulator, accumulator)
    } else if (pointsEqual(accumulator, base)) {
      accumulator = appendMethod2VmPointDouble(builder, accumulator)
      doublings++
    } else {
      accumulator = appendMethod2VmPointAddDistinct(
        builder,
        accumulator,
        base
      )
      additions++
    }

    borrowIn = borrowOut
    if (bit < activeBits - 1) {
      base = appendMethod2VmPointDouble(builder, base)
      doublings++
    }
  }

  if (borrowIn !== 0n) {
    throw new Error('Method 2 VM scalar multiplication borrow mismatch')
  }
  const expected = scalarMultiply(scalar, basePoint)
  if (!pointsEqual(accumulator, expected)) {
    throw new Error('Method 2 VM scalar multiplication witness mismatch')
  }

  return {
    scalar: scalarWitness,
    base: basePoint,
    output: accumulator,
    activeBits,
    additions,
    doublings
  }
}

export function appendMethod2VmRegisterizedFixedBaseScalarMul (
  builder: Method2VmBuilder,
  scalar: bigint,
  activeBits = METHOD2_VM_SCALAR_BITS
): Method2VmRegisterizedScalarMulWitness {
  return appendMethod2VmRegisterizedScalarMul(
    builder,
    scalar,
    SECP256K1_G,
    activeBits
  )
}

export function appendMethod2VmRegisterizedScalarMul (
  builder: Method2VmBuilder,
  scalar: bigint,
  basePoint: SecpPoint,
  activeBits = METHOD2_VM_SCALAR_BITS,
  expectedOutput?: SecpPoint
): Method2VmRegisterizedScalarMulWitness {
  validateBasePoint(basePoint)
  if (expectedOutput !== undefined) validateBasePoint(expectedOutput)
  const scalarWitness = appendMethod2VmScalar(builder, scalar, activeBits)
  const baseCheckpointStart = builder.rowCount()
  appendMethod2VmPointRegisterCheckpoint(builder, basePoint)

  let accumulator = basePoint
  let base = basePoint
  let borrowIn = 1n
  let additions = 0
  let doublings = 0
  let candidateAdditions = 0
  let candidateDoublings = 0
  let stateCheckpoints = 1
  let stateCarries = 0
  let branchMuxes = 0
  let scalarSteps = 0
  let publicOutputBindings = 0
  const compressedOutputBindings = 0

  appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
  appendMethod2VmPointRegisterCheckpoint(builder, base)
  stateCheckpoints += 2

  for (let bit = 0; bit < activeBits; bit++) {
    const previousAccumulator = accumulator
    const previousBase = base
    const decrementedBit = BigInt(scalarWitness.decrementedBits[bit])
    const borrowOut = BigInt(scalarWitness.borrowOuts[bit])
    const addSelector = scalarWitness.addSelectors[bit] as 0 | 1
    const doubleSelector = scalarWitness.doubleSelectors[bit] as 0 | 1
    const doubleCandidate = appendMethod2VmPointDouble(
      builder,
      previousAccumulator
    )
    const addCandidate = appendMethod2VmConditionalPointAddDistinct(
      builder,
      addSelector,
      decrementedBit,
      borrowIn,
      previousAccumulator,
      previousBase
    )
    const activeCandidate = appendMethod2VmLinkedPointMux(
      builder,
      addSelector,
      doubleCandidate,
      addCandidate,
      () => appendAddSelectorSeedRows(
        builder,
        decrementedBit,
        borrowIn,
        addSelector
      )
    )
    if (bit === activeBits - 1 && expectedOutput !== undefined) {
      accumulator = appendMethod2VmLinkedPointMuxToExpected(
        builder,
        Number(decrementedBit) as 0 | 1,
        previousAccumulator,
        activeCandidate,
        expectedOutput,
        () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
      )
      publicOutputBindings++
    } else {
      accumulator = appendMethod2VmLinkedPointMux(
        builder,
        Number(decrementedBit) as 0 | 1,
        previousAccumulator,
        activeCandidate,
        () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
      )
    }
    appendMethod2VmPointRegisterCarry(builder, accumulator, accumulator)
    if (addSelector === 1) additions++
    if (doubleSelector === 1) doublings++
    candidateAdditions++
    candidateDoublings++
    branchMuxes += 2
    scalarSteps++
    stateCarries++

    borrowIn = borrowOut
    if (bit < activeBits - 1) {
      base = appendMethod2VmPointDouble(builder, base)
      appendMethod2VmPointRegisterCarry(builder, previousBase, previousBase)
      appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
      appendMethod2VmPointRegisterCheckpoint(builder, base)
      stateCarries++
      stateCheckpoints += 2
      doublings++
    }
  }

  if (borrowIn !== 0n) {
    throw new Error('Method 2 VM scalar multiplication borrow mismatch')
  }
  const expected = scalarMultiply(scalar, basePoint)
  if (!pointsEqual(accumulator, expected)) {
    throw new Error('Method 2 VM scalar multiplication witness mismatch')
  }

  return {
    scalar: scalarWitness,
    base: basePoint,
    output: accumulator,
    activeBits,
    additions,
    doublings,
    stateCheckpoints,
    stateCarries,
    branchMuxes,
    scalarSteps,
    candidateAdditions,
    candidateDoublings,
    baseCheckpointStart,
    publicOutputBindings,
    compressedOutputBindings
  }
}

export function buildMethod2VmScalarMulProgram (
  scalar: bigint,
  basePoint: SecpPoint,
  expectedOutput: SecpPoint,
  activeBits = METHOD2_VM_SCALAR_BITS,
  publicInputDigest?: number[]
): Method2VmScalarMulProgram {
  validateBasePoint(expectedOutput)
  const builder = new Method2VmBuilder()
  const witness = appendMethod2VmRegisterizedScalarMul(
    builder,
    scalar,
    basePoint,
    activeBits,
    expectedOutput
  )
  fixPointRegisterCheckpointRows(builder, witness.baseCheckpointStart, basePoint)
  if (!pointsEqual(witness.output, expectedOutput)) {
    throw new Error('Method 2 VM scalar multiplication public output mismatch')
  }
  const program = builder.build(publicInputDigest)
  return { program, witness }
}

export function buildMethod2VmScalarMulVerifierProgram (
  basePoint: SecpPoint,
  expectedOutput: SecpPoint,
  activeBits = METHOD2_VM_SCALAR_BITS,
  publicInputDigest?: number[]
): Method2VmProgram {
  validateBasePoint(basePoint)
  validateBasePoint(expectedOutput)
  const builder = new Method2VmBuilder()
  const witness = appendMethod2VmRegisterizedScalarMul(
    builder,
    1n,
    basePoint,
    activeBits,
    expectedOutput
  )
  fixPointRegisterCheckpointRows(builder, witness.baseCheckpointStart, basePoint)
  return builder.build(publicInputDigest)
}

export function appendMethod2VmRegisterizedScalarMulCompressedPoint (
  builder: Method2VmBuilder,
  scalar: bigint,
  basePoint: SecpPoint,
  activeBits = METHOD2_VM_SCALAR_BITS
): Method2VmScalarMulCompressedWitness {
  validateBasePoint(basePoint)
  const scalarWitness = appendMethod2VmScalar(builder, scalar, activeBits)
  const baseCheckpointStart = builder.rowCount()
  appendMethod2VmPointRegisterCheckpoint(builder, basePoint)

  let accumulator = basePoint
  let base = basePoint
  let borrowIn = 1n
  let additions = 0
  let doublings = 0
  let candidateAdditions = 0
  let candidateDoublings = 0
  let stateCheckpoints = 1
  let stateCarries = 0
  let branchMuxes = 0
  let scalarSteps = 0
  let compressedOutputBindings = 0

  appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
  appendMethod2VmPointRegisterCheckpoint(builder, base)
  stateCheckpoints += 2

  for (let bit = 0; bit < activeBits; bit++) {
    const previousAccumulator = accumulator
    const previousBase = base
    const decrementedBit = BigInt(scalarWitness.decrementedBits[bit])
    const borrowOut = BigInt(scalarWitness.borrowOuts[bit])
    const addSelector = scalarWitness.addSelectors[bit] as 0 | 1
    const doubleSelector = scalarWitness.doubleSelectors[bit] as 0 | 1
    const doubleCandidate = appendMethod2VmPointDouble(
      builder,
      previousAccumulator
    )
    const addCandidate = appendMethod2VmConditionalPointAddDistinct(
      builder,
      addSelector,
      decrementedBit,
      borrowIn,
      previousAccumulator,
      previousBase
    )
    const activeCandidate = appendMethod2VmLinkedPointMux(
      builder,
      addSelector,
      doubleCandidate,
      addCandidate,
      () => appendAddSelectorSeedRows(
        builder,
        decrementedBit,
        borrowIn,
        addSelector
      )
    )
    if (bit === activeBits - 1) {
      accumulator = Number(decrementedBit) === 1
        ? activeCandidate
        : previousAccumulator
      const compressed = appendMethod2VmCompressedPointWithLinkedLimbs(
        builder,
        accumulator,
        (limb, value, destination) => {
          appendMethod2VmFinalMuxLimb(
            builder,
            Number(decrementedBit) as 0 | 1,
            previousAccumulator,
            activeCandidate,
            limb,
            value,
            destination,
            () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
          )
          compressedOutputBindings++
        }
      )
      branchMuxes += 1
      scalarSteps++
      if (addSelector === 1) additions++
      if (doubleSelector === 1) doublings++
      candidateAdditions++
      candidateDoublings++
      if (borrowOut !== 0n) {
        throw new Error('Method 2 VM scalar multiplication borrow mismatch')
      }
      const expected = scalarMultiply(scalar, basePoint)
      if (!pointsEqual(accumulator, expected)) {
        throw new Error('Method 2 VM scalar multiplication witness mismatch')
      }
      return {
        scalarMul: {
          scalar: scalarWitness,
          base: basePoint,
          output: accumulator,
          activeBits,
          additions,
          doublings,
          stateCheckpoints,
          stateCarries,
          branchMuxes,
          scalarSteps,
          candidateAdditions,
          candidateDoublings,
          baseCheckpointStart,
          publicOutputBindings: 0,
          compressedOutputBindings
        },
        compressed
      }
    }

    accumulator = appendMethod2VmLinkedPointMux(
      builder,
      Number(decrementedBit) as 0 | 1,
      previousAccumulator,
      activeCandidate,
      () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
    )
    appendMethod2VmPointRegisterCarry(builder, accumulator, accumulator)
    if (addSelector === 1) additions++
    if (doubleSelector === 1) doublings++
    candidateAdditions++
    candidateDoublings++
    branchMuxes += 2
    scalarSteps++
    stateCarries++

    borrowIn = borrowOut
    base = appendMethod2VmPointDouble(builder, base)
    appendMethod2VmPointRegisterCarry(builder, previousBase, previousBase)
    appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
    appendMethod2VmPointRegisterCheckpoint(builder, base)
    stateCarries++
    stateCheckpoints += 2
    doublings++
  }

  throw new Error('Method 2 VM scalar multiplication has no active steps')
}

export function appendMethod2VmRegisterizedScalarMulHmacInput (
  builder: Method2VmBuilder,
  scalar: bigint,
  basePoint: SecpPoint,
  invoice: number[],
  linkage: number[],
  activeBits = METHOD2_VM_SCALAR_BITS,
  validateHmacWitness = true
): Method2VmScalarMulHmacInputWitness {
  validateBasePoint(basePoint)
  const hmacBuilder = new Method2VmHmacInputBuilder(
    builder,
    invoice,
    linkage
  )
  const scalarWitness = appendMethod2VmScalar(builder, scalar, activeBits)
  const baseCheckpointStart = builder.rowCount()
  appendMethod2VmPointRegisterCheckpoint(builder, basePoint)

  let accumulator = basePoint
  let base = basePoint
  let borrowIn = 1n
  let additions = 0
  let doublings = 0
  let candidateAdditions = 0
  let candidateDoublings = 0
  let stateCheckpoints = 1
  let stateCarries = 0
  let branchMuxes = 0
  let scalarSteps = 0
  let compressedOutputBindings = 0

  appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
  appendMethod2VmPointRegisterCheckpoint(builder, base)
  stateCheckpoints += 2

  for (let bit = 0; bit < activeBits; bit++) {
    const previousAccumulator = accumulator
    const previousBase = base
    const decrementedBit = BigInt(scalarWitness.decrementedBits[bit])
    const borrowOut = BigInt(scalarWitness.borrowOuts[bit])
    const addSelector = scalarWitness.addSelectors[bit] as 0 | 1
    const doubleSelector = scalarWitness.doubleSelectors[bit] as 0 | 1
    const doubleCandidate = appendMethod2VmPointDouble(
      builder,
      previousAccumulator
    )
    const addCandidate = appendMethod2VmConditionalPointAddDistinct(
      builder,
      addSelector,
      decrementedBit,
      borrowIn,
      previousAccumulator,
      previousBase
    )
    const activeCandidate = appendMethod2VmLinkedPointMux(
      builder,
      addSelector,
      doubleCandidate,
      addCandidate,
      () => appendAddSelectorSeedRows(
        builder,
        decrementedBit,
        borrowIn,
        addSelector
      )
    )
    if (bit === activeBits - 1) {
      accumulator = Number(decrementedBit) === 1
        ? activeCandidate
        : previousAccumulator
      const compressed = appendMethod2VmCompressedPointWithLinkedLimbs(
        builder,
        accumulator,
        (limb, value, destination) => {
          appendMethod2VmFinalMuxLimb(
            builder,
            Number(decrementedBit) as 0 | 1,
            previousAccumulator,
            activeCandidate,
            limb,
            value,
            destination,
            () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
          )
          compressedOutputBindings++
        },
        (byteIndex, value) => hmacBuilder.consumeSharedByte(byteIndex, value)
      )
      branchMuxes += 1
      scalarSteps++
      if (addSelector === 1) additions++
      if (doubleSelector === 1) doublings++
      candidateAdditions++
      candidateDoublings++
      if (borrowOut !== 0n) {
        throw new Error('Method 2 VM scalar multiplication borrow mismatch')
      }
      const expected = scalarMultiply(scalar, basePoint)
      if (!pointsEqual(accumulator, expected)) {
        throw new Error('Method 2 VM scalar multiplication witness mismatch')
      }
      const scalarMul = {
        scalar: scalarWitness,
        base: basePoint,
        output: accumulator,
        activeBits,
        additions,
        doublings,
        stateCheckpoints,
        stateCarries,
        branchMuxes,
        scalarSteps,
        candidateAdditions,
        candidateDoublings,
        baseCheckpointStart,
        publicOutputBindings: 0,
        compressedOutputBindings
      }
      return {
        scalarMul,
        compressed,
        hmac: hmacBuilder.finish({ validateLinkage: validateHmacWitness })
      }
    }

    accumulator = appendMethod2VmLinkedPointMux(
      builder,
      Number(decrementedBit) as 0 | 1,
      previousAccumulator,
      activeCandidate,
      () => builder.assertEqLinked(decrementedBit, decrementedBit, 'a')
    )
    appendMethod2VmPointRegisterCarry(builder, accumulator, accumulator)
    if (addSelector === 1) additions++
    if (doubleSelector === 1) doublings++
    candidateAdditions++
    candidateDoublings++
    branchMuxes += 2
    scalarSteps++
    stateCarries++

    borrowIn = borrowOut
    base = appendMethod2VmPointDouble(builder, base)
    appendMethod2VmPointRegisterCarry(builder, previousBase, previousBase)
    appendMethod2VmPointRegisterCheckpoint(builder, accumulator)
    appendMethod2VmPointRegisterCheckpoint(builder, base)
    stateCarries++
    stateCheckpoints += 2
    doublings++
  }

  throw new Error('Method 2 VM scalar multiplication has no active steps')
}

export function appendMethod2VmPointRegisterCheckpoint (
  builder: Method2VmBuilder,
  point: SecpPoint
): void {
  validateBasePoint(point)
  const limbs = pointLimbs(point)
  for (const limb of limbs) {
    new Method2VmRegisterProgramBuilder(builder)
      .seed(limb)
      .assertEq(limb)
  }
}

export function appendMethod2VmPointRegisterCarry (
  builder: Method2VmBuilder,
  from: SecpPoint,
  to: SecpPoint
): void {
  validateBasePoint(from)
  validateBasePoint(to)
  const fromLimbs = pointLimbs(from)
  const toLimbs = pointLimbs(to)
  for (let i = 0; i < fromLimbs.length; i++) {
    new Method2VmRegisterProgramBuilder(builder)
      .seed(fromLimbs[i])
      .assertEq(toLimbs[i])
  }
}

export function appendMethod2VmPointMux (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  ifZero: SecpPoint,
  ifOne: SecpPoint
): SecpPoint {
  return appendMethod2VmLinkedPointMux(builder, selector, ifZero, ifOne)
}

export function appendMethod2VmLinkedPointMux (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  ifZero: SecpPoint,
  ifOne: SecpPoint,
  seedSelector: () => void = () => {
    builder.assertEqLinked(selector, selector, 'a')
  }
): SecpPoint {
  validateBasePoint(ifZero)
  validateBasePoint(ifOne)
  const zeroLimbs = pointLimbs(ifZero)
  const oneLimbs = pointLimbs(ifOne)
  const selectedLimbs: number[] = []
  for (let i = 0; i < zeroLimbs.length; i++) {
    const selected = selector === 1 ? oneLimbs[i] : zeroLimbs[i]
    seedSelector()
    builder.assertSelectBitLinked(
      selector,
      zeroLimbs[i],
      oneLimbs[i],
      selected,
      'a'
    )
    builder.assertEq(selected, selected)
    selectedLimbs.push(selected)
  }
  return pointFromLimbs(selectedLimbs)
}

export function appendMethod2VmLinkedPointMuxToExpected (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  ifZero: SecpPoint,
  ifOne: SecpPoint,
  expected: SecpPoint,
  seedSelector: () => void = () => {
    builder.assertEqLinked(selector, selector, 'a')
  }
): SecpPoint {
  validateBasePoint(ifZero)
  validateBasePoint(ifOne)
  validateBasePoint(expected)
  const zeroLimbs = pointLimbs(ifZero)
  const oneLimbs = pointLimbs(ifOne)
  const expectedLimbs = pointLimbs(expected)
  const selectedLimbs: number[] = []
  for (let i = 0; i < zeroLimbs.length; i++) {
    const selected = selector === 1 ? oneLimbs[i] : zeroLimbs[i]
    seedSelector()
    builder.assertSelectBitLinked(
      selector,
      zeroLimbs[i],
      oneLimbs[i],
      selected,
      'a'
    )
    const row = builder.rowCount()
    builder.assertEq(selected, expectedLimbs[i])
    builder.fixCell(row, METHOD2_VM_LAYOUT.b, expectedLimbs[i])
    selectedLimbs.push(selected)
  }
  return pointFromLimbs(selectedLimbs)
}

function appendMethod2VmFinalMuxLimb (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  ifZero: SecpPoint,
  ifOne: SecpPoint,
  limb: number,
  expectedValue: number,
  destination: Method2VmLinkDestination,
  seedSelector: () => void
): void {
  validateBasePoint(ifZero)
  validateBasePoint(ifOne)
  const zeroLimbs = pointLimbs(ifZero)
  const oneLimbs = pointLimbs(ifOne)
  const selected = selector === 1 ? oneLimbs[limb] : zeroLimbs[limb]
  if (selected !== expectedValue) {
    throw new Error('Method 2 VM final mux limb mismatch')
  }
  seedSelector()
  builder.assertSelectBitLinked(
    selector,
    zeroLimbs[limb],
    oneLimbs[limb],
    selected,
    destination
  )
}

function appendMethod2VmConditionalPointAddDistinct (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  decrementedBit: bigint,
  borrowIn: bigint,
  accumulator: SecpPoint,
  base: SecpPoint
): SecpPoint {
  const addLeft = selector === 1 ? accumulator : SECP256K1_G
  const addRight = selector === 1 ? base : pointDouble(SECP256K1_G)
  const output = appendMethod2VmPointAddDistinct(builder, addLeft, addRight)
  appendConditionalPointEquality(
    builder,
    selector,
    addLeft,
    accumulator,
    () => appendAddSelectorSeedRows(
      builder,
      decrementedBit,
      borrowIn,
      selector
    )
  )
  appendConditionalPointEquality(
    builder,
    selector,
    addRight,
    base,
    () => appendAddSelectorSeedRows(
      builder,
      decrementedBit,
      borrowIn,
      selector
    )
  )
  return output
}

function appendConditionalPointEquality (
  builder: Method2VmBuilder,
  selector: 0 | 1,
  maybePublic: SecpPoint,
  expectedWhenSelected: SecpPoint,
  seedSelector: () => void
): void {
  const actualLimbs = pointLimbs(maybePublic)
  const expectedLimbs = pointLimbs(expectedWhenSelected)
  for (let i = 0; i < actualLimbs.length; i++) {
    seedSelector()
    builder.assertSelectBitLinked(
      selector,
      actualLimbs[i],
      expectedLimbs[i],
      actualLimbs[i],
      'a'
    )
    builder.assertEq(actualLimbs[i], actualLimbs[i])
  }
}

function appendAddSelectorSeedRows (
  builder: Method2VmBuilder,
  decrementedBit: bigint,
  borrowIn: bigint,
  addSelector: 0 | 1
): void {
  const oneMinusBorrow = 1n - borrowIn
  builder.assertAdd(oneMinusBorrow, borrowIn, 1n)
  builder.assertMulLinked(decrementedBit, oneMinusBorrow, addSelector, 'a')
}

export function fixPointRegisterCheckpointRows (
  builder: Method2VmBuilder,
  start: number,
  point: SecpPoint
): Method2VmFixedCell[] {
  const fixedCells: Method2VmFixedCell[] = []
  const limbs = pointLimbs(point)
  for (let i = 0; i < limbs.length; i++) {
    const row = start + i * 2
    for (const column of [METHOD2_VM_LAYOUT.a, METHOD2_VM_LAYOUT.b]) {
      const cell = {
        row,
        column,
        value: BigInt(limbs[i])
      }
      builder.fixCell(cell.row, cell.column, cell.value)
      fixedCells.push(cell)
    }
  }
  return fixedCells
}

function appendScalarBitMaterializationRows (
  builder: Method2VmBuilder,
  bits: number[],
  decrementedBits: number[],
  limbs: number[],
  minusOneLimbs: number[],
  activeBits: number
): {
    borrowIns: number[]
    borrowOuts: number[]
    addSelectors: number[]
    doubleSelectors: number[]
  } {
  const borrowIns: number[] = []
  const borrowOuts: number[] = []
  const addSelectors: number[] = []
  const doubleSelectors: number[] = []
  let borrowIn = 1
  for (let limb = 0; limb < METHOD2_VM_SCALAR_LIMBS; limb++) {
    let scalarAccumulator = 0
    let decrementedAccumulator = 0
    for (let bit = 0; bit < 16; bit++) {
      const bitIndex = limb * 16 + bit
      const scalarBit = bits[bitIndex]
      const decrementedBit = decrementedBits[bitIndex]
      const borrowOut = Number(
        (BigInt(decrementedBit) + BigInt(borrowIn) - BigInt(scalarBit)) / 2n
      )
      const oneMinusBorrow = 1 - borrowIn
      const addSelector = decrementedBit * oneMinusBorrow
      const doubleSelector = decrementedBit * borrowIn
      const bitWeight = 1 << bit
      const nextScalarAccumulator =
        scalarAccumulator + scalarBit * bitWeight
      const nextDecrementedAccumulator =
        decrementedAccumulator + decrementedBit * bitWeight
      if (
        scalarBit - borrowIn - decrementedBit + borrowOut * 2 !== 0 ||
        (borrowOut !== 0 && borrowOut !== 1)
      ) {
        throw new Error('Method 2 VM scalar bit borrow mismatch')
      }
      builder.assertScalarBit(
        scalarBit as 0 | 1,
        decrementedBit as 0 | 1,
        borrowIn as 0 | 1,
        borrowOut,
        bitWeight,
        scalarAccumulator,
        nextScalarAccumulator,
        decrementedAccumulator,
        nextDecrementedAccumulator,
        limbs[limb],
        minusOneLimbs[limb],
        bitIndex < activeBits ? 1 : 0,
        bit === 0 ? 1 : 0,
        bit === 15 ? 1 : 0,
        bit === 15 ? 0 : 1
      )
      borrowIns.push(borrowIn)
      borrowOuts.push(borrowOut)
      addSelectors.push(addSelector)
      doubleSelectors.push(doubleSelector)
      borrowIn = borrowOut
      scalarAccumulator = nextScalarAccumulator
      decrementedAccumulator = nextDecrementedAccumulator
    }
    if (scalarAccumulator !== limbs[limb]) {
      throw new Error('Method 2 VM scalar limb reconstruction mismatch')
    }
    if (decrementedAccumulator !== minusOneLimbs[limb]) {
      throw new Error('Method 2 VM decremented limb reconstruction mismatch')
    }
  }
  if (borrowIn !== 0) {
    throw new Error('Method 2 VM scalar decrement final borrow mismatch')
  }
  return {
    borrowIns,
    borrowOuts,
    addSelectors,
    doubleSelectors
  }
}

function appendScalarRangeRows (
  builder: Method2VmBuilder,
  limbs: number[],
  rangeDiffLimbs: number[]
): void {
  let carry = 1n
  for (let limb = 0; limb < METHOD2_VM_SCALAR_LIMBS; limb++) {
    const carryOut = (
      BigInt(limbs[limb]) +
      BigInt(rangeDiffLimbs[limb]) +
      carry -
      BigInt(N_LIMBS[limb])
    ) / 65536n
    if (limb < METHOD2_VM_SCALAR_LIMBS - 1) {
      builder.assertFieldAddLimbCarryLinked(
        limbs[limb],
        rangeDiffLimbs[limb],
        N_LIMBS[limb],
        0,
        0,
        carry,
        carryOut
      )
    } else {
      builder.assertFieldAddLimb(
        limbs[limb],
        rangeDiffLimbs[limb],
        N_LIMBS[limb],
        0,
        0,
        carry,
        carryOut
      )
    }
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM scalar range carry mismatch')
  }
}

function appendScalarMinusOneRows (
  builder: Method2VmBuilder,
  limbs: number[],
  minusOneLimbs: number[]
): void {
  let carry = 0n
  for (let limb = 0; limb < METHOD2_VM_SCALAR_LIMBS; limb++) {
    const addend = limb === 0 ? 1 : 0
    const carryOut = (
      BigInt(minusOneLimbs[limb]) +
      BigInt(addend) +
      carry -
      BigInt(limbs[limb])
    ) / 65536n
    if (limb < METHOD2_VM_SCALAR_LIMBS - 1) {
      builder.assertFieldAddLimbCarryLinked(
        minusOneLimbs[limb],
        addend,
        limbs[limb],
        0,
        0,
        carry,
        carryOut
      )
    } else {
      builder.assertFieldAddLimb(
        minusOneLimbs[limb],
        addend,
        limbs[limb],
        0,
        0,
        carry,
        carryOut
      )
    }
    carry = carryOut
  }
  if (carry !== 0n) {
    throw new Error('Method 2 VM scalar nonzero carry mismatch')
  }
}

function appendBorrowRows (
  builder: Method2VmBuilder,
  scalarBit: bigint,
  decrementedBit: bigint,
  borrowIn: bigint,
  borrowOut: bigint
): void {
  if (
    scalarBit - borrowIn - decrementedBit + borrowOut * 2n !== 0n ||
    (borrowOut !== 0n && borrowOut !== 1n)
  ) {
    throw new Error('Method 2 VM scalar decrement witness mismatch')
  }
  const doubledBorrowOut = borrowOut * 2n
  const left = scalarBit + doubledBorrowOut
  const right = borrowIn + decrementedBit

  builder.assertBool(Number(scalarBit) as 0 | 1)
  builder.assertBool(Number(decrementedBit) as 0 | 1)
  builder.assertBool(Number(borrowIn) as 0 | 1)
  builder.assertBool(Number(borrowOut) as 0 | 1)
  builder.assertMul(2, borrowOut, doubledBorrowOut)
  builder.assertAdd(scalarBit, doubledBorrowOut, left)
  builder.assertAdd(borrowIn, decrementedBit, right)
  builder.assertEq(left, right)
}

function validateScalarInputs (
  scalar: bigint,
  activeBits: number
): void {
  validateScalar(scalar)
  if (
    !Number.isInteger(activeBits) ||
    activeBits < 1 ||
    activeBits > METHOD2_VM_SCALAR_BITS
  ) {
    throw new Error('Method 2 VM scalar multiplication bit count is invalid')
  }
  if (
    activeBits < METHOD2_VM_SCALAR_BITS &&
    scalar >= (1n << BigInt(activeBits))
  ) {
    throw new Error('Method 2 VM scalar does not fit in active bit count')
  }
}

function validateBasePoint (point: SecpPoint): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error('Method 2 VM scalar multiplication base must be affine')
  }
}

function pointLimbs (point: SecpPoint): number[] {
  return [
    ...bigintToU16LimbsLE(point.x, METHOD2_VM_SCALAR_LIMBS),
    ...bigintToU16LimbsLE(point.y, METHOD2_VM_SCALAR_LIMBS)
  ]
}

function pointFromLimbs (limbs: number[]): SecpPoint {
  if (limbs.length !== METHOD2_VM_SCALAR_LIMBS * 2) {
    throw new Error('Method 2 VM point limb count is invalid')
  }
  const x = limbsToBigint(limbs.slice(0, METHOD2_VM_SCALAR_LIMBS))
  const y = limbsToBigint(limbs.slice(METHOD2_VM_SCALAR_LIMBS))
  const point = { x, y }
  validateBasePoint(point)
  return point
}

function limbsToBigint (limbs: number[]): bigint {
  let out = 0n
  for (let i = limbs.length - 1; i >= 0; i--) {
    out = (out << 16n) | BigInt(limbs[i])
  }
  return out
}

function pointsEqual (
  left: SecpPoint,
  right: SecpPoint
): boolean {
  return left.infinity === right.infinity &&
    left.x === right.x &&
    left.y === right.y
}
