import {
  AirDefinition,
  FieldElement,
  F,
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  assertPowerOfTwo,
  evaluateAirTrace,
  proveStark,
  verifyStark
} from '../stark/index.js'
import { toBitsLE } from '../circuit/index.js'

export enum Method2VmOp {
  Nop = 0,
  CopyNextA = 1,
  AssertEq = 2,
  Bool = 3,
  Byte = 4,
  U16 = 5,
  Add = 6,
  Mul = 7,
  U48 = 8,
  FieldAddLimb = 9,
  FieldSubLimb = 10,
  FieldMulLimb = 11,
  Select = 12,
  SelectBit = 13,
  ScalarBit = 14,
  XorConstByte = 15
}

export interface Method2VmLayout {
  enabled: number
  pc: number
  op: number
  selectorStart: number
  selectorCount: number
  a: number
  b: number
  c: number
  auxStart: number
  auxCount: number
  width: number
}

export interface Method2VmTrace {
  rows: FieldElement[][]
  layout: Method2VmLayout
  activeLength: number
}

export interface Method2VmFixedCell {
  row: number
  column: number
  value: FieldElement
}

export interface Method2VmProgram {
  trace: Method2VmTrace
  publicInputDigest?: number[]
  fixedCells?: Method2VmFixedCell[]
}

export type Method2VmLinkDestination = 'a' | 'b' | 'c'
export type Method2VmCarryLinkDestination = Method2VmLinkDestination | 'carry'

const METHOD2_VM_OPS = [
  Method2VmOp.Nop,
  Method2VmOp.CopyNextA,
  Method2VmOp.AssertEq,
  Method2VmOp.Bool,
  Method2VmOp.Byte,
  Method2VmOp.U16,
  Method2VmOp.Add,
  Method2VmOp.Mul,
  Method2VmOp.U48,
  Method2VmOp.FieldAddLimb,
  Method2VmOp.FieldSubLimb,
  Method2VmOp.FieldMulLimb,
  Method2VmOp.Select,
  Method2VmOp.SelectBit,
  Method2VmOp.ScalarBit,
  Method2VmOp.XorConstByte
]

const U16_RADIX = 1n << 16n
const U48_RADIX = 1n << 48n
const FIELD_MUL_CARRY_OFFSET = 1n << 47n
const LINK_NEXT_A = 0
const LINK_NEXT_B = 1
const LINK_NEXT_C = 2
const LINK_NEXT_CARRY = 3
const FIELD_ADD_LINK_OFFSET = 4
const FIELD_MUL_LINK_OFFSET = 2
const SELECT_LINK_OFFSET = 1

export const METHOD2_VM_LAYOUT: Method2VmLayout = {
  enabled: 0,
  pc: 1,
  op: 2,
  selectorStart: 3,
  selectorCount: METHOD2_VM_OPS.length,
  a: 3 + METHOD2_VM_OPS.length,
  b: 4 + METHOD2_VM_OPS.length,
  c: 5 + METHOD2_VM_OPS.length,
  auxStart: 6 + METHOD2_VM_OPS.length,
  auxCount: 16,
  width: 6 + METHOD2_VM_OPS.length + 16
}

export class Method2VmBuilder {
  private readonly rows: FieldElement[][] = []
  private readonly extraFixedCells: Method2VmFixedCell[] = []

  rowCount (): number {
    return this.rows.length
  }

  fixCell (
    row: number,
    column: number,
    value: bigint | number
  ): this {
    this.extraFixedCells.push({
      row,
      column,
      value: F.normalize(BigInt(value))
    })
    return this
  }

  noop (): this {
    this.rows.push(method2VmRow(Method2VmOp.Nop, 0n, 0n, 0n, []))
    return this
  }

  copyNextA (value: bigint | number): this {
    this.rows.push(method2VmRow(Method2VmOp.CopyNextA, value, 0n, 0n, []))
    return this
  }

  assertEq (left: bigint | number, right: bigint | number): this {
    this.rows.push(method2VmRow(Method2VmOp.AssertEq, left, right, 0n, []))
    return this
  }

  assertEqLinked (
    left: bigint | number,
    right: bigint | number,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.AssertEq,
      left,
      right,
      0n,
      linkAux(destination)
    ))
    return this
  }

  assertBool (value: 0 | 1): this {
    this.rows.push(method2VmRow(Method2VmOp.Bool, value, 0n, 0n, []))
    return this
  }

  assertBoolLinked (
    value: 0 | 1,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Bool,
      value,
      0n,
      0n,
      linkAux(destination)
    ))
    return this
  }

  assertByte (value: number): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Byte,
      value,
      0n,
      0n,
      toBitsLE(BigInt(value), 8)
    ))
    return this
  }

  assertU16 (value: number): this {
    this.rows.push(method2VmRow(
      Method2VmOp.U16,
      value,
      0n,
      0n,
      toBitsLE(BigInt(value), 16)
    ))
    return this
  }

  assertAdd (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number
  ): this {
    this.rows.push(method2VmRow(Method2VmOp.Add, left, right, result, []))
    return this
  }

  assertAddLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Add,
      left,
      right,
      result,
      linkAux(destination)
    ))
    return this
  }

  assertMul (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number
  ): this {
    this.rows.push(method2VmRow(Method2VmOp.Mul, left, right, result, []))
    return this
  }

  assertMulLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Mul,
      left,
      right,
      result,
      linkAux(destination)
    ))
    return this
  }

  assertSelect (
    falseValue: bigint | number,
    trueValue: bigint | number,
    selector: 0 | 1,
    result: bigint | number
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Select,
      falseValue,
      trueValue,
      result,
      [selector]
    ))
    return this
  }

  assertSelectLinked (
    falseValue: bigint | number,
    trueValue: bigint | number,
    selector: 0 | 1,
    result: bigint | number,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.Select,
      falseValue,
      trueValue,
      result,
      [selector, ...linkAux(destination)]
    ))
    return this
  }

  assertSelectBitLinked (
    selector: 0 | 1,
    falseValue: bigint | number,
    trueValue: bigint | number,
    result: bigint | number,
    destination: Method2VmLinkDestination
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.SelectBit,
      selector,
      falseValue,
      result,
      [trueValue, ...linkAux(destination)]
    ))
    return this
  }

  assertScalarBit (
    scalarBit: 0 | 1,
    decrementedBit: 0 | 1,
    borrowIn: 0 | 1,
    borrowOut: 0 | 1,
    bitWeight: number,
    scalarAccumulatorIn: bigint | number,
    scalarAccumulatorOut: bigint | number,
    decrementedAccumulatorIn: bigint | number,
    decrementedAccumulatorOut: bigint | number,
    scalarLimb: number,
    decrementedLimb: number,
    active: 0 | 1,
    limbStart: 0 | 1,
    limbEnd: 0 | 1,
    continueAccumulator: 0 | 1
  ): this {
    const oneMinusBorrow = 1 - borrowIn
    const doubleSelector = decrementedBit * borrowIn
    const addSelector = decrementedBit * oneMinusBorrow
    this.rows.push(method2VmRow(
      Method2VmOp.ScalarBit,
      scalarBit,
      decrementedBit,
      borrowIn,
      [
        borrowOut,
        bitWeight,
        scalarAccumulatorIn,
        scalarAccumulatorOut,
        decrementedAccumulatorIn,
        decrementedAccumulatorOut,
        oneMinusBorrow,
        doubleSelector,
        addSelector,
        active,
        scalarLimb,
        decrementedLimb,
        limbEnd,
        continueAccumulator,
        limbStart,
        0
      ]
    ))
    return this
  }

  assertXorConstByteLinked (
    value: number,
    constant: number,
    result: number,
    destination: Method2VmLinkDestination
  ): this {
    assertByteNumber(value, 'Method 2 VM xor value')
    assertByteNumber(constant, 'Method 2 VM xor constant')
    assertByteNumber(result, 'Method 2 VM xor result')
    if ((value ^ constant) !== result) {
      throw new Error('Method 2 VM xor result mismatch')
    }
    const row = this.rows.length
    this.rows.push(method2VmRow(
      Method2VmOp.XorConstByte,
      value,
      constant,
      result,
      [...toBitsLE(BigInt(value), 8), ...linkAux(destination)]
    ))
    this.fixCell(row, METHOD2_VM_LAYOUT.b, constant)
    return this
  }

  assertU48 (
    value: bigint | number,
    limbs?: [number, number, number]
  ): this {
    const normalized = BigInt(value)
    if (normalized < 0n || normalized >= U48_RADIX) {
      throw new Error('Method 2 VM u48 value is out of range')
    }
    const actualLimbs = limbs ?? [
      Number(normalized & 0xffffn),
      Number((normalized >> 16n) & 0xffffn),
      Number((normalized >> 32n) & 0xffffn)
    ]
    for (const limb of actualLimbs) this.assertU16(limb)
    this.rows.push(method2VmRow(
      Method2VmOp.U48,
      normalized,
      actualLimbs[0],
      actualLimbs[1],
      [actualLimbs[2]]
    ))
    return this
  }

  assertFieldAddLimb (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.FieldAddLimb,
      left,
      right,
      result,
      [Number(modulusLimb), wrap, carryIn, carryOut]
    ))
    return this
  }

  assertFieldAddLimbLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number,
    destination: Method2VmCarryLinkDestination
  ): this {
    const aux = [
      Number(modulusLimb),
      wrap,
      carryIn,
      carryOut,
      ...carryLinkAux(destination)
    ]
    this.rows.push(method2VmRow(
      Method2VmOp.FieldAddLimb,
      left,
      right,
      result,
      aux
    ))
    return this
  }

  assertFieldAddLimbCarryLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number
  ): this {
    return this.assertFieldAddLimbLinked(
      left,
      right,
      result,
      modulusLimb,
      wrap,
      carryIn,
      carryOut,
      'carry'
    )
  }

  assertFieldSubLimb (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.FieldSubLimb,
      left,
      right,
      result,
      [Number(modulusLimb), wrap, carryIn, carryOut]
    ))
    return this
  }

  assertFieldSubLimbLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number,
    destination: Method2VmCarryLinkDestination
  ): this {
    const aux = [
      Number(modulusLimb),
      wrap,
      carryIn,
      carryOut,
      ...carryLinkAux(destination)
    ]
    this.rows.push(method2VmRow(
      Method2VmOp.FieldSubLimb,
      left,
      right,
      result,
      aux
    ))
    return this
  }

  assertFieldSubLimbCarryLinked (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number,
    modulusLimb: bigint | number,
    wrap: 0 | 1,
    carryIn: bigint | number,
    carryOut: bigint | number
  ): this {
    return this.assertFieldSubLimbLinked(
      left,
      right,
      result,
      modulusLimb,
      wrap,
      carryIn,
      carryOut,
      'carry'
    )
  }

  assertFieldMulLimb (
    productLimb: bigint | number,
    resultLimb: bigint | number,
    quotientProductLimb: bigint | number,
    carryInStored: bigint | number,
    carryOutStored: bigint | number
  ): this {
    this.rows.push(method2VmRow(
      Method2VmOp.FieldMulLimb,
      productLimb,
      resultLimb,
      quotientProductLimb,
      [carryInStored, carryOutStored]
    ))
    return this
  }

  assertFieldMulLimbLinked (
    productLimb: bigint | number,
    resultLimb: bigint | number,
    quotientProductLimb: bigint | number,
    carryInStored: bigint | number,
    carryOutStored: bigint | number,
    destination: Method2VmCarryLinkDestination
  ): this {
    const aux = [
      carryInStored,
      carryOutStored,
      ...carryLinkAux(destination)
    ]
    this.rows.push(method2VmRow(
      Method2VmOp.FieldMulLimb,
      productLimb,
      resultLimb,
      quotientProductLimb,
      aux
    ))
    return this
  }

  assertFieldMulLimbCarryLinked (
    productLimb: bigint | number,
    resultLimb: bigint | number,
    quotientProductLimb: bigint | number,
    carryInStored: bigint | number,
    carryOutStored: bigint | number
  ): this {
    return this.assertFieldMulLimbLinked(
      productLimb,
      resultLimb,
      quotientProductLimb,
      carryInStored,
      carryOutStored,
      'carry'
    )
  }

  build (publicInputDigest?: number[]): Method2VmProgram {
    const activeRows = this.rows.length > 0
      ? this.rows.map(row => row.slice())
      : [method2VmRow(Method2VmOp.Nop, 0n, 0n, 0n, [])]
    for (let i = 0; i < activeRows.length; i++) {
      activeRows[i][METHOD2_VM_LAYOUT.pc] = BigInt(i)
    }
    const paddedLength = nextPowerOfTwo(Math.max(2, activeRows.length + 1))
    const rows = activeRows.slice()
    while (rows.length < paddedLength) rows.push(disabledMethod2VmRow())
    return {
      trace: {
        rows,
        layout: METHOD2_VM_LAYOUT,
        activeLength: activeRows.length
      },
      fixedCells: [
        ...method2VmFixedControlCells(activeRows),
        ...this.extraFixedCells
      ],
      publicInputDigest
    }
  }
}

export function buildMethod2VmAir (
  program: Method2VmProgram
): AirDefinition {
  validateMethod2VmShape(program)
  return {
    traceWidth: METHOD2_VM_LAYOUT.width,
    boundaryConstraints: method2VmBoundaryConstraints(
      program.trace,
      program.fixedCells
    ),
    fullBoundaryColumns: method2VmFullBoundaryColumns(program.trace),
    transitionDegree: 6,
    publicInputDigest: program.publicInputDigest,
    evaluateTransition: (current, next) =>
      evaluateMethod2VmTransition(current, next)
  }
}

export function validateMethod2VmProgram (
  program: Method2VmProgram
): void {
  validateMethod2VmShape(program)
  const air = buildMethod2VmAir(program)
  const result = evaluateAirTrace(air, program.trace.rows)
  if (!result.valid) {
    const transition = result.transitionFailures[0]
    if (transition !== undefined) {
      throw new Error(`Method 2 VM constraint failed at row ${transition.step}`)
    }
    throw new Error('Method 2 VM boundary constraint failed')
  }
}

export function proveMethod2Vm (
  program: Method2VmProgram,
  options: StarkProverOptions = {}
): StarkProof {
  validateMethod2VmProgram(program)
  return proveStark(buildMethod2VmAir(program), program.trace.rows, options)
}

export function verifyMethod2Vm (
  program: Method2VmProgram,
  proof: StarkProof,
  options: StarkVerifierOptions = {}
): boolean {
  return verifyStark(buildMethod2VmAir(program), proof, options)
}

export function evaluateMethod2VmTransition (
  current: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const enabled = current[METHOD2_VM_LAYOUT.enabled]
  const nextEnabled = next[METHOD2_VM_LAYOUT.enabled]
  const op = current[METHOD2_VM_LAYOUT.op]
  const a = current[METHOD2_VM_LAYOUT.a]
  const b = current[METHOD2_VM_LAYOUT.b]
  const c = current[METHOD2_VM_LAYOUT.c]
  const constraints: FieldElement[] = [
    booleanConstraint(enabled),
    booleanConstraint(nextEnabled)
  ]

  let selectorSum = 0n
  let selectedOp = 0n
  for (let i = 0; i < METHOD2_VM_OPS.length; i++) {
    const selector = current[METHOD2_VM_LAYOUT.selectorStart + i]
    constraints.push(booleanConstraint(selector))
    selectorSum = F.add(selectorSum, selector)
    selectedOp = F.add(selectedOp, F.mul(selector, BigInt(METHOD2_VM_OPS[i])))
  }
  constraints.push(F.sub(selectorSum, enabled))
  constraints.push(F.sub(op, selectedOp))

  const disabled = F.sub(1n, enabled)
  for (let i = 0; i < METHOD2_VM_LAYOUT.width; i++) {
    constraints.push(F.mul(disabled, current[i]))
  }
  constraints.push(F.mul(disabled, nextEnabled))

  constraints.push(F.mul(
    F.mul(enabled, nextEnabled),
    F.sub(next[METHOD2_VM_LAYOUT.pc], F.add(current[METHOD2_VM_LAYOUT.pc], 1n))
  ))

  constraints.push(...evaluateNop(current))
  constraints.push(...evaluateCopyNextA(current, next))
  constraints.push(...evaluateAssertEq(current, next))
  constraints.push(...evaluateBool(current, next))
  constraints.push(...evaluateBitDecomposition(current, 8, Method2VmOp.Byte))
  constraints.push(...evaluateBitDecomposition(current, 16, Method2VmOp.U16))
  constraints.push(...evaluateAdd(current, next, a, b, c))
  constraints.push(...evaluateMul(current, next, a, b, c))
  constraints.push(...evaluateU48(current))
  constraints.push(...evaluateFieldAddLimb(current, next))
  constraints.push(...evaluateFieldSubLimb(current, next))
  constraints.push(...evaluateFieldMulLimb(current, next))
  constraints.push(...evaluateSelect(current, next))
  constraints.push(...evaluateSelectBit(current, next))
  constraints.push(...evaluateScalarBit(current, next))
  constraints.push(...evaluateXorConstByte(current, next))
  return constraints
}

function method2VmBoundaryConstraints (
  trace: Method2VmTrace,
  fixedCells: Method2VmFixedCell[] = []
): Array<{ column: number, row: number, value: FieldElement }> {
  const constraints: Array<{ column: number, row: number, value: FieldElement }> = []
  const finalRow = trace.rows.length - 1
  if (finalRow >= trace.activeLength) {
    for (const column of [
      METHOD2_VM_LAYOUT.a,
      METHOD2_VM_LAYOUT.b,
      METHOD2_VM_LAYOUT.c
    ]) {
      constraints.push({ column, row: finalRow, value: 0n })
    }
    for (let i = 0; i < METHOD2_VM_LAYOUT.auxCount; i++) {
      constraints.push({
        column: METHOD2_VM_LAYOUT.auxStart + i,
        row: finalRow,
        value: 0n
      })
    }
  }
  for (const fixed of fixedCells) {
    constraints.push({
      column: fixed.column,
      row: fixed.row,
      value: fixed.value
    })
  }
  return constraints
}

function method2VmFullBoundaryColumns (
  trace: Method2VmTrace
): Array<{ column: number, values: FieldElement[] }> {
  const columns = [
    METHOD2_VM_LAYOUT.enabled,
    METHOD2_VM_LAYOUT.pc,
    METHOD2_VM_LAYOUT.op
  ]
  for (let i = 0; i < METHOD2_VM_LAYOUT.selectorCount; i++) {
    columns.push(METHOD2_VM_LAYOUT.selectorStart + i)
  }
  return columns.map(column => ({
    column,
    values: trace.rows.map(row => row[column])
  }))
}

function validateMethod2VmShape (program: Method2VmProgram): void {
  const trace = program.trace
  if (trace.layout !== METHOD2_VM_LAYOUT) {
    throw new Error('Method 2 VM trace layout mismatch')
  }
  assertPowerOfTwo(trace.rows.length)
  if (
    !Number.isSafeInteger(trace.activeLength) ||
    trace.activeLength < 1 ||
    trace.activeLength >= trace.rows.length
  ) {
    throw new Error('Method 2 VM active length is invalid')
  }
  for (const row of trace.rows) {
    if (row.length !== METHOD2_VM_LAYOUT.width) {
      throw new Error('Method 2 VM row width mismatch')
    }
  }
  for (const fixed of program.fixedCells ?? []) {
    if (
      !Number.isSafeInteger(fixed.row) ||
      fixed.row < 0 ||
      fixed.row >= trace.activeLength ||
      !Number.isSafeInteger(fixed.column) ||
      fixed.column < 0 ||
      fixed.column >= METHOD2_VM_LAYOUT.width
    ) {
      throw new Error('Method 2 VM fixed cell is invalid')
    }
  }
}

function method2VmFixedControlCells (
  activeRows: FieldElement[][]
): Method2VmFixedCell[] {
  const fixedCells: Method2VmFixedCell[] = []
  for (let row = 0; row < activeRows.length; row++) {
    const op = Number(activeRows[row][METHOD2_VM_LAYOUT.op])
    if (
      op === Method2VmOp.AssertEq ||
      op === Method2VmOp.Bool ||
      op === Method2VmOp.Add ||
      op === Method2VmOp.Mul
    ) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 0, 3)
    } else if (
      op === Method2VmOp.FieldAddLimb ||
      op === Method2VmOp.FieldSubLimb
    ) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 4, 4)
    } else if (op === Method2VmOp.FieldMulLimb) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 2, 4)
    } else if (op === Method2VmOp.Select) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 1, 3)
    } else if (op === Method2VmOp.SelectBit) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 1, 3)
    } else if (op === Method2VmOp.ScalarBit) {
      pushFixedAuxOffsets(fixedCells, activeRows[row], row, [
        1,
        9,
        12,
        13,
        14,
        15
      ])
    } else if (op === Method2VmOp.XorConstByte) {
      pushFixedAuxRange(fixedCells, activeRows[row], row, 8, 3)
    }
  }
  return fixedCells
}

function pushFixedAuxOffsets (
  fixedCells: Method2VmFixedCell[],
  rowValues: FieldElement[],
  row: number,
  offsets: number[]
): void {
  for (const auxOffset of offsets) {
    const column = METHOD2_VM_LAYOUT.auxStart + auxOffset
    fixedCells.push({
      row,
      column,
      value: rowValues[column]
    })
  }
}

function pushFixedAuxRange (
  fixedCells: Method2VmFixedCell[],
  rowValues: FieldElement[],
  row: number,
  auxOffset: number,
  count: number
): void {
  for (let i = 0; i < count; i++) {
    const column = METHOD2_VM_LAYOUT.auxStart + auxOffset + i
    fixedCells.push({
      row,
      column,
      value: rowValues[column]
    })
  }
}

function method2VmRow (
  op: Method2VmOp,
  a: bigint | number,
  b: bigint | number,
  c: bigint | number,
  aux: Array<bigint | number>
): FieldElement[] {
  const row = disabledMethod2VmRow()
  const selector = METHOD2_VM_OPS.indexOf(op)
  if (selector < 0) throw new Error('Unsupported Method 2 VM op')
  row[METHOD2_VM_LAYOUT.enabled] = 1n
  row[METHOD2_VM_LAYOUT.op] = BigInt(op)
  row[METHOD2_VM_LAYOUT.selectorStart + selector] = 1n
  row[METHOD2_VM_LAYOUT.a] = F.normalize(BigInt(a))
  row[METHOD2_VM_LAYOUT.b] = F.normalize(BigInt(b))
  row[METHOD2_VM_LAYOUT.c] = F.normalize(BigInt(c))
  for (let i = 0; i < aux.length; i++) {
    row[METHOD2_VM_LAYOUT.auxStart + i] = BigInt(aux[i])
  }
  return row
}

function disabledMethod2VmRow (): FieldElement[] {
  return new Array<FieldElement>(METHOD2_VM_LAYOUT.width).fill(0n)
}

function evaluateNop (row: FieldElement[]): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.Nop)
  return gateConstraints([
    row[METHOD2_VM_LAYOUT.a],
    row[METHOD2_VM_LAYOUT.b],
    row[METHOD2_VM_LAYOUT.c],
    ...row.slice(
      METHOD2_VM_LAYOUT.auxStart,
      METHOD2_VM_LAYOUT.auxStart + METHOD2_VM_LAYOUT.auxCount
    )
  ], selector)
}

function evaluateCopyNextA (
  current: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(current, Method2VmOp.CopyNextA)
  return gateConstraints([
    F.sub(current[METHOD2_VM_LAYOUT.a], next[METHOD2_VM_LAYOUT.a]),
    current[METHOD2_VM_LAYOUT.b],
    current[METHOD2_VM_LAYOUT.c],
    ...current.slice(
      METHOD2_VM_LAYOUT.auxStart,
      METHOD2_VM_LAYOUT.auxStart + METHOD2_VM_LAYOUT.auxCount
    )
  ], selector)
}

function evaluateAssertEq (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.AssertEq)
  return gateConstraints([
    F.sub(row[METHOD2_VM_LAYOUT.a], row[METHOD2_VM_LAYOUT.b]),
    ...evaluateLinkedNextConstraints(row, next, row[METHOD2_VM_LAYOUT.a], 0)
  ], selector)
}

function evaluateBool (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const value = row[METHOD2_VM_LAYOUT.a]
  const selector = method2VmSelector(row, Method2VmOp.Bool)
  return gateConstraints([
    booleanConstraint(value),
    ...evaluateLinkedNextConstraints(row, next, value, 0)
  ], selector)
}

function evaluateBitDecomposition (
  row: FieldElement[],
  width: number,
  op: Method2VmOp
): FieldElement[] {
  const selector = method2VmSelector(row, op)
  const constraints: FieldElement[] = []
  let value = 0n
  for (let bit = 0; bit < METHOD2_VM_LAYOUT.auxCount; bit++) {
    const bitValue = row[METHOD2_VM_LAYOUT.auxStart + bit]
    if (bit < width) {
      constraints.push(F.mul(selector, booleanConstraint(bitValue)))
      value = F.add(value, F.mul(bitValue, BigInt(1 << bit)))
    } else {
      constraints.push(F.mul(selector, bitValue))
    }
  }
  constraints.push(F.mul(selector, F.sub(row[METHOD2_VM_LAYOUT.a], value)))
  return constraints
}

function evaluateAdd (
  row: FieldElement[],
  next: FieldElement[],
  left: FieldElement,
  right: FieldElement,
  result: FieldElement
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.Add)
  return gateConstraints([
    F.sub(F.add(left, right), result),
    ...evaluateLinkedNextConstraints(row, next, result, 0)
  ], selector)
}

function evaluateMul (
  row: FieldElement[],
  next: FieldElement[],
  left: FieldElement,
  right: FieldElement,
  result: FieldElement
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.Mul)
  return gateConstraints([
    F.sub(F.mul(left, right), result),
    ...evaluateLinkedNextConstraints(row, next, result, 0)
  ], selector)
}

function evaluateU48 (row: FieldElement[]): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.U48)
  const limb0 = row[METHOD2_VM_LAYOUT.b]
  const limb1 = row[METHOD2_VM_LAYOUT.c]
  const limb2 = row[METHOD2_VM_LAYOUT.auxStart]
  return gateConstraints([
    F.sub(
      row[METHOD2_VM_LAYOUT.a],
      F.add(
        F.add(limb0, F.mul(limb1, U16_RADIX)),
        F.mul(limb2, U16_RADIX * U16_RADIX)
      )
    ),
    ...row.slice(
      METHOD2_VM_LAYOUT.auxStart + 1,
      METHOD2_VM_LAYOUT.auxStart + METHOD2_VM_LAYOUT.auxCount
    )
  ], selector)
}

function evaluateSelect (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.Select)
  const choice = row[METHOD2_VM_LAYOUT.auxStart]
  const falseValue = row[METHOD2_VM_LAYOUT.a]
  const trueValue = row[METHOD2_VM_LAYOUT.b]
  const result = row[METHOD2_VM_LAYOUT.c]
  return gateConstraints([
    booleanConstraint(choice),
    F.sub(
      result,
      F.add(falseValue, F.mul(choice, F.sub(trueValue, falseValue)))
    ),
    ...evaluateLinkedNextConstraints(
      row,
      next,
      result,
      SELECT_LINK_OFFSET
    )
  ], selector)
}

function evaluateSelectBit (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.SelectBit)
  const choice = row[METHOD2_VM_LAYOUT.a]
  const falseValue = row[METHOD2_VM_LAYOUT.b]
  const result = row[METHOD2_VM_LAYOUT.c]
  const trueValue = row[METHOD2_VM_LAYOUT.auxStart]
  return gateConstraints([
    booleanConstraint(choice),
    F.sub(
      result,
      F.add(falseValue, F.mul(choice, F.sub(trueValue, falseValue)))
    ),
    ...evaluateLinkedNextConstraints(
      row,
      next,
      result,
      SELECT_LINK_OFFSET
    )
  ], selector)
}

function evaluateScalarBit (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.ScalarBit)
  const scalarBit = row[METHOD2_VM_LAYOUT.a]
  const decrementedBit = row[METHOD2_VM_LAYOUT.b]
  const borrowIn = row[METHOD2_VM_LAYOUT.c]
  const borrowOut = row[METHOD2_VM_LAYOUT.auxStart]
  const bitWeight = row[METHOD2_VM_LAYOUT.auxStart + 1]
  const scalarAccumulatorIn = row[METHOD2_VM_LAYOUT.auxStart + 2]
  const scalarAccumulatorOut = row[METHOD2_VM_LAYOUT.auxStart + 3]
  const decrementedAccumulatorIn = row[METHOD2_VM_LAYOUT.auxStart + 4]
  const decrementedAccumulatorOut = row[METHOD2_VM_LAYOUT.auxStart + 5]
  const oneMinusBorrow = row[METHOD2_VM_LAYOUT.auxStart + 6]
  const doubleSelector = row[METHOD2_VM_LAYOUT.auxStart + 7]
  const addSelector = row[METHOD2_VM_LAYOUT.auxStart + 8]
  const active = row[METHOD2_VM_LAYOUT.auxStart + 9]
  const scalarLimb = row[METHOD2_VM_LAYOUT.auxStart + 10]
  const decrementedLimb = row[METHOD2_VM_LAYOUT.auxStart + 11]
  const limbEnd = row[METHOD2_VM_LAYOUT.auxStart + 12]
  const continueAccumulator = row[METHOD2_VM_LAYOUT.auxStart + 13]
  const limbStart = row[METHOD2_VM_LAYOUT.auxStart + 14]
  const reserved = row[METHOD2_VM_LAYOUT.auxStart + 15]
  return gateConstraints([
    booleanConstraint(scalarBit),
    booleanConstraint(decrementedBit),
    booleanConstraint(borrowIn),
    booleanConstraint(borrowOut),
    booleanConstraint(oneMinusBorrow),
    booleanConstraint(doubleSelector),
    booleanConstraint(addSelector),
    booleanConstraint(active),
    booleanConstraint(limbEnd),
    booleanConstraint(continueAccumulator),
    booleanConstraint(limbStart),
    reserved,
    F.mul(F.sub(1n, active), scalarBit),
    F.mul(F.sub(1n, active), decrementedBit),
    F.sub(F.add(oneMinusBorrow, borrowIn), 1n),
    F.add(
      F.sub(F.sub(scalarBit, borrowIn), decrementedBit),
      F.mul(2n, borrowOut)
    ),
    F.sub(doubleSelector, F.mul(decrementedBit, borrowIn)),
    F.sub(addSelector, F.mul(decrementedBit, oneMinusBorrow)),
    F.sub(F.add(doubleSelector, addSelector), decrementedBit),
    F.sub(
      scalarAccumulatorOut,
      F.add(scalarAccumulatorIn, F.mul(scalarBit, bitWeight))
    ),
    F.sub(
      decrementedAccumulatorOut,
      F.add(
        decrementedAccumulatorIn,
        F.mul(decrementedBit, bitWeight)
      )
    ),
    F.mul(limbStart, scalarAccumulatorIn),
    F.mul(limbStart, decrementedAccumulatorIn),
    F.mul(limbEnd, F.sub(scalarAccumulatorOut, scalarLimb)),
    F.mul(limbEnd, F.sub(decrementedAccumulatorOut, decrementedLimb)),
    F.mul(
      continueAccumulator,
      F.sub(next[METHOD2_VM_LAYOUT.auxStart + 2], scalarAccumulatorOut)
    ),
    F.mul(
      continueAccumulator,
      F.sub(
        next[METHOD2_VM_LAYOUT.auxStart + 4],
        decrementedAccumulatorOut
      )
    )
  ], selector)
}

function evaluateXorConstByte (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.XorConstByte)
  const value = row[METHOD2_VM_LAYOUT.a]
  const constant = row[METHOD2_VM_LAYOUT.b]
  const result = row[METHOD2_VM_LAYOUT.c]
  const constraints: FieldElement[] = []
  let reconstructedValue = 0n
  let reconstructedResult = 0n
  for (let bit = 0; bit < 8; bit++) {
    const bitValue = row[METHOD2_VM_LAYOUT.auxStart + bit]
    const constantBit = bitOfFieldElement(constant, bit)
    constraints.push(booleanConstraint(bitValue))
    reconstructedValue = F.add(
      reconstructedValue,
      F.mul(bitValue, BigInt(1 << bit))
    )
    reconstructedResult = F.add(
      reconstructedResult,
      F.mul(
        constantBit === 0 ? bitValue : F.sub(1n, bitValue),
        BigInt(1 << bit)
      )
    )
  }
  constraints.push(F.sub(value, reconstructedValue))
  constraints.push(F.sub(result, reconstructedResult))
  constraints.push(...evaluateLinkedNextConstraints(
    row,
    next,
    result,
    8
  ))
  return gateConstraints(constraints, selector)
}

function evaluateFieldAddLimb (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.FieldAddLimb)
  const modulusLimb = row[METHOD2_VM_LAYOUT.auxStart]
  const wrap = row[METHOD2_VM_LAYOUT.auxStart + 1]
  const carryIn = row[METHOD2_VM_LAYOUT.auxStart + 2]
  const carryOut = row[METHOD2_VM_LAYOUT.auxStart + 3]
  const left = row[METHOD2_VM_LAYOUT.a]
  const right = row[METHOD2_VM_LAYOUT.b]
  const result = row[METHOD2_VM_LAYOUT.c]
  return gateConstraints([
    booleanConstraint(wrap),
    signedSmallRangeConstraint(carryIn, -2, 2),
    signedSmallRangeConstraint(carryOut, -2, 2),
    F.sub(
      F.add(F.add(left, right), carryIn),
      F.add(
        F.add(result, F.mul(wrap, modulusLimb)),
        F.mul(carryOut, U16_RADIX)
      )
    ),
    ...evaluateLinkedNextConstraints(
      row,
      next,
      result,
      FIELD_ADD_LINK_OFFSET,
      carryOut,
      METHOD2_VM_LAYOUT.auxStart + 2
    )
  ], selector)
}

function evaluateFieldSubLimb (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.FieldSubLimb)
  const modulusLimb = row[METHOD2_VM_LAYOUT.auxStart]
  const wrap = row[METHOD2_VM_LAYOUT.auxStart + 1]
  const carryIn = row[METHOD2_VM_LAYOUT.auxStart + 2]
  const carryOut = row[METHOD2_VM_LAYOUT.auxStart + 3]
  const left = row[METHOD2_VM_LAYOUT.a]
  const right = row[METHOD2_VM_LAYOUT.b]
  const result = row[METHOD2_VM_LAYOUT.c]
  return gateConstraints([
    booleanConstraint(wrap),
    signedSmallRangeConstraint(carryIn, -2, 2),
    signedSmallRangeConstraint(carryOut, -2, 2),
    F.sub(
      F.add(F.sub(left, right), F.add(F.mul(wrap, modulusLimb), carryIn)),
      F.add(result, F.mul(carryOut, U16_RADIX))
    ),
    ...evaluateLinkedNextConstraints(
      row,
      next,
      result,
      FIELD_ADD_LINK_OFFSET,
      carryOut,
      METHOD2_VM_LAYOUT.auxStart + 2
    )
  ], selector)
}

function evaluateFieldMulLimb (
  row: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const selector = method2VmSelector(row, Method2VmOp.FieldMulLimb)
  const productLimb = row[METHOD2_VM_LAYOUT.a]
  const resultLimb = row[METHOD2_VM_LAYOUT.b]
  const quotientProductLimb = row[METHOD2_VM_LAYOUT.c]
  const carryIn = F.sub(
    row[METHOD2_VM_LAYOUT.auxStart],
    FIELD_MUL_CARRY_OFFSET
  )
  const carryOut = F.sub(
    row[METHOD2_VM_LAYOUT.auxStart + 1],
    FIELD_MUL_CARRY_OFFSET
  )
  return gateConstraints([
    F.sub(
      F.add(F.add(resultLimb, quotientProductLimb), carryIn),
      F.add(productLimb, F.mul(carryOut, U16_RADIX))
    ),
    ...evaluateLinkedNextConstraints(
      row,
      next,
      resultLimb,
      FIELD_MUL_LINK_OFFSET,
      row[METHOD2_VM_LAYOUT.auxStart + 1],
      METHOD2_VM_LAYOUT.auxStart
    )
  ], selector)
}

function method2VmSelector (
  row: FieldElement[],
  op: Method2VmOp
): FieldElement {
  return row[METHOD2_VM_LAYOUT.selectorStart + METHOD2_VM_OPS.indexOf(op)]
}

function evaluateLinkedNextConstraints (
  row: FieldElement[],
  next: FieldElement[],
  source: FieldElement,
  linkOffset: number,
  carrySource?: FieldElement,
  carryDestination?: number
): FieldElement[] {
  const flagA = row[METHOD2_VM_LAYOUT.auxStart + linkOffset + LINK_NEXT_A]
  const flagB = row[METHOD2_VM_LAYOUT.auxStart + linkOffset + LINK_NEXT_B]
  const flagC = row[METHOD2_VM_LAYOUT.auxStart + linkOffset + LINK_NEXT_C]
  const flagCarry = carrySource === undefined
    ? 0n
    : row[METHOD2_VM_LAYOUT.auxStart + linkOffset + LINK_NEXT_CARRY]
  const flagSum = F.add(F.add(flagA, flagB), F.add(flagC, flagCarry))
  const constraints: FieldElement[] = [
    booleanConstraint(flagA),
    booleanConstraint(flagB),
    booleanConstraint(flagC),
    booleanConstraint(flagCarry),
    booleanConstraint(flagSum),
    F.mul(flagA, F.sub(source, next[METHOD2_VM_LAYOUT.a])),
    F.mul(flagB, F.sub(source, next[METHOD2_VM_LAYOUT.b])),
    F.mul(flagC, F.sub(source, next[METHOD2_VM_LAYOUT.c]))
  ]
  if (carrySource !== undefined && carryDestination !== undefined) {
    constraints.push(F.mul(
      flagCarry,
      F.sub(carrySource, next[carryDestination])
    ))
  }

  for (let i = 0; i < METHOD2_VM_LAYOUT.auxCount; i++) {
    if (i >= linkOffset + (carrySource === undefined ? 3 : 4)) {
      constraints.push(row[METHOD2_VM_LAYOUT.auxStart + i])
    }
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

function signedSmallRangeConstraint (
  value: FieldElement,
  min: number,
  max: number
): FieldElement {
  let result = 1n
  for (let i = min; i <= max; i++) {
    result = F.mul(result, F.sub(value, F.normalize(BigInt(i))))
  }
  return result
}

function bitOfFieldElement (
  value: FieldElement,
  bit: number
): number {
  if (value < 0n || value > 255n) {
    return 0
  }
  return Number((value >> BigInt(bit)) & 1n)
}

function assertByteNumber (
  value: number,
  label: string
): void {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error(`${label} must be a byte`)
  }
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function linkAux (
  destination: Method2VmLinkDestination
): number[] {
  const aux = [0, 0, 0]
  aux[linkDestinationIndex(destination)] = 1
  return aux
}

function carryLinkAux (
  destination: Method2VmCarryLinkDestination
): number[] {
  const aux = [0, 0, 0, 0]
  aux[carryLinkDestinationIndex(destination)] = 1
  return aux
}

function linkDestinationIndex (
  destination: Method2VmLinkDestination
): number {
  if (destination === 'a') return LINK_NEXT_A
  if (destination === 'b') return LINK_NEXT_B
  if (destination === 'c') return LINK_NEXT_C
  throw new Error('Unsupported Method 2 VM link destination')
}

function carryLinkDestinationIndex (
  destination: Method2VmCarryLinkDestination
): number {
  if (destination === 'carry') return LINK_NEXT_CARRY
  return linkDestinationIndex(destination)
}
