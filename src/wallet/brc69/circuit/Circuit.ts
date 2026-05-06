import {
  AirDefinition,
  FieldElement,
  F,
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  assertPowerOfTwo,
  proveStark,
  verifyStark
} from '../stark/index.js'
import { toBitsLE } from './Limbs.js'

export enum CircuitOp {
  Nop = 0,
  CopyNextA = 1,
  AssertZero = 2,
  Bool = 3,
  U16 = 4,
  Byte = 5,
  Add = 6,
  Mul = 7
}

const VALID_OPS = [
  CircuitOp.Nop,
  CircuitOp.CopyNextA,
  CircuitOp.AssertZero,
  CircuitOp.Bool,
  CircuitOp.U16,
  CircuitOp.Byte,
  CircuitOp.Add,
  CircuitOp.Mul
]

export interface CircuitColumnLayout {
  enabled: number
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

export interface CircuitTrace {
  rows: FieldElement[][]
  layout: CircuitColumnLayout
  activeLength: number
}

export interface CircuitProgram {
  trace: CircuitTrace
  publicInputDigest?: number[]
}

export const CIRCUIT_LAYOUT: CircuitColumnLayout = {
  enabled: 0,
  op: 1,
  selectorStart: 2,
  selectorCount: VALID_OPS.length,
  a: 10,
  b: 11,
  c: 12,
  auxStart: 13,
  auxCount: 16,
  width: 29
}

export class CircuitBuilder {
  private readonly rows: FieldElement[][] = []

  noop (): this {
    this.rows.push(makeRow(CircuitOp.Nop, 0n, 0n, 0n, []))
    return this
  }

  copyNextA (value: bigint | number): this {
    this.rows.push(makeRow(CircuitOp.CopyNextA, value, 0n, 0n, []))
    return this
  }

  assertZero (value: bigint | number): this {
    this.rows.push(makeRow(CircuitOp.AssertZero, value, 0n, 0n, []))
    return this
  }

  assertBool (value: 0 | 1): this {
    this.rows.push(makeRow(CircuitOp.Bool, value, 0n, 0n, []))
    return this
  }

  assertByte (value: number): this {
    this.rows.push(
      makeRow(CircuitOp.Byte, value, 0n, 0n, toBitsLE(BigInt(value), 8))
    )
    return this
  }

  assertU16 (value: number): this {
    this.rows.push(
      makeRow(CircuitOp.U16, value, 0n, 0n, toBitsLE(BigInt(value), 16))
    )
    return this
  }

  assertAdd (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number
  ): this {
    this.rows.push(makeRow(CircuitOp.Add, left, right, result, []))
    return this
  }

  assertMul (
    left: bigint | number,
    right: bigint | number,
    result: bigint | number
  ): this {
    this.rows.push(makeRow(CircuitOp.Mul, left, right, result, []))
    return this
  }

  build (): CircuitProgram {
    const activeRows = this.rows.length > 0
      ? this.rows.map(row => row.slice())
      : [makeRow(CircuitOp.Nop, 0n, 0n, 0n, [])]
    const paddedLength = nextPowerOfTwo(Math.max(2, activeRows.length + 1))
    const rows = activeRows.slice()
    while (rows.length < paddedLength) {
      rows.push(disabledRow())
    }
    return {
      trace: {
        rows,
        layout: CIRCUIT_LAYOUT,
        activeLength: activeRows.length
      }
    }
  }
}

export function buildCircuitAir (
  program: CircuitProgram
): AirDefinition {
  return {
    traceWidth: program.trace.layout.width,
    boundaryConstraints: [],
    transitionDegree: 3,
    publicInputDigest: program.publicInputDigest,
    evaluateTransition: (current, next) => evaluateCircuitTransition(
      current,
      next
    )
  }
}

export function validateCircuitTrace (program: CircuitProgram): void {
  assertPowerOfTwo(program.trace.rows.length)
  for (const row of program.trace.rows) {
    if (row.length !== program.trace.layout.width) {
      throw new Error('Circuit trace row width mismatch')
    }
  }
  const air = buildCircuitAir(program)
  for (let i = 0; i < program.trace.rows.length - 1; i++) {
    const failures = air.evaluateTransition(
      program.trace.rows[i],
      program.trace.rows[i + 1],
      i
    ).filter(value => F.normalize(value) !== 0n)
    if (failures.length > 0) {
      throw new Error(`Circuit constraint failed at row ${i}`)
    }
  }
}

export function proveCircuit (
  program: CircuitProgram,
  options: StarkProverOptions = {}
): StarkProof {
  validateCircuitTrace(program)
  return proveStark(buildCircuitAir(program), program.trace.rows, options)
}

export function verifyCircuit (
  program: CircuitProgram,
  proof: StarkProof,
  options: StarkVerifierOptions = {}
): boolean {
  return verifyStark(buildCircuitAir(program), proof, options)
}

export function evaluateCircuitTransition (
  current: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  const enabled = current[CIRCUIT_LAYOUT.enabled]
  const op = current[CIRCUIT_LAYOUT.op]
  const a = current[CIRCUIT_LAYOUT.a]
  const b = current[CIRCUIT_LAYOUT.b]
  const c = current[CIRCUIT_LAYOUT.c]
  const constraints: FieldElement[] = [
    F.mul(enabled, F.sub(enabled, 1n))
  ]

  let selectorSum = 0n
  let selectedOp = 0n
  for (let i = 0; i < VALID_OPS.length; i++) {
    const selector = current[CIRCUIT_LAYOUT.selectorStart + i]
    constraints.push(F.mul(selector, F.sub(selector, 1n)))
    selectorSum = F.add(selectorSum, selector)
    selectedOp = F.add(selectedOp, F.mul(selector, BigInt(VALID_OPS[i])))
  }
  constraints.push(F.sub(selectorSum, enabled))
  constraints.push(F.sub(op, selectedOp))

  const copy = selectorValue(current, CircuitOp.CopyNextA)
  constraints.push(F.mul(F.mul(enabled, copy), F.sub(a, next[CIRCUIT_LAYOUT.a])))

  const zero = selectorValue(current, CircuitOp.AssertZero)
  constraints.push(F.mul(F.mul(enabled, zero), a))

  const bool = selectorValue(current, CircuitOp.Bool)
  constraints.push(F.mul(F.mul(enabled, bool), F.mul(a, F.sub(a, 1n))))

  const u16 = selectorValue(current, CircuitOp.U16)
  constraints.push(...bitDecompositionConstraints(enabled, u16, current, 16))

  const byte = selectorValue(current, CircuitOp.Byte)
  constraints.push(...bitDecompositionConstraints(enabled, byte, current, 8))

  const add = selectorValue(current, CircuitOp.Add)
  constraints.push(F.mul(F.mul(enabled, add), F.sub(F.add(a, b), c)))

  const mul = selectorValue(current, CircuitOp.Mul)
  constraints.push(F.mul(F.mul(enabled, mul), F.sub(F.mul(a, b), c)))

  return constraints
}

function bitDecompositionConstraints (
  enabled: FieldElement,
  selector: FieldElement,
  row: FieldElement[],
  width: number
): FieldElement[] {
  const constraints: FieldElement[] = []
  let sum = 0n
  for (let i = 0; i < 16; i++) {
    const bit = row[CIRCUIT_LAYOUT.auxStart + i]
    if (i < width) {
      constraints.push(
        F.mul(F.mul(enabled, selector), F.mul(bit, F.sub(bit, 1n)))
      )
      sum = F.add(sum, F.mul(bit, BigInt(1 << i)))
    } else {
      constraints.push(F.mul(F.mul(enabled, selector), bit))
    }
  }
  constraints.push(
    F.mul(F.mul(enabled, selector), F.sub(row[CIRCUIT_LAYOUT.a], sum))
  )
  return constraints
}

function selectorValue (
  row: FieldElement[],
  selected: CircuitOp
): FieldElement {
  const index = VALID_OPS.indexOf(selected)
  if (index < 0) throw new Error('Unknown circuit opcode')
  return row[CIRCUIT_LAYOUT.selectorStart + index]
}

function makeRow (
  op: CircuitOp,
  a: bigint | number,
  b: bigint | number,
  c: bigint | number,
  aux: Array<bigint | number>
): FieldElement[] {
  const row = new Array<FieldElement>(CIRCUIT_LAYOUT.width).fill(0n)
  row[CIRCUIT_LAYOUT.enabled] = 1n
  row[CIRCUIT_LAYOUT.op] = BigInt(op)
  row[CIRCUIT_LAYOUT.selectorStart + VALID_OPS.indexOf(op)] = 1n
  row[CIRCUIT_LAYOUT.a] = F.normalize(a)
  row[CIRCUIT_LAYOUT.b] = F.normalize(b)
  row[CIRCUIT_LAYOUT.c] = F.normalize(c)
  for (let i = 0; i < Math.min(aux.length, CIRCUIT_LAYOUT.auxCount); i++) {
    row[CIRCUIT_LAYOUT.auxStart + i] = F.normalize(aux[i])
  }
  return row
}

function disabledRow (): FieldElement[] {
  return new Array<FieldElement>(CIRCUIT_LAYOUT.width).fill(0n)
}

function nextPowerOfTwo (value: number): number {
  let size = 1
  while (size < value) size <<= 1
  return size
}
