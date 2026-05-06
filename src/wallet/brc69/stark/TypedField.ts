import {
  F,
  FieldElement,
  GOLDILOCKS_MODULUS
} from './Field.js'

export interface TypedFieldElement {
  lo: number
  hi: number
}

export interface TypedFieldColumn {
  lo: Uint32Array
  hi: Uint32Array
}

export interface TypedFieldTrace {
  length: number
  width: number
  columns: TypedFieldColumn[]
}

export function typedFieldElement (
  value: FieldElement | number
): TypedFieldElement {
  const normalized = F.normalize(value)
  return {
    lo: Number(normalized & 0xffffffffn) >>> 0,
    hi: Number((normalized >> 32n) & 0xffffffffn) >>> 0
  }
}

export function typedFieldToBigint (
  element: TypedFieldElement
): FieldElement {
  return F.normalize(
    (BigInt(element.hi >>> 0) << 32n) | BigInt(element.lo >>> 0)
  )
}

export function typedFieldAdd (
  left: TypedFieldElement,
  right: TypedFieldElement
): TypedFieldElement {
  let lo = (left.lo >>> 0) + (right.lo >>> 0)
  let carry = 0
  if (lo >= U32_RADIX) {
    lo -= U32_RADIX
    carry = 1
  }
  let hi = (left.hi >>> 0) + (right.hi >>> 0) + carry
  if (hi >= U32_RADIX) {
    hi -= U32_RADIX
    lo = lo + U32_MINUS_ONE
    if (lo >= U32_RADIX) {
      lo -= U32_RADIX
      hi++
      if (hi >= U32_RADIX) hi -= U32_RADIX
    }
  }
  return normalizeTypedPair(lo, hi)
}

export function typedFieldSub (
  left: TypedFieldElement,
  right: TypedFieldElement
): TypedFieldElement {
  let lo = (left.lo >>> 0) - (right.lo >>> 0)
  let borrow = 0
  if (lo < 0) {
    lo += U32_RADIX
    borrow = 1
  }
  let hi = (left.hi >>> 0) - (right.hi >>> 0) - borrow
  if (hi < 0) {
    hi += U32_RADIX
    lo -= U32_MINUS_ONE
    if (lo < 0) {
      lo += U32_RADIX
      hi--
      if (hi < 0) hi += U32_RADIX
    }
  }
  return normalizeTypedPair(lo, hi)
}

export function typedFieldMul (
  left: TypedFieldElement,
  right: TypedFieldElement
): TypedFieldElement {
  const out = new Uint32Array(2)
  typedFieldMulInto(left.lo, left.hi, right.lo, right.hi, out)
  return { lo: out[0], hi: out[1] }
}

export function typedFieldAddInto (
  leftLo: number,
  leftHi: number,
  rightLo: number,
  rightHi: number,
  out: Uint32Array
): void {
  let lo = (leftLo >>> 0) + (rightLo >>> 0)
  let carry = 0
  if (lo >= U32_RADIX) {
    lo -= U32_RADIX
    carry = 1
  }
  let hi = (leftHi >>> 0) + (rightHi >>> 0) + carry
  if (hi >= U32_RADIX) {
    hi -= U32_RADIX
    lo = lo + U32_MINUS_ONE
    if (lo >= U32_RADIX) {
      lo -= U32_RADIX
      hi++
      if (hi >= U32_RADIX) hi -= U32_RADIX
    }
  }
  normalizeTypedPairInto(lo, hi, out)
}

export function typedFieldSubInto (
  leftLo: number,
  leftHi: number,
  rightLo: number,
  rightHi: number,
  out: Uint32Array
): void {
  let lo = (leftLo >>> 0) - (rightLo >>> 0)
  let borrow = 0
  if (lo < 0) {
    lo += U32_RADIX
    borrow = 1
  }
  let hi = (leftHi >>> 0) - (rightHi >>> 0) - borrow
  if (hi < 0) {
    hi += U32_RADIX
    lo -= U32_MINUS_ONE
    if (lo < 0) {
      lo += U32_RADIX
      hi--
      if (hi < 0) hi += U32_RADIX
    }
  }
  normalizeTypedPairInto(lo, hi, out)
}

export function typedFieldMulInto (
  leftLo: number,
  leftHi: number,
  rightLo: number,
  rightHi: number,
  out: Uint32Array
): void {
  const a = leftLo >>> 0
  const b = leftHi >>> 0
  const c = rightLo >>> 0
  const d = rightHi >>> 0

  const ac0 = a & 0xffff
  const ac1 = a >>> 16
  const cc0 = c & 0xffff
  const cc1 = c >>> 16
  const acP0 = ac0 * cc0
  const acMiddle = Math.floor(acP0 / U16_RADIX) + ac0 * cc1 + ac1 * cc0
  const acLo = ((acMiddle % U16_RADIX) * U16_RADIX + (acP0 & 0xffff)) >>> 0
  const acHi = (ac1 * cc1 + Math.floor(acMiddle / U16_RADIX)) >>> 0

  const ad0 = a & 0xffff
  const ad1 = a >>> 16
  const dc0 = d & 0xffff
  const dc1 = d >>> 16
  const adP0 = ad0 * dc0
  const adMiddle = Math.floor(adP0 / U16_RADIX) + ad0 * dc1 + ad1 * dc0
  const adLo = ((adMiddle % U16_RADIX) * U16_RADIX + (adP0 & 0xffff)) >>> 0
  const adHi = (ad1 * dc1 + Math.floor(adMiddle / U16_RADIX)) >>> 0

  const bc0 = b & 0xffff
  const bc1 = b >>> 16
  const bcP0 = bc0 * cc0
  const bcMiddle = Math.floor(bcP0 / U16_RADIX) + bc0 * cc1 + bc1 * cc0
  const bcLo = ((bcMiddle % U16_RADIX) * U16_RADIX + (bcP0 & 0xffff)) >>> 0
  const bcHi = (bc1 * cc1 + Math.floor(bcMiddle / U16_RADIX)) >>> 0

  const bd0 = b & 0xffff
  const bd1 = b >>> 16
  const bdP0 = bd0 * dc0
  const bdMiddle = Math.floor(bdP0 / U16_RADIX) + bd0 * dc1 + bd1 * dc0
  const bdLo = ((bdMiddle % U16_RADIX) * U16_RADIX + (bdP0 & 0xffff)) >>> 0
  const bdHi = (bd1 * dc1 + Math.floor(bdMiddle / U16_RADIX)) >>> 0

  const limb0 = acLo
  let sum = acHi + adLo + bcLo
  const limb1 = sum % U32_RADIX
  let carry = Math.floor(sum / U32_RADIX)
  sum = adHi + bcHi + bdLo + carry
  const limb2 = sum % U32_RADIX
  carry = Math.floor(sum / U32_RADIX)
  const limb3 = bdHi + carry

  const lo = limb0 - limb2 - limb3
  const hi = limb1 + limb2
  normalizeTypedPairInto(lo, hi, out)
}

export function typedFieldPow (
  base: TypedFieldElement,
  exponent: bigint
): TypedFieldElement {
  return typedFieldElement(F.pow(typedFieldToBigint(base), exponent))
}

export function typedFieldInv (
  value: TypedFieldElement
): TypedFieldElement {
  return typedFieldPow(value, GOLDILOCKS_MODULUS - 2n)
}

export function typedFieldColumn (
  values: FieldElement[]
): TypedFieldColumn {
  const lo = new Uint32Array(values.length)
  const hi = new Uint32Array(values.length)
  for (let i = 0; i < values.length; i++) {
    const element = typedFieldElement(values[i])
    lo[i] = element.lo
    hi[i] = element.hi
  }
  return { lo, hi }
}

export function typedFieldColumnToBigints (
  column: TypedFieldColumn
): FieldElement[] {
  assertTypedColumn(column)
  const out = new Array<FieldElement>(column.lo.length)
  for (let i = 0; i < out.length; i++) {
    out[i] = typedFieldToBigint({
      lo: column.lo[i],
      hi: column.hi[i]
    })
  }
  return out
}

export function typedFieldTraceFromRows (
  rows: FieldElement[][]
): TypedFieldTrace {
  if (rows.length === 0 || rows[0].length === 0) {
    throw new Error('Typed trace requires at least one row and column')
  }
  const length = rows.length
  const width = rows[0].length
  const columns = new Array<TypedFieldColumn>(width)
  for (let column = 0; column < width; column++) {
    const values = new Array<FieldElement>(length)
    for (let row = 0; row < length; row++) {
      if (rows[row].length !== width) {
        throw new Error('Typed trace rows must have equal width')
      }
      values[row] = rows[row][column]
    }
    columns[column] = typedFieldColumn(values)
  }
  return { length, width, columns }
}

export function typedFieldTraceFromRowsColumnMajor (
  rows: FieldElement[][]
): TypedFieldTrace {
  if (rows.length === 0 || rows[0].length === 0) {
    throw new Error('Typed trace requires at least one row and column')
  }
  const length = rows.length
  const width = rows[0].length
  const columns = Array.from({ length: width }, () => ({
    lo: new Uint32Array(length),
    hi: new Uint32Array(length)
  }))
  for (let row = 0; row < length; row++) {
    if (rows[row].length !== width) {
      throw new Error('Typed trace rows must have equal width')
    }
    for (let column = 0; column < width; column++) {
      const element = typedFieldElement(rows[row][column])
      columns[column].lo[row] = element.lo
      columns[column].hi[row] = element.hi
    }
  }
  return { length, width, columns }
}

export function typedFieldTraceToRows (
  trace: TypedFieldTrace
): FieldElement[][] {
  assertTypedTrace(trace)
  const rows = new Array<FieldElement[]>(trace.length)
  for (let row = 0; row < trace.length; row++) {
    rows[row] = new Array<FieldElement>(trace.width)
    for (let column = 0; column < trace.width; column++) {
      rows[row][column] = typedFieldToBigint({
        lo: trace.columns[column].lo[row],
        hi: trace.columns[column].hi[row]
      })
    }
  }
  return rows
}

export function cloneTypedFieldColumn (
  column: TypedFieldColumn
): TypedFieldColumn {
  assertTypedColumn(column)
  return {
    lo: new Uint32Array(column.lo),
    hi: new Uint32Array(column.hi)
  }
}

export function typedFieldColumnBytes (
  column: TypedFieldColumn,
  index: number
): number[] {
  assertTypedColumn(column)
  if (!Number.isInteger(index) || index < 0 || index >= column.lo.length) {
    throw new Error('Typed field column index out of bounds')
  }
  return typedFieldElementBytes({
    lo: column.lo[index],
    hi: column.hi[index]
  })
}

export function typedFieldElementBytes (
  element: TypedFieldElement
): number[] {
  const lo = element.lo >>> 0
  const hi = element.hi >>> 0
  return [
    lo & 0xff,
    (lo >>> 8) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 24) & 0xff,
    hi & 0xff,
    (hi >>> 8) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 24) & 0xff
  ]
}

export function typedFieldColumnValue (
  column: TypedFieldColumn,
  index: number
): FieldElement {
  assertTypedColumn(column)
  if (!Number.isInteger(index) || index < 0 || index >= column.lo.length) {
    throw new Error('Typed field column index out of bounds')
  }
  return typedFieldToBigint({
    lo: column.lo[index],
    hi: column.hi[index]
  })
}

export function writeTypedFieldElementBytesLE (
  out: Uint8Array,
  offset: number,
  lo: number,
  hi: number
): void {
  lo >>>= 0
  hi >>>= 0
  out[offset] = lo & 0xff
  out[offset + 1] = (lo >>> 8) & 0xff
  out[offset + 2] = (lo >>> 16) & 0xff
  out[offset + 3] = (lo >>> 24) & 0xff
  out[offset + 4] = hi & 0xff
  out[offset + 5] = (hi >>> 8) & 0xff
  out[offset + 6] = (hi >>> 16) & 0xff
  out[offset + 7] = (hi >>> 24) & 0xff
}

export function typedFieldRowBytes (
  columns: TypedFieldColumn[],
  row: number
): Uint8Array {
  if (columns.length === 0) throw new Error('Typed row requires at least one column')
  const length = columns[0].lo.length
  if (!Number.isInteger(row) || row < 0 || row >= length) {
    throw new Error('Typed row index out of bounds')
  }
  const out = new Uint8Array(columns.length * 8)
  for (let column = 0; column < columns.length; column++) {
    assertTypedColumn(columns[column])
    if (columns[column].lo.length !== length) {
      throw new Error('Typed row column length mismatch')
    }
    writeTypedFieldElementBytesLE(
      out,
      column * 8,
      columns[column].lo[row],
      columns[column].hi[row]
    )
  }
  return out
}

function assertTypedTrace (trace: TypedFieldTrace): void {
  if (trace.columns.length !== trace.width) {
    throw new Error('Typed trace width mismatch')
  }
  for (const column of trace.columns) {
    assertTypedColumn(column)
    if (column.lo.length !== trace.length) {
      throw new Error('Typed trace length mismatch')
    }
  }
}

function assertTypedColumn (column: TypedFieldColumn): void {
  if (column.lo.length !== column.hi.length) {
    throw new Error('Typed field column lane length mismatch')
  }
}

const U16_RADIX = 0x10000
const U32_RADIX = 0x100000000
const U32_MINUS_ONE = U32_RADIX - 1

function normalizeTypedPair (
  rawLo: number,
  rawHi: number
): TypedFieldElement {
  const out = new Uint32Array(2)
  normalizeTypedPairInto(rawLo, rawHi, out)
  return {
    lo: out[0],
    hi: out[1]
  }
}

function normalizeTypedPairInto (
  rawLo: number,
  rawHi: number,
  out: Uint32Array
): void {
  let lo = rawLo
  let hi = rawHi
  while (lo < 0) {
    const borrow = Math.ceil(-lo / U32_RADIX)
    lo += borrow * U32_RADIX
    hi -= borrow
  }
  while (lo >= U32_RADIX) {
    const carry = Math.floor(lo / U32_RADIX)
    lo -= carry * U32_RADIX
    hi += carry
  }
  while (hi < 0) {
    hi += U32_MINUS_ONE
    lo += 1
    if (lo >= U32_RADIX) {
      lo -= U32_RADIX
      hi += 1
    }
  }
  while (hi >= U32_RADIX) {
    hi -= U32_MINUS_ONE
    lo -= 1
    if (lo < 0) {
      lo += U32_RADIX
      hi -= 1
    }
  }
  if (hi === U32_MINUS_ONE && lo >= 1) {
    hi = 0
    lo -= 1
  }
  out[0] = lo >>> 0
  out[1] = hi >>> 0
}
