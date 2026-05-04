import { compressPoint, isOnCurve } from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  DUAL_BASE_EC_COMPRESSED_POINT_BYTES,
  DUAL_BASE_EC_COMPRESSED_POINT_NIBBLES,
  DualBaseCompressedPointWitness,
  buildDualBaseCompressedPointWitness,
  nibblesToBytes,
  validateDualBaseCompressedPointWitness
} from './DualBaseEcIntegrated.js'
import { FieldElement } from './Field.js'
import {
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_MAX_MULTIPLICITY,
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_RANGE16,
  LOOKUP_BUS_TUPLE_ARITY,
  LookupBusMetrics,
  LookupBusTrace,
  LookupBusTraceItem,
  buildLookupBusTrace,
  lookupBusMetrics,
  proveLookupBus,
  verifyLookupBusProof
} from './LookupBus.js'
import { StarkProof, StarkProverOptions } from './Stark.js'

export interface CompressedPointEncodingTrace {
  point: SecpPoint
  witness: DualBaseCompressedPointWitness
  lookup: LookupBusTrace
  rows: CompressedPointEncodingRow[]
}

export interface CompressedPointEncodingRow {
  byteIndex: number
  byte: number
  lowNibble: number
  highNibble: number
  isPrefix: 0 | 1
  isXByte: 0 | 1
}

export interface CompressedPointEncodingProof {
  rangeProof: StarkProof
}

export interface CompressedPointEncodingMetrics extends LookupBusMetrics {
  bytes: number
  nibbles: number
  uniqueRangeTableRows: number
  rangeSupplyRows: number
  rangeRequests: number
  committedWidth: number
  totalProofBytes?: number
}

export function buildCompressedPointEncodingTrace (
  pointOrWitness: SecpPoint | DualBaseCompressedPointWitness,
  options: { minTraceLength?: number } = {}
): CompressedPointEncodingTrace {
  const witness = isCompressedPointWitness(pointOrWitness)
    ? cloneCompressedPointWitness(pointOrWitness)
    : buildDualBaseCompressedPointWitness(pointOrWitness)
  validateCompressedPointEncodingWitness(witness, witness.point)
  const rows: CompressedPointEncodingRow[] = witness.bytes.map((byte, byteIndex) => ({
    byteIndex,
    byte,
    lowNibble: witness.nibbles[byteIndex * 2],
    highNibble: witness.nibbles[byteIndex * 2 + 1],
    isPrefix: byteIndex === 0 ? 1 : 0,
    isXByte: byteIndex === 0 ? 0 : 1
  }))
  const lookup = buildLookupBusTrace(
    compressedPointRangeItems(witness.nibbles),
    {
      expectedLookupRequests: witness.nibbles.length,
      minTraceLength: options.minTraceLength
    }
  )
  const trace = {
    point: { ...witness.point },
    witness,
    lookup,
    rows
  }
  validateCompressedPointEncodingTrace(trace)
  return trace
}

export function validateCompressedPointEncodingTrace (
  trace: CompressedPointEncodingTrace
): void {
  validateCompressedPointEncodingWitness(trace.witness, trace.point)
  if (trace.rows.length !== DUAL_BASE_EC_COMPRESSED_POINT_BYTES) {
    throw new Error('Compressed point encoding row count mismatch')
  }
  for (let byteIndex = 0; byteIndex < trace.rows.length; byteIndex++) {
    const row = trace.rows[byteIndex]
    const expectedByte = trace.witness.bytes[byteIndex]
    const expectedLow = trace.witness.nibbles[byteIndex * 2]
    const expectedHigh = trace.witness.nibbles[byteIndex * 2 + 1]
    if (
      row.byteIndex !== byteIndex ||
      row.byte !== expectedByte ||
      row.lowNibble !== expectedLow ||
      row.highNibble !== expectedHigh ||
      row.byte !== row.lowNibble + row.highNibble * 16 ||
      row.isPrefix !== (byteIndex === 0 ? 1 : 0) ||
      row.isXByte !== (byteIndex === 0 ? 0 : 1)
    ) {
      throw new Error('Compressed point encoding row mismatch')
    }
  }
  validateCompressedPointLookupTrace(trace.lookup, trace.witness.nibbles)
}

export function validateCompressedPointEncodingWitness (
  witness: DualBaseCompressedPointWitness,
  expectedPoint: SecpPoint
): void {
  validateDualBaseCompressedPointWitness(witness, expectedPoint)
  if (expectedPoint.infinity === true || !isOnCurve(expectedPoint)) {
    throw new Error('Compressed point encoding requires a valid point')
  }
  if (witness.bytes.length !== DUAL_BASE_EC_COMPRESSED_POINT_BYTES) {
    throw new Error('Compressed point encoding byte length mismatch')
  }
  if (witness.nibbles.length !== DUAL_BASE_EC_COMPRESSED_POINT_NIBBLES) {
    throw new Error('Compressed point encoding nibble length mismatch')
  }
  const expectedPrefix = 2 + Number(expectedPoint.y & 1n)
  if (witness.prefix !== expectedPrefix || witness.bytes[0] !== expectedPrefix) {
    throw new Error('Compressed point encoding prefix/parity mismatch')
  }
  if (!bytesEqual(witness.xBytes, bigintToBytesBE(expectedPoint.x, 32))) {
    throw new Error('Compressed point encoding x-byte mismatch')
  }
  if (!bytesEqual(witness.bytes, compressPoint(expectedPoint))) {
    throw new Error('Compressed point encoding compressed byte mismatch')
  }
  if (!bytesEqual(nibblesToBytes(witness.nibbles), witness.bytes)) {
    throw new Error('Compressed point encoding nibble reconstruction mismatch')
  }
  for (const nibble of witness.nibbles) validateNibble(nibble)
}

export function proveCompressedPointEncoding (
  trace: CompressedPointEncodingTrace,
  options: StarkProverOptions = {}
): CompressedPointEncodingProof {
  validateCompressedPointEncodingTrace(trace)
  return {
    rangeProof: proveLookupBus(trace.lookup, options)
  }
}

export function verifyCompressedPointEncoding (
  trace: CompressedPointEncodingTrace,
  proof: CompressedPointEncodingProof
): boolean {
  try {
    validateCompressedPointEncodingTrace(trace)
    return verifyLookupBusProof(trace.lookup.publicInput, proof.rangeProof)
  } catch {
    return false
  }
}

export function compressedPointEncodingMetrics (
  trace: CompressedPointEncodingTrace,
  proof?: CompressedPointEncodingProof
): CompressedPointEncodingMetrics {
  const lookup = lookupBusMetrics(trace.lookup, proof?.rangeProof)
  return {
    ...lookup,
    bytes: DUAL_BASE_EC_COMPRESSED_POINT_BYTES,
    nibbles: DUAL_BASE_EC_COMPRESSED_POINT_NIBBLES,
    uniqueRangeTableRows: 16,
    rangeSupplyRows: trace.lookup.metrics.fixedTableRows,
    rangeRequests: trace.lookup.metrics.lookupRequests,
    committedWidth: LOOKUP_BUS_LAYOUT.width,
    totalProofBytes: proof === undefined ? undefined : lookup.proofBytes
  }
}

export function compressedPointBytesForHmac (
  trace: CompressedPointEncodingTrace
): number[] {
  validateCompressedPointEncodingTrace(trace)
  return trace.witness.bytes.slice()
}

function compressedPointRangeItems (
  nibbles: number[]
): LookupBusTraceItem[] {
  const counts = new Array<number>(16).fill(0)
  for (const nibble of nibbles) {
    validateNibble(nibble)
    counts[nibble]++
  }
  const items: LookupBusTraceItem[] = []
  for (let value = 0; value < counts.length; value++) {
    let remaining = counts[value]
    while (remaining > 0) {
      const multiplicity = Math.min(remaining, LOOKUP_BUS_MAX_MULTIPLICITY)
      const tuple = range16Tuple(value)
      items.push({
        kind: LOOKUP_BUS_ROW_KIND.lookupSupply,
        tag: LOOKUP_BUS_TAG_RANGE16,
        leftValues: tuple,
        rightValues: tuple,
        publicValues: tuple,
        multiplicity
      })
      remaining -= multiplicity
    }
  }
  for (const nibble of nibbles) {
    const tuple = range16Tuple(nibble)
    items.push({
      kind: LOOKUP_BUS_ROW_KIND.lookupRequest,
      tag: LOOKUP_BUS_TAG_RANGE16,
      leftValues: tuple,
      rightValues: tuple,
      multiplicity: 1
    })
  }
  return items
}

function validateCompressedPointLookupTrace (
  lookup: LookupBusTrace,
  nibbles: number[]
): void {
  const expected = buildLookupBusTrace(
    compressedPointRangeItems(nibbles),
    {
      expectedLookupRequests: nibbles.length,
      minTraceLength: lookup.publicInput.traceLength
    }
  )
  if (lookup.publicInput.traceLength !== expected.publicInput.traceLength) {
    throw new Error('Compressed point range trace length mismatch')
  }
  if (
    lookup.publicInput.expectedLookupRequests !==
    expected.publicInput.expectedLookupRequests
  ) {
    throw new Error('Compressed point range lookup request count mismatch')
  }
  if (lookup.rows.length !== expected.rows.length) {
    throw new Error('Compressed point range row count mismatch')
  }
  for (let row = 0; row < lookup.rows.length; row++) {
    if (!fieldRowsEqual(lookup.rows[row], expected.rows[row])) {
      throw new Error('Compressed point range lookup row mismatch')
    }
  }
}

function range16Tuple (value: number): FieldElement[] {
  validateNibble(value)
  const tuple = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  tuple[0] = BigInt(value)
  return tuple
}

function cloneCompressedPointWitness (
  witness: DualBaseCompressedPointWitness
): DualBaseCompressedPointWitness {
  return {
    point: { ...witness.point },
    bytes: witness.bytes.slice(),
    prefix: witness.prefix,
    xBytes: witness.xBytes.slice(),
    nibbles: witness.nibbles.slice()
  }
}

function isCompressedPointWitness (
  value: SecpPoint | DualBaseCompressedPointWitness
): value is DualBaseCompressedPointWitness {
  return Array.isArray((value as DualBaseCompressedPointWitness).bytes) &&
    Array.isArray((value as DualBaseCompressedPointWitness).nibbles)
}

function validateNibble (value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 15) {
    throw new Error('Compressed point nibble is outside range16')
  }
}

function bigintToBytesBE (value: bigint, length: number): number[] {
  if (value < 0n) throw new Error('Cannot encode negative bigint')
  const out = new Array<number>(length)
  let remaining = value
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  if (remaining !== 0n) throw new Error('Bigint does not fit byte length')
  return out
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}

function fieldRowsEqual (left: FieldElement[], right: FieldElement[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}
