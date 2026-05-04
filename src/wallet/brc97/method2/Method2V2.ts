import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { WalletProtocol } from '../../Wallet.interfaces.js'
import {
  SECP256K1_G,
  SECP256K1_N,
  SECP256K1_P,
  compressPoint,
  hmacSha256,
  isOnCurve,
  pointAdd,
  pointDouble,
  scalarMultiply,
  validateScalar
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'

export const BRC69_METHOD2_V2_DOMAIN = 'BRC69_METHOD2_V2'
export const BRC69_METHOD2_V2_AIR_ID = 'BRC69_METHOD2_V2_AIR_ROW_EXPANDED_V1'
export const BRC69_METHOD2_V2_PUBLIC_INPUT_DIGEST_ID =
  'BRC69_METHOD2_V2_PUBLIC_INPUT_DIGEST_V1'
export const BRC69_METHOD2_V2_CURVE_ID = 'secp256k1'
export const BRC69_METHOD2_V2_HASH_ID = 'SHA256'
export const BRC69_METHOD2_V2_HMAC_ID = 'HMAC-SHA256'
export const METHOD2_V2_WINDOW_BITS = 6
export const METHOD2_V2_FULL_WINDOWS = 42
export const METHOD2_V2_FINAL_WINDOW_BITS = 4
export const METHOD2_V2_WINDOW_COUNT = 43
export const METHOD2_V2_LIMB_BITS = 29
export const METHOD2_V2_FALLBACK_LIMB_BITS = 28
export const METHOD2_V2_STARK_BLOWUP_FACTOR = 16
export const METHOD2_V2_STARK_NUM_QUERIES = 48
export const METHOD2_V2_STARK_MAX_REMAINDER_SIZE = 16
export const METHOD2_V2_STARK_COSET_OFFSET = 7n

export interface Method2V2Statement {
  prover: string
  counterparty: string
  protocolID: WalletProtocol
  keyID: string
  linkage: number[]
}

export interface Method2V2Profile {
  family: string
  airId: string
  publicInputDigestId: string
  curveId: string
  hashId: string
  hmacId: string
  windowBits: number
  fullWindows: number
  finalWindowBits: number
  windowCount: number
  limbBits: number
  stark: {
    blowupFactor: number
    numQueries: number
    maxRemainderSize: number
    cosetOffset: bigint
  }
}

export interface Method2V2TableWindow {
  window: number
  bits: number
  g: SecpPoint[]
  b: SecpPoint[]
}

export interface Method2V2FixedWindowTables {
  windowBits: number
  windows: Method2V2TableWindow[]
}

export interface Method2V2SelectionRow {
  phase: 'select'
  window: number
  digit: number
  selector: 0 | 1
  selectorSum: number
  candidateG: SecpPoint
  candidateB: SecpPoint
  selectedG: SecpPoint
  selectedB: SecpPoint
}

export interface Method2V2AccumulationRow {
  phase: 'accumulate'
  window: number
  digit: number
  accGBefore: SecpPoint
  accBBefore: SecpPoint
  selectedG: SecpPoint
  selectedB: SecpPoint
  accGAfter: SecpPoint
  accBAfter: SecpPoint
}

export type Method2V2TraceRow = Method2V2SelectionRow | Method2V2AccumulationRow

export interface Method2V2Trace {
  profile: Method2V2Profile
  scalar: bigint
  digits: number[]
  tables: Method2V2FixedWindowTables
  rows: Method2V2TraceRow[]
  publicA: SecpPoint
  counterpartyB: SecpPoint
  sharedS: SecpPoint
  compressedS: number[]
  invoiceBytes: number[]
  linkage: number[]
  activeRows: number
  privateCommittedWidthEstimate: number
  publicPreprocessedWidthEstimate: number
}

export interface Method2V2Metrics {
  activeRows: number
  paddedRows: number
  privateCommittedWidth: number
  publicPreprocessedWidth: number
  ldeRows: number
  estimatedTraceArea: number
  invoiceLength: number
  innerShaBlocks: number
  outerShaBlocks: number
}

export const METHOD2_V2_PROFILE: Method2V2Profile = {
  family: BRC69_METHOD2_V2_DOMAIN,
  airId: BRC69_METHOD2_V2_AIR_ID,
  publicInputDigestId: BRC69_METHOD2_V2_PUBLIC_INPUT_DIGEST_ID,
  curveId: BRC69_METHOD2_V2_CURVE_ID,
  hashId: BRC69_METHOD2_V2_HASH_ID,
  hmacId: BRC69_METHOD2_V2_HMAC_ID,
  windowBits: METHOD2_V2_WINDOW_BITS,
  fullWindows: METHOD2_V2_FULL_WINDOWS,
  finalWindowBits: METHOD2_V2_FINAL_WINDOW_BITS,
  windowCount: METHOD2_V2_WINDOW_COUNT,
  limbBits: METHOD2_V2_LIMB_BITS,
  stark: {
    blowupFactor: METHOD2_V2_STARK_BLOWUP_FACTOR,
    numQueries: METHOD2_V2_STARK_NUM_QUERIES,
    maxRemainderSize: METHOD2_V2_STARK_MAX_REMAINDER_SIZE,
    cosetOffset: METHOD2_V2_STARK_COSET_OFFSET
  }
}

export function method2V2PublicInputDigest (
  statement: Method2V2Statement,
  invoiceBytes: number[]
): number[] {
  assertBytes(invoiceBytes, 'invoice')
  assertBytes(statement.linkage, 'linkage')
  const writer = new Writer()
  writer.write(toArray(BRC69_METHOD2_V2_PUBLIC_INPUT_DIGEST_ID, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.family, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.airId, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.curveId, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.hashId, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.hmacId, 'utf8'))
  writer.writeUInt8(METHOD2_V2_PROFILE.windowBits)
  writer.writeUInt8(METHOD2_V2_PROFILE.finalWindowBits)
  writer.writeUInt8(METHOD2_V2_PROFILE.windowCount)
  writer.writeUInt8(METHOD2_V2_PROFILE.limbBits)
  writer.writeUInt8(METHOD2_V2_PROFILE.stark.blowupFactor)
  writer.writeUInt8(METHOD2_V2_PROFILE.stark.numQueries)
  writer.writeUInt8(METHOD2_V2_PROFILE.stark.maxRemainderSize)
  writer.write(toArray(statement.prover, 'hex'))
  writer.write(toArray(statement.counterparty, 'hex'))
  writer.writeUInt8(statement.protocolID[0])
  const protocolBytes = toArray(statement.protocolID[1].toLowerCase().trim(), 'utf8')
  writer.writeVarIntNum(protocolBytes.length)
  writer.write(protocolBytes)
  const keyBytes = toArray(statement.keyID, 'utf8')
  writer.writeVarIntNum(keyBytes.length)
  writer.write(keyBytes)
  writer.writeVarIntNum(invoiceBytes.length)
  writer.write(invoiceBytes)
  writer.write(statement.linkage)
  return sha256(writer.toArray())
}

export function method2V2ScalarDigits (scalar: bigint): number[] {
  validateScalar(scalar)
  const digits: number[] = []
  let reconstructed = 0n
  for (let window = 0; window < METHOD2_V2_WINDOW_COUNT; window++) {
    const bits = method2V2WindowBits(window)
    const mask = (1n << BigInt(bits)) - 1n
    const digit = Number((scalar >> BigInt(window * METHOD2_V2_WINDOW_BITS)) & mask)
    digits.push(digit)
    reconstructed += BigInt(digit) << BigInt(window * METHOD2_V2_WINDOW_BITS)
  }
  if (reconstructed !== scalar) {
    throw new Error('Method 2 V2 scalar digit decomposition mismatch')
  }
  return digits
}

export function buildMethod2V2FixedWindowTables (
  counterpartyB: SecpPoint
): Method2V2FixedWindowTables {
  validatePublicPoint(SECP256K1_G, 'generator')
  validatePublicPoint(counterpartyB, 'counterparty')
  const windows: Method2V2TableWindow[] = []
  let gBase = SECP256K1_G
  let bBase = counterpartyB
  for (let window = 0; window < METHOD2_V2_WINDOW_COUNT; window++) {
    const bits = method2V2WindowBits(window)
    const entries = 1 << bits
    const g: SecpPoint[] = []
    const b: SecpPoint[] = []
    let gMultiple = infinityPoint()
    let bMultiple = infinityPoint()
    for (let digit = 0; digit < entries; digit++) {
      g.push(gMultiple)
      b.push(bMultiple)
      if (digit !== 0) {
        validatePublicPoint(g[digit], `G table window ${window} digit ${digit}`)
        validatePublicPoint(b[digit], `B table window ${window} digit ${digit}`)
      }
      gMultiple = pointAdd(gMultiple, gBase)
      bMultiple = pointAdd(bMultiple, bBase)
    }
    windows.push({ window, bits, g, b })
    for (let i = 0; i < METHOD2_V2_WINDOW_BITS; i++) {
      gBase = pointDouble(gBase)
      bBase = pointDouble(bBase)
    }
  }
  return {
    windowBits: METHOD2_V2_WINDOW_BITS,
    windows
  }
}

export function buildMethod2V2Trace (
  scalar: bigint,
  publicA: SecpPoint,
  counterpartyB: SecpPoint,
  invoiceBytes: number[],
  linkage: number[]
): Method2V2Trace {
  validateScalar(scalar)
  validatePublicPoint(publicA, 'prover')
  validatePublicPoint(counterpartyB, 'counterparty')
  assertBytes(invoiceBytes, 'invoice')
  assertBytes(linkage, 'linkage')
  if (linkage.length !== 32) throw new Error('Method 2 V2 linkage must be 32 bytes')

  const expectedA = scalarMultiply(scalar, SECP256K1_G)
  if (!pointsEqual(expectedA, publicA)) {
    throw new Error('Method 2 V2 prover point does not match scalar')
  }
  const sharedS = scalarMultiply(scalar, counterpartyB)
  const compressedS = compressPoint(sharedS)
  const expectedLinkage = hmacSha256(compressedS, invoiceBytes)
  if (!bytesEqual(expectedLinkage, linkage)) {
    throw new Error('Method 2 V2 linkage does not match witness relation')
  }

  const digits = method2V2ScalarDigits(scalar)
  const tables = buildMethod2V2FixedWindowTables(counterpartyB)
  const rows: Method2V2TraceRow[] = []
  let accG = infinityPoint()
  let accB = infinityPoint()

  for (let window = 0; window < METHOD2_V2_WINDOW_COUNT; window++) {
    const digit = digits[window]
    const tableWindow = tables.windows[window]
    let selectedG = infinityPoint()
    let selectedB = infinityPoint()
    let selectorSum = 0
    for (let candidate = 0; candidate < tableWindow.g.length; candidate++) {
      const selector = candidate === digit ? 1 : 0
      selectorSum += selector
      if (selector === 1) {
        selectedG = tableWindow.g[candidate]
        selectedB = tableWindow.b[candidate]
      }
      rows.push({
        phase: 'select',
        window,
        digit: candidate,
        selector,
        selectorSum,
        candidateG: tableWindow.g[candidate],
        candidateB: tableWindow.b[candidate],
        selectedG,
        selectedB
      })
    }
    if (selectorSum !== 1) throw new Error('Method 2 V2 selection witness is invalid')
    const beforeG = accG
    const beforeB = accB
    accG = pointAdd(accG, selectedG)
    accB = pointAdd(accB, selectedB)
    rows.push({
      phase: 'accumulate',
      window,
      digit,
      accGBefore: beforeG,
      accBBefore: beforeB,
      selectedG,
      selectedB,
      accGAfter: accG,
      accBAfter: accB
    })
  }

  const trace: Method2V2Trace = {
    profile: METHOD2_V2_PROFILE,
    scalar,
    digits,
    tables,
    rows,
    publicA,
    counterpartyB,
    sharedS,
    compressedS,
    invoiceBytes: invoiceBytes.slice(),
    linkage: linkage.slice(),
    activeRows: rows.length,
    privateCommittedWidthEstimate: 150,
    publicPreprocessedWidthEstimate: 4
  }
  validateMethod2V2Trace(trace)
  return trace
}

export function validateMethod2V2Trace (trace: Method2V2Trace): void {
  if (trace.profile.family !== BRC69_METHOD2_V2_DOMAIN) {
    throw new Error('Method 2 V2 trace profile mismatch')
  }
  validateScalar(trace.scalar)
  if (trace.digits.length !== METHOD2_V2_WINDOW_COUNT) {
    throw new Error('Method 2 V2 digit count mismatch')
  }
  const expectedDigits = method2V2ScalarDigits(trace.scalar)
  if (!arrayEqual(trace.digits, expectedDigits)) {
    throw new Error('Method 2 V2 trace digits do not reconstruct scalar')
  }
  const expectedTables = buildMethod2V2FixedWindowTables(trace.counterpartyB)
  let rowIndex = 0
  let accG = infinityPoint()
  let accB = infinityPoint()
  for (let window = 0; window < METHOD2_V2_WINDOW_COUNT; window++) {
    const tableWindow = expectedTables.windows[window]
    const digit = trace.digits[window]
    let selectorSum = 0
    let selectedG = infinityPoint()
    let selectedB = infinityPoint()
    for (let candidate = 0; candidate < tableWindow.g.length; candidate++) {
      const row = trace.rows[rowIndex++]
      if (row?.phase !== 'select') {
        throw new Error('Method 2 V2 trace selection row missing')
      }
      const selector = candidate === digit ? 1 : 0
      selectorSum += selector
      if (selector === 1) {
        selectedG = tableWindow.g[candidate]
        selectedB = tableWindow.b[candidate]
      }
      assertSelectionRow(row, window, candidate, selector, selectorSum, tableWindow, selectedG, selectedB)
    }
    const row = trace.rows[rowIndex++]
    if (row?.phase !== 'accumulate') {
      throw new Error('Method 2 V2 trace accumulation row missing')
    }
    assertPointEqual(row.accGBefore, accG, 'accG before')
    assertPointEqual(row.accBBefore, accB, 'accB before')
    assertPointEqual(row.selectedG, selectedG, 'selected G')
    assertPointEqual(row.selectedB, selectedB, 'selected B')
    accG = pointAdd(accG, selectedG)
    accB = pointAdd(accB, selectedB)
    assertPointEqual(row.accGAfter, accG, 'accG after')
    assertPointEqual(row.accBAfter, accB, 'accB after')
  }
  if (rowIndex !== trace.rows.length) {
    throw new Error('Method 2 V2 trace has unexpected trailing rows')
  }
  assertPointEqual(accG, trace.publicA, 'public A')
  assertPointEqual(accB, trace.sharedS, 'shared S')
  if (!bytesEqual(compressPoint(trace.sharedS), trace.compressedS)) {
    throw new Error('Method 2 V2 compressed S mismatch')
  }
  if (!bytesEqual(hmacSha256(trace.compressedS, trace.invoiceBytes), trace.linkage)) {
    throw new Error('Method 2 V2 HMAC linkage mismatch')
  }
}

export function method2V2Metrics (trace: Method2V2Trace): Method2V2Metrics {
  const activeRows = trace.activeRows
  const paddedRows = nextPowerOfTwo(activeRows)
  const innerShaBlocks = Math.ceil((64 + trace.invoiceBytes.length + 9) / 64)
  const outerShaBlocks = Math.ceil((64 + 32 + 9) / 64)
  const ldeRows = paddedRows * METHOD2_V2_STARK_BLOWUP_FACTOR
  const privateCommittedWidth = trace.privateCommittedWidthEstimate
  return {
    activeRows,
    paddedRows,
    privateCommittedWidth,
    publicPreprocessedWidth: trace.publicPreprocessedWidthEstimate,
    ldeRows,
    estimatedTraceArea: ldeRows * privateCommittedWidth,
    invoiceLength: trace.invoiceBytes.length,
    innerShaBlocks,
    outerShaBlocks
  }
}

export function method2V2WindowBits (window: number): number {
  if (!Number.isInteger(window) || window < 0 || window >= METHOD2_V2_WINDOW_COUNT) {
    throw new Error('Method 2 V2 window index out of range')
  }
  return window === METHOD2_V2_WINDOW_COUNT - 1
    ? METHOD2_V2_FINAL_WINDOW_BITS
    : METHOD2_V2_WINDOW_BITS
}

function assertSelectionRow (
  row: Method2V2SelectionRow,
  window: number,
  candidate: number,
  selector: 0 | 1,
  selectorSum: number,
  tableWindow: Method2V2TableWindow,
  selectedG: SecpPoint,
  selectedB: SecpPoint
): void {
  if (
    row.window !== window ||
    row.digit !== candidate ||
    row.selector !== selector ||
    row.selectorSum !== selectorSum
  ) {
    throw new Error('Method 2 V2 selection control mismatch')
  }
  assertPointEqual(row.candidateG, tableWindow.g[candidate], 'candidate G')
  assertPointEqual(row.candidateB, tableWindow.b[candidate], 'candidate B')
  assertPointEqual(row.selectedG, selectedG, 'running selected G')
  assertPointEqual(row.selectedB, selectedB, 'running selected B')
}

function validatePublicPoint (point: SecpPoint, label: string): void {
  if (!isOnCurve(point)) throw new Error(`Invalid Method 2 V2 ${label} point`)
}

function assertPointEqual (left: SecpPoint, right: SecpPoint, label: string): void {
  if (!pointsEqual(left, right)) {
    throw new Error(`Method 2 V2 ${label} point mismatch`)
  }
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  return left.infinity === true
    ? right.infinity === true
    : right.infinity !== true && left.x === right.x && left.y === right.y
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function assertBytes (bytes: number[], label: string): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid Method 2 V2 ${label} byte`)
    }
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false
  }
  return true
}

function arrayEqual (left: number[], right: number[]): boolean {
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false
  }
  return true
}

void SECP256K1_N
void SECP256K1_P
