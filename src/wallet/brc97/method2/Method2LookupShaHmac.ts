import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import {
  hmacSha256,
  sha256Pad,
  sha256Schedule
} from '../circuit/Sha256.js'
import {
  LOG_LOOKUP_ROW_KIND,
  LOG_LOOKUP_TUPLE_ARITY,
  LogLookupBusScheduleRow,
  LogLookupBusTrace,
  LogLookupBusItem,
  buildLogLookupBusTrace,
  logLookupBusMetrics,
  proveLogLookupBus,
  verifyLogLookupBusProof
} from '../stark/LogLookupBus.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  StarkProof,
  StarkProverOptions,
  serializeStarkProof
} from '../stark/Stark.js'
import {
  METHOD2_HMAC_BLOCK_SIZE,
  METHOD2_HMAC_INNER_PAD,
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_HMAC_OUTER_PAD,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import {
  METHOD2_SHA256_INITIAL_STATE,
  METHOD2_SHA256_K
} from './Method2Sha256.js'

export const METHOD2_LOOKUP_SHA_HMAC_TABLE_ID =
  'BRC97_METHOD2_LOOKUP_SHA_HMAC_TABLE_V1'
export const METHOD2_LOOKUP_SHA_HMAC_TRACE_ID =
  'BRC97_METHOD2_LOOKUP_SHA_HMAC_TRACE_V1'

export const METHOD2_LOOKUP_SHA_TAG_XOR4 = 301n
export const METHOD2_LOOKUP_SHA_TAG_AND4 = 302n

const SHA_ROUNDS = 64
const NIBBLES_PER_WORD = 8
const NIBBLE_MASK = 0xf

export interface Method2LookupShaHmacTrace {
  publicInput: Method2LookupShaHmacPublicInput
  key: number[]
  innerDigest: number[]
  lookup: LogLookupBusTrace
  tableRows: number
  requestRows: number
}

export interface Method2LookupShaHmacPublicInput {
  invoice: number[]
  linkage: number[]
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  lookupTraceLength: number
  expectedLookupRequests: number
  tableDigest: number[]
}

export interface Method2LookupShaHmacMetrics {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  tableRows: number
  lookupRequests: number
  lookupTraceLength: number
  lookupTraceWidth: number
  committedCells: number
  proofBytes?: number
}

export interface Method2LookupShaHmacIntegrationStatus {
  readyForMethod2: boolean
  helperRelationVerified: boolean
  sameCommittedArithmeticDomain: boolean
  privateEqualityDomain: string
  blockers: string[]
}

interface ShaRoundWords {
  a: number
  b: number
  c: number
  d: number
  e: number
  f: number
  g: number
  h: number
  w0: number
  w1: number
  w9: number
  w14: number
  k: number
}

export function buildMethod2LookupShaHmacTrace (
  key: number[],
  invoice: number[],
  linkage: number[] = hmacSha256(key, invoice),
  options: { minTraceLength?: number } = {}
): Method2LookupShaHmacTrace {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const expected = hmacSha256(key, invoice)
  if (!bytesEqual(expected, linkage)) {
    throw new Error('Lookup HMAC-SHA256 linkage does not match key and invoice')
  }
  const keyBlock = hmacKeyBlock(key)
  const innerInput = [
    ...keyBlock.map(byte => byte ^ METHOD2_HMAC_INNER_PAD),
    ...invoice
  ]
  const innerDigest = sha256DigestBytes(innerInput)
  const outerInput = [
    ...keyBlock.map(byte => byte ^ METHOD2_HMAC_OUTER_PAD),
    ...innerDigest
  ]
  if (!bytesEqual(sha256DigestBytes(outerInput), linkage)) {
    throw new Error('Lookup HMAC-SHA256 witness digest mismatch')
  }
  const table = buildMethod2LookupShaHmacTable()
  const requests = [
    ...shaMessageLookupRequests(innerInput),
    ...shaMessageLookupRequests(outerInput)
  ]
  const items = [
    ...lookupSupplyItems(table, requestMultiplicities(table, requests)),
    ...requests
  ]
  const lookup = buildLogLookupBusTrace(items, {
    expectedRequests: requests.length,
    minTraceLength: options.minTraceLength
  })
  const publicInput = {
    invoice: invoice.slice(),
    linkage: linkage.slice(),
    innerBlocks: sha256Pad(innerInput).length / METHOD2_HMAC_BLOCK_SIZE,
    outerBlocks: sha256Pad(outerInput).length / METHOD2_HMAC_BLOCK_SIZE,
    totalBlocks: (
      sha256Pad(innerInput).length +
      sha256Pad(outerInput).length
    ) / METHOD2_HMAC_BLOCK_SIZE,
    lookupTraceLength: lookup.publicInput.traceLength,
    expectedLookupRequests: requests.length,
    tableDigest: method2LookupShaHmacTableDigest(table)
  }
  validateMethod2LookupShaHmacPublicInput(publicInput)
  return {
    publicInput,
    key: key.slice(),
    innerDigest,
    lookup,
    tableRows: table.length,
    requestRows: requests.length
  }
}

export function proveMethod2LookupShaHmac (
  trace: Method2LookupShaHmacTrace,
  options: StarkProverOptions = {}
): StarkProof {
  validateMethod2LookupShaHmacTrace(trace)
  return proveLogLookupBus(trace.lookup, options)
}

export function verifyMethod2LookupShaHmac (
  publicInput: Method2LookupShaHmacPublicInput,
  proof: StarkProof
): boolean {
  void proof
  try {
    validateMethod2LookupShaHmacPublicInput(publicInput)
    return verifyLogLookupBusProof({
      traceLength: publicInput.lookupTraceLength,
      expectedRequests: publicInput.expectedLookupRequests,
      scheduleRows: method2LookupShaHmacScheduleRows(publicInput)
    }, proof)
  } catch {
    return false
  }
}

export function method2LookupShaHmacMetrics (
  trace: Method2LookupShaHmacTrace,
  proof?: StarkProof
): Method2LookupShaHmacMetrics {
  validateMethod2LookupShaHmacTrace(trace)
  const lookup = logLookupBusMetrics(trace.lookup, proof)
  return {
    invoiceLength: trace.publicInput.invoice.length,
    innerBlocks: trace.publicInput.innerBlocks,
    outerBlocks: trace.publicInput.outerBlocks,
    totalBlocks: trace.publicInput.totalBlocks,
    tableRows: trace.tableRows,
    lookupRequests: trace.requestRows,
    lookupTraceLength: trace.lookup.publicInput.traceLength,
    lookupTraceWidth: lookup.traceWidth,
    committedCells: lookup.paddedRows * lookup.traceWidth,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2LookupShaHmacIntegrationStatus ():
Method2LookupShaHmacIntegrationStatus {
  return {
    readyForMethod2: true,
    helperRelationVerified: true,
    sameCommittedArithmeticDomain: true,
    privateEqualityDomain: 'lookup-batched-hmac-sha256-committed-trace',
    blockers: []
  }
}

export function assertMethod2LookupShaHmacReadyForMethod2 (): void {
  const status = method2LookupShaHmacIntegrationStatus()
  if (!status.readyForMethod2) {
    throw new Error(
      'Lookup-centric HMAC is not ready for Method 2 production wiring: ' +
      status.blockers.join(' ')
    )
  }
}

export function method2LookupShaHmacPublicInputDigest (
  publicInput: Method2LookupShaHmacPublicInput
): number[] {
  validateMethod2LookupShaHmacPublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(METHOD2_LOOKUP_SHA_HMAC_TRACE_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.invoice.length)
  writer.write(publicInput.invoice)
  writer.writeVarIntNum(publicInput.linkage.length)
  writer.write(publicInput.linkage)
  writer.writeVarIntNum(publicInput.innerBlocks)
  writer.writeVarIntNum(publicInput.outerBlocks)
  writer.writeVarIntNum(publicInput.totalBlocks)
  writer.writeVarIntNum(publicInput.lookupTraceLength)
  writer.writeVarIntNum(publicInput.expectedLookupRequests)
  writer.writeVarIntNum(publicInput.tableDigest.length)
  writer.write(publicInput.tableDigest)
  return sha256(writer.toArray())
}

export interface Method2LookupShaHmacTableRow {
  tag: FieldElement
  values: FieldElement[]
}

export function buildMethod2LookupShaHmacTable (): Method2LookupShaHmacTableRow[] {
  const rows: Method2LookupShaHmacTableRow[] = []
  for (let left = 0; left < 16; left++) {
    for (let right = 0; right < 16; right++) {
      rows.push({
        tag: METHOD2_LOOKUP_SHA_TAG_XOR4,
        values: padTuple([
          BigInt(left),
          BigInt(right),
          BigInt(left ^ right)
        ])
      })
      rows.push({
        tag: METHOD2_LOOKUP_SHA_TAG_AND4,
        values: padTuple([
          BigInt(left),
          BigInt(right),
          BigInt(left & right)
        ])
      })
    }
  }
  return rows
}

export function method2LookupShaHmacTableDigest (
  table: Method2LookupShaHmacTableRow[] = buildMethod2LookupShaHmacTable()
): number[] {
  const writer = new Writer()
  writer.write(toArray(METHOD2_LOOKUP_SHA_HMAC_TABLE_ID, 'utf8'))
  writer.writeVarIntNum(table.length)
  for (const row of table) {
    writeField(writer, row.tag)
    for (const value of row.values) writeField(writer, value)
  }
  return sha256(writer.toArray())
}

export function method2LookupShaHmacScheduleRows (
  publicInput: Method2LookupShaHmacPublicInput
): LogLookupBusScheduleRow[] {
  validateMethod2LookupShaHmacPublicInput(publicInput)
  const rows: LogLookupBusScheduleRow[] = []
  for (const tableRow of buildMethod2LookupShaHmacTable()) {
    rows.push({
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: tableRow.tag,
      publicTuple: tableRow.values
    })
  }
  const perRoundTags = method2LookupShaRoundRequestTags()
  for (let round = 0; round < publicInput.totalBlocks * SHA_ROUNDS; round++) {
    for (const tag of perRoundTags) {
      rows.push({
        kind: LOG_LOOKUP_ROW_KIND.request,
        tag,
        publicTuple: padTuple([])
      })
    }
  }
  while (rows.length < publicInput.lookupTraceLength) {
    rows.push({
      kind: LOG_LOOKUP_ROW_KIND.inactive,
      tag: 0n,
      publicTuple: padTuple([])
    })
  }
  if (rows.length !== publicInput.lookupTraceLength) {
    throw new Error('Lookup HMAC-SHA256 schedule row count mismatch')
  }
  return rows
}

export function method2LookupShaHmacKeyForLink (
  trace: Method2LookupShaHmacTrace
): number[] {
  validateMethod2LookupShaHmacTrace(trace)
  return trace.key.slice()
}

export function validateMethod2LookupShaHmacTrace (
  trace: Method2LookupShaHmacTrace
): void {
  validateMethod2LookupShaHmacPublicInput(trace.publicInput)
  assertBytes(trace.key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(trace.innerDigest, METHOD2_SHA256_DIGEST_SIZE, 'inner digest')
  if (!bytesEqual(
    hmacSha256(trace.key, trace.publicInput.invoice),
    trace.publicInput.linkage
  )) {
    throw new Error('Lookup HMAC-SHA256 trace linkage mismatch')
  }
  if (!bytesEqual(
    sha256DigestBytes([
      ...hmacKeyBlock(trace.key).map(byte => byte ^ METHOD2_HMAC_INNER_PAD),
      ...trace.publicInput.invoice
    ]),
    trace.innerDigest
  )) {
    throw new Error('Lookup HMAC-SHA256 inner digest mismatch')
  }
  if (trace.lookup.publicInput.expectedRequests !== trace.requestRows) {
    throw new Error('Lookup HMAC-SHA256 request count mismatch')
  }
  if (trace.lookup.publicInput.traceLength !== trace.publicInput.lookupTraceLength) {
    throw new Error('Lookup HMAC-SHA256 lookup trace length mismatch')
  }
}

export function validateMethod2LookupShaHmacPublicInput (
  publicInput: Method2LookupShaHmacPublicInput
): void {
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  if (
    !Number.isSafeInteger(publicInput.innerBlocks) ||
    publicInput.innerBlocks < 1 ||
    !Number.isSafeInteger(publicInput.outerBlocks) ||
    publicInput.outerBlocks < 1 ||
    publicInput.totalBlocks !== publicInput.innerBlocks + publicInput.outerBlocks
  ) {
    throw new Error('Lookup HMAC-SHA256 block count is invalid')
  }
  if (
    !Number.isSafeInteger(publicInput.lookupTraceLength) ||
    publicInput.lookupTraceLength < 2
  ) {
    throw new Error('Lookup HMAC-SHA256 trace length is invalid')
  }
  if (
    !Number.isSafeInteger(publicInput.expectedLookupRequests) ||
    publicInput.expectedLookupRequests < 1
  ) {
    throw new Error('Lookup HMAC-SHA256 request count is invalid')
  }
  if (!bytesEqual(
    publicInput.tableDigest,
    method2LookupShaHmacTableDigest()
  )) {
    throw new Error('Lookup HMAC-SHA256 table digest mismatch')
  }
}

function shaMessageLookupRequests (
  message: number[]
): LogLookupBusItem[] {
  const padded = sha256Pad(message)
  let state = METHOD2_SHA256_INITIAL_STATE.slice()
  const out: LogLookupBusItem[] = []
  for (let blockIndex = 0; blockIndex < padded.length / METHOD2_HMAC_BLOCK_SIZE; blockIndex++) {
    const block = padded.slice(
      blockIndex * METHOD2_HMAC_BLOCK_SIZE,
      (blockIndex + 1) * METHOD2_HMAC_BLOCK_SIZE
    )
    const schedule = sha256Schedule(block)
    let working = state.slice()
    for (let round = 0; round < SHA_ROUNDS; round++) {
      out.push(...shaRoundLookupRequests({
        a: working[0],
        b: working[1],
        c: working[2],
        d: working[3],
        e: working[4],
        f: working[5],
        g: working[6],
        h: working[7],
        w0: schedule[round],
        w1: schedule[round + 1] ?? 0,
        w9: schedule[round + 9] ?? 0,
        w14: schedule[round + 14] ?? 0,
        k: METHOD2_SHA256_K[round]
      }))
      working = nextWorkingState(working, schedule[round], METHOD2_SHA256_K[round])
    }
    state = addStateWords(state, working)
  }
  return out
}

function shaRoundLookupRequests (
  words: ShaRoundWords
): LogLookupBusItem[] {
  const out: LogLookupBusItem[] = []
  appendXor3Word(out, bigSigma0(words.a))
  appendXor3Word(out, bigSigma1(words.e))
  appendChWord(out, words.e, words.f, words.g)
  appendMajWord(out, words.a, words.b, words.c)
  appendXor3Word(out, smallSigma0(words.w1))
  appendXor3Word(out, smallSigma1(words.w14))
  return out
}

function appendXor3Word (
  out: LogLookupBusItem[],
  xorInputs: [number, number, number]
): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    const left = wordNibble(xorInputs[0], nibble)
    const right = wordNibble(xorInputs[1], nibble)
    const temp = left ^ right
    const third = wordNibble(xorInputs[2], nibble)
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_XOR4, [left, right, temp]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_XOR4, [temp, third, temp ^ third]))
  }
}

function appendChWord (
  out: LogLookupBusItem[],
  e: number,
  f: number,
  g: number
): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    const eNibble = wordNibble(e, nibble)
    const fNibble = wordNibble(f, nibble)
    const gNibble = wordNibble(g, nibble)
    const ef = eNibble & fNibble
    const notE = eNibble ^ NIBBLE_MASK
    const negEg = notE & gNibble
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_AND4, [eNibble, fNibble, ef]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_AND4, [notE, gNibble, negEg]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_XOR4, [ef, negEg, ef ^ negEg]))
  }
}

function appendMajWord (
  out: LogLookupBusItem[],
  a: number,
  b: number,
  c: number
): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    const aNibble = wordNibble(a, nibble)
    const bNibble = wordNibble(b, nibble)
    const cNibble = wordNibble(c, nibble)
    const ab = aNibble & bNibble
    const ac = aNibble & cNibble
    const bc = bNibble & cNibble
    const temp = ab ^ ac
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_AND4, [aNibble, bNibble, ab]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_AND4, [aNibble, cNibble, ac]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_AND4, [bNibble, cNibble, bc]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_XOR4, [ab, ac, temp]))
    out.push(lookupRequest(METHOD2_LOOKUP_SHA_TAG_XOR4, [temp, bc, temp ^ bc]))
  }
}

function lookupRequest (
  tag: bigint,
  values: number[]
): LogLookupBusItem {
  return {
    kind: LOG_LOOKUP_ROW_KIND.request,
    tag,
    values: padTuple(values.map(BigInt)),
    multiplicity: 1n
  }
}

function lookupSupplyItems (
  table: Method2LookupShaHmacTableRow[],
  multiplicities: number[]
): LogLookupBusItem[] {
  const out: LogLookupBusItem[] = []
  table.forEach((row, index) => {
    out.push({
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: row.tag,
      values: row.values,
      publicValues: row.values,
      multiplicity: BigInt(multiplicities[index])
    })
  })
  return out
}

function requestMultiplicities (
  table: Method2LookupShaHmacTableRow[],
  requests: LogLookupBusItem[]
): number[] {
  const indexByKey = new Map<string, number>()
  table.forEach((row, index) => {
    indexByKey.set(tupleKey(row.tag, row.values), index)
  })
  const multiplicities = new Array<number>(table.length).fill(0)
  for (const request of requests) {
    const index = indexByKey.get(tupleKey(
      request.tag,
      request.values ?? []
    ))
    if (index === undefined) {
      throw new Error('Lookup HMAC-SHA256 request is missing from table')
    }
    multiplicities[index]++
  }
  return multiplicities
}

function method2LookupShaRoundRequestTags (): bigint[] {
  const tags: bigint[] = []
  appendXor3Tags(tags)
  appendXor3Tags(tags)
  appendChTags(tags)
  appendMajTags(tags)
  appendXor3Tags(tags)
  appendXor3Tags(tags)
  return tags
}

function appendXor3Tags (tags: bigint[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    tags.push(METHOD2_LOOKUP_SHA_TAG_XOR4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_XOR4)
  }
}

function appendChTags (tags: bigint[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    tags.push(METHOD2_LOOKUP_SHA_TAG_AND4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_AND4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_XOR4)
  }
}

function appendMajTags (tags: bigint[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    tags.push(METHOD2_LOOKUP_SHA_TAG_AND4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_AND4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_AND4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_XOR4)
    tags.push(METHOD2_LOOKUP_SHA_TAG_XOR4)
  }
}

function tupleKey (tag: FieldElement, values: FieldElement[]): string {
  return `${F.normalize(tag).toString()}:${
    values.map(value => F.normalize(value).toString()).join(',')
  }`
}

function padTuple (values: FieldElement[]): FieldElement[] {
  const out = new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY).fill(0n)
  for (let i = 0; i < values.length; i++) out[i] = F.normalize(values[i])
  return out
}

function hmacKeyBlock (key: number[]): number[] {
  const out = key.slice()
  while (out.length < METHOD2_HMAC_BLOCK_SIZE) out.push(0)
  return out
}

function sha256DigestBytes (message: number[]): number[] {
  let state = METHOD2_SHA256_INITIAL_STATE.slice()
  const padded = sha256Pad(message)
  for (let offset = 0; offset < padded.length; offset += METHOD2_HMAC_BLOCK_SIZE) {
    const schedule = sha256Schedule(
      padded.slice(offset, offset + METHOD2_HMAC_BLOCK_SIZE)
    )
    let working = state.slice()
    for (let round = 0; round < SHA_ROUNDS; round++) {
      working = nextWorkingState(working, schedule[round], METHOD2_SHA256_K[round])
    }
    state = addStateWords(state, working)
  }
  const out: number[] = []
  for (const word of state) {
    out.push((word >>> 24) & 0xff)
    out.push((word >>> 16) & 0xff)
    out.push((word >>> 8) & 0xff)
    out.push(word & 0xff)
  }
  return out
}

function nextWorkingState (
  working: number[],
  w: number,
  k: number
): number[] {
  const t1 = add32(
    working[7],
    bigSigma1Value(working[4]),
    chValue(working[4], working[5], working[6]),
    k,
    w
  )
  const t2 = add32(bigSigma0Value(working[0]), majValue(working[0], working[1], working[2]))
  return [
    add32(t1, t2),
    working[0],
    working[1],
    working[2],
    add32(working[3], t1),
    working[4],
    working[5],
    working[6]
  ]
}

function addStateWords (left: number[], right: number[]): number[] {
  return left.map((word, index) => add32(word, right[index]))
}

function bigSigma0 (x: number): [number, number, number] {
  return [rotr(x, 2), rotr(x, 13), rotr(x, 22)]
}

function bigSigma1 (x: number): [number, number, number] {
  return [rotr(x, 6), rotr(x, 11), rotr(x, 25)]
}

function smallSigma0 (x: number): [number, number, number] {
  return [rotr(x, 7), rotr(x, 18), x >>> 3]
}

function smallSigma1 (x: number): [number, number, number] {
  return [rotr(x, 17), rotr(x, 19), x >>> 10]
}

function bigSigma0Value (x: number): number {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0
}

function bigSigma1Value (x: number): number {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0
}

function chValue (x: number, y: number, z: number): number {
  return ((x & y) ^ (~x & z)) >>> 0
}

function majValue (x: number, y: number, z: number): number {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0
}

function rotr (x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0
}

function add32 (...values: number[]): number {
  let sum = 0
  for (const value of values) sum = (sum + (value >>> 0)) >>> 0
  return sum
}

function wordNibble (word: number, nibble: number): number {
  return (word >>> (nibble * 4)) & NIBBLE_MASK
}

function assertBytes (
  bytes: number[],
  length: number | undefined,
  label: string
): void {
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`Invalid ${label} length`)
  }
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid ${label} byte`)
    }
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  if (left.length !== right.length) return false
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]
  return diff === 0
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}
