import PrivateKey from '../../primitives/PrivateKey.js'
import { WalletCounterparty, WalletProtocol } from '../Wallet.interfaces.js'
import { computeInvoiceNumber } from '../keyLinkage.js'
import { Writer, toArray, toHex } from '../../primitives/utils.js'
import {
  SECP256K1_G,
  SecpPoint,
  compressPoint,
  decompressPublicKey,
  scalarMultiply,
  validateScalar
} from './circuit/index.js'
import { F, FieldElement } from './stark/Field.js'
import {
  MultiTraceStarkProof,
  parseMultiTraceStarkProof,
  serializeMultiTraceStarkProof
} from './stark/Stark.js'
import {
  BRC69Method2WholeStatementPublicInput,
  buildBRC69Method2WholeStatement,
  destroyBRC69Method2WholeStatementWitness,
  proveBRC69Method2WholeStatement,
  validateBRC69Method2WholeStatementPublicInput,
  verifyBRC69Method2WholeStatement
} from './method2/BRC69Method2WholeStatement.js'

export const BRC69_METHOD2_PROOF_TYPE = 1
export const BRC69_METHOD2_PROOF_PAYLOAD_VERSION = 1
export const BRC69_METHOD2_PUBLIC_INPUT_VERSION = 1
export const BRC69_METHOD2_PROOF_PAYLOAD_MAGIC =
  'BRC69_KEY_LINKAGE_PROOF_PAYLOAD'
export const BRC69_METHOD2_PUBLIC_INPUT_MAGIC =
  'BRC69_METHOD2_WHOLE_STATEMENT_PUBLIC_INPUT'

export const BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES = 16 * 1024 * 1024
export const BRC69_METHOD2_MAX_PROOF_BYTES = 16 * 1024 * 1024
export const BRC69_METHOD2_MAX_PAYLOAD_BYTES = 34 * 1024 * 1024

const BRC69_METHOD2_MAX_PUBLIC_INPUT_ROWS = 1_000_000
const BRC69_METHOD2_BUS_SEGMENT_ORDER = [
  'scalar',
  'lookup',
  'bridge',
  'ec',
  'compression',
  'hmac'
] as const
const BRC69_METHOD2_EC_OPERATIONS = [
  'dx',
  'dy',
  'inverse',
  'slope',
  'slopeSquared',
  'xFirstSub',
  'xSecondSub',
  'xDiff',
  'ySum',
  'yRelation'
] as const

export interface SpecificKeyLinkageStatement {
  prover: string
  counterparty: string
  protocolID: WalletProtocol
  keyID: string
  linkage: number[]
}

export interface CreateSpecificKeyLinkageProofArgs {
  proverPrivateKey: PrivateKey | bigint | string
  statement: SpecificKeyLinkageStatement
}

export interface BRC69SpecificKeyLinkageProof {
  publicInput: BRC69Method2WholeStatementPublicInput
  proof: MultiTraceStarkProof
}

export type ParsedSpecificKeyLinkageProofPayload =
  | { proofType: 0 }
  | { proofType: 1, proof: BRC69SpecificKeyLinkageProof }

export function normalizeSpecificKeyLinkageCounterparty (
  counterparty: WalletCounterparty,
  prover: string,
  options: { allowSentinelCounterparty?: boolean } = {}
): string {
  if (counterparty === 'self' || counterparty === 'anyone') {
    if (options.allowSentinelCounterparty !== true) {
      throw new Error(
        'BRC69 Method 2 proof type 1 requires an explicit counterparty public key; sentinel counterparties require proofType 0'
      )
    }
    if (counterparty === 'self') return prover
    return toHex(compressPoint(SECP256K1_G))
  }
  assertCompressedPublicKeyHex(counterparty, 'counterparty')
  return counterparty.toLowerCase()
}

export function createSpecificKeyLinkageProof (
  args: CreateSpecificKeyLinkageProofArgs
): BRC69SpecificKeyLinkageProof {
  const statement = normalizeStatement(args.statement)
  const scalar = privateKeyToScalar(args.proverPrivateKey)
  validateScalar(scalar)

  const publicA = scalarMultiply(scalar)
  if (toHex(compressPoint(publicA)) !== statement.prover) {
    throw new Error('Prover private key does not match public prover key')
  }
  const baseB = decompressPublicKey(toArray(statement.counterparty, 'hex'))
  const invoice = toArray(
    computeInvoiceNumber(statement.protocolID, statement.keyID),
    'utf8'
  )

  const wholeStatement = buildBRC69Method2WholeStatement({
    scalar,
    baseB,
    invoice,
    linkage: statement.linkage
  })
  try {
    return {
      publicInput: wholeStatement.publicInput,
      proof: proveBRC69Method2WholeStatement(wholeStatement)
    }
  } finally {
    destroyBRC69Method2WholeStatementWitness(wholeStatement)
  }
}

export function verifySpecificKeyLinkageProof (
  statement: SpecificKeyLinkageStatement,
  payload: number[] | BRC69SpecificKeyLinkageProof
): boolean {
  try {
    const normalized = normalizeStatement(statement)
    const parsed = Array.isArray(payload)
      ? parseSpecificKeyLinkageProofPayload(payload)
      : { proofType: 1 as const, proof: payload }
    if (parsed.proofType !== 1) return false
    const proof = parsed.proof
    if (!publicInputMatchesStatement(proof.publicInput, normalized)) {
      return false
    }
    return verifyBRC69Method2WholeStatement(proof.publicInput, proof.proof)
  } catch {
    return false
  }
}

export function serializeSpecificKeyLinkageProofPayload (
  proof: BRC69SpecificKeyLinkageProof
): number[] {
  return [
    BRC69_METHOD2_PROOF_TYPE,
    ...serializeBRC69SpecificKeyLinkageProof(proof)
  ]
}

export function parseSpecificKeyLinkageProofPayload (
  payload: number[]
): ParsedSpecificKeyLinkageProofPayload {
  if (!Array.isArray(payload)) throw new Error('proof payload must be bytes')
  if (payload.length > BRC69_METHOD2_MAX_PAYLOAD_BYTES) {
    throw new Error('BRC69 Method 2 proof payload is too large')
  }
  assertBytes(payload, 'proof payload')
  if (payload.length < 1) throw new Error('Proof payload is empty')
  const proofType = payload[0]
  if (proofType === 0) {
    if (payload.length !== 1) {
      throw new Error('Proof type 0 payload must not contain proof bytes')
    }
    return { proofType: 0 }
  }
  if (proofType !== BRC69_METHOD2_PROOF_TYPE) {
    throw new Error('Unsupported BRC69 key linkage proof type')
  }
  return {
    proofType: 1,
    proof: parseBRC69SpecificKeyLinkageProof(payload.slice(1))
  }
}

export function serializeBRC69SpecificKeyLinkageProof (
  proof: BRC69SpecificKeyLinkageProof
): number[] {
  assertBRC69SpecificKeyLinkageProofShape(proof)
  const publicInput = publicInputToBytes(proof.publicInput)
  const starkProof = serializeMultiTraceStarkProof(proof.proof)
  const writer = new Writer()
  writeMagic(writer, BRC69_METHOD2_PROOF_PAYLOAD_MAGIC)
  writer.writeUInt8(BRC69_METHOD2_PROOF_PAYLOAD_VERSION)
  writer.writeVarIntNum(publicInput.length)
  writer.write(publicInput)
  writer.writeVarIntNum(starkProof.length)
  writer.write(starkProof)
  return writer.toArray()
}

export function parseBRC69SpecificKeyLinkageProof (
  bytes: number[]
): BRC69SpecificKeyLinkageProof {
  if (!Array.isArray(bytes)) {
    throw new Error('BRC69 key linkage proof must be bytes')
  }
  if (bytes.length > BRC69_METHOD2_MAX_PAYLOAD_BYTES - 1) {
    throw new Error('BRC69 Method 2 proof payload is too large')
  }
  assertBytes(bytes, 'BRC69 key linkage proof')
  const reader = new BRC69ProofReader(bytes)
  readMagic(reader, BRC69_METHOD2_PROOF_PAYLOAD_MAGIC)
  const version = reader.readUInt8()
  if (version !== BRC69_METHOD2_PROOF_PAYLOAD_VERSION) {
    throw new Error('Unsupported BRC69 key linkage proof payload version')
  }
  const publicInputLength = reader.readVarIntNum()
  if (publicInputLength > BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES) {
    throw new Error('BRC69 Method 2 public input is too large')
  }
  const publicInput = publicInputFromBytes(reader.read(publicInputLength))
  const proofLength = reader.readVarIntNum()
  if (proofLength > BRC69_METHOD2_MAX_PROOF_BYTES) {
    throw new Error('BRC69 Method 2 STARK proof is too large')
  }
  const proof = parseMultiTraceStarkProof(reader.read(proofLength))
  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in BRC69 proof payload')
  }
  const parsed = { publicInput, proof }
  assertBRC69SpecificKeyLinkageProofShape(parsed)
  return parsed
}

function publicInputMatchesStatement (
  publicInput: BRC69Method2WholeStatementPublicInput,
  statement: SpecificKeyLinkageStatement
): boolean {
  const invoice = toArray(
    computeInvoiceNumber(statement.protocolID, statement.keyID),
    'utf8'
  )
  return toHex(compressPoint(publicInput.publicA)) === statement.prover &&
    toHex(compressPoint(publicInput.baseB)) === statement.counterparty &&
    bytesEqual(publicInput.invoice, invoice) &&
    bytesEqual(publicInput.linkage, statement.linkage)
}

function assertBRC69SpecificKeyLinkageProofShape (
  proof: BRC69SpecificKeyLinkageProof
): void {
  validateBRC69Method2WholeStatementPublicInput(proof.publicInput)
}

function publicInputToBytes (
  publicInput: BRC69Method2WholeStatementPublicInput
): number[] {
  return serializeBRC69Method2WholeStatementPublicInput(publicInput)
}

function publicInputFromBytes (
  bytes: number[]
): BRC69Method2WholeStatementPublicInput {
  return parseBRC69Method2WholeStatementPublicInput(bytes)
}

export function serializeBRC69Method2WholeStatementPublicInput (
  publicInput: BRC69Method2WholeStatementPublicInput
): number[] {
  validateBRC69Method2WholeStatementPublicInput(publicInput)
  const writer = new Writer()
  writeMagic(writer, BRC69_METHOD2_PUBLIC_INPUT_MAGIC)
  writer.writeUInt8(BRC69_METHOD2_PUBLIC_INPUT_VERSION)
  writePoint(writer, publicInput.publicA)
  writePoint(writer, publicInput.baseB)
  writeBytes32Length(writer, publicInput.invoice, 'invoice')
  writeBytes32Length(writer, publicInput.linkage, 'linkage')
  writeBytes32Length(
    writer,
    publicInput.preprocessedTableRoot,
    'preprocessed table root'
  )
  writeSegmentBusPublicInput(writer, publicInput.bus)
  writeScalarPublicInput(writer, publicInput.scalar)
  writeLookupPublicInput(writer, publicInput.lookup)
  writeEcPublicInput(writer, publicInput.ec)
  writeCompressionPublicInput(writer, publicInput.compression)
  writeCompactHmacPublicInput(writer, publicInput.hmac)
  writeBridgePublicInput(writer, publicInput.bridge)
  const out = writer.toArray()
  if (out.length > BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES) {
    throw new Error('BRC69 Method 2 public input is too large')
  }
  return out
}

export function parseBRC69Method2WholeStatementPublicInput (
  bytes: number[]
): BRC69Method2WholeStatementPublicInput {
  assertBytes(bytes, 'BRC69 public input')
  if (bytes.length > BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES) {
    throw new Error('BRC69 Method 2 public input is too large')
  }
  const reader = new BRC69ProofReader(bytes)
  readMagic(reader, BRC69_METHOD2_PUBLIC_INPUT_MAGIC)
  const version = reader.readUInt8()
  if (version !== BRC69_METHOD2_PUBLIC_INPUT_VERSION) {
    throw new Error('Unsupported BRC69 Method 2 public input version')
  }
  const parsed: BRC69Method2WholeStatementPublicInput = {
    publicA: readPoint(reader),
    baseB: readPoint(reader),
    invoice: readBytes32Length(reader, 'invoice'),
    linkage: readBytes32Length(reader, 'linkage'),
    preprocessedTableRoot: readBytes32Length(
      reader,
      'preprocessed table root'
    ),
    bus: readSegmentBusPublicInput(reader),
    scalar: readScalarPublicInput(reader),
    lookup: readLookupPublicInput(reader),
    ec: readEcPublicInput(reader),
    compression: readCompressionPublicInput(reader),
    hmac: readCompactHmacPublicInput(reader),
    bridge: readBridgePublicInput(reader)
  }
  if (!reader.eof()) {
    throw new Error('Unexpected trailing bytes in BRC69 public input')
  }
  validateBRC69Method2WholeStatementPublicInput(parsed)
  return parsed
}

function writeSegmentBusPublicInput (
  writer: Writer,
  bus: BRC69Method2WholeStatementPublicInput['bus']
): void {
  writeU32(writer, BRC69_METHOD2_BUS_SEGMENT_ORDER.length)
  for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    const segment = bus.segments[name]
    if (segment === undefined) {
      throw new Error(`BRC69 Method 2 bus segment is missing: ${name}`)
    }
    writeAsciiString(writer, name)
    writeU32(writer, segment.emissionCount)
    writeOptionalU32(writer, segment.selectorCount)
    writeOptionalEndpoint(writer, segment.publicStart)
    writeOptionalEndpoint(writer, segment.publicEnd)
  }
}

function readSegmentBusPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['bus'] {
  const count = readU32(reader)
  if (count !== BRC69_METHOD2_BUS_SEGMENT_ORDER.length) {
    throw new Error('BRC69 Method 2 bus segment count mismatch')
  }
  const segments: BRC69Method2WholeStatementPublicInput['bus']['segments'] = {}
  for (const expectedName of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    const name = readAsciiString(reader)
    if (name !== expectedName) {
      throw new Error('BRC69 Method 2 bus segment order mismatch')
    }
    const segment: BRC69Method2WholeStatementPublicInput['bus']['segments'][string] = {
      emissionCount: readU32(reader)
    }
    const selectorCount = readOptionalU32(reader)
    if (selectorCount !== undefined) segment.selectorCount = selectorCount
    const publicStart = readOptionalEndpoint(reader)
    if (publicStart !== undefined) segment.publicStart = publicStart
    const publicEnd = readOptionalEndpoint(reader)
    if (publicEnd !== undefined) segment.publicEnd = publicEnd
    segments[name] = segment
  }
  return { segments }
}

function writeScalarPublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['scalar']
): void {
  writeU32(writer, input.windowBits)
  writeU32(writer, input.windowCount)
  writeU32(writer, input.activeRows)
  writeU32(writer, input.traceLength)
  writeU32(writer, input.scheduleRows.length)
  for (const row of input.scheduleRows) {
    writeField(writer, row.active)
    writeField(writer, row.window)
    writeField(writer, row.finalWindow)
    writeField(writer, row.nMinusOneLimb)
  }
}

function readScalarPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['scalar'] {
  const input: BRC69Method2WholeStatementPublicInput['scalar'] = {
    windowBits: readU32(reader),
    windowCount: readU32(reader),
    activeRows: readU32(reader),
    traceLength: readU32(reader),
    scheduleRows: []
  }
  input.scheduleRows = readRows(reader, 'scalar schedule', () => ({
    active: readField(reader),
    window: readField(reader),
    finalWindow: readField(reader),
    nMinusOneLimb: readField(reader)
  }))
  return input
}

function writeLookupPublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['lookup']
): void {
  writeU32(writer, input.traceLength)
  writeU32(writer, input.expectedLookupRequests)
  writeU32(writer, input.scheduleRows.length)
  for (const row of input.scheduleRows) {
    writeField(writer, row.kind)
    writeField(writer, row.tag)
    writeFieldArray(writer, row.publicTuple)
  }
}

function readLookupPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['lookup'] {
  const input: BRC69Method2WholeStatementPublicInput['lookup'] = {
    traceLength: readU32(reader),
    expectedLookupRequests: readU32(reader),
    scheduleRows: []
  }
  input.scheduleRows = readRows(reader, 'lookup schedule', () => ({
    kind: readField(reader),
    tag: readField(reader),
    publicTuple: readFieldArray(reader, 'lookup public tuple')
  }))
  return input
}

function writeEcPublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['ec']
): void {
  writePoint(writer, input.publicA)
  writePoint(writer, input.baseB)
  writeU32(writer, input.radixWindowCount)
  writeU32(writer, input.scheduledAdditions)
  writeU32(writer, input.activeRows)
  writeU32(writer, input.paddedRows)
  writeU32(writer, input.schedule.length)
  for (const row of input.schedule) {
    writeU32(writer, row.row)
    writeU32(writer, row.rows)
    writeU32(writer, row.step)
    writer.writeUInt8(row.lane === 'G' ? 1 : 2)
    writer.writeUInt8(ecOperationCode(row.op))
    writer.writeUInt8(row.kind === 'linear' ? 1 : 2)
    writeField(writer, row.metadataSameNext)
    writeField(writer, row.accumulatorLinkNext)
  }
}

function readEcPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['ec'] {
  const input: BRC69Method2WholeStatementPublicInput['ec'] = {
    publicA: readPoint(reader),
    baseB: readPoint(reader),
    radixWindowCount: readU32(reader),
    scheduledAdditions: readU32(reader),
    activeRows: readU32(reader),
    paddedRows: readU32(reader),
    schedule: []
  }
  input.schedule = readRows(reader, 'EC schedule', () => ({
    row: readU32(reader),
    rows: readU32(reader),
    step: readU32(reader),
    lane: readEcLane(reader),
    op: readEcOperation(reader),
    kind: readEcKind(reader),
    metadataSameNext: readField(reader),
    accumulatorLinkNext: readField(reader)
  }))
  return input
}

function writeCompressionPublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['compression']
): void {
  writeU32(writer, input.activeRows)
  writeU32(writer, input.traceLength)
  writeU32(writer, input.scheduleRows.length)
  for (const row of input.scheduleRows) {
    writeField(writer, row.kind)
    writeField(writer, row.byteIndex)
    writeField(writer, row.bitInByte)
    writeField(writer, row.lastBitInByte)
    writeField(writer, row.byteWeight)
    writeFieldArray(writer, row.limbWeights)
  }
}

function readCompressionPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['compression'] {
  const input: BRC69Method2WholeStatementPublicInput['compression'] = {
    activeRows: readU32(reader),
    traceLength: readU32(reader),
    scheduleRows: []
  }
  input.scheduleRows = readRows(reader, 'compression schedule', () => ({
    kind: readField(reader),
    byteIndex: readField(reader),
    bitInByte: readField(reader),
    lastBitInByte: readField(reader),
    byteWeight: readField(reader),
    limbWeights: readFieldArray(reader, 'compression limb weights')
  }))
  return input
}

function writeCompactHmacPublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['hmac']
): void {
  writeBytes32Length(writer, input.invoice, 'HMAC invoice')
  writeBytes32Length(writer, input.linkage, 'HMAC linkage')
  writeU32(writer, input.innerBlocks)
  writeU32(writer, input.outerBlocks)
  writeU32(writer, input.totalBlocks)
  writeU32(writer, input.activeRows)
  writeU32(writer, input.traceLength)
}

function readCompactHmacPublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['hmac'] {
  return {
    invoice: readBytes32Length(reader, 'HMAC invoice'),
    linkage: readBytes32Length(reader, 'HMAC linkage'),
    innerBlocks: readU32(reader),
    outerBlocks: readU32(reader),
    totalBlocks: readU32(reader),
    activeRows: readU32(reader),
    traceLength: readU32(reader)
  }
}

function writeBridgePublicInput (
  writer: Writer,
  input: BRC69Method2WholeStatementPublicInput['bridge']
): void {
  writeU32(writer, input.activeRows)
  writeU32(writer, input.traceLength)
  writeU32(writer, input.scheduleRows.length)
  for (const row of input.scheduleRows) {
    writeField(writer, row.active)
    writeField(writer, row.window)
  }
}

function readBridgePublicInput (
  reader: BRC69ProofReader
): BRC69Method2WholeStatementPublicInput['bridge'] {
  const input: BRC69Method2WholeStatementPublicInput['bridge'] = {
    activeRows: readU32(reader),
    traceLength: readU32(reader),
    scheduleRows: []
  }
  input.scheduleRows = readRows(reader, 'bridge schedule', () => ({
    active: readField(reader),
    window: readField(reader)
  }))
  return input
}

function writeOptionalEndpoint (
  writer: Writer,
  endpoint: { accumulator0: FieldElement, accumulator1: FieldElement } | undefined
): void {
  if (endpoint === undefined) {
    writer.writeUInt8(0)
    return
  }
  writer.writeUInt8(1)
  writeField(writer, endpoint.accumulator0)
  writeField(writer, endpoint.accumulator1)
}

function readOptionalEndpoint (
  reader: BRC69ProofReader
): { accumulator0: FieldElement, accumulator1: FieldElement } | undefined {
  const marker = reader.readUInt8()
  if (marker === 0) return undefined
  if (marker !== 1) throw new Error('Invalid BRC69 optional endpoint marker')
  return {
    accumulator0: readField(reader),
    accumulator1: readField(reader)
  }
}

function writeOptionalU32 (writer: Writer, value: number | undefined): void {
  if (value === undefined) {
    writer.writeUInt8(0)
    return
  }
  writer.writeUInt8(1)
  writeU32(writer, value)
}

function readOptionalU32 (reader: BRC69ProofReader): number | undefined {
  const marker = reader.readUInt8()
  if (marker === 0) return undefined
  if (marker !== 1) throw new Error('Invalid BRC69 optional u32 marker')
  return readU32(reader)
}

function writeFieldArray (writer: Writer, values: FieldElement[]): void {
  writeU32(writer, values.length)
  for (const value of values) writeField(writer, value)
}

function readFieldArray (
  reader: BRC69ProofReader,
  label: string
): FieldElement[] {
  const length = readBoundedRowCount(reader, label)
  const values: FieldElement[] = []
  for (let i = 0; i < length; i++) values.push(readField(reader))
  return values
}

function readRows<T> (
  reader: BRC69ProofReader,
  label: string,
  readRow: () => T
): T[] {
  const length = readBoundedRowCount(reader, label)
  return Array.from({ length }, readRow)
}

function readBoundedRowCount (
  reader: BRC69ProofReader,
  label: string
): number {
  const count = readU32(reader)
  if (count > BRC69_METHOD2_MAX_PUBLIC_INPUT_ROWS) {
    throw new Error(`${label} exceeds BRC69 Method 2 row cap`)
  }
  return count
}

function writePoint (writer: Writer, point: SecpPoint): void {
  if (point.infinity === true) {
    throw new Error('BRC69 Method 2 public input points must be non-infinity')
  }
  writer.write(compressPoint(point))
}

function readPoint (reader: BRC69ProofReader): SecpPoint {
  return decompressPublicKey(reader.read(33))
}

function writeField (writer: Writer, value: FieldElement): void {
  F.assertCanonical(value)
  writer.write(F.toBytesLE(value))
}

function readField (reader: BRC69ProofReader): FieldElement {
  return F.fromBytesLE(reader.read(8))
}

function writeBytes32Length (
  writer: Writer,
  bytes: number[],
  label: string
): void {
  assertBytes(bytes, label)
  writeU32(writer, bytes.length)
  writer.write(bytes)
}

function readBytes32Length (
  reader: BRC69ProofReader,
  label: string
): number[] {
  const length = readU32(reader)
  if (length > BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES) {
    throw new Error(`${label} is too large`)
  }
  const bytes = reader.read(length)
  assertBytes(bytes, label)
  return bytes
}

function writeAsciiString (writer: Writer, value: string): void {
  const bytes = toArray(value, 'utf8')
  writeU32(writer, bytes.length)
  writer.write(bytes)
}

function readAsciiString (reader: BRC69ProofReader): string {
  const length = readU32(reader)
  if (length > 1024) throw new Error('BRC69 string field is too long')
  return String.fromCharCode(...reader.read(length))
}

function writeMagic (writer: Writer, magic: string): void {
  writer.write(toArray(magic, 'utf8'))
}

function readMagic (reader: BRC69ProofReader, magic: string): void {
  const expected = toArray(magic, 'utf8')
  const actual = reader.read(expected.length)
  if (!bytesEqual(actual, expected)) {
    throw new Error(`Invalid ${magic} magic`)
  }
}

function writeU32 (writer: Writer, value: number): void {
  assertU32(value)
  writer.writeUInt32LE(value)
}

function readU32 (reader: BRC69ProofReader): number {
  const bytes = reader.read(4)
  return (
    bytes[0] |
    (bytes[1] << 8) |
    (bytes[2] << 16) |
    (bytes[3] << 24)
  ) >>> 0
}

function assertU32 (value: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0xffffffff
  ) {
    throw new Error('BRC69 Method 2 value exceeds u32 range')
  }
}

function ecOperationCode (
  op: typeof BRC69_METHOD2_EC_OPERATIONS[number]
): number {
  const index = BRC69_METHOD2_EC_OPERATIONS.indexOf(op)
  if (index < 0) throw new Error('Unknown BRC69 EC operation')
  return index + 1
}

function readEcOperation (
  reader: BRC69ProofReader
): typeof BRC69_METHOD2_EC_OPERATIONS[number] {
  const code = reader.readUInt8()
  const op = BRC69_METHOD2_EC_OPERATIONS[code - 1]
  if (op === undefined) throw new Error('Unknown BRC69 EC operation code')
  return op
}

function readEcLane (reader: BRC69ProofReader): 'G' | 'B' {
  const code = reader.readUInt8()
  if (code === 1) return 'G'
  if (code === 2) return 'B'
  throw new Error('Unknown BRC69 EC lane code')
}

function readEcKind (reader: BRC69ProofReader): 'linear' | 'mul' {
  const code = reader.readUInt8()
  if (code === 1) return 'linear'
  if (code === 2) return 'mul'
  throw new Error('Unknown BRC69 EC operation kind code')
}

function normalizeStatement (
  statement: SpecificKeyLinkageStatement
): SpecificKeyLinkageStatement {
  assertCompressedPublicKeyHex(statement.prover, 'prover')
  assertCompressedPublicKeyHex(statement.counterparty, 'counterparty')
  assertBytes(statement.linkage, 'linkage')
  if (statement.linkage.length !== 32) throw new Error('Linkage must be 32 bytes')
  computeInvoiceNumber(statement.protocolID, statement.keyID)
  return {
    prover: statement.prover.toLowerCase(),
    counterparty: statement.counterparty.toLowerCase(),
    protocolID: [
      statement.protocolID[0],
      statement.protocolID[1].toLowerCase().trim()
    ],
    keyID: statement.keyID,
    linkage: statement.linkage.slice()
  }
}

function privateKeyToScalar (
  privateKey: PrivateKey | bigint | string
): bigint {
  if (typeof privateKey === 'bigint') return privateKey
  if (typeof privateKey === 'string') return BigInt(`0x${privateKey}`)
  return BigInt(`0x${privateKey.toString('hex', 64)}`)
}

function assertCompressedPublicKeyHex (
  value: string,
  label: string
): void {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`Invalid ${label} compressed public key`)
  }
  decompressPublicKey(toArray(value, 'hex'))
}

function assertBytes (bytes: number[], label: string): void {
  if (!Array.isArray(bytes)) throw new Error(`${label} must be bytes`)
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

class BRC69ProofReader {
  private position = 0

  constructor (private readonly bytes: number[]) {}

  eof (): boolean {
    return this.position === this.bytes.length
  }

  read (length: number): number[] {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error('Invalid BRC69 proof read length')
    }
    if (this.position + length > this.bytes.length) {
      throw new Error('Truncated BRC69 proof payload')
    }
    const out = this.bytes.slice(this.position, this.position + length)
    this.position += length
    return out
  }

  readUInt8 (): number {
    return this.read(1)[0]
  }

  readVarIntNum (): number {
    const first = this.readUInt8()
    if (first < 0xfd) return first
    if (first === 0xfd) {
      const value = this.readUInt16LE()
      if (value < 0xfd) throw new Error('Non-canonical BRC69 varint')
      return value
    }
    if (first === 0xfe) {
      const value = this.readUInt32LE()
      if (value < 0x10000) throw new Error('Non-canonical BRC69 varint')
      return value
    }
    const value = this.readUInt64LE()
    if (value < 0x100000000) {
      throw new Error('Non-canonical BRC69 varint')
    }
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new Error('BRC69 varint exceeds safe integer range')
    }
    return value
  }

  private readUInt16LE (): number {
    const bytes = this.read(2)
    return bytes[0] | (bytes[1] << 8)
  }

  private readUInt32LE (): number {
    const bytes = this.read(4)
    return (
      bytes[0] |
      (bytes[1] << 8) |
      (bytes[2] << 16) |
      (bytes[3] << 24)
    ) >>> 0
  }

  private readUInt64LE (): number {
    const bytes = this.read(8)
    let value = 0
    let multiplier = 1
    for (const byte of bytes) {
      value += byte * multiplier
      multiplier *= 0x100
    }
    return value
  }
}
