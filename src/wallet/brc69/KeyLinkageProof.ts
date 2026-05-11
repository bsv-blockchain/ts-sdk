import PrivateKey from '../../primitives/PrivateKey.js'
import { WalletCounterparty, WalletProtocol } from '../Wallet.interfaces.js'
import { computeInvoiceNumber } from '../keyLinkage.js'
import { Writer, toArray, toHex } from '../../primitives/utils.js'
import {
  SECP256K1_G,
  compressPoint,
  decompressPublicKey,
  hmacSha256,
  scalarMultiply,
  validateScalar
} from './circuit/index.js'
import {
  MultiTraceStarkProof,
  parseMultiTraceStarkProof,
  serializeMultiTraceStarkProof
} from './stark/Stark.js'
import {
  BRC69Method2WholeStatementPublicInput,
  buildBRC69Method2WholeStatement,
  proveBRC69Method2WholeStatement,
  validateBRC69Method2WholeStatementPublicInput,
  verifyBRC69Method2WholeStatement
} from './method2/BRC69Method2WholeStatement.js'

export const BRC69_METHOD2_PROOF_TYPE = 1

export const BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES = 16 * 1024 * 1024
export const BRC69_METHOD2_MAX_PROOF_BYTES = 16 * 1024 * 1024
export const BRC69_METHOD2_MAX_PAYLOAD_BYTES = 34 * 1024 * 1024

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
  prover: string
): string {
  if (counterparty === 'self') return prover
  if (counterparty === 'anyone') return toHex(compressPoint(SECP256K1_G))
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
  const expectedLinkage = hmacSha256(compressPoint(
    scalarMultiply(scalar, baseB)
  ), invoice)
  if (!bytesEqual(expectedLinkage, statement.linkage)) {
    throw new Error('Linkage does not match BRC69 Method 2 witness relation')
  }

  const wholeStatement = buildBRC69Method2WholeStatement({
    scalar,
    baseB,
    invoice,
    linkage: statement.linkage
  })
  return {
    publicInput: wholeStatement.publicInput,
    proof: proveBRC69Method2WholeStatement(wholeStatement)
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
  validateBRC69Method2WholeStatementPublicInput(publicInput)
  return toArray(JSON.stringify(publicInput, jsonReplacer), 'utf8')
}

function publicInputFromBytes (
  bytes: number[]
): BRC69Method2WholeStatementPublicInput {
  assertBytes(bytes, 'BRC69 public input')
  const parsed = JSON.parse(
    utf8BytesToString(bytes),
    jsonReviver
  ) as BRC69Method2WholeStatementPublicInput
  validateBRC69Method2WholeStatementPublicInput(parsed)
  return parsed
}

function jsonReplacer (_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? `${value}n` : value
}

function jsonReviver (_key: string, value: unknown): unknown {
  if (typeof value === 'string' && /^-?[0-9]+n$/.test(value)) {
    return BigInt(value.slice(0, -1))
  }
  return value
}

function utf8BytesToString (bytes: number[]): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode(...bytes.slice(i, i + 8192))
  }
  return out
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
