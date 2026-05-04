import { hmacSha256 } from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  CompressedPointEncodingMetrics,
  CompressedPointEncodingProof,
  CompressedPointEncodingTrace,
  buildCompressedPointEncodingTrace,
  compressedPointBytesForHmac,
  compressedPointEncodingMetrics,
  proveCompressedPointEncoding,
  verifyCompressedPointEncoding
} from '../stark/CompressedPointEncoding.js'
import {
  DualBaseEcIntegratedMetrics,
  DualBaseEcIntegratedProof,
  DualBaseEcIntegratedTrace,
  buildDualBaseEcIntegratedTrace,
  dualBaseEcIntegratedMetrics,
  proveDualBaseEcIntegrated,
  verifyDualBaseEcIntegrated
} from '../stark/DualBaseEcIntegrated.js'
import {
  DualBaseLookupParameters,
  buildDualBaseLookupPrototype
} from '../stark/DualBaseLookup.js'
import { FieldElement } from '../stark/Field.js'
import {
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_PRIVATE_EQUALITY,
  LOOKUP_BUS_TUPLE_ARITY,
  LookupBusMetrics,
  LookupBusTrace,
  LookupBusTraceItem,
  buildLookupBusTrace,
  lookupBusMetrics,
  proveLookupBus,
  verifyLookupBusProof
} from '../stark/LookupBus.js'
import { StarkProof, StarkProverOptions } from '../stark/Stark.js'
import {
  Method2CompactHmacSha256Metrics,
  Method2CompactHmacSha256Trace,
  buildMethod2CompactHmacSha256Trace,
  method2CompactHmacSha256KeyForLink,
  method2CompactHmacSha256Metrics,
  proveMethod2CompactHmacSha256,
  verifyMethod2CompactHmacSha256
} from './Method2CompactHmacSha256.js'

export interface BRC97StatementPrototypeOptions extends DualBaseLookupParameters {
  encodingMinTraceLength?: number
  keyLinkMinTraceLength?: number
}

export interface BRC97StatementPrototype {
  ec: DualBaseEcIntegratedTrace
  compressedS: CompressedPointEncodingTrace
  hmac: Method2CompactHmacSha256Trace
  keyLink: LookupBusTrace
  invoice: number[]
  linkage: number[]
}

export interface BRC97StatementProof {
  ec: DualBaseEcIntegratedProof
  compressedS: CompressedPointEncodingProof
  hmac: StarkProof
  keyLink: StarkProof
}

export interface BRC97StatementMetrics {
  ec: DualBaseEcIntegratedMetrics
  compressedS: CompressedPointEncodingMetrics
  hmac: Method2CompactHmacSha256Metrics
  keyLink: LookupBusMetrics
  totalProofBytes?: number
}

export function buildBRC97StatementPrototype (
  scalar: bigint,
  baseB: SecpPoint,
  invoice: number[],
  linkage?: number[],
  options: BRC97StatementPrototypeOptions = {}
): BRC97StatementPrototype {
  const lookup = buildDualBaseLookupPrototype(scalar, baseB, options)
  const ec = buildDualBaseEcIntegratedTrace(lookup)
  const compressedS = buildCompressedPointEncodingTrace(ec.compressedS, {
    minTraceLength: options.encodingMinTraceLength
  })
  const key = compressedPointBytesForHmac(compressedS)
  const expectedLinkage = linkage ?? hmacSha256(key, invoice)
  const hmac = buildMethod2CompactHmacSha256Trace(
    key,
    invoice,
    expectedLinkage
  )
  const keyLink = buildBRC97CompressedSToHmacKeyLinkTrace(
    compressedS,
    hmac,
    { minTraceLength: options.keyLinkMinTraceLength }
  )
  const statement = {
    ec,
    compressedS,
    hmac,
    keyLink,
    invoice: invoice.slice(),
    linkage: expectedLinkage.slice()
  }
  validateBRC97StatementPrototype(statement)
  return statement
}

export function buildBRC97CompressedSToHmacKeyLinkTrace (
  compressedS: CompressedPointEncodingTrace,
  hmac: Method2CompactHmacSha256Trace,
  options: { minTraceLength?: number } = {}
): LookupBusTrace {
  const compressedBytes = compressedPointBytesForHmac(compressedS)
  const keyBytes = method2CompactHmacSha256KeyForLink(hmac)
  const items: LookupBusTraceItem[] = []
  for (let byteIndex = 0; byteIndex < compressedBytes.length; byteIndex++) {
    items.push({
      kind: LOOKUP_BUS_ROW_KIND.privateEquality,
      tag: LOOKUP_BUS_TAG_PRIVATE_EQUALITY,
      leftValues: byteLinkTuple(byteIndex, compressedBytes[byteIndex]),
      rightValues: byteLinkTuple(byteIndex, keyBytes[byteIndex]),
      multiplicity: 1
    })
  }
  return buildLookupBusTrace(items, {
    expectedLookupRequests: 0,
    minTraceLength: options.minTraceLength
  })
}

export function validateBRC97StatementPrototype (
  statement: BRC97StatementPrototype
): void {
  const compressedBytes = compressedPointBytesForHmac(statement.compressedS)
  const hmacKey = method2CompactHmacSha256KeyForLink(statement.hmac)
  if (!bytesEqual(compressedBytes, hmacKey)) {
    throw new Error('BRC97 statement compressed-S/HMAC-key link mismatch')
  }
  if (!bytesEqual(statement.invoice, statement.hmac.publicInput.invoice)) {
    throw new Error('BRC97 statement invoice mismatch')
  }
  if (!bytesEqual(statement.linkage, statement.hmac.publicInput.linkage)) {
    throw new Error('BRC97 statement linkage mismatch')
  }
  if (!bytesEqual(hmacSha256(hmacKey, statement.invoice), statement.linkage)) {
    throw new Error('BRC97 statement HMAC mismatch')
  }
  const expectedKeyLink = buildBRC97CompressedSToHmacKeyLinkTrace(
    statement.compressedS,
    statement.hmac,
    { minTraceLength: statement.keyLink.publicInput.traceLength }
  )
  if (!lookupRowsEqual(statement.keyLink, expectedKeyLink)) {
    throw new Error('BRC97 statement key-link trace mismatch')
  }
}

export function proveBRC97StatementPrototype (
  statement: BRC97StatementPrototype,
  options: StarkProverOptions = {}
): BRC97StatementProof {
  validateBRC97StatementPrototype(statement)
  return {
    ec: proveDualBaseEcIntegrated(statement.ec, options),
    compressedS: proveCompressedPointEncoding(statement.compressedS, options),
    hmac: proveMethod2CompactHmacSha256(statement.hmac, options),
    keyLink: proveLookupBus(statement.keyLink, options)
  }
}

export function verifyBRC97StatementPrototype (
  statement: BRC97StatementPrototype,
  proof: BRC97StatementProof
): boolean {
  try {
    validateBRC97StatementPrototype(statement)
    return verifyDualBaseEcIntegrated(statement.ec, proof.ec) &&
      verifyCompressedPointEncoding(statement.compressedS, proof.compressedS) &&
      verifyMethod2CompactHmacSha256(statement.hmac.publicInput, proof.hmac) &&
      verifyLookupBusProof(statement.keyLink.publicInput, proof.keyLink)
  } catch {
    return false
  }
}

export function brc97StatementMetrics (
  statement: BRC97StatementPrototype,
  proof?: BRC97StatementProof
): BRC97StatementMetrics {
  const ec = dualBaseEcIntegratedMetrics(statement.ec, proof?.ec)
  const compressedS = compressedPointEncodingMetrics(
    statement.compressedS,
    proof?.compressedS
  )
  const hmac = method2CompactHmacSha256Metrics(statement.hmac, proof?.hmac)
  const keyLink = lookupBusMetrics(statement.keyLink, proof?.keyLink)
  return {
    ec,
    compressedS,
    hmac,
    keyLink,
    totalProofBytes: proof === undefined
      ? undefined
      : (ec.totalProofBytes ?? 0) +
        (compressedS.totalProofBytes ?? 0) +
        (hmac.proofBytes ?? 0) +
        (keyLink.proofBytes ?? 0)
  }
}

function byteLinkTuple (
  byteIndex: number,
  byte: number
): FieldElement[] {
  if (!Number.isInteger(byteIndex) || byteIndex < 0) {
    throw new Error('Invalid byte-link index')
  }
  if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
    throw new Error('Invalid byte-link byte')
  }
  const tuple = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  tuple[0] = BigInt(byteIndex)
  tuple[1] = BigInt(byte)
  return tuple
}

function lookupRowsEqual (
  left: LookupBusTrace,
  right: LookupBusTrace
): boolean {
  if (
    left.publicInput.traceLength !== right.publicInput.traceLength ||
    left.publicInput.expectedLookupRequests !==
      right.publicInput.expectedLookupRequests ||
    left.rows.length !== right.rows.length
  ) {
    return false
  }
  for (let row = 0; row < left.rows.length; row++) {
    if (!fieldRowsEqual(left.rows[row], right.rows[row])) return false
  }
  return true
}

function fieldRowsEqual (left: FieldElement[], right: FieldElement[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}
