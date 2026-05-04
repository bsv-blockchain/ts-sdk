import { SecpPoint } from '../circuit/Types.js'
import { compressPoint } from '../circuit/index.js'
import {
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TRANSCRIPT_DOMAIN,
  LookupBusMetrics,
  LookupBusPublicInput,
  LookupBusTrace,
  LookupBusTraceItem,
  buildLookupBusAir,
  buildLookupBusTrace,
  lookupBusMetrics,
  proveLookupBus
} from '../stark/LookupBus.js'
import {
  ProductionRadix11EcTrace,
  validateProductionRadix11EcTrace
} from '../stark/ProductionRadix11Ec.js'
import {
  ProductionEcTrace,
  productionEcTracePrivateS,
  productionEcTracePublicA,
  productionEcTraceSelectedPoint
} from '../stark/ProductionEcAir.js'
import { ProductionRadix11LookupPrototype } from '../stark/DualBaseRadix11Metrics.js'
import { secp256k1FieldToLimbs52 } from '../stark/Secp256k1FieldOps.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import {
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import {
  Method2CompactHmacSha256Trace,
  method2CompactHmacSha256KeyForLink,
  validateMethod2CompactHmacSha256Trace
} from './Method2CompactHmacSha256.js'
import {
  BRC97ProductionScalarTrace,
  brc97ProductionScalarDigitTuple
} from './BRC97ProductionScalar.js'
import {
  BRC97ProductionCompressionTrace,
  brc97ProductionCompressionByteTuple,
  brc97ProductionCompressionPointTuple
} from './BRC97ProductionCompression.js'

export const BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT = 101n
export const BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT = 102n
export const BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT = 103n
export const BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT = 104n
export const BRC97_PRODUCTION_BUS_TAG_EC_FINAL_A_PUBLIC = 105n
export const BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT = 106n
export const BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE = 107n
export const BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE = 108n
export const BRC97_PRODUCTION_BUS_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
} as const

export interface BRC97ProductionBusStatementParts {
  lookup?: ProductionRadix11LookupPrototype
  scalar?: BRC97ProductionScalarTrace
  compression?: BRC97ProductionCompressionTrace
  ec: ProductionRadix11EcTrace
  productionEc?: ProductionEcTrace
  hmac: Method2CompactHmacSha256Trace
  minTraceLength?: number
}

export interface BRC97ProductionBusTrace {
  trace: LookupBusTrace
  publicInput: LookupBusPublicInput
  tagCounts: Record<string, number>
}

export interface BRC97ProductionBusMetrics extends LookupBusMetrics {
  committedCells: number
  ldeRows: number
  ldeCells: number
  rowCountsByTag: Record<string, number>
}

export function buildBRC97ProductionBusTrace (
  statementParts: BRC97ProductionBusStatementParts
): BRC97ProductionBusTrace {
  const { ec, hmac } = statementParts
  const lookup = statementParts.lookup ?? ec.lookup
  if (lookup !== ec.lookup) {
    throw new Error('BRC97 production bus lookup/EC trace mismatch')
  }
  if (
    statementParts.scalar !== undefined &&
    statementParts.scalar.lookup !== lookup
  ) {
    throw new Error('BRC97 production bus scalar/lookup trace mismatch')
  }
  validateProductionRadix11EcTrace(ec)
  if (
    statementParts.productionEc !== undefined &&
    statementParts.productionEc.source !== ec
  ) {
    throw new Error('BRC97 production bus hardened/native EC trace mismatch')
  }
  validateMethod2CompactHmacSha256Trace(hmac)
  const hmacKey = method2CompactHmacSha256KeyForLink(hmac)
  const ecPublicA = statementParts.productionEc === undefined
    ? ec.publicA
    : productionEcTracePublicA(statementParts.productionEc)
  const ecPrivateS = statementParts.productionEc === undefined
    ? ec.privateS
    : productionEcTracePrivateS(statementParts.productionEc)
  const ecCompressedS = statementParts.productionEc === undefined
    ? ec.compressedS
    : compressPoint(ecPrivateS)
  const compressedBytes = statementParts.compression?.compressedBytes ??
    ecCompressedS
  if (!bytesEqual(compressedBytes, hmacKey)) {
    throw new Error('BRC97 production bus compressed S/HMAC key mismatch')
  }

  const items: LookupBusTraceItem[] = []
  for (let i = 0; i < ec.steps.length; i++) {
    const step = ec.steps[i]
    const digit = lookup.digits[i]
    if (digit === undefined) {
      throw new Error('BRC97 production bus scalar digit is missing')
    }
    items.push(privateEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
      [
        BigInt(step.window),
        BigInt(step.magnitude),
        BigInt(step.isZero),
        BigInt(step.sign)
      ],
      statementParts.scalar === undefined
        ? [
            BigInt(digit.window),
            BigInt(digit.magnitude),
            BigInt(step.tableRow.isZero),
            BigInt(digit.sign)
          ]
        : brc97ProductionScalarDigitTuple(statementParts.scalar, i)
    ))
    items.push(privateEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
      step.tableRow.values,
      lookupTableRow(lookup, step.tableIndex).values
    ))
    items.push(privateEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
      pointTuple(statementParts.productionEc === undefined
        ? step.g.selected
        : productionEcTraceSelectedPoint(statementParts.productionEc, 'G', i)),
      pointTuple(step.g.selected)
    ))
    items.push(privateEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      pointTuple(statementParts.productionEc === undefined
        ? step.b.selected
        : productionEcTraceSelectedPoint(statementParts.productionEc, 'B', i)),
      pointTuple(step.b.selected)
    ))
  }

  items.push(publicEqualityItem(
    BRC97_PRODUCTION_BUS_TAG_EC_FINAL_A_PUBLIC,
    pointTuple(ecPublicA),
    pointTuple(ec.publicA)
  ))
  items.push(privateEqualityItem(
    BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
    pointTuple(ecPrivateS),
    statementParts.compression === undefined
      ? pointTuple(ecPrivateS)
      : brc97ProductionCompressionPointTuple(statementParts.compression)
  ))
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    items.push(privateEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
      statementParts.compression === undefined
        ? byteTuple(byteIndex, ec.compressedS[byteIndex])
        : brc97ProductionCompressionByteTuple(
          statementParts.compression,
          byteIndex
        ),
      byteTuple(byteIndex, hmacKey[byteIndex])
    ))
  }
  for (let byteIndex = 0; byteIndex < METHOD2_SHA256_DIGEST_SIZE; byteIndex++) {
    items.push(publicEqualityItem(
      BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE,
      byteTuple(byteIndex, hmac.publicInput.linkage[byteIndex]),
      byteTuple(byteIndex, hmac.publicInput.linkage[byteIndex])
    ))
  }

  const trace = buildLookupBusTrace(items, {
    minTraceLength: statementParts.minTraceLength
  })
  return {
    trace,
    publicInput: trace.publicInput,
    tagCounts: countTags(items)
  }
}

export function proveBRC97ProductionBus (
  trace: BRC97ProductionBusTrace,
  options: StarkProverOptions = {}
): StarkProof {
  return proveLookupBus(trace.trace, {
    ...BRC97_PRODUCTION_BUS_STARK_OPTIONS,
    ...options
  })
}

export function verifyBRC97ProductionBus (
  publicInput: LookupBusPublicInput,
  proof: StarkProof
): boolean {
  if (!proofMeetsProductionProfile(proof)) return false
  const air = buildLookupBusAir(publicInput)
  return verifyStark(air, proof, starkVerifierOptions(proof, air.publicInputDigest))
}

export function brc97ProductionBusMetrics (
  trace: BRC97ProductionBusTrace,
  proof?: StarkProof,
  blowupFactor: number = 16
): BRC97ProductionBusMetrics {
  const base = lookupBusMetrics(trace.trace, proof)
  return {
    ...base,
    committedCells: base.paddedRows * base.traceWidth,
    ldeRows: base.paddedRows * blowupFactor,
    ldeCells: base.paddedRows * base.traceWidth * blowupFactor,
    rowCountsByTag: trace.tagCounts,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

function privateEqualityItem (
  tag: bigint,
  leftValues: bigint[],
  rightValues: bigint[]
): LookupBusTraceItem {
  return {
    kind: LOOKUP_BUS_ROW_KIND.privateEquality,
    tag,
    leftValues,
    rightValues,
    multiplicity: 1
  }
}

function publicEqualityItem (
  tag: bigint,
  leftValues: bigint[],
  publicValues: bigint[]
): LookupBusTraceItem {
  return {
    kind: LOOKUP_BUS_ROW_KIND.publicEquality,
    tag,
    leftValues,
    rightValues: publicValues,
    publicValues,
    multiplicity: 1
  }
}

function pointTuple (point: SecpPoint): bigint[] {
  if (point.infinity === true) {
    return [1n, ...new Array<bigint>(10).fill(0n)]
  }
  return [
    0n,
    ...secp256k1FieldToLimbs52(point.x),
    ...secp256k1FieldToLimbs52(point.y)
  ]
}

function byteTuple (index: number, value: number | undefined): bigint[] {
  if (
    value === undefined ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 255
  ) {
    throw new Error('BRC97 production bus byte value is invalid')
  }
  return [BigInt(index), BigInt(value)]
}

function lookupTableRow (
  lookup: ProductionRadix11LookupPrototype,
  index: number
): ProductionRadix11LookupPrototype['table'][number] {
  const row = lookup.table[index]
  if (row === undefined) {
    throw new Error('BRC97 production bus lookup table row is missing')
  }
  return row
}

function countTags (items: LookupBusTraceItem[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const item of items) {
    const key = productionBusTagName(item.tag)
    out[key] = (out[key] ?? 0) + 1
  }
  return out
}

function productionBusTagName (tag: bigint): string {
  if (tag === BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT) return 'scalarDigit'
  if (tag === BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT) return 'pointPairOutput'
  if (tag === BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT) return 'ecSelectedGPoint'
  if (tag === BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT) return 'ecSelectedBPoint'
  if (tag === BRC97_PRODUCTION_BUS_TAG_EC_FINAL_A_PUBLIC) return 'ecFinalAPublic'
  if (tag === BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT) return 'ecPrivateSPoint'
  if (tag === BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE) return 'compressedSKeyByte'
  if (tag === BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE) return 'hmacLinkageByte'
  return `tag${tag.toString()}`
}

function starkVerifierOptions (
  proof: StarkProof,
  publicInputDigest: number[]
): StarkVerifierOptions {
  return {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  }
}

function proofMeetsProductionProfile (proof: StarkProof): boolean {
  return proof.blowupFactor === BRC97_PRODUCTION_BUS_STARK_OPTIONS.blowupFactor &&
    proof.numQueries === BRC97_PRODUCTION_BUS_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize === BRC97_PRODUCTION_BUS_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree === BRC97_PRODUCTION_BUS_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset === BRC97_PRODUCTION_BUS_STARK_OPTIONS.cosetOffset
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}
