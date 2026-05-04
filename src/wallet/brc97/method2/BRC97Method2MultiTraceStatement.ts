import {
  SECP256K1_N,
  compressPoint,
  isOnCurve,
  scalarMultiply
} from '../circuit/Secp256k1.js'
import { hmacSha256 } from '../circuit/Sha256.js'
import { sha256 } from '../../../primitives/Hash.js'
import { toArray } from '../../../primitives/utils.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  LookupBusPublicInput,
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
  LOOKUP_BUS_TUPLE_ARITY,
  buildLookupBusAir
} from '../stark/LookupBus.js'
import {
  MultiTraceCrossConstraintInput,
  MultiTraceStarkDiagnostic,
  MultiTraceStarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  diagnoseMultiTraceStark,
  proveMultiTraceStark,
  serializeMultiTraceStarkProof,
  serializeStarkProof,
  verifyMultiTraceStark
} from '../stark/Stark.js'
import {
  BRC97_RADIX11_TABLE_ROWS,
  BRC97_RADIX11_POINT_LIMBS,
  ProductionRadix11LookupPrototype,
  buildProductionRadix11LookupPrototype,
  buildProductionRadix11PointPairTable,
  productionRadix11TableRoot
} from '../stark/DualBaseRadix11Metrics.js'
import {
  PRODUCTION_EC_LAYOUT,
  ProductionEcPublicInput,
  ProductionEcTrace,
  buildProductionEcAir,
  buildProductionEcTrace,
  productionEcTracePrivateS
} from '../stark/ProductionEcAir.js'
import {
  ProductionRadix11EcTrace,
  buildProductionRadix11EcTrace
} from '../stark/ProductionRadix11Ec.js'
import {
  BRC97_PRODUCTION_COMPRESSION_LAYOUT,
  BRC97ProductionCompressionPublicInput,
  BRC97ProductionCompressionTrace,
  buildBRC97ProductionCompressionAir,
  buildBRC97ProductionCompressionTrace
} from './BRC97ProductionCompression.js'
import {
  BRC97_PRODUCTION_SCALAR_LAYOUT,
  BRC97ProductionScalarPublicInput,
  BRC97ProductionScalarTrace,
  buildBRC97ProductionScalarAir,
  buildBRC97ProductionScalarTrace
} from './BRC97ProductionScalar.js'
import {
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  Method2CompactHmacSha256PublicInput,
  Method2CompactHmacSha256Trace,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  validateMethod2CompactHmacSha256PublicInput
} from './Method2CompactHmacSha256.js'
import {
  assertMethod2LookupShaHmacReadyForMethod2
} from './Method2LookupShaHmac.js'
import {
  METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT,
  Method2LookupBatchedHmacSha256PublicInput,
  Method2LookupBatchedHmacSha256Trace,
  buildMethod2LookupBatchedHmacSha256Air,
  buildMethod2LookupBatchedHmacSha256Trace,
  validateMethod2LookupBatchedHmacSha256PublicInput
} from './Method2LookupBatchedHmacSha256.js'
import {
  BRC97_METHOD2_LINK_BRIDGE_LAYOUT,
  BRC97Method2LinkBridgePublicInput,
  BRC97Method2LinkBridgeTrace,
  buildBRC97Method2LinkBridgeAir,
  buildBRC97Method2LinkBridgeTrace
} from './BRC97Method2LinkBridge.js'
import {
  BRC97_SEGMENT_BUS_KIND_SOURCE,
  BRC97_SEGMENT_BUS_KIND_TARGET,
  BRC97SegmentBusEmission,
  BRC97SegmentBusPublicInput,
  assertBRC97SegmentBusBalanced,
  brc97SegmentBusWrappedLayout,
  wrapBRC97SegmentBusAir,
  wrapBRC97SegmentBusTrace
} from './BRC97SegmentBus.js'
import {
  BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
  BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
  BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
  BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
  BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
  BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT
} from './BRC97ProductionBus.js'
import { F, FieldElement } from '../stark/Field.js'

export const BRC97_METHOD2_MULTI_TRACE_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_MULTI_TRACE_STATEMENT_V2'
export const BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: BRC97_METHOD2_MULTI_TRACE_TRANSCRIPT_DOMAIN
} as const
const BRC97_METHOD2_BUS_SEGMENT_ORDER = [
  'scalar',
  'lookup',
  'bridge',
  'ec',
  'compression',
  'hmac'
] as const

export interface BRC97Method2MultiTraceStatementInput {
  scalar: bigint
  baseB: SecpPoint
  invoice: number[]
  linkage?: number[]
  hmacMode?: 'compact' | 'lookup'
}

export type BRC97Method2HmacMode = 'compact' | 'lookup'

export type BRC97Method2HmacPublicInput =
  Method2CompactHmacSha256PublicInput |
  Method2LookupBatchedHmacSha256PublicInput

export type BRC97Method2HmacTrace =
  Method2CompactHmacSha256Trace |
  Method2LookupBatchedHmacSha256Trace

export interface BRC97Method2MultiTracePublicInput {
  publicA: SecpPoint
  baseB: SecpPoint
  invoice: number[]
  linkage: number[]
  preprocessedTableRoot: number[]
  hmacMode: BRC97Method2HmacMode
  bus: BRC97SegmentBusPublicInput
  scalar: BRC97ProductionScalarPublicInput
  lookup: LookupBusPublicInput
  ec: ProductionEcPublicInput
  compression: BRC97ProductionCompressionPublicInput
  hmac: BRC97Method2HmacPublicInput
  bridge: BRC97Method2LinkBridgePublicInput
}

export interface BRC97Method2MultiTraceStatement {
  publicInput: BRC97Method2MultiTracePublicInput
  lookup: ProductionRadix11LookupPrototype
  scalarTrace: BRC97ProductionScalarTrace
  radixEcTrace: ProductionRadix11EcTrace
  ecTrace: ProductionEcTrace
  compressionTrace: BRC97ProductionCompressionTrace
  hmacTrace: BRC97Method2HmacTrace
  bridgeTrace: BRC97Method2LinkBridgeTrace
  busSegments: Record<string, {
    rows: FieldElement[][]
    air: ReturnType<typeof wrapBRC97SegmentBusAir>
  }>
}

export interface BRC97Method2MultiTraceMetrics {
  segments: Record<string, {
    rows: number
    width: number
    committedCells: number
    proofBytes?: number
  }>
  totalCommittedCells: number
  proofBytes?: number
}

export interface BRC97Method2MultiTraceDiagnostic {
  ok: boolean
  stage: string
  detail?: string
  multiTrace?: MultiTraceStarkDiagnostic
  error?: string
}

export function buildBRC97Method2MultiTraceStatement (
  input: BRC97Method2MultiTraceStatementInput
): BRC97Method2MultiTraceStatement {
  const hmacMode = input.hmacMode ?? 'lookup'
  if (hmacMode === 'lookup') {
    assertMethod2LookupShaHmacReadyForMethod2()
  }
  const publicA = scalarMultiply(input.scalar)
  const lookup = buildProductionRadix11LookupPrototype(input.scalar, input.baseB)
  const scalarTrace = buildBRC97ProductionScalarTrace(lookup)
  const radixEcTrace = buildProductionRadix11EcTrace(lookup, publicA)
  const ecTrace = buildProductionEcTrace(radixEcTrace)
  const privateS = productionEcTracePrivateS(ecTrace)
  const compressionTrace = buildBRC97ProductionCompressionTrace(privateS)
  const key = compressPoint(privateS)
  const linkage = input.linkage ?? hmacSha256(key, input.invoice)
  const hmacTrace = hmacMode === 'lookup'
    ? buildMethod2LookupBatchedHmacSha256Trace(key, input.invoice, linkage)
    : buildMethod2CompactHmacSha256Trace(key, input.invoice, linkage)
  const bridgeTrace = buildBRC97Method2LinkBridgeTrace(lookup, radixEcTrace)
  const basePublicInput = {
    publicA,
    baseB: input.baseB,
    invoice: input.invoice.slice(),
    linkage: linkage.slice(),
    preprocessedTableRoot: productionRadix11TableRoot(
      buildProductionRadix11PointPairTable(input.baseB)
    ),
    hmacMode,
    scalar: scalarTrace.publicInput,
    lookup: lookup.trace.publicInput,
    ec: ecTrace.publicInput,
    compression: compressionTrace.publicInput,
    hmac: hmacTrace.publicInput,
    bridge: bridgeTrace.publicInput
  }
  const challengeDigest = brc97Method2MultiTraceBusChallengeDigest(basePublicInput)
  const busSegments = buildBusWrappedSegments({
    challengeDigest,
    scalarTrace,
    lookup,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace
  })
  const bus: BRC97SegmentBusPublicInput = {
    challengeDigest,
    segments: Object.fromEntries(
      Object.entries(busSegments).map(([name, segment]) => [
        name,
        {
          emissionCount: segment.contribution.emissionCount,
          selectorCount: segment.selectorCount,
          publicStart: name === 'scalar'
            ? { accumulator0: 0n, accumulator1: 0n }
            : undefined,
          publicEnd: name === 'hmac'
            ? { accumulator0: 0n, accumulator1: 0n }
            : undefined
        }
      ])
    )
  }
  assertBRC97SegmentBusBalanced(bus)
  const publicInput = {
    ...basePublicInput,
    bus
  }
  validateBRC97Method2MultiTracePublicInput(publicInput)
  return {
    publicInput,
    lookup,
    scalarTrace,
    radixEcTrace,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace,
    busSegments: Object.fromEntries(
      Object.entries(busSegments).map(([name, segment]) => [
        name,
        { rows: segment.rows, air: segment.air }
      ])
    )
  }
}

export function proveBRC97Method2MultiTraceStatement (
  statement: BRC97Method2MultiTraceStatement,
  options: StarkProverOptions = {}
): MultiTraceStarkProof {
  return proveMultiTraceStark([
    {
      name: 'scalar',
      air: statement.busSegments.scalar.air,
      traceRows: statement.busSegments.scalar.rows
    },
    {
      name: 'lookup',
      air: statement.busSegments.lookup.air,
      traceRows: statement.busSegments.lookup.rows
    },
    {
      name: 'ec',
      air: statement.busSegments.ec.air,
      traceRows: statement.busSegments.ec.rows
    },
    {
      name: 'compression',
      air: statement.busSegments.compression.air,
      traceRows: statement.busSegments.compression.rows
    },
    {
      name: 'hmac',
      air: statement.busSegments.hmac.air,
      traceRows: statement.busSegments.hmac.rows
    },
    {
      name: 'bridge',
      air: statement.busSegments.bridge.air,
      traceRows: statement.busSegments.bridge.rows
    }
  ], {
    ...BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS,
    ...options,
    transcriptDomain: BRC97_METHOD2_MULTI_TRACE_TRANSCRIPT_DOMAIN
  }, buildBRC97Method2SegmentBusCrossConstraintsFromPublicInput(
    statement.publicInput
  ))
}

export function verifyBRC97Method2MultiTraceStatement (
  publicInput: BRC97Method2MultiTracePublicInput,
  proof: MultiTraceStarkProof
): boolean {
  try {
    validateBRC97Method2MultiTracePublicInput(publicInput)
    if (!multiTraceProofMeetsProductionProfile(proof)) return false
    const challengeDigest =
      brc97Method2MultiTraceBusChallengeDigest(publicInput)
    if (!bytesEqual(challengeDigest, publicInput.bus.challengeDigest)) {
      return false
    }
    return verifyMultiTraceStark(
      brc97Method2MultiTraceVerifierSegments(publicInput, challengeDigest),
      proof,
      multiTraceVerifierOptions(),
      buildBRC97Method2SegmentBusCrossConstraintsFromPublicInput(publicInput))
  } catch {
    return false
  }
}

export function diagnoseBRC97Method2MultiTraceStatement (
  publicInput: BRC97Method2MultiTracePublicInput,
  proof: MultiTraceStarkProof
): BRC97Method2MultiTraceDiagnostic {
  try {
    validateBRC97Method2MultiTracePublicInput(publicInput)
    if (!multiTraceProofMeetsProductionProfile(proof)) {
      return {
        ok: false,
        stage: 'production-profile',
        detail: 'proof does not meet the BRC97 Method 2 production profile'
      }
    }
    const challengeDigest =
      brc97Method2MultiTraceBusChallengeDigest(publicInput)
    if (!bytesEqual(challengeDigest, publicInput.bus.challengeDigest)) {
      return {
        ok: false,
        stage: 'bus-challenge',
        detail: 'recomputed bus challenge digest does not match public input'
      }
    }
    const multiTrace = diagnoseMultiTraceStark(
      brc97Method2MultiTraceVerifierSegments(publicInput, challengeDigest),
      proof,
      multiTraceVerifierOptions(),
      buildBRC97Method2SegmentBusCrossConstraintsFromPublicInput(publicInput)
    )
    return {
      ok: multiTrace.ok,
      stage: multiTrace.ok ? 'ok' : 'multi-trace',
      multiTrace
    }
  } catch (err) {
    return {
      ok: false,
      stage: 'exception',
      error: err instanceof Error ? err.message : String(err)
    }
  }
}

export const buildBRC97Method2ProductionStatement =
  buildBRC97Method2MultiTraceStatement

export const proveBRC97Method2ProductionStatement =
  proveBRC97Method2MultiTraceStatement

export const verifyBRC97Method2ProductionStatement =
  verifyBRC97Method2MultiTraceStatement

export function brc97Method2MultiTraceMetrics (
  statement: BRC97Method2MultiTraceStatement,
  proof?: MultiTraceStarkProof
): BRC97Method2MultiTraceMetrics {
  const segments = {
    scalar: segmentMetrics(
      statement.busSegments.scalar.rows.length,
      statement.busSegments.scalar.air.traceWidth,
      proofSegmentBytes(proof, 'scalar')
    ),
    lookup: segmentMetrics(
      statement.busSegments.lookup.rows.length,
      statement.busSegments.lookup.air.traceWidth,
      proofSegmentBytes(proof, 'lookup')
    ),
    ec: segmentMetrics(
      statement.busSegments.ec.rows.length,
      statement.busSegments.ec.air.traceWidth,
      proofSegmentBytes(proof, 'ec')
    ),
    compression: segmentMetrics(
      statement.busSegments.compression.rows.length,
      statement.busSegments.compression.air.traceWidth,
      proofSegmentBytes(proof, 'compression')
    ),
    hmac: segmentMetrics(
      statement.busSegments.hmac.rows.length,
      statement.busSegments.hmac.air.traceWidth,
      proofSegmentBytes(proof, 'hmac')
    ),
    bridge: segmentMetrics(
      statement.busSegments.bridge.rows.length,
      statement.busSegments.bridge.air.traceWidth,
      proofSegmentBytes(proof, 'bridge')
    )
  }
  return {
    segments,
    totalCommittedCells: Object.values(segments).reduce(
      (total, segment) => total + segment.committedCells,
      0
    ),
    proofBytes: proof === undefined
      ? undefined
      : serializeMultiTraceStarkProof(proof).length
  }
}

export function validateBRC97Method2MultiTracePublicInput (
  publicInput: BRC97Method2MultiTracePublicInput
): void {
  if (publicInput.publicA.infinity === true || !isOnCurve(publicInput.publicA)) {
    throw new Error('BRC97 Method 2 multi-trace public A is invalid')
  }
  if (publicInput.baseB.infinity === true || !isOnCurve(publicInput.baseB)) {
    throw new Error('BRC97 Method 2 multi-trace public B is invalid')
  }
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, 32, 'linkage')
  if (
    publicInput.hmacMode !== 'compact' &&
    publicInput.hmacMode !== 'lookup'
  ) {
    throw new Error('BRC97 Method 2 multi-trace HMAC mode is invalid')
  }
  if (!pointsEqual(publicInput.ec.publicA, publicInput.publicA)) {
    throw new Error('BRC97 Method 2 multi-trace EC public A mismatch')
  }
  if (!pointsEqual(publicInput.ec.baseB, publicInput.baseB)) {
    throw new Error('BRC97 Method 2 multi-trace EC public B mismatch')
  }
  if (!bytesEqual(publicInput.hmac.invoice, publicInput.invoice)) {
    throw new Error('BRC97 Method 2 multi-trace invoice mismatch')
  }
  if (!bytesEqual(publicInput.hmac.linkage, publicInput.linkage)) {
    throw new Error('BRC97 Method 2 multi-trace linkage mismatch')
  }
  validateMethod2HmacPublicInput(publicInput.hmacMode, publicInput.hmac)
  if (!bytesEqual(
    publicInput.preprocessedTableRoot,
    productionRadix11TableRoot(buildProductionRadix11PointPairTable(
      publicInput.baseB
    ))
  )) {
    throw new Error('BRC97 Method 2 multi-trace preprocessed table root mismatch')
  }
  if (!bytesEqual(
    publicInput.bus.challengeDigest,
    brc97Method2MultiTraceBusChallengeDigest(publicInput)
  )) {
    throw new Error('BRC97 Method 2 multi-trace bus challenge mismatch')
  }
  assertBRC97SegmentBusBalanced(publicInput.bus)
  validateBusContributions(publicInput.bus)
  validateDeterministicLookupTable(publicInput)
}

function validateMethod2HmacPublicInput (
  mode: BRC97Method2HmacMode,
  publicInput: BRC97Method2HmacPublicInput
): void {
  if (mode === 'lookup') {
    validateMethod2LookupBatchedHmacSha256PublicInput(
      publicInput as Method2LookupBatchedHmacSha256PublicInput
    )
  } else {
    validateMethod2CompactHmacSha256PublicInput(
      publicInput as Method2CompactHmacSha256PublicInput
    )
  }
}

function buildMethod2HmacAir (
  mode: BRC97Method2HmacMode,
  publicInput: BRC97Method2HmacPublicInput
): ReturnType<typeof buildMethod2CompactHmacSha256Air> {
  return mode === 'lookup'
    ? buildMethod2LookupBatchedHmacSha256Air(
      publicInput as Method2LookupBatchedHmacSha256PublicInput
    )
    : buildMethod2CompactHmacSha256Air(
      publicInput as Method2CompactHmacSha256PublicInput
    )
}

function hmacTraceMode (
  trace: BRC97Method2HmacTrace
): BRC97Method2HmacMode {
  return 'relation' in trace.publicInput &&
    trace.publicInput.relation === 'lookup-batched-hmac-sha256'
    ? 'lookup'
    : 'compact'
}

function hmacTraceWidth (mode: BRC97Method2HmacMode): number {
  return mode === 'lookup'
    ? METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width
    : METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
}

function hmacKeyByteOffset (mode: BRC97Method2HmacMode): number {
  return mode === 'lookup'
    ? METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.keyBytes
    : METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes
}

function multiTraceVerifierOptions (): StarkVerifierOptions {
  return {
    ...BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS,
    transcriptDomain: BRC97_METHOD2_MULTI_TRACE_TRANSCRIPT_DOMAIN
  }
}

function brc97Method2MultiTraceVerifierSegments (
  publicInput: BRC97Method2MultiTracePublicInput,
  challengeDigest: number[]
): Array<{ name: string, air: ReturnType<typeof wrapBRC97SegmentBusAir> }> {
  const proofTraceLength = brc97Method2MultiTraceBusProofTraceLength(publicInput)
  return [
    {
      name: 'scalar',
      air: wrapBRC97SegmentBusAir({
        name: 'scalar',
        air: buildBRC97ProductionScalarAir(publicInput.scalar),
        baseTraceLength: publicInput.scalar.traceLength,
        traceLength: proofTraceLength,
        emissions: scalarBusEmissions(publicInput.scalar),
        challengeDigest,
        emissionCount: publicInput.bus.segments.scalar.emissionCount,
        publicStart: publicInput.bus.segments.scalar.publicStart,
        publicEnd: publicInput.bus.segments.scalar.publicEnd
      })
    },
    {
      name: 'lookup',
      air: wrapBRC97SegmentBusAir({
        name: 'lookup',
        air: buildLookupBusAir(publicInput.lookup),
        baseTraceLength: publicInput.lookup.traceLength,
        traceLength: proofTraceLength,
        emissions: lookupBusEmissions(publicInput.ec.radixWindowCount),
        challengeDigest,
        emissionCount: publicInput.bus.segments.lookup.emissionCount,
        publicStart: publicInput.bus.segments.lookup.publicStart,
        publicEnd: publicInput.bus.segments.lookup.publicEnd
      })
    },
    {
      name: 'ec',
      air: wrapBRC97SegmentBusAir({
        name: 'ec',
        air: buildProductionEcAir(publicInput.ec),
        baseTraceLength: publicInput.ec.paddedRows,
        traceLength: proofTraceLength,
        emissions: ecBusEmissions(publicInput.ec),
        challengeDigest,
        emissionCount: publicInput.bus.segments.ec.emissionCount,
        publicStart: publicInput.bus.segments.ec.publicStart,
        publicEnd: publicInput.bus.segments.ec.publicEnd
      })
    },
    {
      name: 'compression',
      air: wrapBRC97SegmentBusAir({
        name: 'compression',
        air: buildBRC97ProductionCompressionAir(publicInput.compression),
        baseTraceLength: publicInput.compression.traceLength,
        traceLength: proofTraceLength,
        emissions: compressionBusEmissions(),
        challengeDigest,
        emissionCount: publicInput.bus.segments.compression.emissionCount,
        publicStart: publicInput.bus.segments.compression.publicStart,
        publicEnd: publicInput.bus.segments.compression.publicEnd
      })
    },
    {
      name: 'hmac',
      air: wrapBRC97SegmentBusAir({
        name: 'hmac',
        air: buildMethod2HmacAir(publicInput.hmacMode, publicInput.hmac),
        baseTraceLength: publicInput.hmac.traceLength,
        traceLength: proofTraceLength,
        emissions: hmacBusEmissions(publicInput.hmacMode),
        challengeDigest,
        emissionCount: publicInput.bus.segments.hmac.emissionCount,
        publicStart: publicInput.bus.segments.hmac.publicStart,
        publicEnd: publicInput.bus.segments.hmac.publicEnd
      })
    },
    {
      name: 'bridge',
      air: wrapBRC97SegmentBusAir({
        name: 'bridge',
        air: buildBRC97Method2LinkBridgeAir(publicInput.bridge),
        baseTraceLength: publicInput.bridge.traceLength,
        traceLength: proofTraceLength,
        emissions: bridgeBusEmissions(publicInput.bridge),
        challengeDigest,
        emissionCount: publicInput.bus.segments.bridge.emissionCount,
        publicStart: publicInput.bus.segments.bridge.publicStart,
        publicEnd: publicInput.bus.segments.bridge.publicEnd
      })
    }
  ]
}

function buildBusWrappedSegments (input: {
  challengeDigest: number[]
  scalarTrace: BRC97ProductionScalarTrace
  lookup: ProductionRadix11LookupPrototype
  ecTrace: ProductionEcTrace
  compressionTrace: BRC97ProductionCompressionTrace
  hmacTrace: BRC97Method2HmacTrace
  bridgeTrace: BRC97Method2LinkBridgeTrace
}): Record<string, ReturnType<typeof wrapBRC97SegmentBusTrace>> {
  const out: Partial<Record<string, ReturnType<typeof wrapBRC97SegmentBusTrace>>> = {}
  const proofTraceLength = Math.max(
    input.scalarTrace.rows.length,
    input.lookup.trace.rows.length,
    input.ecTrace.rows.length,
    input.compressionTrace.rows.length,
    input.hmacTrace.rows.length,
    input.bridgeTrace.rows.length
  )
  let start = { accumulator0: 0n, accumulator1: 0n }
  const wrap = (
    name: typeof BRC97_METHOD2_BUS_SEGMENT_ORDER[number],
    value: Omit<Parameters<typeof wrapBRC97SegmentBusTrace>[0], 'name' | 'challengeDigest' | 'start' | 'publicStart' | 'publicEnd'>
  ): void => {
    const segment = wrapBRC97SegmentBusTrace({
      name,
      ...value,
      proofTraceLength,
      start,
      publicStart: name === 'scalar'
        ? { accumulator0: 0n, accumulator1: 0n }
        : undefined,
      publicEnd: name === 'hmac'
        ? { accumulator0: 0n, accumulator1: 0n }
        : undefined,
      challengeDigest: input.challengeDigest
    })
    out[name] = segment
    start = segment.end
  }
  wrap('scalar', {
    air: buildBRC97ProductionScalarAir(input.scalarTrace),
    rows: input.scalarTrace.rows,
    emissions: scalarBusEmissions(input.scalarTrace.publicInput)
  })
  wrap('lookup', {
    air: buildLookupBusAir(input.lookup.trace.publicInput),
    rows: input.lookup.trace.rows,
    emissions: lookupBusEmissions(input.ecTrace.publicInput.radixWindowCount)
  })
  wrap('bridge', {
    air: buildBRC97Method2LinkBridgeAir(input.bridgeTrace),
    rows: input.bridgeTrace.rows,
    emissions: bridgeBusEmissions(input.bridgeTrace.publicInput)
  })
  wrap('ec', {
    air: buildProductionEcAir(input.ecTrace),
    rows: input.ecTrace.rows,
    emissions: ecBusEmissions(input.ecTrace.publicInput)
  })
  wrap('compression', {
    air: buildBRC97ProductionCompressionAir(input.compressionTrace),
    rows: input.compressionTrace.rows,
    emissions: compressionBusEmissions()
  })
  wrap('hmac', {
    air: buildMethod2HmacAir(
      hmacTraceMode(input.hmacTrace),
      input.hmacTrace.publicInput
    ),
    rows: input.hmacTrace.rows,
    emissions: hmacBusEmissions(hmacTraceMode(input.hmacTrace))
  })
  if (start.accumulator0 !== 0n || start.accumulator1 !== 0n) {
    throw new Error('BRC97 Method 2 segment bus does not balance')
  }
  return out as Record<string, ReturnType<typeof wrapBRC97SegmentBusTrace>>
}

function brc97Method2MultiTraceBusProofTraceLength (
  publicInput: BRC97Method2MultiTracePublicInput
): number {
  return Math.max(
    publicInput.scalar.traceLength,
    publicInput.lookup.traceLength,
    publicInput.ec.paddedRows,
    publicInput.compression.traceLength,
    publicInput.hmac.traceLength,
    publicInput.bridge.traceLength
  )
}

function scalarBusEmissions (
  publicInput: BRC97ProductionScalarPublicInput
): BRC97SegmentBusEmission[] {
  return Array.from({ length: publicInput.windowCount }, (_, row) => ({
    row,
    kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
    values: current => [
      current[BRC97_PRODUCTION_SCALAR_LAYOUT.window],
      current[BRC97_PRODUCTION_SCALAR_LAYOUT.magnitude],
      current[BRC97_PRODUCTION_SCALAR_LAYOUT.isZero],
      current[BRC97_PRODUCTION_SCALAR_LAYOUT.sign]
    ]
  }))
}

function lookupBusEmissions (windowCount: number): BRC97SegmentBusEmission[] {
  return Array.from({ length: windowCount }, (_, step) => ({
    row: BRC97_RADIX11_TABLE_ROWS + step,
    kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
    values: current => tupleFromRow(current, LOOKUP_BUS_LAYOUT.left)
  }))
}

function bridgeBusEmissions (
  publicInput: BRC97Method2LinkBridgePublicInput
): BRC97SegmentBusEmission[] {
  const emissions: BRC97SegmentBusEmission[] = []
  for (let step = 0; step < publicInput.activeRows; step++) {
    emissions.push({
      row: step,
      kind: BRC97_SEGMENT_BUS_KIND_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
      values: current => [
        current[BRC97_METHOD2_LINK_BRIDGE_LAYOUT.window],
        current[BRC97_METHOD2_LINK_BRIDGE_LAYOUT.magnitude],
        current[BRC97_METHOD2_LINK_BRIDGE_LAYOUT.isZero],
        current[BRC97_METHOD2_LINK_BRIDGE_LAYOUT.sign]
      ]
    }, {
      row: step,
      kind: BRC97_SEGMENT_BUS_KIND_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
      values: current => tupleFromRow(
        current,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.tableTuple
      )
    }, {
      row: step,
      kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
      values: current => pointTupleFromLimbs(
        current,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedGInfinity,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedGX,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedGY
      )
    }, {
      row: step,
      kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      values: current => pointTupleFromLimbs(
        current,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedBInfinity,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedBX,
        BRC97_METHOD2_LINK_BRIDGE_LAYOUT.selectedBY
      )
    })
  }
  return emissions
}

function ecBusEmissions (
  publicInput: ProductionEcPublicInput
): BRC97SegmentBusEmission[] {
  const emissions: BRC97SegmentBusEmission[] = []
  const emittedSelected = new Set<string>()
  for (const item of publicInput.schedule) {
    const key = `${item.lane}:${item.step}`
    if (emittedSelected.has(key)) continue
    emittedSelected.add(key)
    emissions.push({
      row: item.row,
      kind: BRC97_SEGMENT_BUS_KIND_TARGET,
      tag: item.lane === 'G'
        ? BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT
        : BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      values: current => pointTupleFromLimbs(
        current,
        PRODUCTION_EC_LAYOUT.selectedInfinity,
        PRODUCTION_EC_LAYOUT.selectedX,
        PRODUCTION_EC_LAYOUT.selectedY
      )
    })
  }
  const finalB = finalEcLaneRow(publicInput, 'B')
  emissions.push({
    row: finalB,
    kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
    values: current => compressionPointInputTupleFromEcRow(current)
  })
  return emissions
}

function compressionBusEmissions (): BRC97SegmentBusEmission[] {
  const emissions: BRC97SegmentBusEmission[] = [{
    row: 256,
    kind: BRC97_SEGMENT_BUS_KIND_TARGET,
    tag: BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
    values: current => [
      ...fieldLimbsFromRow(
        current,
        BRC97_PRODUCTION_COMPRESSION_LAYOUT.xLimbs
      ),
      current[BRC97_PRODUCTION_COMPRESSION_LAYOUT.yLimb0]
    ]
  }, {
    row: 256,
    kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
    values: current => [
      0n,
      current[BRC97_PRODUCTION_COMPRESSION_LAYOUT.byte]
    ]
  }]
  for (let byteIndex = 1; byteIndex < 33; byteIndex++) {
    emissions.push({
      row: (32 - byteIndex) * 8 + 7,
      kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
      values: current => [
        BigInt(byteIndex),
        current[BRC97_PRODUCTION_COMPRESSION_LAYOUT.byte]
      ]
    })
  }
  return emissions
}

function hmacBusEmissions (
  mode: BRC97Method2HmacMode
): BRC97SegmentBusEmission[] {
  const keyOffset = hmacKeyByteOffset(mode)
  return Array.from({ length: 33 }, (_, byteIndex) => ({
    row: 0,
    kind: BRC97_SEGMENT_BUS_KIND_TARGET,
    tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
    values: current => [
      BigInt(byteIndex),
      current[keyOffset + byteIndex]
    ]
  }))
}

function tupleFromRow (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset, offset + LOOKUP_BUS_TUPLE_ARITY)
}

function pointTupleFromLimbs (
  row: FieldElement[],
  infinity: number,
  x: number,
  y: number
): FieldElement[] {
  return [
    row[infinity],
    ...fieldLimbsFromRow(row, x),
    ...fieldLimbsFromRow(row, y)
  ]
}

function compressionPointInputTupleFromEcRow (
  row: FieldElement[]
): FieldElement[] {
  return [
    ...fieldLimbsFromRow(row, PRODUCTION_EC_LAYOUT.afterX),
    row[PRODUCTION_EC_LAYOUT.afterY]
  ]
}

function fieldLimbsFromRow (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset, offset + BRC97_RADIX11_POINT_LIMBS)
}

function finalEcLaneRow (
  publicInput: ProductionEcPublicInput,
  lane: 'G' | 'B'
): number {
  const rows = publicInput.schedule.filter(row => row.lane === lane)
  const item = rows[rows.length - 1]
  if (item === undefined) throw new Error('BRC97 EC final row is missing')
  return item.row + item.rows - 1
}

function buildBRC97Method2SegmentBusCrossConstraintsFromPublicInput (
  publicInput: BRC97Method2MultiTracePublicInput
): MultiTraceCrossConstraintInput[] {
  return buildBRC97Method2SegmentBusCrossConstraintsFromWidths({
    scalar: BRC97_PRODUCTION_SCALAR_LAYOUT.width,
    lookup: LOOKUP_BUS_LAYOUT.width,
    bridge: BRC97_METHOD2_LINK_BRIDGE_LAYOUT.width,
    ec: PRODUCTION_EC_LAYOUT.width,
    compression: BRC97_PRODUCTION_COMPRESSION_LAYOUT.width,
    hmac: hmacTraceWidth(publicInput.hmacMode)
  }, {
    scalar: publicInput.bus.segments.scalar.selectorCount ??
      publicInput.bus.segments.scalar.emissionCount,
    lookup: publicInput.bus.segments.lookup.selectorCount ??
      publicInput.bus.segments.lookup.emissionCount,
    bridge: publicInput.bus.segments.bridge.selectorCount ??
      publicInput.bus.segments.bridge.emissionCount,
    ec: publicInput.bus.segments.ec.selectorCount ??
      publicInput.bus.segments.ec.emissionCount,
    compression: publicInput.bus.segments.compression.selectorCount ??
      publicInput.bus.segments.compression.emissionCount,
    hmac: publicInput.bus.segments.hmac.selectorCount ??
      publicInput.bus.segments.hmac.emissionCount
  })
}

function buildBRC97Method2SegmentBusCrossConstraintsFromWidths (
  widths: Record<typeof BRC97_METHOD2_BUS_SEGMENT_ORDER[number], number>,
  selectorCounts: Record<typeof BRC97_METHOD2_BUS_SEGMENT_ORDER[number], number>
): MultiTraceCrossConstraintInput[] {
  const values: Array<{
    left: typeof BRC97_METHOD2_BUS_SEGMENT_ORDER[number]
    right: typeof BRC97_METHOD2_BUS_SEGMENT_ORDER[number]
    leftColumn: number
    rightColumn: number
  }> = []
  const degreeBound = BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.maskDegree + 1
  for (let index = 0; index + 1 < BRC97_METHOD2_BUS_SEGMENT_ORDER.length; index++) {
    const left = BRC97_METHOD2_BUS_SEGMENT_ORDER[index]
    const right = BRC97_METHOD2_BUS_SEGMENT_ORDER[index + 1]
    const leftLayout = brc97SegmentBusWrappedLayout(
      widths[left],
      selectorCounts[left]
    )
    const rightLayout = brc97SegmentBusWrappedLayout(
      widths[right],
      selectorCounts[right]
    )
    values.push({
      left,
      right,
      leftColumn: leftLayout.end0,
      rightColumn: rightLayout.start0
    }, {
      left,
      right,
      leftColumn: leftLayout.end1,
      rightColumn: rightLayout.start1
    })
  }
  return [{
    name: 'bus-endpoint-chain',
    refs: BRC97_METHOD2_BUS_SEGMENT_ORDER.map(segment => ({
      alias: segment,
      segment
    })),
    degreeBound,
    evaluate: ({ rows }) => values.map(value =>
      F.sub(
        rows[value.left][value.leftColumn],
        rows[value.right][value.rightColumn]
      )
    )
  }]
}

function validateBusContributions (
  bus: BRC97SegmentBusPublicInput
): void {
  for (const name of BRC97_METHOD2_BUS_SEGMENT_ORDER) {
    const segment = bus.segments[name]
    if (segment === undefined) {
      throw new Error(`BRC97 Method 2 multi-trace bus segment missing: ${name}`)
    }
    if (
      !Number.isSafeInteger(segment.emissionCount) ||
      segment.emissionCount < 0
    ) {
      throw new Error('BRC97 Method 2 multi-trace bus emission count is invalid')
    }
    if (
      segment.selectorCount !== undefined &&
      (
        !Number.isSafeInteger(segment.selectorCount) ||
        segment.selectorCount < 0 ||
        segment.selectorCount > segment.emissionCount
      )
    ) {
      throw new Error('BRC97 Method 2 multi-trace bus selector count is invalid')
    }
    assertBusEndpoint(segment.publicStart)
    assertBusEndpoint(segment.publicEnd)
    const expectsStart = name === 'scalar'
    const expectsEnd = name === 'hmac'
    if (!expectedOptionalZeroEndpoint(segment.publicStart, expectsStart)) {
      throw new Error('BRC97 Method 2 multi-trace bus public start mismatch')
    }
    if (!expectedOptionalZeroEndpoint(segment.publicEnd, expectsEnd)) {
      throw new Error('BRC97 Method 2 multi-trace bus public end mismatch')
    }
  }
}

function assertBusEndpoint (
  endpoint: { accumulator0: FieldElement, accumulator1: FieldElement } | undefined
): void {
  if (endpoint === undefined) return
  F.assertCanonical(endpoint.accumulator0)
  F.assertCanonical(endpoint.accumulator1)
}

function expectedOptionalZeroEndpoint (
  endpoint: { accumulator0: FieldElement, accumulator1: FieldElement } | undefined,
  expected: boolean
): boolean {
  if (!expected) return endpoint === undefined
  return endpoint?.accumulator0 === 0n && endpoint.accumulator1 === 0n
}

function brc97Method2MultiTraceBusChallengeDigest (
  publicInput: Omit<BRC97Method2MultiTracePublicInput, 'bus'> |
  BRC97Method2MultiTracePublicInput
): number[] {
  return sha256(toArray(stableJson({
    id: 'BRC97_METHOD2_MULTI_TRACE_BUS_CHALLENGE_V1',
    publicA: publicInput.publicA,
    baseB: publicInput.baseB,
    invoice: publicInput.invoice,
    linkage: publicInput.linkage,
    preprocessedTableRoot: publicInput.preprocessedTableRoot,
    hmacMode: publicInput.hmacMode,
    scalar: publicInput.scalar,
    lookup: publicInput.lookup,
    ec: publicInput.ec,
    compression: publicInput.compression,
    hmac: publicInput.hmac,
    bridge: publicInput.bridge
  }), 'utf8'))
}

function multiTraceProofMeetsProductionProfile (
  proof: MultiTraceStarkProof
): boolean {
  if (proof.transcriptDomain !== BRC97_METHOD2_MULTI_TRACE_TRANSCRIPT_DOMAIN) {
    return false
  }
  if (proof.segments.length !== 6) return false
  if ((proof.crossProofs ?? []).length !== 1) return false
  if ((proof.constantColumnProofs ?? []).length !== 0) return false
  return proof.segments.every(segment =>
    segment.proof.blowupFactor ===
      BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.blowupFactor &&
    segment.proof.numQueries ===
      BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.numQueries &&
    segment.proof.maxRemainderSize ===
      BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.maxRemainderSize &&
    segment.proof.maskDegree ===
      BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.maskDegree &&
    segment.proof.cosetOffset ===
      BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.cosetOffset
  )
}

function validateDeterministicLookupTable (
  publicInput: BRC97Method2MultiTracePublicInput
): void {
  const table = buildProductionRadix11PointPairTable(publicInput.baseB)
  const zeroTuple = new Array<bigint>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  if (
    publicInput.lookup.expectedLookupRequests !==
    publicInput.ec.radixWindowCount
  ) {
    throw new Error('BRC97 Method 2 multi-trace lookup request count mismatch')
  }
  if (publicInput.lookup.scheduleRows.length !== publicInput.lookup.traceLength) {
    throw new Error('BRC97 Method 2 multi-trace lookup schedule is incomplete')
  }
  for (let i = 0; i < table.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupSupply ||
      row.tag !== table[i].tag ||
      !vectorsEqual(row.publicTuple, table[i].values)
    ) {
      throw new Error('BRC97 Method 2 multi-trace lookup table mismatch')
    }
  }
  const requestEnd = BRC97_RADIX11_TABLE_ROWS + publicInput.ec.radixWindowCount
  for (let i = BRC97_RADIX11_TABLE_ROWS; i < requestEnd; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupRequest ||
      row.tag !== LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC97 Method 2 multi-trace lookup request mismatch')
    }
  }
  for (let i = requestEnd; i < publicInput.lookup.scheduleRows.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.inactive ||
      row.tag !== 0n ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC97 Method 2 multi-trace lookup inactive mismatch')
    }
  }
}

function vectorsEqual (left: bigint[], right: bigint[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index])
}

function segmentMetrics (
  rows: number,
  width: number,
  proofBytes?: number
): BRC97Method2MultiTraceMetrics['segments'][string] {
  return {
    rows,
    width,
    committedCells: rows * width,
    proofBytes
  }
}

function proofSegmentBytes (
  proof: MultiTraceStarkProof | undefined,
  name: string
): number | undefined {
  const segment = proof?.segments.find(item => item.name === name)
  return segment === undefined
    ? undefined
    : serializeStarkProof(segment.proof).length
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

function assertBytes (
  value: number[],
  length: number | undefined,
  name: string
): void {
  if (length !== undefined && value.length !== length) {
    throw new Error(`${name} has invalid length`)
  }
  for (const byte of value) {
    if (!Number.isSafeInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${name} contains invalid byte`)
    }
  }
}

function stableJson (value: unknown): string {
  return JSON.stringify(sortJson(value), (_, entry) =>
    typeof entry === 'bigint' ? entry.toString() : entry
  )
}

function sortJson (value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, sortJson(entry)])
    )
  }
  return value
}

export function brc97Method2MultiTraceDeterministicFixture ():
BRC97Method2MultiTraceStatement {
  if (deterministicFixtureCache !== undefined) return deterministicFixtureCache
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  const invoice = Array.from('multi-trace fixture')
    .map(char => char.charCodeAt(0))
  const privateS = scalarMultiply(scalar, baseB)
  deterministicFixtureCache = buildBRC97Method2MultiTraceStatement({
    scalar,
    baseB,
    invoice,
    linkage: hmacSha256(compressPoint(privateS), invoice)
  })
  return deterministicFixtureCache
}

let deterministicFixtureCache: BRC97Method2MultiTraceStatement | undefined
