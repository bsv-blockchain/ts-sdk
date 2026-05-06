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
  BRC69_RADIX11_TABLE_ROWS,
  BRC69_RADIX11_POINT_LIMBS,
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
  BRC69_PRODUCTION_COMPRESSION_LAYOUT,
  BRC69ProductionCompressionPublicInput,
  BRC69ProductionCompressionTrace,
  buildBRC69ProductionCompressionAir,
  buildBRC69ProductionCompressionTrace
} from './BRC69ProductionCompression.js'
import {
  BRC69_PRODUCTION_SCALAR_LAYOUT,
  BRC69ProductionScalarPublicInput,
  BRC69ProductionScalarTrace,
  buildBRC69ProductionScalarAir,
  buildBRC69ProductionScalarTrace
} from './BRC69ProductionScalar.js'
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
  BRC69_METHOD2_LINK_BRIDGE_LAYOUT,
  BRC69Method2LinkBridgePublicInput,
  BRC69Method2LinkBridgeTrace,
  buildBRC69Method2LinkBridgeAir,
  buildBRC69Method2LinkBridgeTrace
} from './BRC69Method2LinkBridge.js'
import {
  BRC69_SEGMENT_BUS_KIND_SOURCE,
  BRC69_SEGMENT_BUS_KIND_TARGET,
  BRC69SegmentBusEmission,
  BRC69SegmentBusPublicInput,
  assertBRC69SegmentBusBalanced,
  brc69SegmentBusWrappedLayout,
  wrapBRC69SegmentBusAir,
  wrapBRC69SegmentBusTrace
} from './BRC69SegmentBus.js'
import {
  BRC69_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
  BRC69_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
  BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
  BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
  BRC69_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
  BRC69_PRODUCTION_BUS_TAG_SCALAR_DIGIT
} from './BRC69ProductionBus.js'
import { F, FieldElement } from '../stark/Field.js'

export const BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN =
  'BRC69_METHOD2_WHOLE_STATEMENT_AIR_V1'
export const BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
} as const
const BRC69_METHOD2_BUS_SEGMENT_ORDER = [
  'scalar',
  'lookup',
  'bridge',
  'ec',
  'compression',
  'hmac'
] as const

export interface BRC69Method2WholeStatementInput {
  scalar: bigint
  baseB: SecpPoint
  invoice: number[]
  linkage?: number[]
}

export type BRC69Method2HmacMode = 'lookup'

export type BRC69Method2HmacPublicInput =
  Method2LookupBatchedHmacSha256PublicInput

export type BRC69Method2HmacTrace =
  Method2LookupBatchedHmacSha256Trace

export interface BRC69Method2WholeStatementPublicInput {
  publicA: SecpPoint
  baseB: SecpPoint
  invoice: number[]
  linkage: number[]
  preprocessedTableRoot: number[]
  hmacMode: BRC69Method2HmacMode
  bus: BRC69SegmentBusPublicInput
  scalar: BRC69ProductionScalarPublicInput
  lookup: LookupBusPublicInput
  ec: ProductionEcPublicInput
  compression: BRC69ProductionCompressionPublicInput
  hmac: BRC69Method2HmacPublicInput
  bridge: BRC69Method2LinkBridgePublicInput
}

export interface BRC69Method2WholeStatement {
  publicInput: BRC69Method2WholeStatementPublicInput
  lookup: ProductionRadix11LookupPrototype
  scalarTrace: BRC69ProductionScalarTrace
  radixEcTrace: ProductionRadix11EcTrace
  ecTrace: ProductionEcTrace
  compressionTrace: BRC69ProductionCompressionTrace
  hmacTrace: BRC69Method2HmacTrace
  bridgeTrace: BRC69Method2LinkBridgeTrace
  busSegments: Record<string, {
    rows: FieldElement[][]
    air: ReturnType<typeof wrapBRC69SegmentBusAir>
  }>
}

export interface BRC69Method2WholeStatementMetrics {
  segments: Record<string, {
    rows: number
    width: number
    committedCells: number
    proofBytes?: number
  }>
  totalCommittedCells: number
  proofBytes?: number
}

export interface BRC69Method2WholeStatementDiagnostic {
  ok: boolean
  stage: string
  detail?: string
  multiTrace?: MultiTraceStarkDiagnostic
  error?: string
}

export function buildBRC69Method2WholeStatement (
  input: BRC69Method2WholeStatementInput
): BRC69Method2WholeStatement {
  const hmacMode: BRC69Method2HmacMode = 'lookup'
  assertMethod2LookupShaHmacReadyForMethod2()
  const publicA = scalarMultiply(input.scalar)
  const lookup = buildProductionRadix11LookupPrototype(input.scalar, input.baseB)
  const scalarTrace = buildBRC69ProductionScalarTrace(lookup)
  const radixEcTrace = buildProductionRadix11EcTrace(lookup, publicA)
  const ecTrace = buildProductionEcTrace(radixEcTrace)
  const privateS = productionEcTracePrivateS(ecTrace)
  const compressionTrace = buildBRC69ProductionCompressionTrace(privateS)
  const key = compressPoint(privateS)
  const linkage = input.linkage ?? hmacSha256(key, input.invoice)
  const hmacTrace = buildMethod2LookupBatchedHmacSha256Trace(
    key,
    input.invoice,
    linkage
  )
  const bridgeTrace = buildBRC69Method2LinkBridgeTrace(lookup, radixEcTrace)
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
  const challengeDigest = brc69Method2WholeStatementBusChallengeDigest(basePublicInput)
  const busSegments = buildBusWrappedSegments({
    challengeDigest,
    scalarTrace,
    lookup,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace
  })
  const bus: BRC69SegmentBusPublicInput = {
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
  assertBRC69SegmentBusBalanced(bus)
  const publicInput = {
    ...basePublicInput,
    bus
  }
  validateBRC69Method2WholeStatementPublicInput(publicInput)
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

export function proveBRC69Method2WholeStatement (
  statement: BRC69Method2WholeStatement,
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
    ...BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
    ...options,
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  }, buildBRC69Method2SegmentBusCrossConstraintsFromPublicInput(
    statement.publicInput
  ))
}

export function verifyBRC69Method2WholeStatement (
  publicInput: BRC69Method2WholeStatementPublicInput,
  proof: MultiTraceStarkProof
): boolean {
  try {
    validateBRC69Method2WholeStatementPublicInput(publicInput)
    if (!multiTraceProofMeetsProductionProfile(proof)) return false
    const challengeDigest =
      brc69Method2WholeStatementBusChallengeDigest(publicInput)
    if (!bytesEqual(challengeDigest, publicInput.bus.challengeDigest)) {
      return false
    }
    return verifyMultiTraceStark(
      brc69Method2WholeStatementVerifierSegments(publicInput, challengeDigest),
      proof,
      multiTraceVerifierOptions(),
      buildBRC69Method2SegmentBusCrossConstraintsFromPublicInput(publicInput))
  } catch {
    return false
  }
}

export function diagnoseBRC69Method2WholeStatement (
  publicInput: BRC69Method2WholeStatementPublicInput,
  proof: MultiTraceStarkProof
): BRC69Method2WholeStatementDiagnostic {
  try {
    validateBRC69Method2WholeStatementPublicInput(publicInput)
    if (!multiTraceProofMeetsProductionProfile(proof)) {
      return {
        ok: false,
        stage: 'production-profile',
        detail: 'proof does not meet the BRC69 Method 2 production profile'
      }
    }
    const challengeDigest =
      brc69Method2WholeStatementBusChallengeDigest(publicInput)
    if (!bytesEqual(challengeDigest, publicInput.bus.challengeDigest)) {
      return {
        ok: false,
        stage: 'bus-challenge',
        detail: 'recomputed bus challenge digest does not match public input'
      }
    }
    const multiTrace = diagnoseMultiTraceStark(
      brc69Method2WholeStatementVerifierSegments(publicInput, challengeDigest),
      proof,
      multiTraceVerifierOptions(),
      buildBRC69Method2SegmentBusCrossConstraintsFromPublicInput(publicInput)
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

export const buildBRC69Method2ProductionStatement =
  buildBRC69Method2WholeStatement

export const proveBRC69Method2ProductionStatement =
  proveBRC69Method2WholeStatement

export const verifyBRC69Method2ProductionStatement =
  verifyBRC69Method2WholeStatement

export function brc69Method2WholeStatementMetrics (
  statement: BRC69Method2WholeStatement,
  proof?: MultiTraceStarkProof
): BRC69Method2WholeStatementMetrics {
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

export function validateBRC69Method2WholeStatementPublicInput (
  publicInput: BRC69Method2WholeStatementPublicInput
): void {
  if (publicInput.publicA.infinity === true || !isOnCurve(publicInput.publicA)) {
    throw new Error('BRC69 Method 2 multi-trace public A is invalid')
  }
  if (publicInput.baseB.infinity === true || !isOnCurve(publicInput.baseB)) {
    throw new Error('BRC69 Method 2 multi-trace public B is invalid')
  }
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, 32, 'linkage')
  if (publicInput.hmacMode !== 'lookup') {
    throw new Error('BRC69 Method 2 whole-statement HMAC mode must be lookup')
  }
  if (!pointsEqual(publicInput.ec.publicA, publicInput.publicA)) {
    throw new Error('BRC69 Method 2 multi-trace EC public A mismatch')
  }
  if (!pointsEqual(publicInput.ec.baseB, publicInput.baseB)) {
    throw new Error('BRC69 Method 2 multi-trace EC public B mismatch')
  }
  if (!bytesEqual(publicInput.hmac.invoice, publicInput.invoice)) {
    throw new Error('BRC69 Method 2 multi-trace invoice mismatch')
  }
  if (!bytesEqual(publicInput.hmac.linkage, publicInput.linkage)) {
    throw new Error('BRC69 Method 2 multi-trace linkage mismatch')
  }
  validateMethod2HmacPublicInput(publicInput.hmacMode, publicInput.hmac)
  if (!bytesEqual(
    publicInput.preprocessedTableRoot,
    productionRadix11TableRoot(buildProductionRadix11PointPairTable(
      publicInput.baseB
    ))
  )) {
    throw new Error('BRC69 Method 2 multi-trace preprocessed table root mismatch')
  }
  if (!bytesEqual(
    publicInput.bus.challengeDigest,
    brc69Method2WholeStatementBusChallengeDigest(publicInput)
  )) {
    throw new Error('BRC69 Method 2 multi-trace bus challenge mismatch')
  }
  assertBRC69SegmentBusBalanced(publicInput.bus)
  validateBusContributions(publicInput.bus)
  validateDeterministicLookupTable(publicInput)
}

function validateMethod2HmacPublicInput (
  mode: BRC69Method2HmacMode,
  publicInput: BRC69Method2HmacPublicInput
): void {
  if (mode !== 'lookup') {
    throw new Error('BRC69 Method 2 whole-statement HMAC mode must be lookup')
  }
  validateMethod2LookupBatchedHmacSha256PublicInput(publicInput)
}

function buildMethod2HmacAir (
  mode: BRC69Method2HmacMode,
  publicInput: BRC69Method2HmacPublicInput
): ReturnType<typeof buildMethod2LookupBatchedHmacSha256Air> {
  if (mode !== 'lookup') {
    throw new Error('BRC69 Method 2 whole-statement HMAC mode must be lookup')
  }
  return buildMethod2LookupBatchedHmacSha256Air(publicInput)
}

function hmacTraceMode (
  trace: BRC69Method2HmacTrace
): BRC69Method2HmacMode {
  if (trace.publicInput.relation !== 'lookup-batched-hmac-sha256') {
    throw new Error('BRC69 Method 2 whole-statement HMAC trace must be lookup')
  }
  return 'lookup'
}

function hmacTraceWidth (mode: BRC69Method2HmacMode): number {
  if (mode !== 'lookup') {
    throw new Error('BRC69 Method 2 whole-statement HMAC mode must be lookup')
  }
  return METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.width
}

function hmacKeyByteOffset (mode: BRC69Method2HmacMode): number {
  if (mode !== 'lookup') {
    throw new Error('BRC69 Method 2 whole-statement HMAC mode must be lookup')
  }
  return METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.keyBytes
}

function multiTraceVerifierOptions (): StarkVerifierOptions {
  return {
    ...BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  }
}

function brc69Method2WholeStatementVerifierSegments (
  publicInput: BRC69Method2WholeStatementPublicInput,
  challengeDigest: number[]
): Array<{ name: string, air: ReturnType<typeof wrapBRC69SegmentBusAir> }> {
  const proofTraceLength = brc69Method2WholeStatementBusProofTraceLength(publicInput)
  return [
    {
      name: 'scalar',
      air: wrapBRC69SegmentBusAir({
        name: 'scalar',
        air: buildBRC69ProductionScalarAir(publicInput.scalar),
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
      air: wrapBRC69SegmentBusAir({
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
      air: wrapBRC69SegmentBusAir({
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
      air: wrapBRC69SegmentBusAir({
        name: 'compression',
        air: buildBRC69ProductionCompressionAir(publicInput.compression),
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
      air: wrapBRC69SegmentBusAir({
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
      air: wrapBRC69SegmentBusAir({
        name: 'bridge',
        air: buildBRC69Method2LinkBridgeAir(publicInput.bridge),
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
  scalarTrace: BRC69ProductionScalarTrace
  lookup: ProductionRadix11LookupPrototype
  ecTrace: ProductionEcTrace
  compressionTrace: BRC69ProductionCompressionTrace
  hmacTrace: BRC69Method2HmacTrace
  bridgeTrace: BRC69Method2LinkBridgeTrace
}): Record<string, ReturnType<typeof wrapBRC69SegmentBusTrace>> {
  const out: Partial<Record<string, ReturnType<typeof wrapBRC69SegmentBusTrace>>> = {}
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
    name: typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number],
    value: Omit<Parameters<typeof wrapBRC69SegmentBusTrace>[0], 'name' | 'challengeDigest' | 'start' | 'publicStart' | 'publicEnd'>
  ): void => {
    const segment = wrapBRC69SegmentBusTrace({
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
    air: buildBRC69ProductionScalarAir(input.scalarTrace),
    rows: input.scalarTrace.rows,
    emissions: scalarBusEmissions(input.scalarTrace.publicInput)
  })
  wrap('lookup', {
    air: buildLookupBusAir(input.lookup.trace.publicInput),
    rows: input.lookup.trace.rows,
    emissions: lookupBusEmissions(input.ecTrace.publicInput.radixWindowCount)
  })
  wrap('bridge', {
    air: buildBRC69Method2LinkBridgeAir(input.bridgeTrace),
    rows: input.bridgeTrace.rows,
    emissions: bridgeBusEmissions(input.bridgeTrace.publicInput)
  })
  wrap('ec', {
    air: buildProductionEcAir(input.ecTrace),
    rows: input.ecTrace.rows,
    emissions: ecBusEmissions(input.ecTrace.publicInput)
  })
  wrap('compression', {
    air: buildBRC69ProductionCompressionAir(input.compressionTrace),
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
    throw new Error('BRC69 Method 2 segment bus does not balance')
  }
  return out as Record<string, ReturnType<typeof wrapBRC69SegmentBusTrace>>
}

function brc69Method2WholeStatementBusProofTraceLength (
  publicInput: BRC69Method2WholeStatementPublicInput
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
  publicInput: BRC69ProductionScalarPublicInput
): BRC69SegmentBusEmission[] {
  return Array.from({ length: publicInput.windowCount }, (_, row) => ({
    row,
    kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC69_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
    values: current => [
      current[BRC69_PRODUCTION_SCALAR_LAYOUT.window],
      current[BRC69_PRODUCTION_SCALAR_LAYOUT.magnitude],
      current[BRC69_PRODUCTION_SCALAR_LAYOUT.isZero],
      current[BRC69_PRODUCTION_SCALAR_LAYOUT.sign]
    ]
  }))
}

function lookupBusEmissions (windowCount: number): BRC69SegmentBusEmission[] {
  return Array.from({ length: windowCount }, (_, step) => ({
    row: BRC69_RADIX11_TABLE_ROWS + step,
    kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC69_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
    values: current => tupleFromRow(current, LOOKUP_BUS_LAYOUT.left)
  }))
}

function bridgeBusEmissions (
  publicInput: BRC69Method2LinkBridgePublicInput
): BRC69SegmentBusEmission[] {
  const emissions: BRC69SegmentBusEmission[] = []
  for (let step = 0; step < publicInput.activeRows; step++) {
    emissions.push({
      row: step,
      kind: BRC69_SEGMENT_BUS_KIND_TARGET,
      tag: BRC69_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
      values: current => [
        current[BRC69_METHOD2_LINK_BRIDGE_LAYOUT.window],
        current[BRC69_METHOD2_LINK_BRIDGE_LAYOUT.magnitude],
        current[BRC69_METHOD2_LINK_BRIDGE_LAYOUT.isZero],
        current[BRC69_METHOD2_LINK_BRIDGE_LAYOUT.sign]
      ]
    }, {
      row: step,
      kind: BRC69_SEGMENT_BUS_KIND_TARGET,
      tag: BRC69_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
      values: current => tupleFromRow(
        current,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.tableTuple
      )
    }, {
      row: step,
      kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
      values: current => pointTupleFromLimbs(
        current,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedGInfinity,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedGX,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedGY
      )
    }, {
      row: step,
      kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      values: current => pointTupleFromLimbs(
        current,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedBInfinity,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedBX,
        BRC69_METHOD2_LINK_BRIDGE_LAYOUT.selectedBY
      )
    })
  }
  return emissions
}

function ecBusEmissions (
  publicInput: ProductionEcPublicInput
): BRC69SegmentBusEmission[] {
  const emissions: BRC69SegmentBusEmission[] = []
  const emittedSelected = new Set<string>()
  for (const item of publicInput.schedule) {
    const key = `${item.lane}:${item.step}`
    if (emittedSelected.has(key)) continue
    emittedSelected.add(key)
    emissions.push({
      row: item.row,
      kind: BRC69_SEGMENT_BUS_KIND_TARGET,
      tag: item.lane === 'G'
        ? BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT
        : BRC69_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
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
    kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC69_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
    values: current => compressionPointInputTupleFromEcRow(current)
  })
  return emissions
}

function compressionBusEmissions (): BRC69SegmentBusEmission[] {
  const emissions: BRC69SegmentBusEmission[] = [{
    row: 256,
    kind: BRC69_SEGMENT_BUS_KIND_TARGET,
    tag: BRC69_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
    values: current => [
      ...fieldLimbsFromRow(
        current,
        BRC69_PRODUCTION_COMPRESSION_LAYOUT.xLimbs
      ),
      current[BRC69_PRODUCTION_COMPRESSION_LAYOUT.yLimb0]
    ]
  }, {
    row: 256,
    kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
    tag: BRC69_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
    values: current => [
      0n,
      current[BRC69_PRODUCTION_COMPRESSION_LAYOUT.byte]
    ]
  }]
  for (let byteIndex = 1; byteIndex < 33; byteIndex++) {
    emissions.push({
      row: (32 - byteIndex) * 8 + 7,
      kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
      tag: BRC69_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
      values: current => [
        BigInt(byteIndex),
        current[BRC69_PRODUCTION_COMPRESSION_LAYOUT.byte]
      ]
    })
  }
  return emissions
}

function hmacBusEmissions (
  mode: BRC69Method2HmacMode
): BRC69SegmentBusEmission[] {
  const keyOffset = hmacKeyByteOffset(mode)
  return Array.from({ length: 33 }, (_, byteIndex) => ({
    row: 0,
    kind: BRC69_SEGMENT_BUS_KIND_TARGET,
    tag: BRC69_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
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
  return row.slice(offset, offset + BRC69_RADIX11_POINT_LIMBS)
}

function finalEcLaneRow (
  publicInput: ProductionEcPublicInput,
  lane: 'G' | 'B'
): number {
  const rows = publicInput.schedule.filter(row => row.lane === lane)
  const item = rows[rows.length - 1]
  if (item === undefined) throw new Error('BRC69 EC final row is missing')
  return item.row + item.rows - 1
}

function buildBRC69Method2SegmentBusCrossConstraintsFromPublicInput (
  publicInput: BRC69Method2WholeStatementPublicInput
): MultiTraceCrossConstraintInput[] {
  return buildBRC69Method2SegmentBusCrossConstraintsFromWidths({
    scalar: BRC69_PRODUCTION_SCALAR_LAYOUT.width,
    lookup: LOOKUP_BUS_LAYOUT.width,
    bridge: BRC69_METHOD2_LINK_BRIDGE_LAYOUT.width,
    ec: PRODUCTION_EC_LAYOUT.width,
    compression: BRC69_PRODUCTION_COMPRESSION_LAYOUT.width,
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

function buildBRC69Method2SegmentBusCrossConstraintsFromWidths (
  widths: Record<typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number], number>,
  selectorCounts: Record<typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number], number>
): MultiTraceCrossConstraintInput[] {
  const values: Array<{
    left: typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number]
    right: typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number]
    leftColumn: number
    rightColumn: number
  }> = []
  const degreeBound = BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree + 1
  for (let index = 0; index + 1 < BRC69_METHOD2_BUS_SEGMENT_ORDER.length; index++) {
    const left = BRC69_METHOD2_BUS_SEGMENT_ORDER[index]
    const right = BRC69_METHOD2_BUS_SEGMENT_ORDER[index + 1]
    const leftLayout = brc69SegmentBusWrappedLayout(
      widths[left],
      selectorCounts[left]
    )
    const rightLayout = brc69SegmentBusWrappedLayout(
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
    refs: BRC69_METHOD2_BUS_SEGMENT_ORDER.map(segment => ({
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
  bus: BRC69SegmentBusPublicInput
): void {
  for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    const segment = bus.segments[name]
    if (segment === undefined) {
      throw new Error(`BRC69 Method 2 multi-trace bus segment missing: ${name}`)
    }
    if (
      !Number.isSafeInteger(segment.emissionCount) ||
      segment.emissionCount < 0
    ) {
      throw new Error('BRC69 Method 2 multi-trace bus emission count is invalid')
    }
    if (
      segment.selectorCount !== undefined &&
      (
        !Number.isSafeInteger(segment.selectorCount) ||
        segment.selectorCount < 0 ||
        segment.selectorCount > segment.emissionCount
      )
    ) {
      throw new Error('BRC69 Method 2 multi-trace bus selector count is invalid')
    }
    assertBusEndpoint(segment.publicStart)
    assertBusEndpoint(segment.publicEnd)
    const expectsStart = name === 'scalar'
    const expectsEnd = name === 'hmac'
    if (!expectedOptionalZeroEndpoint(segment.publicStart, expectsStart)) {
      throw new Error('BRC69 Method 2 multi-trace bus public start mismatch')
    }
    if (!expectedOptionalZeroEndpoint(segment.publicEnd, expectsEnd)) {
      throw new Error('BRC69 Method 2 multi-trace bus public end mismatch')
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

function brc69Method2WholeStatementBusChallengeDigest (
  publicInput: Omit<BRC69Method2WholeStatementPublicInput, 'bus'> |
  BRC69Method2WholeStatementPublicInput
): number[] {
  return sha256(toArray(stableJson({
    id: 'BRC69_METHOD2_WHOLE_STATEMENT_BUS_CHALLENGE_V1',
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
  if (proof.transcriptDomain !== BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN) {
    return false
  }
  if (proof.segments.length !== 6) return false
  if ((proof.crossProofs ?? []).length !== 1) return false
  if ((proof.constantColumnProofs ?? []).length !== 0) return false
  return proof.segments.every(segment =>
    segment.proof.blowupFactor ===
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor &&
    segment.proof.numQueries ===
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries &&
    segment.proof.maxRemainderSize ===
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize &&
    segment.proof.maskDegree ===
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree &&
    segment.proof.cosetOffset ===
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset
  )
}

function validateDeterministicLookupTable (
  publicInput: BRC69Method2WholeStatementPublicInput
): void {
  const table = buildProductionRadix11PointPairTable(publicInput.baseB)
  const zeroTuple = new Array<bigint>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  if (
    publicInput.lookup.expectedLookupRequests !==
    publicInput.ec.radixWindowCount
  ) {
    throw new Error('BRC69 Method 2 multi-trace lookup request count mismatch')
  }
  if (publicInput.lookup.scheduleRows.length !== publicInput.lookup.traceLength) {
    throw new Error('BRC69 Method 2 multi-trace lookup schedule is incomplete')
  }
  for (let i = 0; i < table.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupSupply ||
      row.tag !== table[i].tag ||
      !vectorsEqual(row.publicTuple, table[i].values)
    ) {
      throw new Error('BRC69 Method 2 multi-trace lookup table mismatch')
    }
  }
  const requestEnd = BRC69_RADIX11_TABLE_ROWS + publicInput.ec.radixWindowCount
  for (let i = BRC69_RADIX11_TABLE_ROWS; i < requestEnd; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupRequest ||
      row.tag !== LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC69 Method 2 multi-trace lookup request mismatch')
    }
  }
  for (let i = requestEnd; i < publicInput.lookup.scheduleRows.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.inactive ||
      row.tag !== 0n ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC69 Method 2 multi-trace lookup inactive mismatch')
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
): BRC69Method2WholeStatementMetrics['segments'][string] {
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

export function brc69Method2WholeStatementDeterministicFixture ():
BRC69Method2WholeStatement {
  if (deterministicFixtureCache !== undefined) return deterministicFixtureCache
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  const invoice = Array.from('multi-trace fixture')
    .map(char => char.charCodeAt(0))
  const privateS = scalarMultiply(scalar, baseB)
  deterministicFixtureCache = buildBRC69Method2WholeStatement({
    scalar,
    baseB,
    invoice,
    linkage: hmacSha256(compressPoint(privateS), invoice)
  })
  return deterministicFixtureCache
}

let deterministicFixtureCache: BRC69Method2WholeStatement | undefined
