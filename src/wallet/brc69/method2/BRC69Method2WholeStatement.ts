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
import { AirDefinition } from '../stark/Air.js'
import {
  LookupBusPublicInput,
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_BASE_LAYOUT,
  LOOKUP_BUS_ACCUMULATOR_LAYOUT,
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
  LOOKUP_BUS_TUPLE_ARITY,
  buildLookupBusAccumulatorAir,
  buildLookupBusAccumulatorRows,
  buildLookupBusAir,
  deriveLookupBusChallenges,
  evaluateLookupBusAccumulatorTransition,
  lookupBusChallengeInputFromRoot
} from '../stark/LookupBus.js'
import {
  MultiTraceStarkDiagnostic,
  MultiTraceCommittedSegmentSummary,
  MultiTraceCrossConstraintInput,
  MultiTraceStarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  diagnoseMultiTraceStark,
  provePhasedMultiTraceStark,
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
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  Method2CompactHmacSha256PublicInput,
  Method2CompactHmacSha256Trace,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  validateMethod2CompactHmacSha256PublicInput
} from './Method2CompactHmacSha256.js'
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
  BRC69SegmentBusChallengeInput,
  BRC69SegmentBusEmission,
  BRC69SegmentBusPublicInput,
  assertBRC69SegmentBusBalanced,
  brc69SegmentBusChallengeInputFromRoot,
  buildBRC69SegmentBusAccumulatorAir,
  buildBRC69SegmentBusAccumulatorTrace,
  brc69SegmentBusWrappedLayout,
  deriveBRC69SegmentBusChallenges,
  evaluateBRC69SegmentBusAccumulatorTransition
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
  'BRC69_METHOD2_WHOLE_STATEMENT_AIR'
export const BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 192,
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

export type BRC69Method2HmacPublicInput =
  Method2CompactHmacSha256PublicInput

export type BRC69Method2HmacTrace =
  Method2CompactHmacSha256Trace

export interface BRC69Method2WholeStatementPublicInput {
  publicA: SecpPoint
  baseB: SecpPoint
  invoice: number[]
  linkage: number[]
  preprocessedTableRoot: number[]
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
  baseSegments: Record<string, {
    rows: FieldElement[][]
    air: AirDefinition
  }>
  baseSegment: {
    rows: FieldElement[][]
    air: AirDefinition
  }
  busProofTraceLength: number
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
  const publicA = scalarMultiply(input.scalar)
  const lookup = buildProductionRadix11LookupPrototype(input.scalar, input.baseB)
  const scalarTrace = buildBRC69ProductionScalarTrace(lookup)
  const radixEcTrace = buildProductionRadix11EcTrace(lookup, publicA)
  const ecTrace = buildProductionEcTrace(radixEcTrace)
  const privateS = productionEcTracePrivateS(ecTrace)
  const compressionTrace = buildBRC69ProductionCompressionTrace(privateS)
  const key = compressPoint(privateS)
  const linkage = input.linkage ?? hmacSha256(key, input.invoice)
  const hmacTrace = buildMethod2CompactHmacSha256Trace(
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
    scalar: scalarTrace.publicInput,
    lookup: lookup.trace.publicInput,
    ec: ecTrace.publicInput,
    compression: compressionTrace.publicInput,
    hmac: hmacTrace.publicInput,
    bridge: bridgeTrace.publicInput
  }
  const baseSegments = buildBasePaddedSegments({
    scalarTrace,
    lookup,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace
  })
  const proofTraceLength = brc69Method2WholeStatementTraceLengthFromTraces({
    scalarTrace,
    lookup,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace
  })
  const bus: BRC69SegmentBusPublicInput = {
    segments: buildBusPublicSegments(basePublicInput)
  }
  assertBRC69SegmentBusBalanced(bus)
  const publicInput = {
    ...basePublicInput,
    bus
  }
  validateBRC69Method2WholeStatementPublicInput(publicInput)
  const typedBaseSegments = Object.fromEntries(
    Object.entries(baseSegments).map(([name, segment]) => [
      name,
      { rows: segment.rows, air: segment.air }
    ])
  ) as Record<string, { rows: FieldElement[][], air: AirDefinition }>
  const baseSegment = buildBRC69Method2WholeStatementSegment(
    typedBaseSegments,
    'BRC69_METHOD2_WHOLE_STATEMENT_BASE_AIR'
  )
  return {
    publicInput,
    lookup,
    scalarTrace,
    radixEcTrace,
    ecTrace,
    compressionTrace,
    hmacTrace,
    bridgeTrace,
    baseSegments: typedBaseSegments,
    baseSegment,
    busProofTraceLength: proofTraceLength
  }
}

export function proveBRC69Method2WholeStatement (
  statement: BRC69Method2WholeStatement,
  options: StarkProverOptions = {}
): MultiTraceStarkProof {
  return provePhasedMultiTraceStark([
    {
      name: 'base',
      air: statement.baseSegment.air,
      traceRows: statement.baseSegment.rows
    }
  ], ({ committedSegments }) => {
    const base = committedSegmentByName(committedSegments, 'base')
    const phase = buildSecondPhaseBusProof(statement, base.traceRoot)
    return {
      segments: [{
        name: 'bus',
        air: phase.busSegment.air,
        traceRows: phase.busSegment.rows
      }],
      crossConstraints: phase.crossConstraints
    }
  }, {
    ...BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
    ...options,
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  })
}

export function verifyBRC69Method2WholeStatement (
  publicInput: BRC69Method2WholeStatementPublicInput,
  proof: MultiTraceStarkProof
): boolean {
  try {
    validateBRC69Method2WholeStatementPublicInput(publicInput)
    if (!multiTraceProofMeetsProofType1Shape(proof)) return false
    const baseRoot = proof.segments.find(segment => segment.name === 'base')
      ?.proof.traceRoot
    if (baseRoot === undefined) return false
    const verifier = brc69Method2WholeStatementVerifierSegments(
      publicInput,
      baseRoot
    )
    return verifyMultiTraceStark(
      verifier.segments,
      proof,
      multiTraceVerifierOptions(),
      verifier.crossConstraints)
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
    if (!multiTraceProofMeetsProofType1Shape(proof)) {
      return {
        ok: false,
        stage: 'proof-shape',
        detail: 'proof does not meet the BRC69 Method 2 proof type 1 shape'
      }
    }
    const baseRoot = proof.segments.find(segment => segment.name === 'base')
      ?.proof.traceRoot
    if (baseRoot === undefined) {
      return {
        ok: false,
        stage: 'proof-shape',
        detail: 'base proof segment is missing'
      }
    }
    const verifier = brc69Method2WholeStatementVerifierSegments(
      publicInput,
      baseRoot
    )
    const multiTrace = diagnoseMultiTraceStark(
      verifier.segments,
      proof,
      multiTraceVerifierOptions(),
      verifier.crossConstraints
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
    base: segmentMetrics(
      statement.baseSegment.rows.length,
      statement.baseSegment.air.traceWidth,
      proofSegmentBytes(proof, 'base')
    ),
    bus: segmentMetrics(
      statement.busProofTraceLength,
      buildBusAccumulatorWholeAir(
        statement.publicInput,
        zeroBusChallengeInput(statement.publicInput)
      ).traceWidth,
      proofSegmentBytes(proof, 'bus')
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
  validateMethod2CompactHmacSha256PublicInput(publicInput.hmac)
  if (!bytesEqual(
    publicInput.preprocessedTableRoot,
    productionRadix11TableRoot(buildProductionRadix11PointPairTable(
      publicInput.baseB
    ))
  )) {
    throw new Error('BRC69 Method 2 multi-trace preprocessed table root mismatch')
  }
  assertBRC69SegmentBusBalanced(publicInput.bus)
  validateBusContributions(publicInput.bus)
  validateDeterministicLookupTable(publicInput)
}

function assertCompactHmacTrace (
  trace: BRC69Method2HmacTrace
): void {
  validateMethod2CompactHmacSha256PublicInput(trace.publicInput)
  if (trace.layout.width !== METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width) {
    throw new Error('BRC69 Method 2 whole-statement HMAC trace must be compact')
  }
}

function buildBasePaddedSegments (input: {
  scalarTrace: BRC69ProductionScalarTrace
  lookup: ProductionRadix11LookupPrototype
  ecTrace: ProductionEcTrace
  compressionTrace: BRC69ProductionCompressionTrace
  hmacTrace: BRC69Method2HmacTrace
  bridgeTrace: BRC69Method2LinkBridgeTrace
}): Record<string, { rows: FieldElement[][], air: AirDefinition }> {
  const proofTraceLength = brc69Method2WholeStatementTraceLengthFromTraces(input)
  assertCompactHmacTrace(input.hmacTrace)
  return {
    scalar: padBaseSegment({
      air: buildBRC69ProductionScalarAir(input.scalarTrace),
      rows: input.scalarTrace.rows,
      traceLength: proofTraceLength,
      name: 'scalar'
    }),
    lookup: padBaseSegment({
      air: buildLookupBusAir(input.lookup.trace.publicInput),
      rows: input.lookup.trace.baseRows,
      traceLength: proofTraceLength,
      name: 'lookup'
    }),
    bridge: padBaseSegment({
      air: buildBRC69Method2LinkBridgeAir(input.bridgeTrace),
      rows: input.bridgeTrace.rows,
      traceLength: proofTraceLength,
      name: 'bridge'
    }),
    ec: padBaseSegment({
      air: buildProductionEcAir(input.ecTrace),
      rows: input.ecTrace.rows,
      traceLength: proofTraceLength,
      name: 'ec'
    }),
    compression: padBaseSegment({
      air: buildBRC69ProductionCompressionAir(input.compressionTrace),
      rows: input.compressionTrace.rows,
      traceLength: proofTraceLength,
      name: 'compression'
    }),
    hmac: padBaseSegment({
      air: buildMethod2CompactHmacSha256Air(input.hmacTrace.publicInput),
      rows: input.hmacTrace.rows,
      traceLength: proofTraceLength,
      name: 'hmac'
    })
  }
}

function padBaseSegment (input: {
  name: string
  air: AirDefinition
  rows: FieldElement[][]
  traceLength: number
}): { rows: FieldElement[][], air: AirDefinition } {
  const width = input.air.traceWidth
  const activeColumn = width
  const zero = new Array<FieldElement>(width).fill(0n)
  const rows = Array.from({ length: input.traceLength }, (_, rowIndex) => {
    const base = input.rows[rowIndex] ?? zero
    return [
      ...base,
      rowIndex + 1 < input.rows.length ? 1n : 0n
    ]
  })
  return {
    rows,
    air: {
      ...input.air,
      traceWidth: width + 1,
      publicInputDigest: sha256(toArray(stableJson({
        id: 'BRC69_METHOD2_PADDED_BASE_SEGMENT_AIR',
        name: input.name,
        originalDigest: input.air.publicInputDigest ?? [],
        baseTraceLength: input.rows.length,
        traceLength: input.traceLength
      }), 'utf8')),
      boundaryConstraints: input.air.boundaryConstraints.map(constraint => {
        if (constraint.row >= input.rows.length) {
          throw new Error('BRC69 Method 2 base boundary row is out of bounds')
        }
        return { ...constraint }
      }),
      fullBoundaryColumns: [
        ...(input.air.fullBoundaryColumns ?? []).map(column => {
          if (column.values.length > input.traceLength) {
            throw new Error('BRC69 Method 2 base full boundary column is too long')
          }
          return {
            column: column.column,
            values: [
              ...column.values,
              ...new Array<FieldElement>(
                input.traceLength - column.values.length
              ).fill(0n)
            ]
          }
        }),
        {
          column: activeColumn,
          values: Array.from({ length: input.traceLength }, (_, rowIndex) =>
            rowIndex + 1 < input.rows.length ? 1n : 0n
          )
        }
      ],
      evaluateTransition: (current, next, step) => {
        const currentBase = current.slice(0, width)
        const nextBase = next.slice(0, width)
        return input.air.evaluateTransition(currentBase, nextBase, step)
          .map(value => F.mul(current[activeColumn], value))
      }
    }
  }
}

function buildBusPublicSegments (
  publicInput: Omit<BRC69Method2WholeStatementPublicInput, 'bus'>
): BRC69SegmentBusPublicInput['segments'] {
  return Object.fromEntries(
    BRC69_METHOD2_BUS_SEGMENT_ORDER.map(name => {
      const emissions = busEmissionsForPublicInput(name, publicInput)
      return [name, {
        emissionCount: emissions.length,
        selectorCount: brc69SegmentBusSelectorRows(emissions).length,
        publicStart: name === 'scalar'
          ? { accumulator0: 0n, accumulator1: 0n }
          : undefined,
        publicEnd: name === 'hmac'
          ? { accumulator0: 0n, accumulator1: 0n }
          : undefined
      }]
    })
  )
}

function multiTraceVerifierOptions (): StarkVerifierOptions {
  return {
    ...BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  }
}

function brc69Method2WholeStatementVerifierSegments (
  publicInput: BRC69Method2WholeStatementPublicInput,
  baseTraceRoot: number[]
): {
    segments: Array<{ name: string, air: AirDefinition }>
    crossConstraints: MultiTraceCrossConstraintInput[]
  } {
  const baseSegments = buildBaseVerifierSegments(publicInput)
  const baseSegment = buildBRC69Method2WholeStatementSegment(
    baseSegments,
    'BRC69_METHOD2_WHOLE_STATEMENT_BASE_AIR'
  )
  const phase = buildSecondPhaseBusVerifier(publicInput, baseTraceRoot)
  return {
    segments: [
      { name: 'base', air: baseSegment.air },
      { name: 'bus', air: phase.busSegment.air }
    ],
    crossConstraints: phase.crossConstraints
  }
}

function buildSecondPhaseBusProof (
  statement: BRC69Method2WholeStatement,
  baseTraceRoot: number[]
): {
    busSegment: { rows: FieldElement[][], air: AirDefinition }
    crossConstraints: MultiTraceCrossConstraintInput[]
  } {
  const basePublicDigest = brc69Method2WholeStatementBasePublicInputDigest(
    statement.publicInput
  )
  const lookupChallengeInput = lookupBusChallengeInputFromRoot(
    statement.publicInput.lookup,
    baseTraceRoot,
    BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  )
  const segmentChallengeInput = brc69SegmentBusChallengeInputFromRoot(
    basePublicDigest,
    baseTraceRoot,
    BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  )
  const lookupChallenges = deriveLookupBusChallenges(lookupChallengeInput)
  const lookupAccumulatorRows = buildLookupBusAccumulatorRows(
    statement.lookup.trace.baseRows,
    lookupChallenges
  )
  const busParts = buildBusAccumulatorTraceParts({
    publicInput: statement.publicInput,
    baseRows: statement.baseSegments,
    challenges: deriveBRC69SegmentBusChallenges(segmentChallengeInput)
  })
  const busSegment = buildCombinedBusAccumulatorSegment(
    statement.publicInput,
    busParts,
    lookupAccumulatorRows,
    lookupChallengeInput
  )
  return {
    busSegment,
    crossConstraints: [
      lookupAccumulatorCrossConstraintForWhole(
        statement.publicInput,
        lookupChallengeInput
      ),
      segmentBusCrossConstraintForWhole(
        statement.publicInput,
        segmentChallengeInput
      )
    ]
  }
}

function buildSecondPhaseBusVerifier (
  publicInput: BRC69Method2WholeStatementPublicInput,
  baseTraceRoot: number[]
): {
    busSegment: { air: AirDefinition }
    crossConstraints: MultiTraceCrossConstraintInput[]
  } {
  const basePublicDigest = brc69Method2WholeStatementBasePublicInputDigest(
    publicInput
  )
  const lookupChallengeInput = lookupBusChallengeInputFromRoot(
    publicInput.lookup,
    baseTraceRoot,
    BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  )
  const segmentChallengeInput = brc69SegmentBusChallengeInputFromRoot(
    basePublicDigest,
    baseTraceRoot,
    BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  )
  return {
    busSegment: {
      air: buildCombinedBusAccumulatorAir(
        publicInput,
        lookupChallengeInput
      )
    },
    crossConstraints: [
      lookupAccumulatorCrossConstraintForWhole(publicInput, lookupChallengeInput),
      segmentBusCrossConstraintForWhole(publicInput, segmentChallengeInput)
    ]
  }
}

function buildBaseVerifierSegments (
  publicInput: BRC69Method2WholeStatementPublicInput
): Record<string, { rows: FieldElement[][], air: AirDefinition }> {
  const traceLength = brc69Method2WholeStatementBusProofTraceLength(publicInput)
  const emptyRows = (width: number, length: number): FieldElement[][] =>
    Array.from({ length }, () => new Array<FieldElement>(width).fill(0n))
  return {
    scalar: padBaseSegment({
      name: 'scalar',
      air: buildBRC69ProductionScalarAir(publicInput.scalar),
      rows: emptyRows(BRC69_PRODUCTION_SCALAR_LAYOUT.width, publicInput.scalar.traceLength),
      traceLength
    }),
    lookup: padBaseSegment({
      name: 'lookup',
      air: buildLookupBusAir(publicInput.lookup),
      rows: emptyRows(LOOKUP_BUS_BASE_LAYOUT.width, publicInput.lookup.traceLength),
      traceLength
    }),
    bridge: padBaseSegment({
      name: 'bridge',
      air: buildBRC69Method2LinkBridgeAir(publicInput.bridge),
      rows: emptyRows(BRC69_METHOD2_LINK_BRIDGE_LAYOUT.width, publicInput.bridge.traceLength),
      traceLength
    }),
    ec: padBaseSegment({
      name: 'ec',
      air: buildProductionEcAir(publicInput.ec),
      rows: emptyRows(PRODUCTION_EC_LAYOUT.width, publicInput.ec.paddedRows),
      traceLength
    }),
    compression: padBaseSegment({
      name: 'compression',
      air: buildBRC69ProductionCompressionAir(publicInput.compression),
      rows: emptyRows(BRC69_PRODUCTION_COMPRESSION_LAYOUT.width, publicInput.compression.traceLength),
      traceLength
    }),
    hmac: padBaseSegment({
      name: 'hmac',
      air: buildMethod2CompactHmacSha256Air(publicInput.hmac),
      rows: emptyRows(METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width, publicInput.hmac.traceLength),
      traceLength
    })
  }
}

function buildBusAccumulatorTraceParts (input: {
  publicInput: BRC69Method2WholeStatementPublicInput
  baseRows: Record<string, { rows: FieldElement[][], air: AirDefinition }>
  challenges: ReturnType<typeof deriveBRC69SegmentBusChallenges>
}): Record<string, ReturnType<typeof buildBRC69SegmentBusAccumulatorTrace>> {
  const out: Partial<Record<string, ReturnType<typeof buildBRC69SegmentBusAccumulatorTrace>>> = {}
  const traceLength = brc69Method2WholeStatementBusProofTraceLength(input.publicInput)
  let start = { accumulator0: 0n, accumulator1: 0n }
  for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    const segment = buildBRC69SegmentBusAccumulatorTrace({
      name,
      baseRows: input.baseRows[name].rows,
      proofTraceLength: traceLength,
      emissions: busEmissionsForPublicInput(name, input.publicInput),
      challenges: input.challenges,
      start,
      publicStart: input.publicInput.bus.segments[name].publicStart,
      publicEnd: input.publicInput.bus.segments[name].publicEnd
    })
    out[name] = segment
    start = segment.end
  }
  if (start.accumulator0 !== 0n || start.accumulator1 !== 0n) {
    throw new Error('BRC69 Method 2 segment bus does not balance')
  }
  return out as Record<string, ReturnType<typeof buildBRC69SegmentBusAccumulatorTrace>>
}

function buildCombinedBusAccumulatorSegment (
  publicInput: BRC69Method2WholeStatementPublicInput,
  busParts: Record<string, ReturnType<typeof buildBRC69SegmentBusAccumulatorTrace>>,
  lookupAccumulatorRows: FieldElement[][],
  lookupChallengeInput: ReturnType<typeof lookupBusChallengeInputFromRoot>
): { rows: FieldElement[][], air: AirDefinition } {
  const traceLength = lookupAccumulatorRows.length
  const rows = Array.from({ length: traceLength }, (_, rowIndex) => {
    const row = lookupAccumulatorRows[rowIndex].slice()
    for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
      row.push(...busParts[name].rows[rowIndex])
    }
    return row
  })
  return {
    rows,
    air: buildCombinedBusAccumulatorAir(publicInput, lookupChallengeInput)
  }
}

function buildCombinedBusAccumulatorAir (
  publicInput: BRC69Method2WholeStatementPublicInput,
  lookupChallengeInput: ReturnType<typeof lookupBusChallengeInputFromRoot>
): AirDefinition {
  const traceLength = brc69Method2WholeStatementBusProofTraceLength(publicInput)
  const parts = [
    {
      name: 'lookupAccumulator',
      air: buildLookupBusAccumulatorAir(publicInput.lookup, lookupChallengeInput)
    },
    ...BRC69_METHOD2_BUS_SEGMENT_ORDER.map(name => ({
      name,
      air: buildBRC69SegmentBusAccumulatorAir({
        name,
        traceLength,
        emissions: busEmissionsForPublicInput(name, publicInput),
        publicStart: publicInput.bus.segments[name].publicStart,
        publicEnd: publicInput.bus.segments[name].publicEnd
      })
    }))
  ]
  return combineAirParts(
    parts,
    'BRC69_METHOD2_WHOLE_STATEMENT_BUS_ACCUMULATOR_AIR',
    BRC69_METHOD2_BUS_SEGMENT_ORDER
  )
}

function buildBusAccumulatorWholeAir (
  publicInput: BRC69Method2WholeStatementPublicInput,
  challengeInput: ReturnType<typeof lookupBusChallengeInputFromRoot>
): AirDefinition {
  return buildCombinedBusAccumulatorAir(publicInput, challengeInput)
}

function combineAirParts (
  segments: Array<{ name: string, air: AirDefinition }>,
  digestId: string,
  endpointLinkedNames: readonly string[] = []
): AirDefinition {
  let offset = 0
  const parts = segments.map(segment => {
    const current = {
      ...segment,
      offset,
      end: offset + segment.air.traceWidth
    }
    offset = current.end
    return current
  })
  const boundaryConstraints = parts.flatMap(part =>
    part.air.boundaryConstraints.map(constraint => ({
      ...constraint,
      column: constraint.column + part.offset
    }))
  )
  const fullBoundaryColumns = parts.flatMap(part =>
    (part.air.fullBoundaryColumns ?? []).map(column => ({
      ...column,
      column: column.column + part.offset
    }))
  )
  const currentScratch = parts.map(part =>
    new Array<FieldElement>(part.air.traceWidth)
  )
  const nextScratch = parts.map(part =>
    new Array<FieldElement>(part.air.traceWidth)
  )
  return {
    traceWidth: offset,
    transitionDegree: Math.max(
      2,
      ...parts.map(part => part.air.transitionDegree ?? 2)
    ),
    publicInputDigest: sha256(toArray(stableJson({
      id: digestId,
      transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN,
      segments: parts.map(part => ({
        name: part.name,
        offset: part.offset,
        traceWidth: part.air.traceWidth,
        publicInputDigest: part.air.publicInputDigest ?? []
      }))
    }), 'utf8')),
    boundaryConstraints,
    fullBoundaryColumns,
    evaluateTransition: (current, next, step) => {
      const constraints: FieldElement[] = []
      for (let partIndex = 0; partIndex < parts.length; partIndex++) {
        const part = parts[partIndex]
        const currentPart = currentScratch[partIndex]
        const nextPart = nextScratch[partIndex]
        for (let column = 0; column < part.air.traceWidth; column++) {
          currentPart[column] = current[part.offset + column]
          nextPart[column] = next[part.offset + column]
        }
        constraints.push(...part.air.evaluateTransition(
          currentPart,
          nextPart,
          step
        ))
      }
      const linked = endpointLinkedNames
        .map(name => parts.find(part => part.name === name))
        .filter((part): part is typeof parts[number] => part !== undefined)
      appendSameTraceBusEndpointConstraints(constraints, current, linked)
      return constraints
    }
  }
}

function lookupAccumulatorCrossConstraintForWhole (
  publicInput: BRC69Method2WholeStatementPublicInput,
  challengeInput: ReturnType<typeof lookupBusChallengeInputFromRoot>
): MultiTraceCrossConstraintInput {
  const challenges = deriveLookupBusChallenges(challengeInput)
  const offsets = basePartOffsets(publicInput)
  const busOffsets = busPartOffsets(publicInput)
  return {
    name: 'lookup-accumulator',
    degreeBound: wholeStatementBusCrossDegreeBound(publicInput),
    refs: [
      { alias: 'base', segment: 'base' },
      { alias: 'bus', segment: 'bus' },
      { alias: 'nextBus', segment: 'bus', shift: 1 }
    ],
    evaluate: ({ rows }) => {
      const baseLookup = slicePart(rows.base, offsets.lookup)
      const acc = slicePart(rows.bus, busOffsets.lookupAccumulator)
      const nextAcc = slicePart(rows.nextBus, busOffsets.lookupAccumulator)
      return evaluateLookupBusAccumulatorTransition(
        baseLookup,
        acc,
        nextAcc,
        challenges
      )
    }
  }
}

function segmentBusCrossConstraintForWhole (
  publicInput: BRC69Method2WholeStatementPublicInput,
  challengeInput: BRC69SegmentBusChallengeInput
): MultiTraceCrossConstraintInput {
  const challenges = deriveBRC69SegmentBusChallenges(challengeInput)
  const baseOffsets = basePartOffsets(publicInput)
  const busOffsets = busPartOffsets(publicInput)
  return {
    name: 'segment-bus-accumulator',
    degreeBound: wholeStatementBusCrossDegreeBound(publicInput),
    refs: [
      { alias: 'base', segment: 'base' },
      { alias: 'bus', segment: 'bus' },
      { alias: 'nextBus', segment: 'bus', shift: 1 }
    ],
    evaluate: ({ rows }) => {
      const constraints: FieldElement[] = []
      for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
        const layout = brc69SegmentBusWrappedLayout(
          0,
          publicInput.bus.segments[name].selectorCount ??
            publicInput.bus.segments[name].emissionCount
        )
        constraints.push(...evaluateBRC69SegmentBusAccumulatorTransition({
          baseRow: slicePart(rows.base, baseOffsets[name]),
          accumulatorCurrent: slicePart(rows.bus, busOffsets[name]),
          accumulatorNext: slicePart(rows.nextBus, busOffsets[name]),
          emissions: busEmissionsForPublicInput(name, publicInput),
          layout,
          challenges
        }))
      }
      return constraints
    }
  }
}

function wholeStatementBusCrossDegreeBound (
  publicInput: BRC69Method2WholeStatementPublicInput
): number {
  const traceLength = brc69Method2WholeStatementBusProofTraceLength(publicInput)
  return Math.min(
    traceLength * 12,
    traceLength * BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor - 1
  )
}


function buildBRC69Method2WholeStatementSegment (
  busSegments: Record<string, { rows: FieldElement[][], air: AirDefinition }>,
  digestId: string
): { rows: FieldElement[][], air: AirDefinition } {
  const ordered = BRC69_METHOD2_BUS_SEGMENT_ORDER.map(name => {
    const segment = busSegments[name]
    if (segment === undefined) {
      throw new Error(`BRC69 Method 2 whole-statement segment missing: ${name}`)
    }
    return { name, ...segment }
  })
  const traceLength = ordered[0].rows.length
  if (!ordered.every(segment => segment.rows.length === traceLength)) {
    throw new Error('BRC69 Method 2 whole-statement segments must share a trace length')
  }
  const rows = Array.from({ length: traceLength }, (_, rowIndex) => {
    const row: FieldElement[] = []
    for (const segment of ordered) {
      row.push(...segment.rows[rowIndex])
    }
    return row
  })
  return {
    rows,
    air: buildBRC69Method2WholeStatementAir(ordered.map(segment => ({
      name: segment.name,
      air: segment.air
    })), digestId, false)
  }
}

function buildBRC69Method2WholeStatementAir (
  segments: Array<{
    name: typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number]
    air: AirDefinition
  }>,
  digestId: string,
  linkBusEndpoints: boolean
): AirDefinition {
  const orderedNames = segments.map(segment => segment.name)
  if (orderedNames.join(',') !== BRC69_METHOD2_BUS_SEGMENT_ORDER.join(',')) {
    throw new Error('BRC69 Method 2 whole-statement segment order mismatch')
  }
  let offset = 0
  const parts = segments.map(segment => {
    const current = {
      ...segment,
      offset,
      end: offset + segment.air.traceWidth
    }
    offset = current.end
    return current
  })
  const boundaryConstraints = parts.flatMap(part =>
    part.air.boundaryConstraints.map(constraint => ({
      ...constraint,
      column: constraint.column + part.offset
    }))
  )
  const fullBoundaryColumns = parts.flatMap(part =>
    (part.air.fullBoundaryColumns ?? []).map(column => ({
      ...column,
      column: column.column + part.offset
    }))
  )
  const unmaskedColumns = parts.flatMap(part =>
    (part.air.unmaskedColumns ?? []).map(column => column + part.offset)
  )
  const currentScratch = parts.map(part =>
    new Array<FieldElement>(part.air.traceWidth)
  )
  const nextScratch = parts.map(part =>
    new Array<FieldElement>(part.air.traceWidth)
  )
  return {
    traceWidth: offset,
    transitionDegree: Math.max(
      2,
      ...parts.map(part => part.air.transitionDegree ?? 2)
    ),
    publicInputDigest: sha256(toArray(stableJson({
      id: digestId,
      transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN,
      segments: parts.map(part => ({
        name: part.name,
        offset: part.offset,
        traceWidth: part.air.traceWidth,
        publicInputDigest: part.air.publicInputDigest ?? []
      }))
    }), 'utf8')),
    boundaryConstraints,
    fullBoundaryColumns,
    unmaskedColumns,
    evaluateTransition: (current, next, step) => {
      const constraints: FieldElement[] = []
      for (let partIndex = 0; partIndex < parts.length; partIndex++) {
        const part = parts[partIndex]
        const currentPart = currentScratch[partIndex]
        const nextPart = nextScratch[partIndex]
        for (let column = 0; column < part.air.traceWidth; column++) {
          currentPart[column] = current[part.offset + column]
          nextPart[column] = next[part.offset + column]
        }
        constraints.push(...part.air.evaluateTransition(
          currentPart,
          nextPart,
          step
        ))
      }
      if (linkBusEndpoints) {
        appendSameTraceBusEndpointConstraints(constraints, current, parts)
      }
      return constraints
    }
  }
}

function appendSameTraceBusEndpointConstraints (
  constraints: FieldElement[],
  row: FieldElement[],
  parts: Array<{ offset: number, air: AirDefinition }>
): void {
  for (let index = 0; index + 1 < parts.length; index++) {
    const left = parts[index]
    const right = parts[index + 1]
    constraints.push(F.sub(
      row[left.offset + left.air.traceWidth - 5],
      row[right.offset + right.air.traceWidth - 7]
    ))
    constraints.push(F.sub(
      row[left.offset + left.air.traceWidth - 4],
      row[right.offset + right.air.traceWidth - 6]
    ))
  }
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

function brc69Method2WholeStatementTraceLengthFromTraces (input: {
  scalarTrace: BRC69ProductionScalarTrace
  lookup: ProductionRadix11LookupPrototype
  ecTrace: ProductionEcTrace
  compressionTrace: BRC69ProductionCompressionTrace
  hmacTrace: BRC69Method2HmacTrace
  bridgeTrace: BRC69Method2LinkBridgeTrace
}): number {
  return Math.max(
    input.scalarTrace.rows.length,
    input.lookup.trace.baseRows.length,
    input.ecTrace.rows.length,
    input.compressionTrace.rows.length,
    input.hmacTrace.rows.length,
    input.bridgeTrace.rows.length
  )
}

function busEmissionsForPublicInput (
  name: typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number],
  publicInput: Omit<BRC69Method2WholeStatementPublicInput, 'bus'> |
    BRC69Method2WholeStatementPublicInput
): BRC69SegmentBusEmission[] {
  if (name === 'scalar') return scalarBusEmissions(publicInput.scalar)
  if (name === 'lookup') return lookupBusEmissions(publicInput.ec.radixWindowCount)
  if (name === 'bridge') return bridgeBusEmissions(publicInput.bridge)
  if (name === 'ec') return ecBusEmissions(publicInput.ec)
  if (name === 'compression') return compressionBusEmissions()
  return hmacBusEmissions()
}

function brc69SegmentBusSelectorRows (
  emissions: BRC69SegmentBusEmission[]
): number[] {
  const seen = new Set<number>()
  const rows: number[] = []
  for (const emission of emissions) {
    if (seen.has(emission.row)) continue
    seen.add(emission.row)
    rows.push(emission.row)
  }
  return rows
}

function basePartOffsets (
  publicInput: BRC69Method2WholeStatementPublicInput
): Record<typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number], {
    offset: number
    width: number
  }> {
  const widths: Record<typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number], number> = {
    scalar: BRC69_PRODUCTION_SCALAR_LAYOUT.width + 1,
    lookup: LOOKUP_BUS_BASE_LAYOUT.width + 1,
    bridge: BRC69_METHOD2_LINK_BRIDGE_LAYOUT.width + 1,
    ec: PRODUCTION_EC_LAYOUT.width + 1,
    compression: BRC69_PRODUCTION_COMPRESSION_LAYOUT.width + 1,
    hmac: METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width + 1
  }
  void publicInput
  let offset = 0
  const out = {} as Record<typeof BRC69_METHOD2_BUS_SEGMENT_ORDER[number], {
    offset: number
    width: number
  }>
  for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    out[name] = { offset, width: widths[name] }
    offset += widths[name]
  }
  return out
}

function busPartOffsets (
  publicInput: BRC69Method2WholeStatementPublicInput
): Record<string, { offset: number, width: number }> {
  let offset = LOOKUP_BUS_ACCUMULATOR_LAYOUT.width
  const out: Record<string, { offset: number, width: number }> = {
    lookupAccumulator: {
      offset: 0,
      width: LOOKUP_BUS_ACCUMULATOR_LAYOUT.width
    }
  }
  for (const name of BRC69_METHOD2_BUS_SEGMENT_ORDER) {
    const width = brc69SegmentBusWrappedLayout(
      0,
      publicInput.bus.segments[name].selectorCount ??
        publicInput.bus.segments[name].emissionCount
    ).width
    out[name] = { offset, width }
    offset += width
  }
  return out
}

function slicePart (
  row: FieldElement[],
  part: { offset: number, width: number }
): FieldElement[] {
  return row.slice(part.offset, part.offset + part.width)
}

function zeroBusChallengeInput (
  publicInput: BRC69Method2WholeStatementPublicInput
): ReturnType<typeof lookupBusChallengeInputFromRoot> {
  return lookupBusChallengeInputFromRoot(
    publicInput.lookup,
    new Array(32).fill(0),
    BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  )
}

function committedSegmentByName (
  segments: MultiTraceCommittedSegmentSummary[],
  name: string
): MultiTraceCommittedSegmentSummary {
  const segment = segments.find(item => item.name === name)
  if (segment === undefined) {
    throw new Error(`BRC69 Method 2 committed segment is missing: ${name}`)
  }
  return segment
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

function hmacBusEmissions (): BRC69SegmentBusEmission[] {
  const keyOffset = METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes
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

function brc69Method2WholeStatementBasePublicInputDigest (
  publicInput: Omit<BRC69Method2WholeStatementPublicInput, 'bus'> |
  BRC69Method2WholeStatementPublicInput
): number[] {
  return sha256(toArray(stableJson({
    id: 'BRC69_METHOD2_WHOLE_STATEMENT_BASE_PUBLIC_INPUT',
    publicA: publicInput.publicA,
    baseB: publicInput.baseB,
    invoice: publicInput.invoice,
    linkage: publicInput.linkage,
    preprocessedTableRoot: publicInput.preprocessedTableRoot,
    scalar: publicInput.scalar,
    lookup: publicInput.lookup,
    ec: publicInput.ec,
    compression: publicInput.compression,
    hmac: publicInput.hmac,
    bridge: publicInput.bridge
  }), 'utf8'))
}

function multiTraceProofMeetsProofType1Shape (
  proof: MultiTraceStarkProof
): boolean {
  if (proof.transcriptDomain !== BRC69_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN) {
    return false
  }
  if (
    proof.segments.length !== 2 ||
    proof.segments[0].name !== 'base' ||
    proof.segments[1].name !== 'bus'
  ) {
    return false
  }
  if ((proof.crossProofs ?? []).length !== 2) return false
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
