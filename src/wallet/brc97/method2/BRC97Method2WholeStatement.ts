import { sha256 } from '../../../primitives/Hash.js'
import { toArray } from '../../../primitives/utils.js'
import {
  SECP256K1_P,
  compressPoint,
  hmacSha256,
  isOnCurve,
  scalarMultiply
} from '../circuit/index.js'
import { SecpPoint } from '../circuit/Types.js'
import { AirDefinition } from '../stark/Air.js'
import {
  BRC97_RADIX11_POINT_LIMBS,
  BRC97_RADIX11_TABLE_ROWS,
  ProductionRadix11LookupPrototype,
  buildProductionRadix11LookupPrototype,
  buildProductionRadix11PointPairTable,
  productionRadix11TableRoot
} from '../stark/DualBaseRadix11Metrics.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
  LOOKUP_BUS_TUPLE_ARITY,
  LookupBusPublicInput,
  buildLookupBusAir,
  compressLookupBusTuple
} from '../stark/LookupBus.js'
import {
  PRODUCTION_EC_LAYOUT,
  ProductionEcPublicInput,
  ProductionEcTrace,
  buildProductionEcAir,
  buildProductionEcTrace,
  productionEcTracePrivateS
} from '../stark/ProductionEcAir.js'
import { buildProductionRadix11EcTrace } from '../stark/ProductionRadix11Ec.js'
import { secp256k1FieldToLimbs52 } from '../stark/Secp256k1FieldOps.js'
import {
  StarkProof,
  StarkProverOptions,
  StarkVerifierOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import { FiatShamirTranscript } from '../stark/Transcript.js'
import {
  BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
  BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT,
  BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
  BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
  BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
  BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT
} from './BRC97ProductionBus.js'
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
  buildMethod2CompactHmacSha256Trace
} from './Method2CompactHmacSha256.js'
import { METHOD2_HMAC_KEY_SIZE } from './Method2Hmac.js'

export const BRC97_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_WHOLE_STATEMENT_AIR_V1'
export const BRC97_METHOD2_WHOLE_STATEMENT_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_WHOLE_STATEMENT_PUBLIC_INPUT_V1'
export const BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS = {
  blowupFactor: 16,
  numQueries: 48,
  maxRemainderSize: 16,
  maskDegree: 2,
  cosetOffset: 7n,
  transcriptDomain: BRC97_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
} as const

const EQ_LANES = METHOD2_HMAC_KEY_SIZE
const EQ_SOURCE = 1n
const EQ_TARGET = 2n
const EQ_BIND_NONE = 0n
const EQ_BIND_SCALAR_DIGIT = 1n
const EQ_BIND_BRIDGE_SCALAR_DIGIT = 2n
const EQ_BIND_LOOKUP_POINT_PAIR = 3n
const EQ_BIND_BRIDGE_POINT_PAIR = 4n
const EQ_BIND_BRIDGE_SELECTED_G = 5n
const EQ_BIND_BRIDGE_SELECTED_B = 6n
const EQ_BIND_EC_SELECTED_G = 7n
const EQ_BIND_EC_SELECTED_B = 8n
const EQ_BIND_EC_FINAL_S_COMPRESSION_INPUT = 9n
const EQ_BIND_COMPRESSION_S_INPUT = 10n
const EQ_BIND_COMPRESSION_BYTE = 11n
const EQ_BIND_HMAC_KEY_BYTE = 12n
const EQ_BIND_VALUES = [
  EQ_BIND_NONE,
  EQ_BIND_SCALAR_DIGIT,
  EQ_BIND_BRIDGE_SCALAR_DIGIT,
  EQ_BIND_LOOKUP_POINT_PAIR,
  EQ_BIND_BRIDGE_POINT_PAIR,
  EQ_BIND_BRIDGE_SELECTED_G,
  EQ_BIND_BRIDGE_SELECTED_B,
  EQ_BIND_EC_SELECTED_G,
  EQ_BIND_EC_SELECTED_B,
  EQ_BIND_EC_FINAL_S_COMPRESSION_INPUT,
  EQ_BIND_COMPRESSION_S_INPUT,
  EQ_BIND_COMPRESSION_BYTE,
  EQ_BIND_HMAC_KEY_BYTE
]
const EQ_KIND_VALUES = [0n, EQ_SOURCE, EQ_TARGET]
const FIELD_RADIX = 1n << 52n
const P_52 = bigintToLimbs(SECP256K1_P, BRC97_RADIX11_POINT_LIMBS, FIELD_RADIX)

const TAG_S_COMPRESSION_INPUT =
  BRC97_PRODUCTION_BUS_TAG_EC_PRIVATE_S_POINT

export interface BRC97Method2WholeStatementInput {
  scalar: bigint
  baseB: SecpPoint
  invoice: number[]
  linkage?: number[]
}

export interface BRC97Method2WholeStatementRegion {
  start: number
  length: number
}

export interface BRC97Method2WholeStatementRegions {
  scalar: BRC97Method2WholeStatementRegion
  lookup: BRC97Method2WholeStatementRegion
  bridge: BRC97Method2WholeStatementRegion
  ec: BRC97Method2WholeStatementRegion
  compression: BRC97Method2WholeStatementRegion
  hmac: BRC97Method2WholeStatementRegion
}

export interface BRC97Method2WholeStatementEqualityLaneSchedule {
  kind: FieldElement
  tag: FieldElement
  bindType: FieldElement
}

export interface BRC97Method2WholeStatementEqualityScheduleRow {
  lanes: BRC97Method2WholeStatementEqualityLaneSchedule[]
}

export interface BRC97Method2WholeStatementPublicInput {
  publicA: SecpPoint
  baseB: SecpPoint
  invoice: number[]
  linkage: number[]
  traceLength: number
  regions: BRC97Method2WholeStatementRegions
  scalar: BRC97ProductionScalarPublicInput
  lookup: LookupBusPublicInput
  ec: ProductionEcPublicInput
  compression: BRC97ProductionCompressionPublicInput
  hmac: Method2CompactHmacSha256PublicInput
}

export interface BRC97Method2WholeStatementLayout {
  scalar: number
  lookup: number
  bridge: number
  ec: number
  compression: number
  hmac: number
  bridgeActive: number
  bridgeWindow: number
  bridgeMagnitude: number
  bridgeIsZero: number
  bridgeSign: number
  bridgePointPair: number
  bridgeSelectedG: number
  bridgeSelectedB: number
  bridgeCarryG: number
  bridgeCarryB: number
  scalarNext: number
  lookupNext: number
  ecNext: number
  compressionNext: number
  hmacNext: number
  eqAccumulator0: number
  eqAccumulator1: number
  eqLanes: number
  width: number
}

export interface BRC97Method2WholeStatementTrace {
  rows: FieldElement[][]
  layout: BRC97Method2WholeStatementLayout
  publicInput: BRC97Method2WholeStatementPublicInput
  scalarTrace: BRC97ProductionScalarTrace
  lookup: ProductionRadix11LookupPrototype
  ecTrace: ProductionEcTrace
  compressionTrace: BRC97ProductionCompressionTrace
  hmacTrace: Method2CompactHmacSha256Trace
  equalitySchedule: BRC97Method2WholeStatementEqualityScheduleRow[]
}

export interface BRC97Method2WholeStatementMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  proofBytes?: number
}

interface WholeEqualityChallenges {
  alpha0: FieldElement
  alpha1: FieldElement
}

export function buildBRC97Method2WholeStatementTrace (
  input: BRC97Method2WholeStatementInput
): BRC97Method2WholeStatementTrace {
  const publicA = scalarMultiply(input.scalar)
  const lookup = buildProductionRadix11LookupPrototype(input.scalar, input.baseB)
  const scalarTrace = buildBRC97ProductionScalarTrace(lookup)
  const nativeEc = buildProductionRadix11EcTrace(lookup, publicA)
  const ecTrace = buildProductionEcTrace(nativeEc)
  const privateS = productionEcTracePrivateS(ecTrace)
  const compressionTrace = buildBRC97ProductionCompressionTrace(privateS)
  const key = compressPoint(privateS)
  const linkage = input.linkage ?? hmacSha256(key, input.invoice)
  const hmacTrace = buildMethod2CompactHmacSha256Trace(
    key,
    input.invoice,
    linkage
  )
  const layout = wholeLayout()
  const regions = wholeRegions({
    scalar: scalarTrace.rows.length,
    lookup: lookup.trace.rows.length,
    bridge: lookup.digits.length,
    ec: ecTrace.rows.length,
    compression: compressionTrace.rows.length,
    hmac: hmacTrace.rows.length
  })
  const traceLength = nextPowerOfTwo(
    regions.hmac.start + regions.hmac.length + 1
  )
  const rows = emptyRows(traceLength, layout.width)
  copyRows(rows, regions.scalar.start, layout.scalar, scalarTrace.rows)
  copyRows(rows, regions.lookup.start, layout.lookup, lookup.trace.rows)
  copyRows(rows, regions.ec.start, layout.ec, ecTrace.rows)
  copyRows(
    rows,
    regions.compression.start,
    layout.compression,
    compressionTrace.rows
  )
  copyRows(rows, regions.hmac.start, layout.hmac, hmacTrace.rows)
  writeBridgeRows(rows, layout, regions, lookup)
  writeRegionTransitionSelectors(rows, layout, regions)

  const equalitySchedule = wholeEqualitySchedule(
    traceLength,
    regions,
    lookup.digits.length,
    ecTrace.publicInput.schedule
  )
  const publicInput: BRC97Method2WholeStatementPublicInput = {
    publicA,
    baseB: input.baseB,
    invoice: input.invoice.slice(),
    linkage: linkage.slice(),
    traceLength,
    regions,
    scalar: scalarTrace.publicInput,
    lookup: lookup.trace.publicInput,
    ec: ecTrace.publicInput,
    compression: compressionTrace.publicInput,
    hmac: hmacTrace.publicInput
  }
  writeEqualityBusRows(rows, layout, publicInput, equalitySchedule)
  validateBRC97Method2WholeStatementPublicInput(publicInput)
  return {
    rows,
    layout,
    publicInput,
    scalarTrace,
    lookup,
    ecTrace,
    compressionTrace,
    hmacTrace,
    equalitySchedule
  }
}

export function buildBRC97Method2WholeStatementAir (
  input: BRC97Method2WholeStatementTrace | BRC97Method2WholeStatementPublicInput,
  publicInputDigest = brc97Method2WholeStatementPublicInputDigest(
    'rows' in input ? input.publicInput : input
  )
): AirDefinition {
  const publicInput = 'rows' in input ? input.publicInput : input
  validateBRC97Method2WholeStatementPublicInput(publicInput)
  const layout = wholeLayout()
  const challenges = wholeEqualityChallenges(publicInputDigest)
  const scalarAir = buildBRC97ProductionScalarAir(publicInput.scalar)
  const lookupAir = buildLookupBusAir(publicInput.lookup)
  const ecAir = buildProductionEcAir(publicInput.ec)
  const compressionAir = buildBRC97ProductionCompressionAir(publicInput.compression)
  const hmacAir = buildMethod2CompactHmacSha256Air(publicInput.hmac)
  const equalitySchedule = wholeEqualitySchedule(
    publicInput.traceLength,
    publicInput.regions,
    publicInput.ec.radixWindowCount,
    publicInput.ec.schedule
  )
  return {
    traceWidth: layout.width,
    transitionDegree: 32,
    publicInputDigest,
    boundaryConstraints: [
      ...translateBoundaryConstraints(
        scalarAir,
        publicInput.regions.scalar,
        layout.scalar
      ),
      ...translateBoundaryConstraints(
        lookupAir,
        publicInput.regions.lookup,
        layout.lookup
      ),
      ...translateBoundaryConstraints(ecAir, publicInput.regions.ec, layout.ec),
      ...translateBoundaryConstraints(
        compressionAir,
        publicInput.regions.compression,
        layout.compression
      ),
      ...translateBoundaryConstraints(
        hmacAir,
        publicInput.regions.hmac,
        layout.hmac
      ),
      { column: layout.eqAccumulator0, row: 0, value: 0n },
      { column: layout.eqAccumulator1, row: 0, value: 0n },
      {
        column: layout.eqAccumulator0,
        row: publicInput.traceLength - 1,
        value: 0n
      },
      {
        column: layout.eqAccumulator1,
        row: publicInput.traceLength - 1,
        value: 0n
      }
    ],
    fullBoundaryColumns: [
      ...translateFullBoundaryColumns(
        scalarAir,
        publicInput.regions.scalar,
        layout.scalar,
        publicInput.traceLength
      ),
      ...translateFullBoundaryColumns(
        lookupAir,
        publicInput.regions.lookup,
        layout.lookup,
        publicInput.traceLength
      ),
      ...translateFullBoundaryColumns(
        ecAir,
        publicInput.regions.ec,
        layout.ec,
        publicInput.traceLength
      ),
      ...translateFullBoundaryColumns(
        compressionAir,
        publicInput.regions.compression,
        layout.compression,
        publicInput.traceLength
      ),
      ...translateFullBoundaryColumns(
        hmacAir,
        publicInput.regions.hmac,
        layout.hmac,
        publicInput.traceLength
      ),
      ...wholeEqualityFullBoundaryColumns(publicInput, layout, equalitySchedule)
    ],
    evaluateTransition: (current, next) => [
      ...gateConstraints(
        scalarAir.evaluateTransition(
          rowSlice(current, layout.scalar, scalarAir.traceWidth),
          rowSlice(next, layout.scalar, scalarAir.traceWidth),
          0
        ),
        regionTransitionSelector(current, layout, 'scalar')
      ),
      ...gateConstraints(
        lookupAir.evaluateTransition(
          rowSlice(current, layout.lookup, lookupAir.traceWidth),
          rowSlice(next, layout.lookup, lookupAir.traceWidth),
          0
        ),
        regionTransitionSelector(current, layout, 'lookup')
      ),
      ...evaluateBridgeTransition(current, layout),
      ...gateConstraints(
        ecAir.evaluateTransition(
          rowSlice(current, layout.ec, ecAir.traceWidth),
          rowSlice(next, layout.ec, ecAir.traceWidth),
          0
        ),
        regionTransitionSelector(current, layout, 'ec')
      ),
      ...gateConstraints(
        compressionAir.evaluateTransition(
          rowSlice(current, layout.compression, compressionAir.traceWidth),
          rowSlice(next, layout.compression, compressionAir.traceWidth),
          0
        ),
        regionTransitionSelector(current, layout, 'compression')
      ),
      ...gateConstraints(
        hmacAir.evaluateTransition(
          rowSlice(current, layout.hmac, hmacAir.traceWidth),
          rowSlice(next, layout.hmac, hmacAir.traceWidth),
          0
        ),
        regionTransitionSelector(current, layout, 'hmac')
      ),
      ...evaluateWholeEqualityTransition(current, next, layout, challenges)
    ]
  }
}

export function proveBRC97Method2WholeStatement (
  trace: BRC97Method2WholeStatementTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildBRC97Method2WholeStatementAir(trace)
  return proveStark(air, trace.rows, {
    ...BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: BRC97_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  })
}

export function verifyBRC97Method2WholeStatement (
  publicInput: BRC97Method2WholeStatementPublicInput,
  proof: StarkProof
): boolean {
  try {
    if (!wholeProofMeetsProductionProfile(proof)) return false
    const publicInputDigest =
      brc97Method2WholeStatementPublicInputDigest(publicInput)
    if (!bytesEqual(proof.publicInputDigest, publicInputDigest)) return false
    const air = buildBRC97Method2WholeStatementAir(
      publicInput,
      publicInputDigest
    )
    return verifyStark(air, proof, wholeVerifierOptions(proof))
  } catch {
    return false
  }
}

export function brc97Method2WholeStatementMetrics (
  trace: BRC97Method2WholeStatementTrace,
  proof?: StarkProof,
  blowupFactor: number = 16
): BRC97Method2WholeStatementMetrics {
  return {
    activeRows:
      trace.publicInput.regions.scalar.length +
      trace.publicInput.regions.lookup.length +
      trace.publicInput.regions.bridge.length +
      trace.publicInput.regions.ec.length +
      trace.publicInput.regions.compression.length +
      trace.publicInput.regions.hmac.length,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    ldeRows: trace.publicInput.traceLength * blowupFactor,
    ldeCells: trace.publicInput.traceLength * trace.layout.width * blowupFactor,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function brc97Method2WholeStatementPublicInputDigest (
  publicInput: BRC97Method2WholeStatementPublicInput
): number[] {
  validateBRC97Method2WholeStatementPublicInput(publicInput)
  return sha256(toArray(stableJson({
    id: BRC97_METHOD2_WHOLE_STATEMENT_PUBLIC_INPUT_ID,
    publicInput: wholePublicInputDigestPayload(publicInput)
  }), 'utf8'))
}

export function validateBRC97Method2WholeStatementPublicInput (
  publicInput: BRC97Method2WholeStatementPublicInput
): void {
  if (publicInput.publicA.infinity === true || !isOnCurve(publicInput.publicA)) {
    throw new Error('BRC97 whole statement public A is invalid')
  }
  if (publicInput.baseB.infinity === true || !isOnCurve(publicInput.baseB)) {
    throw new Error('BRC97 whole statement public B is invalid')
  }
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, 32, 'linkage')
  if (!pointsEqual(publicInput.ec.publicA, publicInput.publicA)) {
    throw new Error('BRC97 whole statement EC public A mismatch')
  }
  if (!pointsEqual(publicInput.ec.baseB, publicInput.baseB)) {
    throw new Error('BRC97 whole statement EC public B mismatch')
  }
  if (!bytesEqual(publicInput.hmac.invoice, publicInput.invoice)) {
    throw new Error('BRC97 whole statement invoice mismatch')
  }
  if (!bytesEqual(publicInput.hmac.linkage, publicInput.linkage)) {
    throw new Error('BRC97 whole statement linkage mismatch')
  }
  validateWholeRegions(publicInput)
  validateDeterministicLookupTable(publicInput)
}

function wholeLayout (): BRC97Method2WholeStatementLayout {
  const scalar = 0
  const lookup = scalar + BRC97_PRODUCTION_SCALAR_LAYOUT.width
  const ec = lookup + LOOKUP_BUS_LAYOUT.width
  const compression = ec + PRODUCTION_EC_LAYOUT.width
  const hmac = compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.width
  const bridge = hmac + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
  const bridgeActive = bridge
  const bridgeWindow = bridgeActive + 1
  const bridgeMagnitude = bridgeWindow + 1
  const bridgeIsZero = bridgeMagnitude + 1
  const bridgeSign = bridgeIsZero + 1
  const bridgePointPair = bridgeSign + 1
  const bridgeSelectedG = bridgePointPair + LOOKUP_BUS_TUPLE_ARITY
  const bridgeSelectedB = bridgeSelectedG + 1 + BRC97_RADIX11_POINT_LIMBS * 2
  const bridgeCarryG = bridgeSelectedB + 1 + BRC97_RADIX11_POINT_LIMBS * 2
  const bridgeCarryB = bridgeCarryG + BRC97_RADIX11_POINT_LIMBS
  const scalarNext = bridgeCarryB + BRC97_RADIX11_POINT_LIMBS
  const lookupNext = scalarNext + 1
  const ecNext = lookupNext + 1
  const compressionNext = ecNext + 1
  const hmacNext = compressionNext + 1
  const eqAccumulator0 = hmacNext + 1
  const eqAccumulator1 = eqAccumulator0 + 1
  const eqLanes = eqAccumulator1 + 1
  return {
    scalar,
    lookup,
    bridge,
    ec,
    compression,
    hmac,
    bridgeActive,
    bridgeWindow,
    bridgeMagnitude,
    bridgeIsZero,
    bridgeSign,
    bridgePointPair,
    bridgeSelectedG,
    bridgeSelectedB,
    bridgeCarryG,
    bridgeCarryB,
    scalarNext,
    lookupNext,
    ecNext,
    compressionNext,
    hmacNext,
    eqAccumulator0,
    eqAccumulator1,
    eqLanes,
    width: eqLanes + EQ_LANES * equalityLaneWidth()
  }
}

function wholeRegions (
  lengths: Record<keyof BRC97Method2WholeStatementRegions, number>
): BRC97Method2WholeStatementRegions {
  let start = 0
  const scalar = { start, length: lengths.scalar }
  start += scalar.length
  const lookup = { start, length: lengths.lookup }
  start += lookup.length
  const bridge = { start, length: lengths.bridge }
  start += bridge.length
  const ec = { start, length: lengths.ec }
  start += ec.length
  const compression = { start, length: lengths.compression }
  start += compression.length
  const hmac = { start, length: lengths.hmac }
  return { scalar, lookup, bridge, ec, compression, hmac }
}

function wholeEqualitySchedule (
  traceLength: number,
  regions: BRC97Method2WholeStatementRegions,
  windowCount: number,
  ecSchedule: ProductionEcPublicInput['schedule']
): BRC97Method2WholeStatementEqualityScheduleRow[] {
  const schedule = Array.from({ length: traceLength }, () => ({
    lanes: Array.from({ length: EQ_LANES }, () => inactiveLaneSchedule())
  }))
  for (let step = 0; step < windowCount; step++) {
    setLane(schedule, regions.scalar.start + step, 0, {
      kind: EQ_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
      bindType: EQ_BIND_SCALAR_DIGIT
    })
    setLane(schedule, regions.bridge.start + step, 0, {
      kind: EQ_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_SCALAR_DIGIT,
      bindType: EQ_BIND_BRIDGE_SCALAR_DIGIT
    })
    setLane(
      schedule,
      regions.lookup.start + BRC97_RADIX11_TABLE_ROWS + step,
      0,
      {
        kind: EQ_SOURCE,
        tag: BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
        bindType: EQ_BIND_LOOKUP_POINT_PAIR
      }
    )
    setLane(schedule, regions.bridge.start + step, 1, {
      kind: EQ_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_POINT_PAIR_OUTPUT,
      bindType: EQ_BIND_BRIDGE_POINT_PAIR
    })
    setLane(schedule, regions.bridge.start + step, 2, {
      kind: EQ_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
      bindType: EQ_BIND_BRIDGE_SELECTED_G
    })
    setLane(schedule, ecSelectedRow(regions, ecSchedule, 'G', step), 0, {
      kind: EQ_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_G_POINT,
      bindType: EQ_BIND_EC_SELECTED_G
    })
    setLane(schedule, regions.bridge.start + step, 3, {
      kind: EQ_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      bindType: EQ_BIND_BRIDGE_SELECTED_B
    })
    setLane(schedule, ecSelectedRow(regions, ecSchedule, 'B', step), 0, {
      kind: EQ_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_EC_SELECTED_B_POINT,
      bindType: EQ_BIND_EC_SELECTED_B
    })
  }
  setLane(schedule, ecFinalBRow(regions, ecSchedule), 0, {
    kind: EQ_SOURCE,
    tag: TAG_S_COMPRESSION_INPUT,
    bindType: EQ_BIND_EC_FINAL_S_COMPRESSION_INPUT
  })
  setLane(schedule, regions.compression.start + 256, 0, {
    kind: EQ_TARGET,
    tag: TAG_S_COMPRESSION_INPUT,
    bindType: EQ_BIND_COMPRESSION_S_INPUT
  })
  setLane(schedule, regions.compression.start + 256, 1, {
    kind: EQ_SOURCE,
    tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
    bindType: EQ_BIND_COMPRESSION_BYTE
  })
  for (let byteIndex = 1; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    const compressionRow =
      regions.compression.start + (32 - byteIndex) * 8 + 7
    setLane(schedule, compressionRow, 0, {
      kind: EQ_SOURCE,
      tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
      bindType: EQ_BIND_COMPRESSION_BYTE
    })
  }
  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    setLane(schedule, regions.hmac.start, byteIndex, {
      kind: EQ_TARGET,
      tag: BRC97_PRODUCTION_BUS_TAG_COMPRESSED_S_KEY_BYTE,
      bindType: EQ_BIND_HMAC_KEY_BYTE
    })
  }
  return schedule
}

function writeBridgeRows (
  rows: FieldElement[][],
  layout: BRC97Method2WholeStatementLayout,
  regions: BRC97Method2WholeStatementRegions,
  lookup: ProductionRadix11LookupPrototype
): void {
  for (let step = 0; step < lookup.digits.length; step++) {
    const row = rows[regions.bridge.start + step]
    const digit = lookup.digits[step]
    const tableRow = lookup.table[lookup.selectedIndexes[step]]
    if (tableRow === undefined) {
      throw new Error('BRC97 whole statement bridge table row missing')
    }
    row[layout.bridgeActive] = 1n
    row[layout.bridgeWindow] = BigInt(digit.window)
    row[layout.bridgeMagnitude] = BigInt(digit.magnitude)
    row[layout.bridgeIsZero] = BigInt(tableRow.isZero)
    row[layout.bridgeSign] = BigInt(digit.sign)
    writeVector(row, layout.bridgePointPair, tableRow.values)
    writeVector(row, layout.bridgeSelectedG, pointTuple(
      applyBridgeSign(tableRow.g, digit.sign, digit.magnitude)
    ))
    writeVector(row, layout.bridgeSelectedB, pointTuple(
      applyBridgeSign(tableRow.b, digit.sign, digit.magnitude)
    ))
    writeVector(row, layout.bridgeCarryG, signRelationCarries(
      pointYLimbs(tableRow.g),
      pointYLimbsFromTuple(row, layout.bridgeSelectedG),
      digit.sign
    ))
    writeVector(row, layout.bridgeCarryB, signRelationCarries(
      pointYLimbs(tableRow.b),
      pointYLimbsFromTuple(row, layout.bridgeSelectedB),
      digit.sign
    ))
  }
}

function writeRegionTransitionSelectors (
  rows: FieldElement[][],
  layout: BRC97Method2WholeStatementLayout,
  regions: BRC97Method2WholeStatementRegions
): void {
  writeRegionNext(rows, layout.scalarNext, regions.scalar)
  writeRegionNext(rows, layout.lookupNext, regions.lookup)
  writeRegionNext(rows, layout.ecNext, regions.ec)
  writeRegionNext(rows, layout.compressionNext, regions.compression)
  writeRegionNext(rows, layout.hmacNext, regions.hmac)
}

function writeRegionNext (
  rows: FieldElement[][],
  column: number,
  region: BRC97Method2WholeStatementRegion
): void {
  for (let i = 0; i + 1 < region.length; i++) {
    rows[region.start + i][column] = 1n
  }
}

function writeEqualityBusRows (
  rows: FieldElement[][],
  layout: BRC97Method2WholeStatementLayout,
  publicInput: BRC97Method2WholeStatementPublicInput,
  equalitySchedule: BRC97Method2WholeStatementEqualityScheduleRow[]
): void {
  const challenges = wholeEqualityChallenges(
    brc97Method2WholeStatementPublicInputDigest(publicInput)
  )
  let accumulator0 = 0n
  let accumulator1 = 0n
  for (let rowIndex = 0; rowIndex < rows.length; rowIndex++) {
    const row = rows[rowIndex]
    row[layout.eqAccumulator0] = accumulator0
    row[layout.eqAccumulator1] = accumulator1
    let delta0 = 0n
    let delta1 = 0n
    for (let lane = 0; lane < EQ_LANES; lane++) {
      const schedule = equalitySchedule[rowIndex].lanes[lane]
      const laneOffset = equalityLaneOffset(layout, lane)
      row[laneOffset] = schedule.kind
      row[laneOffset + 1] = schedule.tag
      row[laneOffset + 2] = schedule.bindType
      const tuple = equalityTupleForBinding(row, layout, lane, schedule.bindType)
      writeVector(row, laneOffset + 3, tuple)
      const compressed0 = compressLookupBusTuple(
        schedule.tag,
        tuple,
        challenges.alpha0
      )
      const compressed1 = compressLookupBusTuple(
        schedule.tag,
        tuple,
        challenges.alpha1
      )
      row[laneOffset + 3 + LOOKUP_BUS_TUPLE_ARITY] = compressed0
      row[laneOffset + 4 + LOOKUP_BUS_TUPLE_ARITY] = compressed1
      if (schedule.kind === EQ_SOURCE) {
        delta0 = F.add(delta0, compressed0)
        delta1 = F.add(delta1, compressed1)
      } else if (schedule.kind === EQ_TARGET) {
        delta0 = F.sub(delta0, compressed0)
        delta1 = F.sub(delta1, compressed1)
      }
    }
    if (rowIndex + 1 < rows.length) {
      accumulator0 = F.add(accumulator0, delta0)
      accumulator1 = F.add(accumulator1, delta1)
    }
  }
  if (accumulator0 !== 0n || accumulator1 !== 0n) {
    throw new Error('BRC97 whole statement equality bus does not balance')
  }
}

function evaluateWholeEqualityTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  challenges: WholeEqualityChallenges
): FieldElement[] {
  const constraints: FieldElement[] = []
  let delta0 = 0n
  let delta1 = 0n
  for (let lane = 0; lane < EQ_LANES; lane++) {
    const laneOffset = equalityLaneOffset(layout, lane)
    const kind = current[laneOffset]
    const tag = current[laneOffset + 1]
    const bindType = current[laneOffset + 2]
    const tuple = current.slice(
      laneOffset + 3,
      laneOffset + 3 + LOOKUP_BUS_TUPLE_ARITY
    )
    const compressed0 = current[laneOffset + 3 + LOOKUP_BUS_TUPLE_ARITY]
    const compressed1 = current[laneOffset + 4 + LOOKUP_BUS_TUPLE_ARITY]
    const source = selector(kind, EQ_SOURCE, EQ_KIND_VALUES)
    const target = selector(kind, EQ_TARGET, EQ_KIND_VALUES)
    const active = F.add(source, target)
    constraints.push(domainConstraint(kind, EQ_KIND_VALUES))
    constraints.push(domainConstraint(bindType, EQ_BIND_VALUES))
    constraints.push(F.mul(active, F.sub(
      compressed0,
      compressLookupBusTuple(tag, tuple, challenges.alpha0)
    )))
    constraints.push(F.mul(active, F.sub(
      compressed1,
      compressLookupBusTuple(tag, tuple, challenges.alpha1)
    )))
    constraints.push(...equalityBindingConstraints(
      current,
      layout,
      lane,
      bindType,
      active
    ))
    for (const value of tuple) {
      constraints.push(F.mul(F.sub(1n, active), value))
    }
    constraints.push(F.mul(F.sub(1n, active), compressed0))
    constraints.push(F.mul(F.sub(1n, active), compressed1))
    delta0 = F.add(delta0, F.mul(F.sub(source, target), compressed0))
    delta1 = F.add(delta1, F.mul(F.sub(source, target), compressed1))
  }
  constraints.push(F.sub(
    next[layout.eqAccumulator0],
    F.add(current[layout.eqAccumulator0], delta0)
  ))
  constraints.push(F.sub(
    next[layout.eqAccumulator1],
    F.add(current[layout.eqAccumulator1], delta1)
  ))
  return constraints
}

function equalityBindingConstraints (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  lane: number,
  bindType: FieldElement,
  active: FieldElement
): FieldElement[] {
  const constraints: FieldElement[] = []
  const tupleOffset = equalityLaneOffset(layout, lane) + 3
  for (const candidate of EQ_BIND_VALUES) {
    if (candidate === EQ_BIND_NONE) continue
    const binding = F.mul(active, selector(bindType, candidate, EQ_BIND_VALUES))
    constraints.push(...tupleEquality(
      row,
      tupleOffset,
      equalityTupleForBinding(row, layout, lane, candidate),
      binding
    ))
  }
  return constraints
}

function equalityTupleForBinding (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  lane: number,
  bindType: FieldElement
): FieldElement[] {
  if (bindType === EQ_BIND_SCALAR_DIGIT) {
    return padTuple([
      row[layout.scalar + BRC97_PRODUCTION_SCALAR_LAYOUT.window],
      row[layout.scalar + BRC97_PRODUCTION_SCALAR_LAYOUT.magnitude],
      row[layout.scalar + BRC97_PRODUCTION_SCALAR_LAYOUT.isZero],
      row[layout.scalar + BRC97_PRODUCTION_SCALAR_LAYOUT.sign]
    ])
  }
  if (bindType === EQ_BIND_BRIDGE_SCALAR_DIGIT) {
    return padTuple([
      row[layout.bridgeWindow],
      row[layout.bridgeMagnitude],
      row[layout.bridgeIsZero],
      row[layout.bridgeSign]
    ])
  }
  if (bindType === EQ_BIND_LOOKUP_POINT_PAIR) {
    return row.slice(
      layout.lookup + LOOKUP_BUS_LAYOUT.left,
      layout.lookup + LOOKUP_BUS_LAYOUT.left + LOOKUP_BUS_TUPLE_ARITY
    )
  }
  if (bindType === EQ_BIND_BRIDGE_POINT_PAIR) {
    return row.slice(
      layout.bridgePointPair,
      layout.bridgePointPair + LOOKUP_BUS_TUPLE_ARITY
    )
  }
  if (bindType === EQ_BIND_BRIDGE_SELECTED_G) {
    return padTuple(row.slice(
      layout.bridgeSelectedG,
      layout.bridgeSelectedG + 1 + BRC97_RADIX11_POINT_LIMBS * 2
    ))
  }
  if (bindType === EQ_BIND_BRIDGE_SELECTED_B) {
    return padTuple(row.slice(
      layout.bridgeSelectedB,
      layout.bridgeSelectedB + 1 + BRC97_RADIX11_POINT_LIMBS * 2
    ))
  }
  if (bindType === EQ_BIND_EC_SELECTED_G || bindType === EQ_BIND_EC_SELECTED_B) {
    return padTuple([
      row[layout.ec + PRODUCTION_EC_LAYOUT.selectedInfinity],
      ...row.slice(
        layout.ec + PRODUCTION_EC_LAYOUT.selectedX,
        layout.ec + PRODUCTION_EC_LAYOUT.selectedX + BRC97_RADIX11_POINT_LIMBS
      ),
      ...row.slice(
        layout.ec + PRODUCTION_EC_LAYOUT.selectedY,
        layout.ec + PRODUCTION_EC_LAYOUT.selectedY + BRC97_RADIX11_POINT_LIMBS
      )
    ])
  }
  if (bindType === EQ_BIND_EC_FINAL_S_COMPRESSION_INPUT) {
    return padTuple([
      ...row.slice(
        layout.ec + PRODUCTION_EC_LAYOUT.afterX,
        layout.ec + PRODUCTION_EC_LAYOUT.afterX + BRC97_RADIX11_POINT_LIMBS
      ),
      row[layout.ec + PRODUCTION_EC_LAYOUT.afterY]
    ])
  }
  if (bindType === EQ_BIND_COMPRESSION_S_INPUT) {
    return padTuple([
      ...row.slice(
        layout.compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.xLimbs,
        layout.compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.xLimbs +
          BRC97_RADIX11_POINT_LIMBS
      ),
      row[layout.compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.yLimb0]
    ])
  }
  if (bindType === EQ_BIND_COMPRESSION_BYTE) {
    return padTuple([
      row[layout.compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.byteIndex],
      row[layout.compression + BRC97_PRODUCTION_COMPRESSION_LAYOUT.byte]
    ])
  }
  if (bindType === EQ_BIND_HMAC_KEY_BYTE) {
    return padTuple([
      BigInt(lane),
      hmacKeyByteFromBits(row, layout, lane)
    ])
  }
  return padTuple([])
}

function evaluateBridgeTransition (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout
): FieldElement[] {
  const active = row[layout.bridgeActive]
  const sign = row[layout.bridgeSign]
  const isZero = row[layout.bridgeIsZero]
  const constraints: FieldElement[] = [
    F.mul(active, F.sub(active, 1n)),
    F.mul(active, F.sub(sign, F.mul(sign, sign))),
    F.mul(active, F.sub(isZero, F.mul(isZero, isZero))),
    F.mul(active, F.mul(isZero, sign)),
    F.mul(active, F.sub(row[layout.bridgePointPair], row[layout.bridgeWindow])),
    F.mul(active, F.sub(
      row[layout.bridgePointPair + 1],
      row[layout.bridgeMagnitude]
    )),
    F.mul(active, F.sub(
      row[layout.bridgePointPair + 2],
      row[layout.bridgeIsZero]
    )),
    F.mul(active, F.sub(row[layout.bridgeSelectedG], isZero)),
    F.mul(active, F.sub(row[layout.bridgeSelectedB], isZero))
  ]
  constraints.push(...bridgePointConstraints(
    row,
    layout,
    layout.bridgePointPair + 3,
    layout.bridgePointPair + 8,
    layout.bridgeSelectedG + 1,
    layout.bridgeSelectedG + 6,
    layout.bridgeCarryG,
    active,
    sign
  ))
  constraints.push(...bridgePointConstraints(
    row,
    layout,
    layout.bridgePointPair + 13,
    layout.bridgePointPair + 18,
    layout.bridgeSelectedB + 1,
    layout.bridgeSelectedB + 6,
    layout.bridgeCarryB,
    active,
    sign
  ))
  return constraints
}

function bridgePointConstraints (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  tableX: number,
  tableY: number,
  selectedX: number,
  selectedY: number,
  carry: number,
  active: FieldElement,
  sign: FieldElement
): FieldElement[] {
  const constraints: FieldElement[] = []
  for (let limb = 0; limb < BRC97_RADIX11_POINT_LIMBS; limb++) {
    constraints.push(F.mul(active, F.sub(row[selectedX + limb], row[tableX + limb])))
    const carryIn = limb === 0 ? 0n : row[carry + limb - 1]
    const carryOut = row[carry + limb]
    const signedYEquation = F.sub(
      F.add(
        F.sub(row[selectedY + limb], row[tableY + limb]),
        F.mul(sign, F.sub(F.mul(2n, row[tableY + limb]), P_52[limb]))
      ),
      F.sub(F.mul(carryOut, FIELD_RADIX), carryIn)
    )
    constraints.push(F.mul(active, signedYEquation))
  }
  constraints.push(F.mul(active, row[carry + BRC97_RADIX11_POINT_LIMBS - 1]))
  return constraints
}

function regionTransitionSelector (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  region: keyof BRC97Method2WholeStatementRegions
): FieldElement {
  if (region === 'scalar') return row[layout.scalarNext]
  if (region === 'lookup') return row[layout.lookupNext]
  if (region === 'ec') return row[layout.ecNext]
  if (region === 'compression') return row[layout.compressionNext]
  if (region === 'hmac') return row[layout.hmacNext]
  if (region === 'bridge') return row[layout.bridgeActive]
  return 0n
}

function translateBoundaryConstraints (
  air: AirDefinition,
  region: BRC97Method2WholeStatementRegion,
  offset: number
): AirDefinition['boundaryConstraints'] {
  return air.boundaryConstraints.map(constraint => ({
    column: offset + constraint.column,
    row: region.start + constraint.row,
    value: constraint.value
  }))
}

function translateFullBoundaryColumns (
  air: AirDefinition,
  region: BRC97Method2WholeStatementRegion,
  offset: number,
  traceLength: number
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  return (air.fullBoundaryColumns ?? []).map(column => {
    const values = new Array<FieldElement>(traceLength).fill(0n)
    for (let i = 0; i < column.values.length; i++) {
      values[region.start + i] = column.values[i]
    }
    return {
      column: offset + column.column,
      values
    }
  })
}

function wholeEqualityFullBoundaryColumns (
  publicInput: BRC97Method2WholeStatementPublicInput,
  layout: BRC97Method2WholeStatementLayout,
  equalitySchedule: BRC97Method2WholeStatementEqualityScheduleRow[]
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const columns: NonNullable<AirDefinition['fullBoundaryColumns']> = []
  const bridgeActive = new Array<FieldElement>(publicInput.traceLength).fill(0n)
  for (let i = 0; i < publicInput.regions.bridge.length; i++) {
    bridgeActive[publicInput.regions.bridge.start + i] = 1n
  }
  columns.push({ column: layout.bridgeActive, values: bridgeActive })
  columns.push(
    regionNextFullBoundaryColumn(
      layout.scalarNext,
      publicInput.regions.scalar,
      publicInput.traceLength
    ),
    regionNextFullBoundaryColumn(
      layout.lookupNext,
      publicInput.regions.lookup,
      publicInput.traceLength
    ),
    regionNextFullBoundaryColumn(
      layout.ecNext,
      publicInput.regions.ec,
      publicInput.traceLength
    ),
    regionNextFullBoundaryColumn(
      layout.compressionNext,
      publicInput.regions.compression,
      publicInput.traceLength
    ),
    regionNextFullBoundaryColumn(
      layout.hmacNext,
      publicInput.regions.hmac,
      publicInput.traceLength
    )
  )
  for (let lane = 0; lane < EQ_LANES; lane++) {
    const laneOffset = equalityLaneOffset(layout, lane)
    columns.push({
      column: laneOffset,
      values: equalitySchedule.map(row => row.lanes[lane].kind)
    })
    columns.push({
      column: laneOffset + 1,
      values: equalitySchedule.map(row => row.lanes[lane].tag)
    })
    columns.push({
      column: laneOffset + 2,
      values: equalitySchedule.map(row => row.lanes[lane].bindType)
    })
  }
  return columns
}

function regionNextFullBoundaryColumn (
  column: number,
  region: BRC97Method2WholeStatementRegion,
  traceLength: number
): NonNullable<AirDefinition['fullBoundaryColumns']>[number] {
  const values = new Array<FieldElement>(traceLength).fill(0n)
  for (let i = 0; i + 1 < region.length; i++) {
    values[region.start + i] = 1n
  }
  return { column, values }
}

function validateWholeRegions (
  publicInput: BRC97Method2WholeStatementPublicInput
): void {
  const regions = publicInput.regions
  const expected: BRC97Method2WholeStatementRegions = {
    scalar: { start: 0, length: publicInput.scalar.traceLength },
    lookup: {
      start: publicInput.scalar.traceLength,
      length: publicInput.lookup.traceLength
    },
    bridge: {
      start: publicInput.scalar.traceLength + publicInput.lookup.traceLength,
      length: publicInput.ec.radixWindowCount
    },
    ec: {
      start: publicInput.scalar.traceLength +
        publicInput.lookup.traceLength +
        publicInput.ec.radixWindowCount,
      length: publicInput.ec.paddedRows
    },
    compression: {
      start: publicInput.scalar.traceLength +
        publicInput.lookup.traceLength +
        publicInput.ec.radixWindowCount +
        publicInput.ec.paddedRows,
      length: publicInput.compression.traceLength
    },
    hmac: {
      start: publicInput.scalar.traceLength +
        publicInput.lookup.traceLength +
        publicInput.ec.radixWindowCount +
        publicInput.ec.paddedRows +
        publicInput.compression.traceLength,
      length: publicInput.hmac.traceLength
    }
  }
  for (const key of Object.keys(expected) as Array<keyof BRC97Method2WholeStatementRegions>) {
    if (
      regions[key].start !== expected[key].start ||
      regions[key].length !== expected[key].length
    ) {
      throw new Error('BRC97 whole statement region layout mismatch')
    }
  }
  const minimumTraceLength = expected.hmac.start + expected.hmac.length + 1
  if (
    publicInput.traceLength !== nextPowerOfTwo(minimumTraceLength) ||
    publicInput.traceLength < minimumTraceLength
  ) {
    throw new Error('BRC97 whole statement trace length mismatch')
  }
}

function validateDeterministicLookupTable (
  publicInput: BRC97Method2WholeStatementPublicInput
): void {
  const table = buildProductionRadix11PointPairTable(publicInput.baseB)
  const zeroTuple = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  if (publicInput.lookup.traceLength !== publicInput.regions.lookup.length) {
    throw new Error('BRC97 whole statement lookup trace length mismatch')
  }
  if (
    publicInput.lookup.expectedLookupRequests !==
    publicInput.ec.radixWindowCount
  ) {
    throw new Error('BRC97 whole statement lookup request count mismatch')
  }
  if (publicInput.lookup.scheduleRows.length !== publicInput.lookup.traceLength) {
    throw new Error('BRC97 whole statement lookup table schedule is incomplete')
  }
  for (let i = 0; i < table.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupSupply ||
      row.tag !== table[i].tag ||
      !vectorsEqual(row.publicTuple, table[i].values)
    ) {
      throw new Error('BRC97 whole statement lookup table does not match public B')
    }
  }
  const requestEnd = table.length + publicInput.ec.radixWindowCount
  for (let i = table.length; i < requestEnd; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.lookupRequest ||
      row.tag !== LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC97 whole statement lookup request schedule mismatch')
    }
  }
  for (let i = requestEnd; i < publicInput.lookup.scheduleRows.length; i++) {
    const row = publicInput.lookup.scheduleRows[i]
    if (
      row.kind !== LOOKUP_BUS_ROW_KIND.inactive ||
      row.tag !== 0n ||
      !vectorsEqual(row.publicTuple, zeroTuple)
    ) {
      throw new Error('BRC97 whole statement lookup inactive schedule mismatch')
    }
  }
}

function wholePublicInputDigestPayload (
  publicInput: BRC97Method2WholeStatementPublicInput
): unknown {
  const table = buildProductionRadix11PointPairTable(publicInput.baseB)
  return {
    publicA: publicInput.publicA,
    baseB: publicInput.baseB,
    invoice: publicInput.invoice,
    linkage: publicInput.linkage,
    traceLength: publicInput.traceLength,
    regions: publicInput.regions,
    scalar: publicInput.scalar,
    lookup: {
      traceLength: publicInput.lookup.traceLength,
      expectedLookupRequests: publicInput.lookup.expectedLookupRequests,
      tableRows: BRC97_RADIX11_TABLE_ROWS,
      tableTag: LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
      tableRoot: productionRadix11TableRoot(table)
    },
    ec: publicInput.ec,
    compression: publicInput.compression,
    hmac: publicInput.hmac,
    layoutWidth: wholeLayout().width
  }
}

function wholeEqualityChallenges (
  publicInputDigest: number[]
): WholeEqualityChallenges {
  const transcript = new FiatShamirTranscript(
    `${BRC97_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN}:equality`
  )
  transcript.absorb('public-input', publicInputDigest)
  return {
    alpha0: nonZeroChallenge(transcript, 'alpha-0'),
    alpha1: nonZeroChallenge(transcript, 'alpha-1')
  }
}

function nonZeroChallenge (
  transcript: FiatShamirTranscript,
  label: string
): FieldElement {
  for (let i = 0; i < 16; i++) {
    const value = transcript.challengeFieldElement(`${label}-${i}`)
    if (value !== 0n) return value
  }
  throw new Error('BRC97 whole statement could not derive challenge')
}

function wholeProofMeetsProductionProfile (proof: StarkProof): boolean {
  return proof.blowupFactor ===
    BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor &&
    proof.numQueries === BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize ===
      BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree ===
      BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset ===
      BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset
}

function wholeVerifierOptions (proof: StarkProof): StarkVerifierOptions {
  return {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain: BRC97_METHOD2_WHOLE_STATEMENT_TRANSCRIPT_DOMAIN
  }
}

function equalityLaneWidth (): number {
  return 5 + LOOKUP_BUS_TUPLE_ARITY
}

function equalityLaneOffset (
  layout: BRC97Method2WholeStatementLayout,
  lane: number
): number {
  return layout.eqLanes + lane * equalityLaneWidth()
}

function inactiveLaneSchedule ():
BRC97Method2WholeStatementEqualityLaneSchedule {
  return { kind: 0n, tag: 0n, bindType: EQ_BIND_NONE }
}

function setLane (
  schedule: BRC97Method2WholeStatementEqualityScheduleRow[],
  row: number,
  lane: number,
  value: BRC97Method2WholeStatementEqualityLaneSchedule
): void {
  if (row < 0 || row >= schedule.length || lane < 0 || lane >= EQ_LANES) {
    throw new Error('BRC97 whole statement equality schedule out of range')
  }
  schedule[row].lanes[lane] = value
}

function ecSelectedRow (
  regions: BRC97Method2WholeStatementRegions,
  schedule: ProductionEcPublicInput['schedule'],
  lane: 'G' | 'B',
  step: number
): number {
  const op = schedule.find(item =>
    item.lane === lane && item.step === step
  )
  if (op === undefined) throw new Error('BRC97 whole statement EC row missing')
  return regions.ec.start + op.row
}

function ecFinalBRow (
  regions: BRC97Method2WholeStatementRegions,
  schedule: ProductionEcPublicInput['schedule']
): number {
  for (let i = schedule.length - 1; i >= 0; i--) {
    const op = schedule[i]
    if (op.lane === 'B') return regions.ec.start + op.row + op.rows - 1
  }
  throw new Error('BRC97 whole statement EC final B row missing')
}

function hmacKeyByteFromBits (
  row: FieldElement[],
  layout: BRC97Method2WholeStatementLayout,
  byteIndex: number
): FieldElement {
  return row[
    layout.hmac +
    METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes +
    byteIndex
  ]
}

function selector (
  value: FieldElement,
  target: FieldElement,
  domain: FieldElement[]
): FieldElement {
  let numerator = 1n
  let denominator = 1n
  for (const candidate of domain) {
    if (candidate === target) continue
    numerator = F.mul(numerator, F.sub(value, candidate))
    denominator = F.mul(denominator, F.sub(target, candidate))
  }
  return F.div(numerator, denominator)
}

function domainConstraint (
  value: FieldElement,
  domain: FieldElement[]
): FieldElement {
  let out = 1n
  for (const candidate of domain) out = F.mul(out, F.sub(value, candidate))
  return out
}

function tupleEquality (
  row: FieldElement[],
  tupleOffset: number,
  expected: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return Array.from({ length: LOOKUP_BUS_TUPLE_ARITY }, (_, i) =>
    F.mul(selector, F.sub(row[tupleOffset + i], expected[i] ?? 0n))
  )
}

function padTuple (values: FieldElement[]): FieldElement[] {
  const out = values.slice()
  while (out.length < LOOKUP_BUS_TUPLE_ARITY) out.push(0n)
  if (out.length !== LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('BRC97 whole statement tuple is too large')
  }
  return out
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function rowSlice (
  row: FieldElement[],
  offset: number,
  width: number
): FieldElement[] {
  return row.slice(offset, offset + width)
}

function copyRows (
  rows: FieldElement[][],
  start: number,
  offset: number,
  sourceRows: FieldElement[][]
): void {
  for (let row = 0; row < sourceRows.length; row++) {
    for (let column = 0; column < sourceRows[row].length; column++) {
      rows[start + row][offset + column] = sourceRows[row][column]
    }
  }
}

function pointTuple (point: SecpPoint): FieldElement[] {
  if (point.infinity === true) {
    return [
      1n,
      ...new Array<FieldElement>(BRC97_RADIX11_POINT_LIMBS * 2).fill(0n)
    ]
  }
  return [
    0n,
    ...secp256k1FieldToLimbs52(point.x),
    ...secp256k1FieldToLimbs52(point.y)
  ]
}

function applyBridgeSign (
  point: SecpPoint,
  sign: 0 | 1,
  magnitude: number
): SecpPoint {
  if (magnitude === 0) return { x: 0n, y: 0n, infinity: true }
  if (sign === 0) return point
  return {
    x: point.x,
    y: point.y === 0n ? 0n : SECP256K1_P - point.y
  }
}

function pointYLimbs (point: SecpPoint): FieldElement[] {
  return point.infinity === true
    ? new Array<FieldElement>(BRC97_RADIX11_POINT_LIMBS).fill(0n)
    : secp256k1FieldToLimbs52(point.y)
}

function pointYLimbsFromTuple (
  row: FieldElement[],
  offset: number
): FieldElement[] {
  return row.slice(offset + 6, offset + 6 + BRC97_RADIX11_POINT_LIMBS)
}

function signRelationCarries (
  tableY: FieldElement[],
  selectedY: FieldElement[],
  sign: 0 | 1
): FieldElement[] {
  const carries: FieldElement[] = []
  let carry = 0n
  for (let limb = 0; limb < BRC97_RADIX11_POINT_LIMBS; limb++) {
    const value = selectedY[limb] - tableY[limb] +
      BigInt(sign) * (2n * tableY[limb] - P_52[limb]) +
      carry
    if (value % FIELD_RADIX !== 0n) {
      throw new Error('BRC97 whole statement sign bridge carry is invalid')
    }
    carry = value / FIELD_RADIX
    carries.push(F.normalize(carry))
  }
  if (carry !== 0n) {
    throw new Error('BRC97 whole statement sign bridge final carry is nonzero')
  }
  return carries
}

function writeVector (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < values.length; i++) row[offset + i] = F.normalize(values[i])
}

function vectorsEqual (left: FieldElement[], right: FieldElement[]): boolean {
  return left.length === right.length &&
    left.every((value, index) => F.normalize(value) === F.normalize(right[index]))
}

function pointsEqual (left: SecpPoint, right: SecpPoint): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

function bytesEqual (left: number[], right: number[]): boolean {
  return left.length === right.length &&
    left.every((byte, index) => byte === right[index])
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
  if (typeof value === 'bigint') return `"${value.toString()}"`
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
  return `{${entries.map(([key, entry]) =>
    `${JSON.stringify(key)}:${stableJson(entry)}`
  ).join(',')}}`
}

function emptyRows (height: number, width: number): FieldElement[][] {
  return new Array<FieldElement[]>(height)
    .fill([])
    .map(() => new Array<FieldElement>(width).fill(0n))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function bigintToLimbs (
  value: bigint,
  count: number,
  radix: bigint
): bigint[] {
  const limbs: bigint[] = []
  let current = value
  for (let i = 0; i < count; i++) {
    limbs.push(current % radix)
    current /= radix
  }
  if (current !== 0n) throw new Error('BRC97 whole statement limb overflow')
  return limbs
}
