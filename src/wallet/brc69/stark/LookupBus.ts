import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from './Air.js'
import { F, FieldElement } from './Field.js'
import {
  MultiTraceCommittedSegmentSummary,
  MultiTraceCrossConstraintInput,
  MultiTraceStarkProof,
  StarkProverOptions,
  diagnoseMultiTraceStark,
  provePhasedMultiTraceStark,
  serializeMultiTraceStarkProof,
  verifyMultiTraceStark
} from './Stark.js'
import { FiatShamirTranscript } from './Transcript.js'

export const LOOKUP_BUS_TRANSCRIPT_DOMAIN = 'BRC69_LOOKUP_BUS_PROTOTYPE_V1'
export const LOOKUP_BUS_PUBLIC_INPUT_DIGEST_ID =
  'BRC69_LOOKUP_BUS_PUBLIC_INPUT_DIGEST_V1'
export const LOOKUP_BUS_TUPLE_ARITY = 23
export const LOOKUP_BUS_MAX_MULTIPLICITY = 3

export const LOOKUP_BUS_TAG_RANGE16 = 1n
export const LOOKUP_BUS_TAG_TOY_POINT_PAIR = 2n
export const LOOKUP_BUS_TAG_PRIVATE_EQUALITY = 3n
export const LOOKUP_BUS_TAG_PUBLIC_EQUALITY = 4n
export const LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR = 5n
export const LOOKUP_BUS_COMPRESSION_CHALLENGES = 2

export const LOOKUP_BUS_ROW_KIND = {
  inactive: 0n,
  lookupRequest: 1n,
  lookupSupply: 2n,
  privateEquality: 3n,
  publicEquality: 4n,
  fixedTable: 2n
} as const

const LOOKUP_BUS_CANONICAL_ROW_KINDS = [
  LOOKUP_BUS_ROW_KIND.inactive,
  LOOKUP_BUS_ROW_KIND.lookupRequest,
  LOOKUP_BUS_ROW_KIND.lookupSupply,
  LOOKUP_BUS_ROW_KIND.privateEquality,
  LOOKUP_BUS_ROW_KIND.publicEquality
]
const LOOKUP_BUS_KIND_SELECTOR_DENOMINATOR_INVERSES =
  LOOKUP_BUS_CANONICAL_ROW_KINDS.reduce<Record<string, FieldElement>>(
    (out, target) => {
      let denominator = 1n
      for (const candidate of LOOKUP_BUS_CANONICAL_ROW_KINDS) {
        if (candidate !== target) {
          denominator = F.mul(denominator, F.sub(target, candidate))
        }
      }
      out[target.toString()] = F.inv(denominator)
      return out
    },
    {}
  )
const LOOKUP_BUS_MULTIPLICITY_SELECTOR_DENOMINATOR_INVERSES =
  Array.from({ length: LOOKUP_BUS_MAX_MULTIPLICITY + 1 }, (_, target) => {
    let denominator = 1n
    for (let candidate = 0; candidate <= LOOKUP_BUS_MAX_MULTIPLICITY; candidate++) {
      if (candidate !== target) {
        denominator = F.mul(denominator, BigInt(target - candidate))
      }
    }
    return F.inv(denominator)
  })

export const LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 8,
  maskDegree: 1,
  cosetOffset: 3n,
  transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
} as const

export interface LookupBusLayout {
  kind: number
  tag: number
  multiplicity: number
  left: number
  right: number
  publicTuple: number
  lookupInverse0: number
  lookupInverse1: number
  equalityAccumulator0: number
  equalityAccumulator1: number
  lookupAccumulator0: number
  lookupAccumulator1: number
  lookupRequestCount: number
  transitionActive: number
  width: number
}

export interface LookupBusBaseLayout {
  kind: number
  tag: number
  multiplicity: number
  left: number
  right: number
  publicTuple: number
  width: number
}

export interface LookupBusAccumulatorLayout {
  lookupInverse0: number
  lookupInverse1: number
  equalityAccumulator0: number
  equalityAccumulator1: number
  lookupAccumulator0: number
  lookupAccumulator1: number
  lookupRequestCount: number
  transitionActive: number
  width: number
}

export interface LookupBusScheduleRow {
  kind: FieldElement
  tag: FieldElement
  publicTuple: FieldElement[]
}

export interface LookupBusTraceItem {
  kind: FieldElement
  tag: FieldElement
  leftValues?: FieldElement[]
  rightValues?: FieldElement[]
  publicValues?: FieldElement[]
  multiplicity?: number
}

export interface LookupBusPublicInput {
  traceLength: number
  expectedLookupRequests: number
  scheduleRows: LookupBusScheduleRow[]
}

export interface LookupBusTrace {
  publicInput: LookupBusPublicInput
  baseRows: FieldElement[][]
  metrics: LookupBusMetrics
}

export interface LookupBusMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  fixedTableRows: number
  lookupRequests: number
  lookupSupplies: number
  fixedLookups: number
  equalityRows: number
  baseTraceWidth?: number
  accumulatorTraceWidth?: number
  proofBytes?: number
}

export interface LookupBusTableRow {
  tag: FieldElement
  values: FieldElement[]
}

export const LOOKUP_BUS_BASE_LAYOUT: LookupBusBaseLayout = {
  kind: 0,
  tag: 1,
  multiplicity: 2,
  left: 3,
  right: 3 + LOOKUP_BUS_TUPLE_ARITY,
  publicTuple: 3 + LOOKUP_BUS_TUPLE_ARITY * 2,
  width: 3 + LOOKUP_BUS_TUPLE_ARITY * 3
}

export const LOOKUP_BUS_ACCUMULATOR_LAYOUT: LookupBusAccumulatorLayout = {
  lookupInverse0: 0,
  lookupInverse1: 1,
  equalityAccumulator0: 2,
  equalityAccumulator1: 3,
  lookupAccumulator0: 4,
  lookupAccumulator1: 5,
  lookupRequestCount: 6,
  transitionActive: 7,
  width: 8
}

export const LOOKUP_BUS_LAYOUT: LookupBusLayout = {
  ...LOOKUP_BUS_BASE_LAYOUT,
  lookupInverse0: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse0,
  lookupInverse1: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse1,
  equalityAccumulator0: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator0,
  equalityAccumulator1: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator1,
  lookupAccumulator0: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator0,
  lookupAccumulator1: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator1,
  lookupRequestCount: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupRequestCount,
  transitionActive: LOOKUP_BUS_ACCUMULATOR_LAYOUT.transitionActive,
  width: LOOKUP_BUS_BASE_LAYOUT.width
}

export interface LookupBusChallengeInput {
  publicInputDigest: number[]
  baseTraceRoot: number[]
  transcriptDomain?: string
}

export interface LookupBusChallenges {
  alpha0: FieldElement
  alpha1: FieldElement
  alphaPowers0: FieldElement[]
  alphaPowers1: FieldElement[]
  beta0: FieldElement
  beta1: FieldElement
}

const LOOKUP_BUS_ZERO_TUPLE =
  new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
const LOOKUP_BUS_INACTIVE_SCHEDULE_ROW: LookupBusScheduleRow = {
  kind: LOOKUP_BUS_ROW_KIND.inactive,
  tag: 0n,
  publicTuple: LOOKUP_BUS_ZERO_TUPLE
}

export function buildLookupBusRange16Table (): LookupBusTableRow[] {
  return Array.from({ length: 16 }, (_, value) => ({
    tag: LOOKUP_BUS_TAG_RANGE16,
    values: padTuple([BigInt(value)])
  }))
}

export function lookupBusNonAdaptiveCollisionSecurityBits (
  tupleArity = LOOKUP_BUS_TUPLE_ARITY,
  challengeCount = LOOKUP_BUS_COMPRESSION_CHALLENGES
): number {
  if (
    !Number.isSafeInteger(tupleArity) ||
    tupleArity < 1 ||
    !Number.isSafeInteger(challengeCount) ||
    challengeCount < 1
  ) {
    throw new Error('Lookup bus collision parameters are invalid')
  }
  return challengeCount * (
    Math.log2(Number(F.p - 1n)) -
    Math.log2(tupleArity)
  )
}

export function buildLookupBusToyPointPairTable (
  windows = 2,
  magnitudes = 4
): LookupBusTableRow[] {
  if (
    !Number.isSafeInteger(windows) ||
    windows < 1 ||
    !Number.isSafeInteger(magnitudes) ||
    magnitudes < 1
  ) {
    throw new Error('Lookup bus toy point table dimensions are invalid')
  }
  const rows: LookupBusTableRow[] = []
  for (let window = 0; window < windows; window++) {
    for (let magnitude = 0; magnitude < magnitudes; magnitude++) {
      const w = BigInt(window)
      const m = BigInt(magnitude)
      rows.push({
        tag: LOOKUP_BUS_TAG_TOY_POINT_PAIR,
        values: padTuple([
          w,
          m,
          F.add(1000n, F.add(F.mul(w, 100n), m)),
          F.add(2000n, F.add(F.mul(w, 100n), m)),
          F.add(3000n, F.add(F.mul(w, 100n), m)),
          F.add(4000n, F.add(F.mul(w, 100n), m))
        ])
      })
    }
  }
  return rows
}

export function lookupBusFixedTableItems (
  table: LookupBusTableRow[],
  multiplicities: Record<number, number>
): LookupBusTraceItem[] {
  if (table.length === 0) throw new Error('Lookup bus fixed table is empty')
  return table.map((row, index) => ({
    kind: LOOKUP_BUS_ROW_KIND.lookupSupply,
    tag: row.tag,
    leftValues: row.values,
    rightValues: row.values,
    publicValues: row.values,
    multiplicity: multiplicities[index] ?? 0
  }))
}

export function lookupBusLookupRequestItems (
  table: LookupBusTableRow[],
  indexes: number[]
): LookupBusTraceItem[] {
  return indexes.map(index => lookupBusLookupRequestItem(table[index]))
}

export function lookupBusLookupRequestItem (
  row: LookupBusTableRow
): LookupBusTraceItem {
  if (row === undefined) throw new Error('Lookup bus request row is missing')
  return {
    kind: LOOKUP_BUS_ROW_KIND.lookupRequest,
    tag: row.tag,
    leftValues: row.values,
    rightValues: row.values,
    multiplicity: 1
  }
}

export function buildLookupBusTrace (
  items: LookupBusTraceItem[],
  options: {
    expectedLookupRequests?: number
    minTraceLength?: number
  } = {}
): LookupBusTrace {
  const activeRows = items.length
  const lookupRequests = items.filter(item =>
    item.kind === LOOKUP_BUS_ROW_KIND.lookupRequest
  ).length
  const lookupSupplies = items.reduce((total, item) => {
    return item.kind === LOOKUP_BUS_ROW_KIND.lookupSupply
      ? total + itemMultiplicity(item, LOOKUP_BUS_ROW_KIND.lookupSupply)
      : total
  }, 0)
  const expectedLookupRequests = options.expectedLookupRequests ?? lookupRequests
  const traceLength = nextPowerOfTwo(Math.max(
    2,
    options.minTraceLength ?? 0,
    items.length + 1
  ))
  const scheduleRows = new Array<LookupBusScheduleRow>(traceLength)
  const rows = new Array<FieldElement[]>(traceLength)
  const publicInput: LookupBusPublicInput = {
    traceLength,
    expectedLookupRequests,
    scheduleRows
  }
  for (let rowIndex = 0; rowIndex < traceLength; rowIndex++) {
    const item = items[rowIndex]
    if (item === undefined) {
      scheduleRows[rowIndex] = LOOKUP_BUS_INACTIVE_SCHEDULE_ROW
      continue
    }
    const kind = normalizeKind(item.kind)
    const tag = F.normalize(item.tag)
    const publicTuple = normalizeTuple(item.publicValues ?? LOOKUP_BUS_ZERO_TUPLE)
    scheduleRows[rowIndex] = {
      kind,
      tag,
      publicTuple
    }
  }
  for (let rowIndex = 0; rowIndex < traceLength; rowIndex++) {
    const item = items[rowIndex]
    const schedule = scheduleRows[rowIndex]
    const kind = schedule.kind
    const tag = schedule.tag
    const left = item === undefined
      ? LOOKUP_BUS_ZERO_TUPLE
      : normalizeTuple(item.leftValues ?? LOOKUP_BUS_ZERO_TUPLE)
    const right = item === undefined
      ? LOOKUP_BUS_ZERO_TUPLE
      : normalizeTuple(item.rightValues ?? LOOKUP_BUS_ZERO_TUPLE)
    const publicTuple = schedule.publicTuple
    const multiplicityValue = itemMultiplicity(item, kind)
    validateMultiplicity(multiplicityValue)
    const multiplicity = BigInt(multiplicityValue)
    rows[rowIndex] = emptyLookupBusBaseRow()
    rows[rowIndex][LOOKUP_BUS_LAYOUT.kind] = kind
    rows[rowIndex][LOOKUP_BUS_LAYOUT.tag] = tag
    rows[rowIndex][LOOKUP_BUS_LAYOUT.multiplicity] = multiplicity
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.left, left)
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.right, right)
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.publicTuple, publicTuple)
  }

  return {
    publicInput,
    baseRows: rows,
    metrics: {
      activeRows,
      paddedRows: traceLength,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
      baseTraceWidth: LOOKUP_BUS_BASE_LAYOUT.width,
      accumulatorTraceWidth: LOOKUP_BUS_ACCUMULATOR_LAYOUT.width,
      fixedTableRows: items.filter(item => item.kind === LOOKUP_BUS_ROW_KIND.lookupSupply).length,
      lookupRequests,
      lookupSupplies,
      fixedLookups: lookupRequests,
      equalityRows: items.filter(item =>
        item.kind === LOOKUP_BUS_ROW_KIND.privateEquality ||
        item.kind === LOOKUP_BUS_ROW_KIND.publicEquality
      ).length
    }
  }
}

export function buildLookupBusAir (
  publicInput: LookupBusPublicInput
): AirDefinition {
  validateLookupBusPublicInput(publicInput)
  const digest = lookupBusPublicInputDigest(publicInput)
  return {
    traceWidth: LOOKUP_BUS_LAYOUT.width,
    transitionDegree: 11,
    publicInputDigest: digest,
    boundaryConstraints: [],
    fullBoundaryColumns: [
      {
        column: LOOKUP_BUS_LAYOUT.kind,
        values: publicInput.scheduleRows.map(row => row.kind)
      },
      {
        column: LOOKUP_BUS_LAYOUT.tag,
        values: publicInput.scheduleRows.map(row => row.tag)
      },
      ...Array.from({ length: LOOKUP_BUS_TUPLE_ARITY }, (_, index) => ({
        column: LOOKUP_BUS_LAYOUT.publicTuple + index,
        values: publicInput.scheduleRows.map(row => row.publicTuple[index])
      }))
    ],
    evaluateTransition: (current, next) =>
      evaluateLookupBusBaseTransition(current, next)
  }
}

export function buildLookupBusAccumulatorAir (
  publicInput: LookupBusPublicInput,
  challengeInput: LookupBusChallengeInput
): AirDefinition {
  validateLookupBusPublicInput(publicInput)
  const lastRow = publicInput.traceLength - 1
  return {
    traceWidth: LOOKUP_BUS_ACCUMULATOR_LAYOUT.width,
    transitionDegree: 1,
    publicInputDigest: lookupBusAccumulatorPublicInputDigest(
      publicInput,
      challengeInput
    ),
    boundaryConstraints: [
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator0, row: 0, value: 0n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator1, row: 0, value: 0n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator0, row: 0, value: 1n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator1, row: 0, value: 1n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupRequestCount, row: 0, value: 0n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator0, row: lastRow, value: 0n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator1, row: lastRow, value: 0n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator0, row: lastRow, value: 1n },
      { column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator1, row: lastRow, value: 1n },
      {
        column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupRequestCount,
        row: lastRow,
        value: BigInt(publicInput.expectedLookupRequests)
      }
    ],
    fullBoundaryColumns: [{
      column: LOOKUP_BUS_ACCUMULATOR_LAYOUT.transitionActive,
      values: Array.from({ length: publicInput.traceLength }, (_, row) =>
        row + 1 < publicInput.traceLength ? 1n : 0n
      )
    }],
    evaluateTransition: () => []
  }
}

export function proveLookupBus (
  trace: LookupBusTrace,
  options: StarkProverOptions = {}
): MultiTraceStarkProof {
  const air = buildLookupBusAir(trace.publicInput)
  return provePhasedMultiTraceStark([{
    name: 'lookup-base',
    air,
    traceRows: trace.baseRows
  }], ({ committedSegments }) => {
    const base = committedSegmentByName(committedSegments, 'lookup-base')
    const challengeInput = lookupBusChallengeInput(
      trace.publicInput,
      base,
      LOOKUP_BUS_TRANSCRIPT_DOMAIN
    )
    const challenges = deriveLookupBusChallenges(challengeInput)
    const accumulatorRows = buildLookupBusAccumulatorRows(
      trace.baseRows,
      challenges
    )
    return {
      segments: [{
        name: 'lookup-accumulator',
        air: buildLookupBusAccumulatorAir(trace.publicInput, challengeInput),
        traceRows: accumulatorRows
      }],
      crossConstraints: [
        lookupBusAccumulatorCrossConstraint(
          'lookup-base',
          'lookup-accumulator',
          challengeInput,
          lookupBusCrossDegreeBound(
            trace.publicInput.traceLength,
            options.blowupFactor ?? LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS.blowupFactor
          )
        )
      ]
    }
  }, {
    ...LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS,
    ...options,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  })
}

export function verifyLookupBusProof (
  publicInput: LookupBusPublicInput,
  proof: MultiTraceStarkProof
): boolean {
  if (!lookupBusProofMeetsMinimumProfile(proof)) return false
  const air = buildLookupBusAir(publicInput)
  const baseProof = proof.segments.find(segment => segment.name === 'lookup-base')
  if (baseProof === undefined) return false
  const challengeInput = lookupBusChallengeInputFromRoot(
    publicInput,
    baseProof.proof.traceRoot,
    LOOKUP_BUS_TRANSCRIPT_DOMAIN
  )
  return verifyMultiTraceStark([
    {
      name: 'lookup-base',
      air
    },
    {
      name: 'lookup-accumulator',
      air: buildLookupBusAccumulatorAir(publicInput, challengeInput)
    }
  ], proof, {
    blowupFactor: baseProof.proof.blowupFactor,
    numQueries: baseProof.proof.numQueries,
    maxRemainderSize: baseProof.proof.maxRemainderSize,
    maskDegree: baseProof.proof.maskDegree,
    cosetOffset: baseProof.proof.cosetOffset,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  }, [
    lookupBusAccumulatorCrossConstraint(
      'lookup-base',
      'lookup-accumulator',
      challengeInput,
      lookupBusCrossDegreeBound(
        publicInput.traceLength,
        baseProof.proof.blowupFactor
      )
    )
  ])
}

export function diagnoseLookupBusProof (
  publicInput: LookupBusPublicInput,
  proof: MultiTraceStarkProof
): ReturnType<typeof diagnoseMultiTraceStark> {
  if (!lookupBusProofMeetsMinimumProfile(proof)) {
    return { ok: false, stage: 'proof-shape' }
  }
  const air = buildLookupBusAir(publicInput)
  const baseProof = proof.segments.find(segment => segment.name === 'lookup-base')
  if (baseProof === undefined) return { ok: false, stage: 'proof-shape' }
  const challengeInput = lookupBusChallengeInputFromRoot(
    publicInput,
    baseProof.proof.traceRoot,
    LOOKUP_BUS_TRANSCRIPT_DOMAIN
  )
  return diagnoseMultiTraceStark([
    {
      name: 'lookup-base',
      air
    },
    {
      name: 'lookup-accumulator',
      air: buildLookupBusAccumulatorAir(publicInput, challengeInput)
    }
  ], proof, {
    blowupFactor: baseProof.proof.blowupFactor,
    numQueries: baseProof.proof.numQueries,
    maxRemainderSize: baseProof.proof.maxRemainderSize,
    maskDegree: baseProof.proof.maskDegree,
    cosetOffset: baseProof.proof.cosetOffset,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  }, [
    lookupBusAccumulatorCrossConstraint(
      'lookup-base',
      'lookup-accumulator',
      challengeInput,
      lookupBusCrossDegreeBound(
        publicInput.traceLength,
        baseProof.proof.blowupFactor
      )
    )
  ])
}

function lookupBusProofMeetsMinimumProfile (
  proof: MultiTraceStarkProof
): boolean {
  if (proof.transcriptDomain !== LOOKUP_BUS_TRANSCRIPT_DOMAIN) return false
  if (
    proof.segments.length !== 2 ||
    proof.segments[0].name !== 'lookup-base' ||
    proof.segments[1].name !== 'lookup-accumulator'
  ) {
    return false
  }
  if ((proof.crossProofs ?? []).length !== 1) return false
  if ((proof.constantColumnProofs ?? []).length !== 0) return false
  return proof.segments.every(segment =>
    segment.proof.blowupFactor >= LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS.blowupFactor &&
    segment.proof.numQueries >= LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS.numQueries &&
    segment.proof.maxRemainderSize >= LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS.maxRemainderSize &&
    segment.proof.maskDegree >= LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS.maskDegree &&
    segment.proof.cosetOffset !== 0n
  )
}

function lookupBusCrossDegreeBound (
  traceLength: number,
  blowupFactor: number
): number {
  return Math.min(traceLength * 12, traceLength * blowupFactor - 1)
}

export function lookupBusMetrics (
  trace: LookupBusTrace,
  proof?: MultiTraceStarkProof
): LookupBusMetrics {
  return {
    ...trace.metrics,
    proofBytes: proof === undefined
      ? undefined
      : serializeMultiTraceStarkProof(proof).length
  }
}

export function lookupBusPublicInputDigest (
  publicInput: LookupBusPublicInput
): number[] {
  validateLookupBusPublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(LOOKUP_BUS_PUBLIC_INPUT_DIGEST_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.expectedLookupRequests)
  writer.writeVarIntNum(publicInput.scheduleRows.length)
  for (const row of publicInput.scheduleRows) {
    writeField(writer, row.kind)
    writeField(writer, row.tag)
    for (const value of row.publicTuple) writeField(writer, value)
  }
  return sha256(writer.toArray())
}

export function evaluateLookupBusBaseTransition (
  current: FieldElement[],
  next: FieldElement[]
): FieldElement[] {
  void next
  const layout = LOOKUP_BUS_LAYOUT
  const kind = current[layout.kind]
  const multiplicity = current[layout.multiplicity]
  const inactive = kindSelector(kind, LOOKUP_BUS_ROW_KIND.inactive)
  const request = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupRequest)
  const supply = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupSupply)
  const privateEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.privateEquality)
  const publicEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.publicEquality)
  const equality = F.add(privateEquality, publicEquality)
  const constraints: FieldElement[] = [
    kindDomainConstraint(kind),
    F.mul(inactive, multiplicity),
    F.mul(request, F.sub(multiplicity, 1n)),
    F.mul(supply, multiplicityRangeConstraint(multiplicity)),
    F.mul(equality, F.sub(multiplicity, 1n))
  ]

  for (let i = 0; i < LOOKUP_BUS_TUPLE_ARITY; i++) {
    const left = current[layout.left + i]
    const right = current[layout.right + i]
    const publicValue = current[layout.publicTuple + i]
    constraints.push(F.mul(equality, F.sub(left, right)))
    constraints.push(F.mul(supply, F.sub(left, publicValue)))
    constraints.push(F.mul(supply, F.sub(right, publicValue)))
    constraints.push(F.mul(publicEquality, F.sub(right, publicValue)))
    constraints.push(F.mul(inactive, left))
    constraints.push(F.mul(inactive, right))
  }

  return constraints
}

export function evaluateLookupBusAccumulatorTransition (
  baseCurrent: FieldElement[],
  accumulatorCurrent: FieldElement[],
  accumulatorNext: FieldElement[],
  challenges: LookupBusChallenges
): FieldElement[] {
  const base = LOOKUP_BUS_BASE_LAYOUT
  const acc = LOOKUP_BUS_ACCUMULATOR_LAYOUT
  const kind = baseCurrent[base.kind]
  const tag = baseCurrent[base.tag]
  const multiplicity = baseCurrent[base.multiplicity]
  const request = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupRequest)
  const supply = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupSupply)
  const privateEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.privateEquality)
  const publicEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.publicEquality)
  const lookup = F.add(request, supply)
  const active = accumulatorCurrent[acc.transitionActive]
  const compressedLeft0 = compressPaddedLookupBusTuple(
    tag,
    baseCurrent,
    base.left,
    challenges.alphaPowers0
  )
  const compressedLeft1 = compressPaddedLookupBusTuple(
    tag,
    baseCurrent,
    base.left,
    challenges.alphaPowers1
  )
  const compressedRight0 = compressPaddedLookupBusTuple(
    tag,
    baseCurrent,
    base.right,
    challenges.alphaPowers0
  )
  const compressedRight1 = compressPaddedLookupBusTuple(
    tag,
    baseCurrent,
    base.right,
    challenges.alphaPowers1
  )
  const lookupFactor0 = F.add(challenges.beta0, compressedLeft0)
  const lookupFactor1 = F.add(challenges.beta1, compressedLeft1)
  const lookupFactorPower0 = powerForMultiplicity(lookupFactor0, multiplicity)
  const lookupFactorPower1 = powerForMultiplicity(lookupFactor1, multiplicity)
  const equalityDelta0 = equalityContribution(
    kind,
    multiplicity,
    compressedLeft0,
    compressedRight0
  )
  const equalityDelta1 = equalityContribution(
    kind,
    multiplicity,
    compressedLeft1,
    compressedRight1
  )
  const expectedLookupAccumulator0 = lookupAccumulatorNext(
    accumulatorCurrent[acc.lookupAccumulator0],
    request,
    supply,
    lookupFactor0,
    accumulatorCurrent[acc.lookupInverse0]
  )
  const expectedLookupAccumulator1 = lookupAccumulatorNext(
    accumulatorCurrent[acc.lookupAccumulator1],
    request,
    supply,
    lookupFactor1,
    accumulatorCurrent[acc.lookupInverse1]
  )
  return [
    F.mul(active, F.mul(supply, F.sub(
      F.mul(accumulatorCurrent[acc.lookupInverse0], lookupFactorPower0),
      1n
    ))),
    F.mul(active, F.mul(supply, F.sub(
      F.mul(accumulatorCurrent[acc.lookupInverse1], lookupFactorPower1),
      1n
    ))),
    F.mul(active, F.mul(F.sub(1n, supply), accumulatorCurrent[acc.lookupInverse0])),
    F.mul(active, F.mul(F.sub(1n, supply), accumulatorCurrent[acc.lookupInverse1])),
    F.mul(active, F.sub(accumulatorNext[acc.equalityAccumulator0], F.add(
      accumulatorCurrent[acc.equalityAccumulator0],
      equalityDelta0
    ))),
    F.mul(active, F.sub(accumulatorNext[acc.equalityAccumulator1], F.add(
      accumulatorCurrent[acc.equalityAccumulator1],
      equalityDelta1
    ))),
    F.mul(active, F.sub(accumulatorNext[acc.lookupAccumulator0], expectedLookupAccumulator0)),
    F.mul(active, F.sub(accumulatorNext[acc.lookupAccumulator1], expectedLookupAccumulator1)),
    F.mul(active, F.sub(accumulatorNext[acc.lookupRequestCount], F.add(
      accumulatorCurrent[acc.lookupRequestCount],
      request
    ))),
    F.mul(active, F.mul(F.sub(1n, lookup), accumulatorCurrent[acc.lookupInverse0])),
    F.mul(active, F.mul(F.sub(1n, lookup), accumulatorCurrent[acc.lookupInverse1]))
  ]
}

export function compressLookupBusTuple (
  tag: FieldElement,
  values: FieldElement[],
  alpha: FieldElement
): FieldElement {
  return compressPaddedLookupBusTuple(
    F.normalize(tag),
    normalizeTuple(values),
    0,
    lookupChallengePowers(alpha)
  )
}

function compressPaddedLookupBusTuple (
  tag: FieldElement,
  tuple: FieldElement[],
  offset: number,
  powers: FieldElement[]
): FieldElement {
  let accumulator = F.normalize(tag)
  for (let i = 0; i < LOOKUP_BUS_TUPLE_ARITY; i++) {
    accumulator = F.add(accumulator, F.mul(powers[i], tuple[offset + i]))
  }
  return accumulator
}

export function lookupBusChallengeDigest (
  input: LookupBusChallengeInput
): number[] {
  assertDigest(input.publicInputDigest, 'lookup bus public input digest')
  assertDigest(input.baseTraceRoot, 'lookup bus base trace root')
  const writer = new Writer()
  writer.write(toArray('BRC69_LOOKUP_BUS_POST_COMMITMENT_CHALLENGES_V1', 'utf8'))
  writer.write(toArray(input.transcriptDomain ?? LOOKUP_BUS_TRANSCRIPT_DOMAIN, 'utf8'))
  writer.write(input.publicInputDigest)
  writer.write(input.baseTraceRoot)
  return sha256(writer.toArray())
}

export function lookupBusChallengeInputFromRoot (
  publicInput: LookupBusPublicInput,
  baseTraceRoot: number[],
  transcriptDomain = LOOKUP_BUS_TRANSCRIPT_DOMAIN
): LookupBusChallengeInput {
  return {
    publicInputDigest: lookupBusPublicInputDigest(publicInput),
    baseTraceRoot: baseTraceRoot.slice(),
    transcriptDomain
  }
}

export function lookupBusChallengeInput (
  publicInput: LookupBusPublicInput,
  base: MultiTraceCommittedSegmentSummary,
  transcriptDomain = LOOKUP_BUS_TRANSCRIPT_DOMAIN
): LookupBusChallengeInput {
  return lookupBusChallengeInputFromRoot(
    publicInput,
    base.traceRoot,
    transcriptDomain
  )
}

export function lookupBusAccumulatorPublicInputDigest (
  publicInput: LookupBusPublicInput,
  challengeInput: LookupBusChallengeInput
): number[] {
  const writer = new Writer()
  writer.write(toArray('BRC69_LOOKUP_BUS_ACCUMULATOR_AIR_V1', 'utf8'))
  writer.write(lookupBusPublicInputDigest(publicInput))
  writer.write(lookupBusChallengeDigest(challengeInput))
  return sha256(writer.toArray())
}

export function deriveLookupBusChallenges (
  input: LookupBusChallengeInput
): LookupBusChallenges {
  const challengeDigest = lookupBusChallengeDigest(input)
  const transcript = new FiatShamirTranscript(`${LOOKUP_BUS_TRANSCRIPT_DOMAIN}:challenges`)
  transcript.absorb('post-commitment-challenge-digest', challengeDigest)
  const alpha0 = nonZeroChallenge(transcript, 'alpha-0')
  const alpha1 = nonZeroChallenge(transcript, 'alpha-1')
  return {
    alpha0,
    alpha1,
    alphaPowers0: lookupChallengePowers(alpha0),
    alphaPowers1: lookupChallengePowers(alpha1),
    beta0: nonZeroChallenge(transcript, 'beta-0'),
    beta1: nonZeroChallenge(transcript, 'beta-1')
  }
}

export function buildLookupBusAccumulatorRows (
  baseRows: FieldElement[][],
  challenges: LookupBusChallenges
): FieldElement[][] {
  const rows = new Array<FieldElement[]>(baseRows.length)
  let equalityAccumulator0 = 0n
  let equalityAccumulator1 = 0n
  let lookupAccumulator0 = 1n
  let lookupAccumulator1 = 1n
  let lookupRequestCount = 0n
  for (let rowIndex = 0; rowIndex < baseRows.length; rowIndex++) {
    const baseRow = baseRows[rowIndex]
    const kind = baseRow[LOOKUP_BUS_BASE_LAYOUT.kind]
    const tag = baseRow[LOOKUP_BUS_BASE_LAYOUT.tag]
    const multiplicity = baseRow[LOOKUP_BUS_BASE_LAYOUT.multiplicity]
    const compressedLeft0 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : compressPaddedLookupBusTuple(
        tag,
        baseRow,
        LOOKUP_BUS_BASE_LAYOUT.left,
        challenges.alphaPowers0
      )
    const compressedLeft1 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : compressPaddedLookupBusTuple(
        tag,
        baseRow,
        LOOKUP_BUS_BASE_LAYOUT.left,
        challenges.alphaPowers1
      )
    const lookupFactor0 = isLookupKind(kind)
      ? F.add(challenges.beta0, compressedLeft0)
      : 0n
    const lookupFactor1 = isLookupKind(kind)
      ? F.add(challenges.beta1, compressedLeft1)
      : 0n
    const lookupInverse0 = kind === LOOKUP_BUS_ROW_KIND.lookupSupply
      ? F.inv(powerForMultiplicityValue(lookupFactor0, Number(multiplicity)))
      : 0n
    const lookupInverse1 = kind === LOOKUP_BUS_ROW_KIND.lookupSupply
      ? F.inv(powerForMultiplicityValue(lookupFactor1, Number(multiplicity)))
      : 0n
    const row = new Array<FieldElement>(LOOKUP_BUS_ACCUMULATOR_LAYOUT.width).fill(0n)
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse0] = lookupInverse0
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse1] = lookupInverse1
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator0] = equalityAccumulator0
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.equalityAccumulator1] = equalityAccumulator1
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator0] = lookupAccumulator0
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator1] = lookupAccumulator1
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupRequestCount] = lookupRequestCount
    row[LOOKUP_BUS_ACCUMULATOR_LAYOUT.transitionActive] =
      rowIndex + 1 < baseRows.length ? 1n : 0n
    rows[rowIndex] = row

    if (rowIndex + 1 < baseRows.length) {
      const contribution = evaluateLookupBusAccumulatorStep(
        baseRow,
        row,
        challenges
      )
      equalityAccumulator0 = F.add(
        equalityAccumulator0,
        contribution.equalityDelta0
      )
      equalityAccumulator1 = F.add(
        equalityAccumulator1,
        contribution.equalityDelta1
      )
      lookupAccumulator0 = contribution.lookupAccumulator0
      lookupAccumulator1 = contribution.lookupAccumulator1
      lookupRequestCount = F.add(
        lookupRequestCount,
        kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupRequest)
      )
    }
  }
  return rows
}

export function lookupBusAccumulatorCrossConstraint (
  baseSegment: string,
  accumulatorSegment: string,
  challengeInput: LookupBusChallengeInput,
  degreeBound?: number
): MultiTraceCrossConstraintInput {
  const challenges = deriveLookupBusChallenges(challengeInput)
  return {
    name: 'lookup-bus-accumulator',
    degreeBound,
    refs: [
      { alias: 'base', segment: baseSegment },
      { alias: 'accumulator', segment: accumulatorSegment },
      { alias: 'nextAccumulator', segment: accumulatorSegment, shift: 1 }
    ],
    evaluate: ({ rows }) => evaluateLookupBusAccumulatorTransition(
      rows.base,
      rows.accumulator,
      rows.nextAccumulator,
      challenges
    )
  }
}

function lookupChallengePowers (alpha: FieldElement): FieldElement[] {
  const powers = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY)
  let power = F.normalize(alpha)
  for (let i = 0; i < LOOKUP_BUS_TUPLE_ARITY; i++) {
    powers[i] = power
    power = F.mul(power, alpha)
  }
  return powers
}

function nonZeroChallenge (
  transcript: FiatShamirTranscript,
  label: string
): FieldElement {
  for (let i = 0; i < 16; i++) {
    const value = transcript.challengeFieldElement(`${label}-${i}`)
    if (value !== 0n) return value
  }
  throw new Error('Lookup bus could not derive non-zero challenge')
}

function equalityContribution (
  kind: FieldElement,
  multiplicity: FieldElement,
  left: FieldElement,
  right: FieldElement
): FieldElement {
  const equality = F.add(
    kindSelector(kind, LOOKUP_BUS_ROW_KIND.privateEquality),
    kindSelector(kind, LOOKUP_BUS_ROW_KIND.publicEquality)
  )
  return F.mul(equality, F.mul(multiplicity, F.sub(left, right)))
}

function lookupAccumulatorNext (
  current: FieldElement,
  request: FieldElement,
  supply: FieldElement,
  factor: FieldElement,
  inverse: FieldElement
): FieldElement {
  const requestNext = F.mul(current, factor)
  const supplyNext = F.mul(current, inverse)
  let expected = current
  expected = F.add(expected, F.mul(request, F.sub(requestNext, current)))
  expected = F.add(expected, F.mul(supply, F.sub(supplyNext, current)))
  return expected
}

function evaluateLookupBusAccumulatorStep (
  baseRow: FieldElement[],
  accumulatorRow: FieldElement[],
  challenges: LookupBusChallenges
): {
    equalityDelta0: FieldElement
    equalityDelta1: FieldElement
    lookupAccumulator0: FieldElement
    lookupAccumulator1: FieldElement
  } {
  const kind = baseRow[LOOKUP_BUS_BASE_LAYOUT.kind]
  const tag = baseRow[LOOKUP_BUS_BASE_LAYOUT.tag]
  const multiplicity = baseRow[LOOKUP_BUS_BASE_LAYOUT.multiplicity]
  const request = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupRequest)
  const supply = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupSupply)
  const compressedLeft0 = compressPaddedLookupBusTuple(
    tag,
    baseRow,
    LOOKUP_BUS_BASE_LAYOUT.left,
    challenges.alphaPowers0
  )
  const compressedLeft1 = compressPaddedLookupBusTuple(
    tag,
    baseRow,
    LOOKUP_BUS_BASE_LAYOUT.left,
    challenges.alphaPowers1
  )
  const compressedRight0 = compressPaddedLookupBusTuple(
    tag,
    baseRow,
    LOOKUP_BUS_BASE_LAYOUT.right,
    challenges.alphaPowers0
  )
  const compressedRight1 = compressPaddedLookupBusTuple(
    tag,
    baseRow,
    LOOKUP_BUS_BASE_LAYOUT.right,
    challenges.alphaPowers1
  )
  const lookupFactor0 = F.add(challenges.beta0, compressedLeft0)
  const lookupFactor1 = F.add(challenges.beta1, compressedLeft1)
  return {
    equalityDelta0: equalityContribution(
      kind,
      multiplicity,
      compressedLeft0,
      compressedRight0
    ),
    equalityDelta1: equalityContribution(
      kind,
      multiplicity,
      compressedLeft1,
      compressedRight1
    ),
    lookupAccumulator0: lookupAccumulatorNext(
      accumulatorRow[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator0],
      request,
      supply,
      lookupFactor0,
      accumulatorRow[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse0]
    ),
    lookupAccumulator1: lookupAccumulatorNext(
      accumulatorRow[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupAccumulator1],
      request,
      supply,
      lookupFactor1,
      accumulatorRow[LOOKUP_BUS_ACCUMULATOR_LAYOUT.lookupInverse1]
    )
  }
}

function kindDomainConstraint (kind: FieldElement): FieldElement {
  let out = 1n
  for (const candidate of LOOKUP_BUS_CANONICAL_ROW_KINDS) {
    out = F.mul(out, F.sub(kind, candidate))
  }
  return out
}

function kindSelector (
  kind: FieldElement,
  target: FieldElement
): FieldElement {
  let numerator = 1n
  for (const candidate of LOOKUP_BUS_CANONICAL_ROW_KINDS) {
    if (candidate === target) continue
    numerator = F.mul(numerator, F.sub(kind, candidate))
  }
  return F.mul(
    numerator,
    LOOKUP_BUS_KIND_SELECTOR_DENOMINATOR_INVERSES[target.toString()]
  )
}

function multiplicityRangeConstraint (multiplicity: FieldElement): FieldElement {
  let out = 1n
  for (let i = 0; i <= LOOKUP_BUS_MAX_MULTIPLICITY; i++) {
    out = F.mul(out, F.sub(multiplicity, BigInt(i)))
  }
  return out
}

function powerForMultiplicity (
  factor: FieldElement,
  multiplicity: FieldElement
): FieldElement {
  let out = 0n
  for (let i = 0; i <= LOOKUP_BUS_MAX_MULTIPLICITY; i++) {
    out = F.add(out, F.mul(
      multiplicitySelector(multiplicity, i),
      powerForMultiplicityValue(factor, i)
    ))
  }
  return out
}

function multiplicitySelector (
  multiplicity: FieldElement,
  target: number
): FieldElement {
  let numerator = 1n
  for (let candidate = 0; candidate <= LOOKUP_BUS_MAX_MULTIPLICITY; candidate++) {
    if (candidate === target) continue
    numerator = F.mul(numerator, F.sub(multiplicity, BigInt(candidate)))
  }
  return F.mul(
    numerator,
    LOOKUP_BUS_MULTIPLICITY_SELECTOR_DENOMINATOR_INVERSES[target]
  )
}

function powerForMultiplicityValue (
  factor: FieldElement,
  multiplicity: number
): FieldElement {
  let out = 1n
  for (let i = 0; i < multiplicity; i++) out = F.mul(out, factor)
  return out
}

function validateLookupBusPublicInput (publicInput: LookupBusPublicInput): void {
  if (
    !Number.isSafeInteger(publicInput.traceLength) ||
    publicInput.traceLength < 2 ||
    !isPowerOfTwo(publicInput.traceLength)
  ) {
    throw new Error('Lookup bus trace length must be a power of two')
  }
  if (
    !Number.isSafeInteger(publicInput.expectedLookupRequests) ||
    publicInput.expectedLookupRequests < 0
  ) {
    throw new Error('Lookup bus expected lookup request count is invalid')
  }
  if (publicInput.scheduleRows.length !== publicInput.traceLength) {
    throw new Error('Lookup bus schedule length mismatch')
  }
  for (const row of publicInput.scheduleRows) {
    normalizeKind(row.kind)
    F.assertCanonical(row.tag)
    if (row.publicTuple.length !== LOOKUP_BUS_TUPLE_ARITY) {
      throw new Error('Lookup bus public tuple arity mismatch')
    }
    for (const value of row.publicTuple) F.assertCanonical(value)
  }
}

function normalizeKind (kind: FieldElement): FieldElement {
  const normalized = F.normalize(kind)
  if (!LOOKUP_BUS_CANONICAL_ROW_KINDS.some(value => value === normalized)) {
    throw new Error('Lookup bus row kind is invalid')
  }
  return normalized
}

function validateMultiplicity (multiplicity: number): void {
  if (
    !Number.isSafeInteger(multiplicity) ||
    multiplicity < 0 ||
    multiplicity > LOOKUP_BUS_MAX_MULTIPLICITY
  ) {
    throw new Error('Lookup bus multiplicity is invalid')
  }
}

function isLookupKind (kind: FieldElement): boolean {
  return kind === LOOKUP_BUS_ROW_KIND.lookupRequest ||
    kind === LOOKUP_BUS_ROW_KIND.lookupSupply
}

function itemMultiplicity (
  item: LookupBusTraceItem | undefined,
  kind: FieldElement
): number {
  if (item === undefined) return 0
  if (item.multiplicity !== undefined) return item.multiplicity
  if (
    kind === LOOKUP_BUS_ROW_KIND.lookupRequest ||
    kind === LOOKUP_BUS_ROW_KIND.privateEquality ||
    kind === LOOKUP_BUS_ROW_KIND.publicEquality
  ) {
    return 1
  }
  return 0
}

function emptyLookupBusBaseRow (): FieldElement[] {
  return new Array<FieldElement>(LOOKUP_BUS_LAYOUT.width).fill(0n)
}

function normalizeTuple (values: FieldElement[]): FieldElement[] {
  if (values.length === 0) return LOOKUP_BUS_ZERO_TUPLE
  if (values.length === LOOKUP_BUS_TUPLE_ARITY) {
    let canonical = true
    for (const value of values) {
      if (F.normalize(value) !== value) {
        canonical = false
        break
      }
    }
    if (canonical) return values
  }
  if (values.length > LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('Lookup bus tuple is too wide')
  }
  const out = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  for (let i = 0; i < values.length; i++) {
    out[i] = F.normalize(values[i])
  }
  return out
}

function padTuple (values: FieldElement[]): FieldElement[] {
  return normalizeTuple(values).slice()
}

function writePaddedTuple (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < LOOKUP_BUS_TUPLE_ARITY; i++) {
    row[offset + i] = values[i]
  }
}

function tuplesEqual (
  left: FieldElement[],
  right: FieldElement[]
): boolean {
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false
  }
  return true
}

function assertDigest (bytes: number[], name: string): void {
  if (!Array.isArray(bytes) || bytes.length !== 32) {
    throw new Error(`${name} must be 32 bytes`)
  }
  for (const byte of bytes) {
    if (!Number.isSafeInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${name} contains invalid byte`)
    }
  }
}

function committedSegmentByName (
  segments: MultiTraceCommittedSegmentSummary[],
  name: string
): MultiTraceCommittedSegmentSummary {
  const segment = segments.find(item => item.name === name)
  if (segment === undefined) {
    throw new Error(`lookup bus committed segment is missing: ${name}`)
  }
  return segment
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(value))
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function isPowerOfTwo (value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0
}
