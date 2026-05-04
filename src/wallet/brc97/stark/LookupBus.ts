import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from './Air.js'
import { F, FieldElement } from './Field.js'
import { StarkProof, StarkProverOptions, proveStark, serializeStarkProof, verifyStark } from './Stark.js'
import { FiatShamirTranscript } from './Transcript.js'

export const LOOKUP_BUS_TRANSCRIPT_DOMAIN = 'BRC97_LOOKUP_BUS_PROTOTYPE_V1'
export const LOOKUP_BUS_PUBLIC_INPUT_DIGEST_ID =
  'BRC97_LOOKUP_BUS_PUBLIC_INPUT_DIGEST_V1'
export const LOOKUP_BUS_TUPLE_ARITY = 23
export const LOOKUP_BUS_MAX_MULTIPLICITY = 3

export const LOOKUP_BUS_TAG_RANGE16 = 1n
export const LOOKUP_BUS_TAG_TOY_POINT_PAIR = 2n
export const LOOKUP_BUS_TAG_PRIVATE_EQUALITY = 3n
export const LOOKUP_BUS_TAG_PUBLIC_EQUALITY = 4n
export const LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR = 5n

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
  compressedLeft0: number
  compressedLeft1: number
  compressedRight0: number
  compressedRight1: number
  lookupFactor0: number
  lookupFactor1: number
  lookupInverse0: number
  lookupInverse1: number
  equalityAccumulator0: number
  equalityAccumulator1: number
  lookupAccumulator0: number
  lookupAccumulator1: number
  lookupRequestCount: number
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
  rows: FieldElement[][]
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
  proofBytes?: number
}

export interface LookupBusTableRow {
  tag: FieldElement
  values: FieldElement[]
}

export const LOOKUP_BUS_LAYOUT: LookupBusLayout = {
  kind: 0,
  tag: 1,
  multiplicity: 2,
  left: 3,
  right: 3 + LOOKUP_BUS_TUPLE_ARITY,
  publicTuple: 3 + LOOKUP_BUS_TUPLE_ARITY * 2,
  compressedLeft0: 3 + LOOKUP_BUS_TUPLE_ARITY * 3,
  compressedLeft1: 4 + LOOKUP_BUS_TUPLE_ARITY * 3,
  compressedRight0: 5 + LOOKUP_BUS_TUPLE_ARITY * 3,
  compressedRight1: 6 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupFactor0: 7 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupFactor1: 8 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupInverse0: 9 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupInverse1: 10 + LOOKUP_BUS_TUPLE_ARITY * 3,
  equalityAccumulator0: 11 + LOOKUP_BUS_TUPLE_ARITY * 3,
  equalityAccumulator1: 12 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupAccumulator0: 13 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupAccumulator1: 14 + LOOKUP_BUS_TUPLE_ARITY * 3,
  lookupRequestCount: 15 + LOOKUP_BUS_TUPLE_ARITY * 3,
  width: 16 + LOOKUP_BUS_TUPLE_ARITY * 3
}

interface LookupBusChallenges {
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
  const digest = lookupBusPublicInputDigest(publicInput)
  const challenges = deriveLookupBusChallenges(digest)
  let equalityAccumulator0 = 0n
  let equalityAccumulator1 = 0n
  let lookupAccumulator0 = 1n
  let lookupAccumulator1 = 1n
  let lookupRequestCount = 0n

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
    const compressedLeft0 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : compressPaddedLookupBusTuple(tag, left, 0, challenges.alphaPowers0)
    const compressedLeft1 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : compressPaddedLookupBusTuple(tag, left, 0, challenges.alphaPowers1)
    const sameTuple = left === right || tuplesEqual(left, right)
    const compressedRight0 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : sameTuple
        ? compressedLeft0
        : compressPaddedLookupBusTuple(tag, right, 0, challenges.alphaPowers0)
    const compressedRight1 = kind === LOOKUP_BUS_ROW_KIND.inactive
      ? 0n
      : sameTuple
        ? compressedLeft1
        : compressPaddedLookupBusTuple(tag, right, 0, challenges.alphaPowers1)
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

    rows[rowIndex] = emptyLookupBusRow()
    rows[rowIndex][LOOKUP_BUS_LAYOUT.kind] = kind
    rows[rowIndex][LOOKUP_BUS_LAYOUT.tag] = tag
    rows[rowIndex][LOOKUP_BUS_LAYOUT.multiplicity] = multiplicity
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.left, left)
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.right, right)
    writePaddedTuple(rows[rowIndex], LOOKUP_BUS_LAYOUT.publicTuple, publicTuple)
    rows[rowIndex][LOOKUP_BUS_LAYOUT.compressedLeft0] = compressedLeft0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.compressedLeft1] = compressedLeft1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.compressedRight0] = compressedRight0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.compressedRight1] = compressedRight1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupFactor0] = lookupFactor0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupFactor1] = lookupFactor1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupInverse0] = lookupInverse0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupInverse1] = lookupInverse1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.equalityAccumulator0] = equalityAccumulator0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.equalityAccumulator1] = equalityAccumulator1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupAccumulator0] = lookupAccumulator0
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupAccumulator1] = lookupAccumulator1
    rows[rowIndex][LOOKUP_BUS_LAYOUT.lookupRequestCount] = lookupRequestCount

    if (rowIndex < traceLength - 1) {
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
      equalityAccumulator0 = F.add(equalityAccumulator0, equalityDelta0)
      equalityAccumulator1 = F.add(equalityAccumulator1, equalityDelta1)
      if (kind === LOOKUP_BUS_ROW_KIND.lookupRequest) {
        lookupAccumulator0 = F.mul(lookupAccumulator0, lookupFactor0)
        lookupAccumulator1 = F.mul(lookupAccumulator1, lookupFactor1)
        lookupRequestCount = F.add(lookupRequestCount, 1n)
      } else if (kind === LOOKUP_BUS_ROW_KIND.lookupSupply) {
        lookupAccumulator0 = F.mul(lookupAccumulator0, lookupInverse0)
        lookupAccumulator1 = F.mul(lookupAccumulator1, lookupInverse1)
      }
    }
  }

  return {
    publicInput,
    rows,
    metrics: {
      activeRows,
      paddedRows: traceLength,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
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
  const challenges = deriveLookupBusChallenges(digest)
  const lastRow = publicInput.traceLength - 1
  return {
    traceWidth: LOOKUP_BUS_LAYOUT.width,
    transitionDegree: 11,
    publicInputDigest: digest,
    boundaryConstraints: [
      { column: LOOKUP_BUS_LAYOUT.equalityAccumulator0, row: 0, value: 0n },
      { column: LOOKUP_BUS_LAYOUT.equalityAccumulator1, row: 0, value: 0n },
      { column: LOOKUP_BUS_LAYOUT.lookupAccumulator0, row: 0, value: 1n },
      { column: LOOKUP_BUS_LAYOUT.lookupAccumulator1, row: 0, value: 1n },
      { column: LOOKUP_BUS_LAYOUT.lookupRequestCount, row: 0, value: 0n },
      { column: LOOKUP_BUS_LAYOUT.equalityAccumulator0, row: lastRow, value: 0n },
      { column: LOOKUP_BUS_LAYOUT.equalityAccumulator1, row: lastRow, value: 0n },
      { column: LOOKUP_BUS_LAYOUT.lookupAccumulator0, row: lastRow, value: 1n },
      { column: LOOKUP_BUS_LAYOUT.lookupAccumulator1, row: lastRow, value: 1n },
      {
        column: LOOKUP_BUS_LAYOUT.lookupRequestCount,
        row: lastRow,
        value: BigInt(publicInput.expectedLookupRequests)
      }
    ],
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
      evaluateLookupBusTransition(current, next, challenges)
  }
}

export function proveLookupBus (
  trace: LookupBusTrace,
  options: StarkProverOptions = {}
): StarkProof {
  const air = buildLookupBusAir(trace.publicInput)
  return proveStark(air, trace.rows, {
    ...LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  })
}

export function verifyLookupBusProof (
  publicInput: LookupBusPublicInput,
  proof: StarkProof
): boolean {
  const air = buildLookupBusAir(publicInput)
  return verifyStark(air, proof, {
    ...LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
  })
}

export function lookupBusMetrics (
  trace: LookupBusTrace,
  proof?: StarkProof
): LookupBusMetrics {
  return {
    ...trace.metrics,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
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

export function evaluateLookupBusTransition (
  current: FieldElement[],
  next: FieldElement[],
  challenges: LookupBusChallenges
): FieldElement[] {
  const layout = LOOKUP_BUS_LAYOUT
  const kind = current[layout.kind]
  const tag = current[layout.tag]
  const multiplicity = current[layout.multiplicity]
  const inactive = kindSelector(kind, LOOKUP_BUS_ROW_KIND.inactive)
  const request = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupRequest)
  const supply = kindSelector(kind, LOOKUP_BUS_ROW_KIND.lookupSupply)
  const privateEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.privateEquality)
  const publicEquality = kindSelector(kind, LOOKUP_BUS_ROW_KIND.publicEquality)
  const equality = F.add(privateEquality, publicEquality)
  const lookup = F.add(request, supply)
  const active = F.sub(1n, inactive)
  const compressedLeft0 = compressPaddedLookupBusTuple(
    tag,
    current,
    layout.left,
    challenges.alphaPowers0
  )
  const compressedLeft1 = compressPaddedLookupBusTuple(
    tag,
    current,
    layout.left,
    challenges.alphaPowers1
  )
  const compressedRight0 = compressPaddedLookupBusTuple(
    tag,
    current,
    layout.right,
    challenges.alphaPowers0
  )
  const compressedRight1 = compressPaddedLookupBusTuple(
    tag,
    current,
    layout.right,
    challenges.alphaPowers1
  )
  const lookupFactor0 = F.add(challenges.beta0, current[layout.compressedLeft0])
  const lookupFactor1 = F.add(challenges.beta1, current[layout.compressedLeft1])
  const lookupFactorPower0 = powerForMultiplicity(lookupFactor0, multiplicity)
  const lookupFactorPower1 = powerForMultiplicity(lookupFactor1, multiplicity)
  const equalityDelta0 = equalityContribution(
    kind,
    multiplicity,
    current[layout.compressedLeft0],
    current[layout.compressedRight0]
  )
  const equalityDelta1 = equalityContribution(
    kind,
    multiplicity,
    current[layout.compressedLeft1],
    current[layout.compressedRight1]
  )
  const expectedLookupAccumulator0 = lookupAccumulatorNext(
    current[layout.lookupAccumulator0],
    request,
    supply,
    current[layout.lookupFactor0],
    current[layout.lookupInverse0]
  )
  const expectedLookupAccumulator1 = lookupAccumulatorNext(
    current[layout.lookupAccumulator1],
    request,
    supply,
    current[layout.lookupFactor1],
    current[layout.lookupInverse1]
  )
  const constraints: FieldElement[] = [
    kindDomainConstraint(kind),
    F.mul(inactive, multiplicity),
    F.mul(request, F.sub(multiplicity, 1n)),
    F.mul(supply, multiplicityRangeConstraint(multiplicity)),
    F.mul(equality, F.sub(multiplicity, 1n)),
    F.mul(active, F.sub(current[layout.compressedLeft0], compressedLeft0)),
    F.mul(active, F.sub(current[layout.compressedLeft1], compressedLeft1)),
    F.mul(active, F.sub(current[layout.compressedRight0], compressedRight0)),
    F.mul(active, F.sub(current[layout.compressedRight1], compressedRight1)),
    F.mul(active, F.sub(current[layout.compressedLeft0], current[layout.compressedRight0])),
    F.mul(active, F.sub(current[layout.compressedLeft1], current[layout.compressedRight1])),
    F.mul(lookup, F.sub(current[layout.lookupFactor0], lookupFactor0)),
    F.mul(lookup, F.sub(current[layout.lookupFactor1], lookupFactor1)),
    F.mul(F.sub(1n, lookup), current[layout.lookupFactor0]),
    F.mul(F.sub(1n, lookup), current[layout.lookupFactor1]),
    F.mul(supply, F.sub(F.mul(current[layout.lookupInverse0], lookupFactorPower0), 1n)),
    F.mul(supply, F.sub(F.mul(current[layout.lookupInverse1], lookupFactorPower1), 1n)),
    F.mul(F.sub(1n, supply), current[layout.lookupInverse0]),
    F.mul(F.sub(1n, supply), current[layout.lookupInverse1]),
    F.sub(next[layout.equalityAccumulator0], F.add(
      current[layout.equalityAccumulator0],
      equalityDelta0
    )),
    F.sub(next[layout.equalityAccumulator1], F.add(
      current[layout.equalityAccumulator1],
      equalityDelta1
    )),
    F.sub(next[layout.lookupAccumulator0], expectedLookupAccumulator0),
    F.sub(next[layout.lookupAccumulator1], expectedLookupAccumulator1),
    F.sub(next[layout.lookupRequestCount], F.add(
      current[layout.lookupRequestCount],
      request
    ))
  ]

  for (let i = 0; i < LOOKUP_BUS_TUPLE_ARITY; i++) {
    const left = current[layout.left + i]
    const right = current[layout.right + i]
    const publicValue = current[layout.publicTuple + i]
    constraints.push(F.mul(supply, F.sub(left, publicValue)))
    constraints.push(F.mul(supply, F.sub(right, publicValue)))
    constraints.push(F.mul(publicEquality, F.sub(right, publicValue)))
    constraints.push(F.mul(inactive, left))
    constraints.push(F.mul(inactive, right))
  }
  constraints.push(F.mul(inactive, current[layout.compressedLeft0]))
  constraints.push(F.mul(inactive, current[layout.compressedLeft1]))
  constraints.push(F.mul(inactive, current[layout.compressedRight0]))
  constraints.push(F.mul(inactive, current[layout.compressedRight1]))

  return constraints
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

function deriveLookupBusChallenges (publicInputDigest: number[]): LookupBusChallenges {
  const transcript = new FiatShamirTranscript(`${LOOKUP_BUS_TRANSCRIPT_DOMAIN}:challenges`)
  transcript.absorb('public-input', publicInputDigest)
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

function emptyLookupBusRow (): FieldElement[] {
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
