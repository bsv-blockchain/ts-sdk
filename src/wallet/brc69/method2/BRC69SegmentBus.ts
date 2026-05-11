import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition, BoundaryConstraint, FullBoundaryColumn } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import { LOOKUP_BUS_TUPLE_ARITY } from '../stark/LookupBus.js'
import {
  MultiTraceCommittedSegmentSummary
} from '../stark/Stark.js'
import { FiatShamirTranscript } from '../stark/Transcript.js'

export const BRC69_SEGMENT_BUS_PUBLIC_INPUT_ID =
  'BRC69_METHOD2_SEGMENT_BUS_PUBLIC_INPUT_V1'
export const BRC69_SEGMENT_BUS_COMPRESSION_CHALLENGES = 2

export const BRC69_SEGMENT_BUS_KIND_SOURCE = 1n
export const BRC69_SEGMENT_BUS_KIND_TARGET = 2n

export interface BRC69SegmentBusChallenges {
  alpha0: FieldElement
  alpha1: FieldElement
}

export interface BRC69SegmentBusContribution {
  accumulator0: FieldElement
  accumulator1: FieldElement
  emissionCount: number
}

export interface BRC69SegmentBusEndpoint {
  accumulator0: FieldElement
  accumulator1: FieldElement
}

export interface BRC69SegmentBusEmission {
  row: number
  kind: typeof BRC69_SEGMENT_BUS_KIND_SOURCE |
    typeof BRC69_SEGMENT_BUS_KIND_TARGET
  tag: FieldElement
  values: (row: FieldElement[]) => FieldElement[]
}

interface IndexedBRC69SegmentBusEmission extends BRC69SegmentBusEmission {
  selectorIndex: number
}

export interface BRC69SegmentBusWrappedTrace {
  name: string
  rows: FieldElement[][]
  air: AirDefinition
  contribution: BRC69SegmentBusContribution
  start: BRC69SegmentBusEndpoint
  end: BRC69SegmentBusEndpoint
  selectorCount: number
}

export interface BRC69SegmentBusWrappedLayout {
  selectorStart: number
  selectorCount: number
  accumulator0: number
  accumulator1: number
  start0: number
  start1: number
  end0: number
  end1: number
  first: number
  penultimate: number
  baseTransitionActive: number
  width: number
}

export interface BRC69SegmentBusPublicInput {
  segments: Record<string, {
    emissionCount: number
    selectorCount?: number
    publicStart?: BRC69SegmentBusEndpoint
    publicEnd?: BRC69SegmentBusEndpoint
  }>
}

export interface BRC69SegmentBusChallengeInput {
  publicInputDigest: number[]
  baseTraceRoot: number[]
  transcriptDomain?: string
}

export function deriveBRC69SegmentBusChallenges (
  input: BRC69SegmentBusChallengeInput
): BRC69SegmentBusChallenges {
  const challengeDigest = brc69SegmentBusChallengeDigest(input)
  const transcript = new FiatShamirTranscript(
    `${BRC69_SEGMENT_BUS_PUBLIC_INPUT_ID}:challenges`
  )
  transcript.absorb('post-commitment-challenge-digest', challengeDigest)
  return {
    alpha0: nonZeroChallenge(transcript, 'alpha-0'),
    alpha1: nonZeroChallenge(transcript, 'alpha-1')
  }
}

export function brc69SegmentBusChallengeDigest (
  input: BRC69SegmentBusChallengeInput
): number[] {
  assertDigest(input.publicInputDigest, 'BRC69 segment bus public input digest')
  assertDigest(input.baseTraceRoot, 'BRC69 segment bus base trace root')
  const writer = new Writer()
  writer.write(toArray('BRC69_SEGMENT_BUS_POST_COMMITMENT_CHALLENGES_V1', 'utf8'))
  writer.write(toArray(input.transcriptDomain ?? BRC69_SEGMENT_BUS_PUBLIC_INPUT_ID, 'utf8'))
  writer.write(input.publicInputDigest)
  writer.write(input.baseTraceRoot)
  return sha256(writer.toArray())
}

export function brc69SegmentBusChallengeInputFromRoot (
  publicInputDigest: number[],
  baseTraceRoot: number[],
  transcriptDomain?: string
): BRC69SegmentBusChallengeInput {
  return {
    publicInputDigest: publicInputDigest.slice(),
    baseTraceRoot: baseTraceRoot.slice(),
    transcriptDomain
  }
}

export function brc69SegmentBusChallengeInput (
  publicInputDigest: number[],
  base: MultiTraceCommittedSegmentSummary,
  transcriptDomain?: string
): BRC69SegmentBusChallengeInput {
  return brc69SegmentBusChallengeInputFromRoot(
    publicInputDigest,
    base.traceRoot,
    transcriptDomain
  )
}

export function brc69SegmentBusNonAdaptiveCollisionSecurityBits (
  tupleArity = LOOKUP_BUS_TUPLE_ARITY,
  challengeCount = BRC69_SEGMENT_BUS_COMPRESSION_CHALLENGES
): number {
  if (
    !Number.isSafeInteger(tupleArity) ||
    tupleArity < 1 ||
    !Number.isSafeInteger(challengeCount) ||
    challengeCount < 1
  ) {
    throw new Error('BRC69 segment bus collision parameters are invalid')
  }
  return challengeCount * (
    Math.log2(Number(F.p - 1n)) -
    Math.log2(tupleArity)
  )
}

export function buildBRC69SegmentBusAccumulatorTrace (input: {
  name: string
  baseRows: FieldElement[][]
  proofTraceLength?: number
  emissions: BRC69SegmentBusEmission[]
  challenges: BRC69SegmentBusChallenges
  start?: BRC69SegmentBusEndpoint
  publicStart?: BRC69SegmentBusEndpoint
  publicEnd?: BRC69SegmentBusEndpoint
}): BRC69SegmentBusWrappedTrace {
  const proofTraceLength = input.proofTraceLength ?? input.baseRows.length
  const emissionRows = emissionsByRow(input.emissions, proofTraceLength)
  const selectorCount = brc69SegmentBusSelectorCount(input.emissions)
  const layout = brc69SegmentBusWrappedLayout(0, selectorCount)
  const contribution = evaluateSegmentContribution(
    input.baseRows,
    emissionRows,
    input.challenges
  )
  const start = normalizeEndpoint(input.start ?? {
    accumulator0: 0n,
    accumulator1: 0n
  })
  const end = {
    accumulator0: F.add(start.accumulator0, contribution.accumulator0),
    accumulator1: F.add(start.accumulator1, contribution.accumulator1)
  }
  const rows = appendAccumulatorOnlyColumns(
    input.baseRows,
    proofTraceLength,
    emissionRows,
    input.challenges,
    start,
    layout
  )
  const air = buildBRC69SegmentBusAccumulatorAir({
    name: input.name,
    traceLength: proofTraceLength,
    emissions: input.emissions,
    publicStart: input.publicStart,
    publicEnd: input.publicEnd
  })
  return {
    name: input.name,
    rows,
    air,
    contribution,
    start,
    end,
    selectorCount
  }
}

export function buildBRC69SegmentBusAccumulatorAir (input: {
  name: string
  traceLength: number
  emissions: BRC69SegmentBusEmission[]
  publicStart?: BRC69SegmentBusEndpoint
  publicEnd?: BRC69SegmentBusEndpoint
}): AirDefinition {
  const selectorCount = brc69SegmentBusSelectorCount(input.emissions)
  const layout = brc69SegmentBusWrappedLayout(0, selectorCount)
  return {
    traceWidth: layout.width,
    transitionDegree: 2,
    publicInputDigest: brc69SegmentBusAccumulatorAirDigest({
      name: input.name,
      traceLength: input.traceLength,
      emissionScheduleDigest: brc69SegmentBusEmissionScheduleDigest(
        input.emissions
      ),
      publicStart: input.publicStart,
      publicEnd: input.publicEnd
    }),
    boundaryConstraints: [
      ...endpointBoundaryConstraints(
        layout.start0,
        layout.start1,
        0,
        input.publicStart
      ),
      ...endpointBoundaryConstraints(
        layout.end0,
        layout.end1,
        0,
        input.publicEnd
      )
    ],
    fullBoundaryColumns: [
      ...busEmissionSelectorColumns(
        layout.selectorStart,
        input.traceLength,
        input.emissions
      ),
      busSelectorColumn(layout.first, input.traceLength, 0),
      busSelectorColumn(layout.penultimate, input.traceLength, input.traceLength - 2),
      baseTransitionActiveColumn(
        layout.baseTransitionActive,
        input.traceLength,
        input.traceLength
      )
    ],
    evaluateTransition: (current, next) => [
      F.sub(next[layout.start0], current[layout.start0]),
      F.sub(next[layout.start1], current[layout.start1]),
      F.sub(next[layout.end0], current[layout.end0]),
      F.sub(next[layout.end1], current[layout.end1]),
      F.mul(
        current[layout.first],
        F.sub(current[layout.accumulator0], current[layout.start0])
      ),
      F.mul(
        current[layout.first],
        F.sub(current[layout.accumulator1], current[layout.start1])
      ),
      F.mul(
        current[layout.penultimate],
        F.sub(next[layout.accumulator0], current[layout.end0])
      ),
      F.mul(
        current[layout.penultimate],
        F.sub(next[layout.accumulator1], current[layout.end1])
      )
    ]
  }
}

export function evaluateBRC69SegmentBusAccumulatorTransition (input: {
  baseRow: FieldElement[]
  accumulatorCurrent: FieldElement[]
  accumulatorNext: FieldElement[]
  emissions: BRC69SegmentBusEmission[]
  layout: BRC69SegmentBusWrappedLayout
  challenges: BRC69SegmentBusChallenges
}): FieldElement[] {
  const contribution = evaluateSelectedRowContribution(
    input.baseRow,
    input.accumulatorCurrent,
    indexBusEmissions(input.emissions),
    input.layout,
    input.challenges
  )
  const active = input.accumulatorCurrent[input.layout.baseTransitionActive]
  return [
    F.mul(active, F.sub(
      input.accumulatorNext[input.layout.accumulator0],
      F.add(
        input.accumulatorCurrent[input.layout.accumulator0],
        contribution.accumulator0
      )
    )),
    F.mul(active, F.sub(
      input.accumulatorNext[input.layout.accumulator1],
      F.add(
        input.accumulatorCurrent[input.layout.accumulator1],
        contribution.accumulator1
      )
    ))
  ]
}

export function brc69SegmentBusWrappedLayout (
  originalWidth: number,
  selectorCount: number = 0
): BRC69SegmentBusWrappedLayout {
  if (
    !Number.isSafeInteger(selectorCount) ||
    selectorCount < 0
  ) {
    throw new Error('BRC69 segment bus selector count is invalid')
  }
  const accumulator0 = originalWidth + selectorCount
  return {
    selectorStart: originalWidth,
    selectorCount,
    accumulator0,
    accumulator1: accumulator0 + 1,
    start0: accumulator0 + 2,
    start1: accumulator0 + 3,
    end0: accumulator0 + 4,
    end1: accumulator0 + 5,
    first: accumulator0 + 6,
    penultimate: accumulator0 + 7,
    baseTransitionActive: accumulator0 + 8,
    width: accumulator0 + 9
  }
}

export function brc69SegmentBusSelectorCount (
  emissions: BRC69SegmentBusEmission[]
): number {
  return emissionSelectorRows(emissions).length
}

export function brc69SegmentBusPublicInputDigest (
  publicInput: BRC69SegmentBusPublicInput
): number[] {
  const writer = new Writer()
  writer.write(toArray(BRC69_SEGMENT_BUS_PUBLIC_INPUT_ID, 'utf8'))
  const names = Object.keys(publicInput.segments).sort()
  writer.writeVarIntNum(names.length)
  for (const name of names) {
    const segment = publicInput.segments[name]
    writer.write(toArray(name, 'utf8'))
    writer.writeVarIntNum(segment.emissionCount)
    writer.writeVarIntNum(segment.selectorCount ?? segment.emissionCount)
    writeOptionalEndpoint(writer, segment.publicStart)
    writeOptionalEndpoint(writer, segment.publicEnd)
  }
  return sha256(writer.toArray())
}

export function brc69SegmentBusAccumulatorAirDigest (input: {
  name: string
  traceLength: number
  emissionScheduleDigest?: number[]
  publicStart?: BRC69SegmentBusEndpoint
  publicEnd?: BRC69SegmentBusEndpoint
}): number[] {
  const writer = new Writer()
  writer.write(toArray('BRC69_SEGMENT_BUS_ACCUMULATOR_AIR_V1', 'utf8'))
  writer.write(toArray(input.name, 'utf8'))
  writer.writeVarIntNum(input.traceLength)
  if (input.emissionScheduleDigest === undefined) {
    writer.writeVarIntNum(0)
  } else {
    writer.writeVarIntNum(input.emissionScheduleDigest.length)
    writer.write(input.emissionScheduleDigest)
  }
  writeOptionalEndpoint(writer, input.publicStart)
  writeOptionalEndpoint(writer, input.publicEnd)
  return sha256(writer.toArray())
}

export function assertBRC69SegmentBusBalanced (
  bus: BRC69SegmentBusPublicInput
): void {
  for (const [name, segment] of Object.entries(bus.segments)) {
    if (
      !Number.isSafeInteger(segment.emissionCount) ||
      segment.emissionCount < 0
    ) {
      throw new Error(`BRC69 segment bus emission count is invalid: ${name}`)
    }
    if (
      segment.selectorCount !== undefined &&
      (
        !Number.isSafeInteger(segment.selectorCount) ||
        segment.selectorCount < 0 ||
        segment.selectorCount > segment.emissionCount
      )
    ) {
      throw new Error(`BRC69 segment bus selector count is invalid: ${name}`)
    }
    assertOptionalEndpoint(segment.publicStart)
    assertOptionalEndpoint(segment.publicEnd)
  }
}

export function compressBRC69SegmentBusTuple (
  tag: FieldElement,
  values: FieldElement[],
  alpha: FieldElement
): FieldElement {
  const tuple = padTuple(values)
  let accumulator = F.normalize(tag)
  let power = alpha
  for (const value of tuple) {
    accumulator = F.add(accumulator, F.mul(power, F.normalize(value)))
    power = F.mul(power, alpha)
  }
  return accumulator
}

function appendAccumulatorOnlyColumns (
  baseRows: FieldElement[][],
  proofTraceLength: number,
  emissionRows: IndexedBRC69SegmentBusEmission[][],
  challenges: BRC69SegmentBusChallenges,
  start: BRC69SegmentBusEndpoint,
  layout: BRC69SegmentBusWrappedLayout
): FieldElement[][] {
  let accumulator0 = start.accumulator0
  let accumulator1 = start.accumulator1
  const contribution = evaluateSegmentContribution(baseRows, emissionRows, challenges)
  const end = {
    accumulator0: F.add(start.accumulator0, contribution.accumulator0),
    accumulator1: F.add(start.accumulator1, contribution.accumulator1)
  }
  const out = new Array<FieldElement[]>(proofTraceLength)
  const zeroBase = new Array<FieldElement>(baseRows[0].length).fill(0n)
  for (let rowIndex = 0; rowIndex < proofTraceLength; rowIndex++) {
    const baseRow = baseRows[rowIndex] ?? zeroBase
    const row = new Array<FieldElement>(layout.width).fill(0n)
    for (const emission of emissionRows[rowIndex] ?? []) {
      row[layout.selectorStart + emission.selectorIndex] = 1n
    }
    row[layout.accumulator0] = accumulator0
    row[layout.accumulator1] = accumulator1
    row[layout.start0] = start.accumulator0
    row[layout.start1] = start.accumulator1
    row[layout.end0] = end.accumulator0
    row[layout.end1] = end.accumulator1
    row[layout.first] = rowIndex === 0 ? 1n : 0n
    row[layout.penultimate] = rowIndex === proofTraceLength - 2 ? 1n : 0n
    row[layout.baseTransitionActive] =
      rowIndex + 1 < proofTraceLength ? 1n : 0n
    out[rowIndex] = row
    if (rowIndex + 1 < proofTraceLength) {
      const rowContribution = evaluateRowContribution(
        baseRow,
        emissionRows[rowIndex] ?? [],
        challenges
      )
      accumulator0 = F.add(accumulator0, rowContribution.accumulator0)
      accumulator1 = F.add(accumulator1, rowContribution.accumulator1)
    }
  }
  return out
}

function evaluateSegmentContribution (
  rows: FieldElement[][],
  emissionRows: BRC69SegmentBusEmission[][],
  challenges: BRC69SegmentBusChallenges
): BRC69SegmentBusContribution {
  let accumulator0 = 0n
  let accumulator1 = 0n
  let emissionCount = 0
  const zeroBase = new Array<FieldElement>(rows[0].length).fill(0n)
  for (let rowIndex = 0; rowIndex + 1 < emissionRows.length; rowIndex++) {
    const contribution = evaluateRowContribution(
      rows[rowIndex] ?? zeroBase,
      emissionRows[rowIndex] ?? [],
      challenges
    )
    accumulator0 = F.add(accumulator0, contribution.accumulator0)
    accumulator1 = F.add(accumulator1, contribution.accumulator1)
    emissionCount += contribution.emissionCount
  }
  return {
    accumulator0,
    accumulator1,
    emissionCount
  }
}

function normalizeEndpoint (
  endpoint: BRC69SegmentBusEndpoint
): BRC69SegmentBusEndpoint {
  return {
    accumulator0: F.normalize(endpoint.accumulator0),
    accumulator1: F.normalize(endpoint.accumulator1)
  }
}

function endpointBoundaryConstraints (
  accumulator0: number,
  accumulator1: number,
  row: number,
  endpoint: BRC69SegmentBusEndpoint | undefined
): BoundaryConstraint[] {
  if (endpoint === undefined) return []
  const normalized = normalizeEndpoint(endpoint)
  return [
    { column: accumulator0, row, value: normalized.accumulator0 },
    { column: accumulator1, row, value: normalized.accumulator1 }
  ]
}

function assertOptionalEndpoint (
  endpoint: BRC69SegmentBusEndpoint | undefined
): void {
  if (endpoint === undefined) return
  F.assertCanonical(endpoint.accumulator0)
  F.assertCanonical(endpoint.accumulator1)
}

function evaluateRowContribution (
  row: FieldElement[],
  emissions: BRC69SegmentBusEmission[],
  challenges: BRC69SegmentBusChallenges
): BRC69SegmentBusContribution {
  let accumulator0 = 0n
  let accumulator1 = 0n
  for (const emission of emissions) {
    const value0 = compressBRC69SegmentBusTuple(
      emission.tag,
      emission.values(row),
      challenges.alpha0
    )
    const value1 = compressBRC69SegmentBusTuple(
      emission.tag,
      emission.values(row),
      challenges.alpha1
    )
    if (emission.kind === BRC69_SEGMENT_BUS_KIND_SOURCE) {
      accumulator0 = F.add(accumulator0, value0)
      accumulator1 = F.add(accumulator1, value1)
    } else {
      accumulator0 = F.sub(accumulator0, value0)
      accumulator1 = F.sub(accumulator1, value1)
    }
  }
  return {
    accumulator0,
    accumulator1,
    emissionCount: emissions.length
  }
}

function evaluateSelectedRowContribution (
  baseRow: FieldElement[],
  wrappedRow: FieldElement[],
  emissions: IndexedBRC69SegmentBusEmission[],
  layout: BRC69SegmentBusWrappedLayout,
  challenges: BRC69SegmentBusChallenges
): BRC69SegmentBusContribution {
  let accumulator0 = 0n
  let accumulator1 = 0n
  for (const emission of emissions) {
    if (emission.selectorIndex >= layout.selectorCount) {
      throw new Error('BRC69 segment bus selector index is out of bounds')
    }
    const selector = F.normalize(
      wrappedRow[layout.selectorStart + emission.selectorIndex]
    )
    const value0 = compressBRC69SegmentBusTuple(
      emission.tag,
      emission.values(baseRow),
      challenges.alpha0
    )
    const value1 = compressBRC69SegmentBusTuple(
      emission.tag,
      emission.values(baseRow),
      challenges.alpha1
    )
    if (emission.kind === BRC69_SEGMENT_BUS_KIND_SOURCE) {
      accumulator0 = F.add(accumulator0, F.mul(selector, value0))
      accumulator1 = F.add(accumulator1, F.mul(selector, value1))
    } else {
      accumulator0 = F.sub(accumulator0, F.mul(selector, value0))
      accumulator1 = F.sub(accumulator1, F.mul(selector, value1))
    }
  }
  return {
    accumulator0,
    accumulator1,
    emissionCount: emissions.length
  }
}

function emissionsByRow (
  emissions: BRC69SegmentBusEmission[],
  traceLength: number
): IndexedBRC69SegmentBusEmission[][] {
  const out = Array.from(
    { length: traceLength },
    () => [] as IndexedBRC69SegmentBusEmission[]
  )
  const selectorByRow = new Map<number, number>()
  for (const emission of emissions) {
    if (
      !Number.isSafeInteger(emission.row) ||
      emission.row < 0 ||
      emission.row + 1 >= traceLength
    ) {
      throw new Error('BRC69 segment bus emission row is out of bounds')
    }
    let selectorIndex = selectorByRow.get(emission.row)
    if (selectorIndex === undefined) {
      selectorIndex = selectorByRow.size
      selectorByRow.set(emission.row, selectorIndex)
    }
    out[emission.row].push({ ...emission, selectorIndex })
  }
  return out
}

function indexBusEmissions (
  emissions: BRC69SegmentBusEmission[]
): IndexedBRC69SegmentBusEmission[] {
  const selectorByRow = new Map<number, number>()
  return emissions.map(emission => {
    let selectorIndex = selectorByRow.get(emission.row)
    if (selectorIndex === undefined) {
      selectorIndex = selectorByRow.size
      selectorByRow.set(emission.row, selectorIndex)
    }
    return { ...emission, selectorIndex }
  })
}

function busSelectorColumn (
  column: number,
  traceLength: number,
  selectedRow: number
): FullBoundaryColumn {
  const values = new Array<FieldElement>(traceLength).fill(0n)
  if (selectedRow >= 0 && selectedRow < traceLength) values[selectedRow] = 1n
  return { column, values }
}

function baseTransitionActiveColumn (
  column: number,
  traceLength: number,
  baseTraceLength: number
): FullBoundaryColumn {
  if (
    !Number.isSafeInteger(baseTraceLength) ||
    baseTraceLength < 1 ||
    baseTraceLength > traceLength
  ) {
    throw new Error('BRC69 segment bus base trace length is invalid')
  }
  const values = new Array<FieldElement>(traceLength).fill(0n)
  for (let row = 0; row + 1 < baseTraceLength; row++) {
    values[row] = 1n
  }
  return { column, values }
}

function busEmissionSelectorColumns (
  selectorStart: number,
  traceLength: number,
  emissions: BRC69SegmentBusEmission[]
): FullBoundaryColumn[] {
  return emissionSelectorRows(emissions).map((row, index) =>
    busSelectorColumn(selectorStart + index, traceLength, row)
  )
}

function emissionSelectorRows (
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

function brc69SegmentBusEmissionScheduleDigest (
  emissions: BRC69SegmentBusEmission[]
): number[] {
  const writer = new Writer()
  writer.write(toArray('BRC69_SEGMENT_BUS_EMISSION_SCHEDULE_V1', 'utf8'))
  writer.writeVarIntNum(emissions.length)
  for (const emission of emissions) {
    writer.writeVarIntNum(emission.row)
    writeField(writer, emission.kind)
    writeField(writer, emission.tag)
  }
  return sha256(writer.toArray())
}

function padTuple (values: FieldElement[]): FieldElement[] {
  if (values.length > LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('BRC69 segment bus tuple arity exceeds lookup bus arity')
  }
  const out = new Array<FieldElement>(LOOKUP_BUS_TUPLE_ARITY).fill(0n)
  for (let i = 0; i < values.length; i++) out[i] = F.normalize(values[i])
  return out
}

function nonZeroChallenge (
  transcript: FiatShamirTranscript,
  label: string
): FieldElement {
  for (let i = 0; i < 16; i++) {
    const value = transcript.challengeFieldElement(`${label}-${i}`)
    if (value !== 0n) return value
  }
  throw new Error('BRC69 segment bus could not derive a non-zero challenge')
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}

function writeOptionalEndpoint (
  writer: Writer,
  endpoint: BRC69SegmentBusEndpoint | undefined
): void {
  if (endpoint === undefined) {
    writer.writeUInt8(0)
    return
  }
  writer.writeUInt8(1)
  writeField(writer, endpoint.accumulator0)
  writeField(writer, endpoint.accumulator1)
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
