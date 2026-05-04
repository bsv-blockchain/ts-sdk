import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition, BoundaryConstraint, FullBoundaryColumn } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import { LOOKUP_BUS_TUPLE_ARITY } from '../stark/LookupBus.js'
import { FiatShamirTranscript } from '../stark/Transcript.js'

export const BRC97_SEGMENT_BUS_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_SEGMENT_BUS_PUBLIC_INPUT_V1'
export const BRC97_SEGMENT_BUS_WRAPPED_AIR_ID =
  'BRC97_METHOD2_SEGMENT_BUS_WRAPPED_AIR_V1'

export const BRC97_SEGMENT_BUS_KIND_SOURCE = 1n
export const BRC97_SEGMENT_BUS_KIND_TARGET = 2n

export interface BRC97SegmentBusChallenges {
  alpha0: FieldElement
  alpha1: FieldElement
}

export interface BRC97SegmentBusContribution {
  accumulator0: FieldElement
  accumulator1: FieldElement
  emissionCount: number
}

export interface BRC97SegmentBusEndpoint {
  accumulator0: FieldElement
  accumulator1: FieldElement
}

export interface BRC97SegmentBusEmission {
  row: number
  kind: typeof BRC97_SEGMENT_BUS_KIND_SOURCE |
    typeof BRC97_SEGMENT_BUS_KIND_TARGET
  tag: FieldElement
  values: (row: FieldElement[]) => FieldElement[]
}

interface IndexedBRC97SegmentBusEmission extends BRC97SegmentBusEmission {
  selectorIndex: number
}

export interface BRC97SegmentBusWrappedTrace {
  name: string
  rows: FieldElement[][]
  air: AirDefinition
  contribution: BRC97SegmentBusContribution
  start: BRC97SegmentBusEndpoint
  end: BRC97SegmentBusEndpoint
  selectorCount: number
}

export interface BRC97SegmentBusWrappedLayout {
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

export interface BRC97SegmentBusPublicInput {
  challengeDigest: number[]
  segments: Record<string, {
    emissionCount: number
    selectorCount?: number
    publicStart?: BRC97SegmentBusEndpoint
    publicEnd?: BRC97SegmentBusEndpoint
  }>
}

export function deriveBRC97SegmentBusChallenges (
  challengeDigest: number[]
): BRC97SegmentBusChallenges {
  const transcript = new FiatShamirTranscript(
    `${BRC97_SEGMENT_BUS_PUBLIC_INPUT_ID}:challenges`
  )
  transcript.absorb('challenge-digest', challengeDigest)
  return {
    alpha0: nonZeroChallenge(transcript, 'alpha-0'),
    alpha1: nonZeroChallenge(transcript, 'alpha-1')
  }
}

export function wrapBRC97SegmentBusTrace (input: {
  name: string
  air: AirDefinition
  rows: FieldElement[][]
  proofTraceLength?: number
  emissions: BRC97SegmentBusEmission[]
  challengeDigest: number[]
  start?: BRC97SegmentBusEndpoint
  publicStart?: BRC97SegmentBusEndpoint
  publicEnd?: BRC97SegmentBusEndpoint
}): BRC97SegmentBusWrappedTrace {
  const proofTraceLength = input.proofTraceLength ?? input.rows.length
  const challenges = deriveBRC97SegmentBusChallenges(input.challengeDigest)
  const emissionRows = emissionsByRow(input.emissions, proofTraceLength)
  const selectorCount = brc97SegmentBusSelectorCount(input.emissions)
  const layout = brc97SegmentBusWrappedLayout(
    input.air.traceWidth,
    selectorCount
  )
  const contribution = evaluateSegmentContribution(
    input.rows,
    emissionRows,
    challenges
  )
  const start = normalizeEndpoint(input.start ?? {
    accumulator0: 0n,
    accumulator1: 0n
  })
  const end = {
    accumulator0: F.add(start.accumulator0, contribution.accumulator0),
    accumulator1: F.add(start.accumulator1, contribution.accumulator1)
  }
  const rows = appendAccumulatorColumns(
    input.rows,
    proofTraceLength,
    emissionRows,
    challenges,
    start,
    layout
  )
  const air = wrapBRC97SegmentBusAir({
    name: input.name,
    air: input.air,
    baseTraceLength: input.rows.length,
    traceLength: proofTraceLength,
    emissions: input.emissions,
    challengeDigest: input.challengeDigest,
    emissionCount: contribution.emissionCount,
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

export function wrapBRC97SegmentBusAir (input: {
  name: string
  air: AirDefinition
  baseTraceLength?: number
  traceLength: number
  emissions: BRC97SegmentBusEmission[]
  challengeDigest: number[]
  emissionCount: number
  publicStart?: BRC97SegmentBusEndpoint
  publicEnd?: BRC97SegmentBusEndpoint
}): AirDefinition {
  const challenges = deriveBRC97SegmentBusChallenges(input.challengeDigest)
  const originalWidth = input.air.traceWidth
  const baseTraceLength = input.baseTraceLength ?? input.traceLength
  const indexedEmissions = indexBusEmissions(input.emissions)
  const selectorCount = brc97SegmentBusSelectorCount(input.emissions)
  const layout = brc97SegmentBusWrappedLayout(
    originalWidth,
    selectorCount
  )
  return {
    ...input.air,
    traceWidth: layout.width,
    unmaskedColumns: input.air.unmaskedColumns,
    publicInputDigest: brc97SegmentBusWrappedAirDigest({
      name: input.name,
      originalDigest: input.air.publicInputDigest ?? [],
      challengeDigest: input.challengeDigest,
      baseTraceLength,
      emissionCount: input.emissionCount,
      emissionScheduleDigest: brc97SegmentBusEmissionScheduleDigest(
        input.emissions
      ),
      publicStart: input.publicStart,
      publicEnd: input.publicEnd
    }),
    boundaryConstraints: [
      ...translateBoundaryConstraints(
        input.air.boundaryConstraints,
        baseTraceLength
      ),
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
      ...translateFullBoundaryColumns(
        input.air.fullBoundaryColumns ?? [],
        input.traceLength
      ),
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
        baseTraceLength
      )
    ],
    transitionDegree: Math.max(
      (input.air.transitionDegree ?? 2) + 1,
      2
    ),
    evaluateTransition: (current, next) => {
      const currentBase = current.slice(0, originalWidth)
      const nextBase = next.slice(0, originalWidth)
      const baseTransitionActive = current[layout.baseTransitionActive]
      const constraints = input.air.evaluateTransition(currentBase, nextBase, 0)
        .map(value => F.mul(baseTransitionActive, value))
      const contribution = evaluateSelectedRowContribution(
        currentBase,
        current,
        indexedEmissions,
        layout,
        challenges
      )
      constraints.push(F.sub(
        next[layout.accumulator0],
        F.add(current[layout.accumulator0], contribution.accumulator0)
      ))
      constraints.push(F.sub(
        next[layout.accumulator1],
        F.add(current[layout.accumulator1], contribution.accumulator1)
      ))
      constraints.push(F.sub(next[layout.start0], current[layout.start0]))
      constraints.push(F.sub(next[layout.start1], current[layout.start1]))
      constraints.push(F.sub(next[layout.end0], current[layout.end0]))
      constraints.push(F.sub(next[layout.end1], current[layout.end1]))
      constraints.push(F.mul(
        current[layout.first],
        F.sub(current[layout.accumulator0], current[layout.start0])
      ))
      constraints.push(F.mul(
        current[layout.first],
        F.sub(current[layout.accumulator1], current[layout.start1])
      ))
      constraints.push(F.mul(
        current[layout.penultimate],
        F.sub(next[layout.accumulator0], current[layout.end0])
      ))
      constraints.push(F.mul(
        current[layout.penultimate],
        F.sub(next[layout.accumulator1], current[layout.end1])
      ))
      return constraints
    }
  }
}

export function brc97SegmentBusWrappedLayout (
  originalWidth: number,
  selectorCount: number = 0
): BRC97SegmentBusWrappedLayout {
  if (
    !Number.isSafeInteger(selectorCount) ||
    selectorCount < 0
  ) {
    throw new Error('BRC97 segment bus selector count is invalid')
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

export function brc97SegmentBusSelectorCount (
  emissions: BRC97SegmentBusEmission[]
): number {
  return emissionSelectorRows(emissions).length
}

export function brc97SegmentBusPublicInputDigest (
  publicInput: BRC97SegmentBusPublicInput
): number[] {
  const writer = new Writer()
  writer.write(toArray(BRC97_SEGMENT_BUS_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.challengeDigest.length)
  writer.write(publicInput.challengeDigest)
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

export function brc97SegmentBusWrappedAirDigest (input: {
  name: string
  originalDigest: number[]
  challengeDigest: number[]
  baseTraceLength?: number
  emissionCount: number
  emissionScheduleDigest?: number[]
  publicStart?: BRC97SegmentBusEndpoint
  publicEnd?: BRC97SegmentBusEndpoint
}): number[] {
  const writer = new Writer()
  writer.write(toArray(BRC97_SEGMENT_BUS_WRAPPED_AIR_ID, 'utf8'))
  writer.write(toArray(input.name, 'utf8'))
  writer.writeVarIntNum(input.originalDigest.length)
  writer.write(input.originalDigest)
  writer.writeVarIntNum(input.challengeDigest.length)
  writer.write(input.challengeDigest)
  writer.writeVarIntNum(input.baseTraceLength ?? 0)
  writer.writeVarIntNum(input.emissionCount)
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

export function assertBRC97SegmentBusBalanced (
  bus: BRC97SegmentBusPublicInput
): void {
  for (const [name, segment] of Object.entries(bus.segments)) {
    if (
      !Number.isSafeInteger(segment.emissionCount) ||
      segment.emissionCount < 0
    ) {
      throw new Error(`BRC97 segment bus emission count is invalid: ${name}`)
    }
    if (
      segment.selectorCount !== undefined &&
      (
        !Number.isSafeInteger(segment.selectorCount) ||
        segment.selectorCount < 0 ||
        segment.selectorCount > segment.emissionCount
      )
    ) {
      throw new Error(`BRC97 segment bus selector count is invalid: ${name}`)
    }
    assertOptionalEndpoint(segment.publicStart)
    assertOptionalEndpoint(segment.publicEnd)
  }
}

export function compressBRC97SegmentBusTuple (
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

function appendAccumulatorColumns (
  rows: FieldElement[][],
  proofTraceLength: number,
  emissionRows: IndexedBRC97SegmentBusEmission[][],
  challenges: BRC97SegmentBusChallenges,
  start: BRC97SegmentBusEndpoint,
  layout: BRC97SegmentBusWrappedLayout
): FieldElement[][] {
  let accumulator0 = start.accumulator0
  let accumulator1 = start.accumulator1
  const contribution = evaluateSegmentContribution(rows, emissionRows, challenges)
  const end = {
    accumulator0: F.add(start.accumulator0, contribution.accumulator0),
    accumulator1: F.add(start.accumulator1, contribution.accumulator1)
  }
  const out = new Array<FieldElement[]>(proofTraceLength)
  const zeroBase = new Array<FieldElement>(rows[0].length).fill(0n)
  for (let rowIndex = 0; rowIndex < proofTraceLength; rowIndex++) {
    const row = rows[rowIndex] ?? zeroBase
    const first = rowIndex === 0 ? 1n : 0n
    const penultimate = rowIndex === proofTraceLength - 2 ? 1n : 0n
    const next = row.slice()
    const selectors = new Array<FieldElement>(layout.selectorCount).fill(0n)
    for (const emission of emissionRows[rowIndex] ?? []) {
      selectors[emission.selectorIndex] = 1n
    }
    const baseTransitionActive = rowIndex + 1 < rows.length ? 1n : 0n
    next.push(...selectors)
    next.push(
      accumulator0,
      accumulator1,
      start.accumulator0,
      start.accumulator1,
      end.accumulator0,
      end.accumulator1,
      first,
      penultimate,
      baseTransitionActive
    )
    out[rowIndex] = next
    if (rowIndex + 1 < proofTraceLength) {
      const rowContribution = evaluateRowContribution(
        row,
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
  emissionRows: BRC97SegmentBusEmission[][],
  challenges: BRC97SegmentBusChallenges
): BRC97SegmentBusContribution {
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
  endpoint: BRC97SegmentBusEndpoint
): BRC97SegmentBusEndpoint {
  return {
    accumulator0: F.normalize(endpoint.accumulator0),
    accumulator1: F.normalize(endpoint.accumulator1)
  }
}

function endpointBoundaryConstraints (
  accumulator0: number,
  accumulator1: number,
  row: number,
  endpoint: BRC97SegmentBusEndpoint | undefined
): BoundaryConstraint[] {
  if (endpoint === undefined) return []
  const normalized = normalizeEndpoint(endpoint)
  return [
    { column: accumulator0, row, value: normalized.accumulator0 },
    { column: accumulator1, row, value: normalized.accumulator1 }
  ]
}

function assertOptionalEndpoint (
  endpoint: BRC97SegmentBusEndpoint | undefined
): void {
  if (endpoint === undefined) return
  F.assertCanonical(endpoint.accumulator0)
  F.assertCanonical(endpoint.accumulator1)
}

function evaluateRowContribution (
  row: FieldElement[],
  emissions: BRC97SegmentBusEmission[],
  challenges: BRC97SegmentBusChallenges
): BRC97SegmentBusContribution {
  let accumulator0 = 0n
  let accumulator1 = 0n
  for (const emission of emissions) {
    const value0 = compressBRC97SegmentBusTuple(
      emission.tag,
      emission.values(row),
      challenges.alpha0
    )
    const value1 = compressBRC97SegmentBusTuple(
      emission.tag,
      emission.values(row),
      challenges.alpha1
    )
    if (emission.kind === BRC97_SEGMENT_BUS_KIND_SOURCE) {
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
  emissions: IndexedBRC97SegmentBusEmission[],
  layout: BRC97SegmentBusWrappedLayout,
  challenges: BRC97SegmentBusChallenges
): BRC97SegmentBusContribution {
  let accumulator0 = 0n
  let accumulator1 = 0n
  for (const emission of emissions) {
    if (emission.selectorIndex >= layout.selectorCount) {
      throw new Error('BRC97 segment bus selector index is out of bounds')
    }
    const selector = F.normalize(
      wrappedRow[layout.selectorStart + emission.selectorIndex]
    )
    const value0 = compressBRC97SegmentBusTuple(
      emission.tag,
      emission.values(baseRow),
      challenges.alpha0
    )
    const value1 = compressBRC97SegmentBusTuple(
      emission.tag,
      emission.values(baseRow),
      challenges.alpha1
    )
    if (emission.kind === BRC97_SEGMENT_BUS_KIND_SOURCE) {
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
  emissions: BRC97SegmentBusEmission[],
  traceLength: number
): IndexedBRC97SegmentBusEmission[][] {
  const out = Array.from(
    { length: traceLength },
    () => [] as IndexedBRC97SegmentBusEmission[]
  )
  const selectorByRow = new Map<number, number>()
  for (const emission of emissions) {
    if (
      !Number.isSafeInteger(emission.row) ||
      emission.row < 0 ||
      emission.row + 1 >= traceLength
    ) {
      throw new Error('BRC97 segment bus emission row is out of bounds')
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
  emissions: BRC97SegmentBusEmission[]
): IndexedBRC97SegmentBusEmission[] {
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

function translateBoundaryConstraints (
  constraints: BoundaryConstraint[],
  traceLength: number
): BoundaryConstraint[] {
  return constraints.map(constraint => {
    if (constraint.row >= traceLength) {
      throw new Error('BRC97 segment bus boundary row is out of bounds')
    }
    return { ...constraint }
  })
}

function translateFullBoundaryColumns (
  columns: FullBoundaryColumn[],
  traceLength: number
): FullBoundaryColumn[] {
  return columns.map(column => {
    if (column.values.length > traceLength) {
      throw new Error('BRC97 segment bus full boundary column is too long')
    }
    return {
      column: column.column,
      values: [
        ...column.values,
        ...new Array<FieldElement>(traceLength - column.values.length).fill(0n)
      ]
    }
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
    throw new Error('BRC97 segment bus base trace length is invalid')
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
  emissions: BRC97SegmentBusEmission[]
): FullBoundaryColumn[] {
  return emissionSelectorRows(emissions).map((row, index) =>
    busSelectorColumn(selectorStart + index, traceLength, row)
  )
}

function emissionSelectorRows (
  emissions: BRC97SegmentBusEmission[]
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

function brc97SegmentBusEmissionScheduleDigest (
  emissions: BRC97SegmentBusEmission[]
): number[] {
  const writer = new Writer()
  writer.write(toArray('BRC97_SEGMENT_BUS_EMISSION_SCHEDULE_V1', 'utf8'))
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
    throw new Error('BRC97 segment bus tuple arity exceeds lookup bus arity')
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
  throw new Error('BRC97 segment bus could not derive a non-zero challenge')
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}

function writeOptionalEndpoint (
  writer: Writer,
  endpoint: BRC97SegmentBusEndpoint | undefined
): void {
  if (endpoint === undefined) {
    writer.writeUInt8(0)
    return
  }
  writer.writeUInt8(1)
  writeField(writer, endpoint.accumulator0)
  writeField(writer, endpoint.accumulator1)
}
