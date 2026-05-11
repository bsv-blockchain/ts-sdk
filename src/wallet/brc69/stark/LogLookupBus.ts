import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from './Air.js'
import { F, FieldElement } from './Field.js'
import {
  StarkProof,
  StarkProverOptions,
  serializeStarkProof
} from './Stark.js'
import { FiatShamirTranscript } from './Transcript.js'

export const LOG_LOOKUP_BUS_TRANSCRIPT_DOMAIN =
  'BRC69_LOG_LOOKUP_BUS_V1'
export const LOG_LOOKUP_BUS_PUBLIC_INPUT_ID =
  'BRC69_LOG_LOOKUP_BUS_PUBLIC_INPUT_V1'
export const LOG_LOOKUP_TUPLE_ARITY = 4

export const LOG_LOOKUP_ROW_KIND = {
  inactive: 0n,
  request: 1n,
  supply: 2n
} as const

export interface LogLookupBusLayout {
  kind: number
  tag: number
  multiplicity: number
  tuple: number
  publicTuple: number
  compressed0: number
  compressed1: number
  inverse0: number
  inverse1: number
  accumulator0: number
  accumulator1: number
  requestCount: number
  supplyCount: number
  width: number
}

export interface LogLookupBusScheduleRow {
  kind: FieldElement
  tag: FieldElement
  publicTuple: FieldElement[]
}

export interface LogLookupBusPublicInput {
  traceLength: number
  expectedRequests: number
  scheduleRows: LogLookupBusScheduleRow[]
}

export interface LogLookupBusItem {
  kind: FieldElement
  tag: FieldElement
  values?: FieldElement[]
  publicValues?: FieldElement[]
  multiplicity?: FieldElement
}

export interface LogLookupBusTrace {
  publicInput: LogLookupBusPublicInput
  rows: FieldElement[][]
  metrics: LogLookupBusMetrics
}

export interface LogLookupBusMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  tableRows: number
  requestRows: number
  committedCells: number
  proofBytes?: number
}

interface LogLookupChallenges {
  alpha0: FieldElement
  alpha1: FieldElement
  alphaPowers0: FieldElement[]
  alphaPowers1: FieldElement[]
  beta0: FieldElement
  beta1: FieldElement
}

export const LOG_LOOKUP_BUS_LAYOUT: LogLookupBusLayout = {
  kind: 0,
  tag: 1,
  multiplicity: 2,
  tuple: 3,
  publicTuple: 3 + LOG_LOOKUP_TUPLE_ARITY,
  compressed0: 3 + LOG_LOOKUP_TUPLE_ARITY * 2,
  compressed1: 4 + LOG_LOOKUP_TUPLE_ARITY * 2,
  inverse0: 5 + LOG_LOOKUP_TUPLE_ARITY * 2,
  inverse1: 6 + LOG_LOOKUP_TUPLE_ARITY * 2,
  accumulator0: 7 + LOG_LOOKUP_TUPLE_ARITY * 2,
  accumulator1: 8 + LOG_LOOKUP_TUPLE_ARITY * 2,
  requestCount: 9 + LOG_LOOKUP_TUPLE_ARITY * 2,
  supplyCount: 10 + LOG_LOOKUP_TUPLE_ARITY * 2,
  width: 11 + LOG_LOOKUP_TUPLE_ARITY * 2
}

const ZERO_TUPLE = new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY).fill(0n)
const KIND_VALUES = [
  LOG_LOOKUP_ROW_KIND.inactive,
  LOG_LOOKUP_ROW_KIND.request,
  LOG_LOOKUP_ROW_KIND.supply
]

export function buildLogLookupBusTrace (
  items: LogLookupBusItem[],
  options: {
    expectedRequests?: number
    minTraceLength?: number
  } = {}
): LogLookupBusTrace {
  const traceLength = nextPowerOfTwo(Math.max(
    2,
    options.minTraceLength ?? 0,
    items.length + 1
  ))
  const scheduleRows = new Array<LogLookupBusScheduleRow>(traceLength)
  const rows = new Array<FieldElement[]>(traceLength)
  const expectedRequests = options.expectedRequests ??
    items.filter(item => item.kind === LOG_LOOKUP_ROW_KIND.request).length
  const publicInput = {
    traceLength,
    expectedRequests,
    scheduleRows
  }
  for (let row = 0; row < traceLength; row++) {
    const item = items[row]
    if (item === undefined) {
      scheduleRows[row] = {
        kind: LOG_LOOKUP_ROW_KIND.inactive,
        tag: 0n,
        publicTuple: ZERO_TUPLE
      }
    } else {
      scheduleRows[row] = {
        kind: F.normalize(item.kind),
        tag: F.normalize(item.tag),
        publicTuple: normalizeTuple(item.publicValues ?? ZERO_TUPLE)
      }
    }
  }
  const digest = logLookupBusPublicInputDigest(publicInput)
  const challenges = deriveLogLookupChallenges(digest)
  let accumulator0 = 0n
  let accumulator1 = 0n
  let requestCount = 0n
  let supplyCount = 0n
  for (let row = 0; row < traceLength; row++) {
    const item = items[row]
    const schedule = scheduleRows[row]
    const kind = schedule.kind
    const active = kind === LOG_LOOKUP_ROW_KIND.inactive ? 0n : 1n
    const request = kind === LOG_LOOKUP_ROW_KIND.request ? 1n : 0n
    const supply = kind === LOG_LOOKUP_ROW_KIND.supply ? 1n : 0n
    const multiplicity = item === undefined
      ? 0n
      : F.normalize(item.multiplicity ?? (request === 1n ? 1n : 0n))
    const tuple = item === undefined
      ? ZERO_TUPLE
      : normalizeTuple(item.values ?? ZERO_TUPLE)
    const compressed0 = active === 0n
      ? 0n
      : compressLogLookupTuple(
        schedule.tag,
        tuple,
        challenges.alphaPowers0
      )
    const compressed1 = active === 0n
      ? 0n
      : compressLogLookupTuple(
        schedule.tag,
        tuple,
        challenges.alphaPowers1
      )
    const inverse0 = active === 0n
      ? 0n
      : F.inv(F.add(challenges.beta0, compressed0))
    const inverse1 = active === 0n
      ? 0n
      : F.inv(F.add(challenges.beta1, compressed1))
    const traceRow = new Array<FieldElement>(LOG_LOOKUP_BUS_LAYOUT.width).fill(0n)
    traceRow[LOG_LOOKUP_BUS_LAYOUT.kind] = kind
    traceRow[LOG_LOOKUP_BUS_LAYOUT.tag] = schedule.tag
    traceRow[LOG_LOOKUP_BUS_LAYOUT.multiplicity] = multiplicity
    writeTuple(traceRow, LOG_LOOKUP_BUS_LAYOUT.tuple, tuple)
    writeTuple(traceRow, LOG_LOOKUP_BUS_LAYOUT.publicTuple, schedule.publicTuple)
    traceRow[LOG_LOOKUP_BUS_LAYOUT.compressed0] = compressed0
    traceRow[LOG_LOOKUP_BUS_LAYOUT.compressed1] = compressed1
    traceRow[LOG_LOOKUP_BUS_LAYOUT.inverse0] = inverse0
    traceRow[LOG_LOOKUP_BUS_LAYOUT.inverse1] = inverse1
    traceRow[LOG_LOOKUP_BUS_LAYOUT.accumulator0] = accumulator0
    traceRow[LOG_LOOKUP_BUS_LAYOUT.accumulator1] = accumulator1
    traceRow[LOG_LOOKUP_BUS_LAYOUT.requestCount] = requestCount
    traceRow[LOG_LOOKUP_BUS_LAYOUT.supplyCount] = supplyCount
    rows[row] = traceRow

    if (row + 1 < traceLength) {
      accumulator0 = F.add(accumulator0, logLookupDelta(
        request,
        supply,
        multiplicity,
        inverse0
      ))
      accumulator1 = F.add(accumulator1, logLookupDelta(
        request,
        supply,
        multiplicity,
        inverse1
      ))
      requestCount = F.add(requestCount, request)
      supplyCount = F.add(supplyCount, F.mul(supply, multiplicity))
    }
  }
  return {
    publicInput,
    rows,
    metrics: {
      activeRows: items.length,
      paddedRows: traceLength,
      traceWidth: LOG_LOOKUP_BUS_LAYOUT.width,
      tableRows: items.filter(item => item.kind === LOG_LOOKUP_ROW_KIND.supply).length,
      requestRows: items.filter(item => item.kind === LOG_LOOKUP_ROW_KIND.request).length,
      committedCells: traceLength * LOG_LOOKUP_BUS_LAYOUT.width
    }
  }
}

export function buildLogLookupBusAir (
  publicInput: LogLookupBusPublicInput
): AirDefinition {
  validateLogLookupBusPublicInput(publicInput)
  const digest = logLookupBusPublicInputDigest(publicInput)
  const challenges = deriveLogLookupChallenges(digest)
  const lastRow = publicInput.traceLength - 1
  return {
    traceWidth: LOG_LOOKUP_BUS_LAYOUT.width,
    transitionDegree: 5,
    publicInputDigest: digest,
    boundaryConstraints: [
      { column: LOG_LOOKUP_BUS_LAYOUT.accumulator0, row: 0, value: 0n },
      { column: LOG_LOOKUP_BUS_LAYOUT.accumulator1, row: 0, value: 0n },
      { column: LOG_LOOKUP_BUS_LAYOUT.requestCount, row: 0, value: 0n },
      { column: LOG_LOOKUP_BUS_LAYOUT.supplyCount, row: 0, value: 0n },
      { column: LOG_LOOKUP_BUS_LAYOUT.accumulator0, row: lastRow, value: 0n },
      { column: LOG_LOOKUP_BUS_LAYOUT.accumulator1, row: lastRow, value: 0n },
      {
        column: LOG_LOOKUP_BUS_LAYOUT.requestCount,
        row: lastRow,
        value: BigInt(publicInput.expectedRequests)
      },
      {
        column: LOG_LOOKUP_BUS_LAYOUT.supplyCount,
        row: lastRow,
        value: BigInt(publicInput.expectedRequests)
      }
    ],
    fullBoundaryColumns: [
      {
        column: LOG_LOOKUP_BUS_LAYOUT.kind,
        values: publicInput.scheduleRows.map(row => row.kind)
      },
      {
        column: LOG_LOOKUP_BUS_LAYOUT.tag,
        values: publicInput.scheduleRows.map(row => row.tag)
      },
      ...Array.from({ length: LOG_LOOKUP_TUPLE_ARITY }, (_, index) => ({
        column: LOG_LOOKUP_BUS_LAYOUT.publicTuple + index,
        values: publicInput.scheduleRows.map(row => row.publicTuple[index])
      }))
    ],
    evaluateTransition: (current, next) =>
      evaluateLogLookupTransition(current, next, challenges)
  }
}

export function proveLogLookupBus (
  trace: LogLookupBusTrace,
  options: StarkProverOptions = {}
): StarkProof {
  void trace
  void options
  throw new Error(
    'Standalone log lookup bus proofs are disabled; use the phased post-commitment bus proof path'
  )
}

export function verifyLogLookupBusProof (
  publicInput: LogLookupBusPublicInput,
  proof: StarkProof
): boolean {
  void publicInput
  void proof
  return false
}

export function logLookupBusMetrics (
  trace: LogLookupBusTrace,
  proof?: StarkProof
): LogLookupBusMetrics {
  return {
    ...trace.metrics,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function logLookupBusPublicInputDigest (
  publicInput: LogLookupBusPublicInput
): number[] {
  validateLogLookupBusPublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(LOG_LOOKUP_BUS_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.expectedRequests)
  writer.writeVarIntNum(publicInput.scheduleRows.length)
  for (const row of publicInput.scheduleRows) {
    writeField(writer, row.kind)
    writeField(writer, row.tag)
    for (const value of row.publicTuple) writeField(writer, value)
  }
  return sha256(writer.toArray())
}

export function evaluateLogLookupTransition (
  current: FieldElement[],
  next: FieldElement[],
  challenges: LogLookupChallenges
): FieldElement[] {
  const layout = LOG_LOOKUP_BUS_LAYOUT
  const kind = current[layout.kind]
  const inactive = kindSelector(kind, LOG_LOOKUP_ROW_KIND.inactive)
  const request = kindSelector(kind, LOG_LOOKUP_ROW_KIND.request)
  const supply = kindSelector(kind, LOG_LOOKUP_ROW_KIND.supply)
  const active = F.sub(1n, inactive)
  const compressed0 = compressLogLookupTuple(
    current[layout.tag],
    current.slice(layout.tuple, layout.tuple + LOG_LOOKUP_TUPLE_ARITY),
    challenges.alphaPowers0
  )
  const compressed1 = compressLogLookupTuple(
    current[layout.tag],
    current.slice(layout.tuple, layout.tuple + LOG_LOOKUP_TUPLE_ARITY),
    challenges.alphaPowers1
  )
  const delta0 = logLookupDelta(
    request,
    supply,
    current[layout.multiplicity],
    current[layout.inverse0]
  )
  const delta1 = logLookupDelta(
    request,
    supply,
    current[layout.multiplicity],
    current[layout.inverse1]
  )
  const constraints = [
    kindDomainConstraint(kind),
    F.mul(inactive, current[layout.multiplicity]),
    F.mul(request, F.sub(current[layout.multiplicity], 1n)),
    F.mul(active, F.sub(current[layout.compressed0], compressed0)),
    F.mul(active, F.sub(current[layout.compressed1], compressed1)),
    F.mul(active, F.sub(
      F.mul(
        F.add(challenges.beta0, current[layout.compressed0]),
        current[layout.inverse0]
      ),
      1n
    )),
    F.mul(active, F.sub(
      F.mul(
        F.add(challenges.beta1, current[layout.compressed1]),
        current[layout.inverse1]
      ),
      1n
    )),
    F.mul(inactive, current[layout.compressed0]),
    F.mul(inactive, current[layout.compressed1]),
    F.mul(inactive, current[layout.inverse0]),
    F.mul(inactive, current[layout.inverse1]),
    F.sub(next[layout.accumulator0], F.add(current[layout.accumulator0], delta0)),
    F.sub(next[layout.accumulator1], F.add(current[layout.accumulator1], delta1)),
    F.sub(next[layout.requestCount], F.add(current[layout.requestCount], request)),
    F.sub(
      next[layout.supplyCount],
      F.add(current[layout.supplyCount], F.mul(supply, current[layout.multiplicity]))
    )
  ]
  for (let i = 0; i < LOG_LOOKUP_TUPLE_ARITY; i++) {
    constraints.push(F.mul(
      supply,
      F.sub(current[layout.tuple + i], current[layout.publicTuple + i])
    ))
    constraints.push(F.mul(
      inactive,
      current[layout.tuple + i]
    ))
  }
  return constraints
}

export function compressLogLookupTuple (
  tag: FieldElement,
  tuple: FieldElement[],
  powers: FieldElement[]
): FieldElement {
  let accumulator = F.normalize(tag)
  for (let i = 0; i < LOG_LOOKUP_TUPLE_ARITY; i++) {
    accumulator = F.add(
      accumulator,
      F.mul(powers[i], F.normalize(tuple[i] ?? 0n))
    )
  }
  return accumulator
}

export function validateLogLookupBusPublicInput (
  publicInput: LogLookupBusPublicInput
): void {
  if (
    !Number.isSafeInteger(publicInput.traceLength) ||
    publicInput.traceLength < 2
  ) {
    throw new Error('Log lookup trace length is invalid')
  }
  if (publicInput.scheduleRows.length !== publicInput.traceLength) {
    throw new Error('Log lookup schedule length mismatch')
  }
  if (
    !Number.isSafeInteger(publicInput.expectedRequests) ||
    publicInput.expectedRequests < 0
  ) {
    throw new Error('Log lookup expected request count is invalid')
  }
  for (const row of publicInput.scheduleRows) {
    if (!KIND_VALUES.includes(F.normalize(row.kind) as typeof KIND_VALUES[number])) {
      throw new Error('Log lookup schedule kind is invalid')
    }
    if (row.publicTuple.length !== LOG_LOOKUP_TUPLE_ARITY) {
      throw new Error('Log lookup public tuple arity mismatch')
    }
  }
}

export function deriveLogLookupChallenges (
  publicInputDigest: number[]
): LogLookupChallenges {
  const transcript = new FiatShamirTranscript(
    `${LOG_LOOKUP_BUS_TRANSCRIPT_DOMAIN}:challenges`
  )
  transcript.absorb('public-input', publicInputDigest)
  const alpha0 = nonZeroChallenge(transcript, 'alpha-0')
  const alpha1 = nonZeroChallenge(transcript, 'alpha-1')
  return {
    alpha0,
    alpha1,
    alphaPowers0: challengePowers(alpha0),
    alphaPowers1: challengePowers(alpha1),
    beta0: nonZeroChallenge(transcript, 'beta-0'),
    beta1: nonZeroChallenge(transcript, 'beta-1')
  }
}

function logLookupDelta (
  request: FieldElement,
  supply: FieldElement,
  multiplicity: FieldElement,
  inverse: FieldElement
): FieldElement {
  return F.sub(
    F.mul(request, inverse),
    F.mul(supply, F.mul(multiplicity, inverse))
  )
}

function normalizeTuple (values: FieldElement[]): FieldElement[] {
  const out = new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY).fill(0n)
  for (let i = 0; i < Math.min(values.length, out.length); i++) {
    out[i] = F.normalize(values[i])
  }
  return out
}

function writeTuple (
  row: FieldElement[],
  offset: number,
  values: FieldElement[]
): void {
  for (let i = 0; i < LOG_LOOKUP_TUPLE_ARITY; i++) {
    row[offset + i] = F.normalize(values[i] ?? 0n)
  }
}

function kindDomainConstraint (kind: FieldElement): FieldElement {
  let out = 1n
  for (const value of KIND_VALUES) out = F.mul(out, F.sub(kind, value))
  return out
}

function kindSelector (
  kind: FieldElement,
  target: FieldElement
): FieldElement {
  let numerator = 1n
  let denominator = 1n
  for (const value of KIND_VALUES) {
    if (value === target) continue
    numerator = F.mul(numerator, F.sub(kind, value))
    denominator = F.mul(denominator, F.sub(target, value))
  }
  return F.mul(numerator, F.inv(denominator))
}

function challengePowers (alpha: FieldElement): FieldElement[] {
  const out = new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY)
  let power = F.normalize(alpha)
  for (let i = 0; i < out.length; i++) {
    out[i] = power
    power = F.mul(power, alpha)
  }
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
  throw new Error('Log lookup bus could not derive a non-zero challenge')
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function writeField (writer: Writer, value: FieldElement): void {
  writer.write(F.toBytesLE(F.normalize(value)))
}
