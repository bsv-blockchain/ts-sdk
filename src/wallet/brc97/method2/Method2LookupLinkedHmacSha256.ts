import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { AirDefinition } from '../stark/Air.js'
import { F, FieldElement } from '../stark/Field.js'
import {
  LOG_LOOKUP_BUS_LAYOUT,
  LOG_LOOKUP_ROW_KIND,
  LOG_LOOKUP_TUPLE_ARITY,
  LogLookupBusItem,
  LogLookupBusPublicInput,
  LogLookupBusScheduleRow,
  buildLogLookupBusTrace,
  deriveLogLookupChallenges,
  evaluateLogLookupTransition,
  logLookupBusPublicInputDigest
} from '../stark/LogLookupBus.js'
import {
  StarkProof,
  StarkProverOptions,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/Stark.js'
import { FiatShamirTranscript } from '../stark/Transcript.js'
import {
  hmacSha256
} from '../circuit/Sha256.js'
import {
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  Method2CompactHmacSha256PublicInput,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  evaluateMethod2CompactHmacSha256Transition,
  method2CompactHmacSha256PublicInput,
  validateMethod2CompactHmacSha256PublicInput
} from './Method2CompactHmacSha256.js'
import {
  METHOD2_HMAC_KEY_SIZE,
  METHOD2_SHA256_DIGEST_SIZE
} from './Method2Hmac.js'
import {
  METHOD2_LOOKUP_SHA_TAG_AND4,
  METHOD2_LOOKUP_SHA_TAG_XOR4,
  buildMethod2LookupShaHmacTable,
  method2LookupShaHmacTableDigest
} from './Method2LookupShaHmac.js'

export const METHOD2_LOOKUP_LINKED_HMAC_SHA256_TRANSCRIPT_DOMAIN =
  'BRC97_METHOD2_LOOKUP_LINKED_HMAC_SHA256_AIR_V1'
export const METHOD2_LOOKUP_LINKED_HMAC_SHA256_PUBLIC_INPUT_ID =
  'BRC97_METHOD2_LOOKUP_LINKED_HMAC_SHA256_PUBLIC_INPUT_V1'

export const METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 16,
  maskDegree: 1,
  cosetOffset: 3n,
  transcriptDomain: METHOD2_LOOKUP_LINKED_HMAC_SHA256_TRANSCRIPT_DOMAIN
} as const

const SHA_ROUNDS = 64
const BLOCK_STRIDE = SHA_ROUNDS + 1
const NIBBLES_PER_WORD = 8
const LINK_SELECTOR_COUNT = 17
const NIBBLE_SELECTOR_COUNT = 8
const TABLE_ROWS = 512
const REQUESTS_PER_ROUND = 128
const WORD_BITS = 32

const LINK_NONE = 0
const LINK_XOR_SIGMA0_FIRST = 1
const LINK_XOR_SIGMA0_SECOND = 2
const LINK_XOR_SIGMA1_FIRST = 3
const LINK_XOR_SIGMA1_SECOND = 4
const LINK_CH_AND_EF = 5
const LINK_CH_AND_NOT_E_G = 6
const LINK_CH_XOR = 7
const LINK_MAJ_AND_AB = 8
const LINK_MAJ_AND_AC = 9
const LINK_MAJ_AND_BC = 10
const LINK_MAJ_XOR_AB_AC = 11
const LINK_MAJ_XOR_TEMP_BC = 12
const LINK_XOR_SMALL0_FIRST = 13
const LINK_XOR_SMALL0_SECOND = 14
const LINK_XOR_SMALL1_FIRST = 15
const LINK_XOR_SMALL1_SECOND = 16

export interface Method2LookupLinkedHmacSha256Layout {
  compact: number
  logLookup: number
  compactHash0: number
  compactHash1: number
  compactRegionActive: number
  compactHoldActive: number
  compactTransitionActive: number
  linkSelectors: number
  nibbleSelectors: number
  keyBytes: number
  width: number
}

export interface Method2LookupLinkedHmacSha256PublicInput {
  relation: 'lookup-linked-hmac-sha256'
  invoice: number[]
  linkage: number[]
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  compactActiveRows: number
  compactTraceLength: number
  activeRows: number
  traceLength: number
  expectedLookupRequests: number
  lookupTableRows: number
  tableDigest: number[]
}

export interface Method2LookupLinkedHmacSha256Trace {
  publicInput: Method2LookupLinkedHmacSha256PublicInput
  key: number[]
  rows: FieldElement[][]
  layout: Method2LookupLinkedHmacSha256Layout
  compact: ReturnType<typeof buildMethod2CompactHmacSha256Trace>
}

export interface Method2LookupLinkedHmacSha256Metrics {
  invoiceLength: number
  innerBlocks: number
  outerBlocks: number
  totalBlocks: number
  activeRows: number
  paddedRows: number
  traceWidth: number
  compactWidth: number
  lookupWidth: number
  lookupRequests: number
  lookupTableRows: number
  committedCells: number
  proofBytes?: number
}

interface LinkedScheduleRow {
  compactSourceRow: number
  compactRegionActive: FieldElement
  compactHoldActive: FieldElement
  compactTransitionActive: FieldElement
  linkCode: number
  nibble: number
  logSchedule: LogLookupBusScheduleRow
}

interface LinkedSchedule {
  rows: LinkedScheduleRow[]
  logPublicInput: LogLookupBusPublicInput
  compactFirstPhysicalRow: number[]
  compactLastPhysicalRow: number[]
}

interface LinkDescriptor {
  code: number
  nibble: number
  tag: FieldElement
}

interface HashChallenges {
  gammaPowers0: FieldElement[]
  gammaPowers1: FieldElement[]
}

export const METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT:
Method2LookupLinkedHmacSha256Layout = (() => {
  const compact = 0
  const logLookup = METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
  const compactHash0 = logLookup + LOG_LOOKUP_BUS_LAYOUT.width
  const compactHash1 = compactHash0 + 1
  const compactRegionActive = compactHash1 + 1
  const compactHoldActive = compactRegionActive + 1
  const compactTransitionActive = compactHoldActive + 1
  const linkSelectors = compactTransitionActive + 1
  const nibbleSelectors = linkSelectors + LINK_SELECTOR_COUNT
  return {
    compact,
    logLookup,
    compactHash0,
    compactHash1,
    compactRegionActive,
    compactHoldActive,
    compactTransitionActive,
    linkSelectors,
    nibbleSelectors,
    keyBytes: compact + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes,
    width: nibbleSelectors + NIBBLE_SELECTOR_COUNT
  }
})()

export function buildMethod2LookupLinkedHmacSha256Trace (
  key: number[],
  invoice: number[],
  linkage: number[] = hmacSha256(key, invoice),
  options: { minTraceLength?: number } = {}
): Method2LookupLinkedHmacSha256Trace {
  assertBytes(key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  if (!bytesEqual(hmacSha256(key, invoice), linkage)) {
    throw new Error('Lookup-linked HMAC-SHA256 linkage does not match key and invoice')
  }
  const compact = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
  const publicInput = method2LookupLinkedHmacSha256PublicInput(
    invoice,
    linkage,
    options
  )
  const schedule = buildLinkedSchedule(publicInput)
  const requests: LogLookupBusItem[] = []
  const requestRows: number[] = []
  for (let row = 0; row < schedule.rows.length; row++) {
    const item = logItemForLinkedRow(schedule.rows[row], compact.rows)
    requests.push(item)
    if (item.kind === LOG_LOOKUP_ROW_KIND.request) requestRows.push(row)
  }
  const table = buildMethod2LookupShaHmacTable()
  const multiplicities = requestMultiplicities(
    table,
    requestRows.map(row => requests[row])
  )
  const items = requests.slice(0, publicInput.activeRows - TABLE_ROWS)
  table.forEach((tableRow, index) => {
    items.push({
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: tableRow.tag,
      values: tableRow.values,
      publicValues: tableRow.values,
      multiplicity: BigInt(multiplicities[index])
    })
  })
  const logLookup = buildLogLookupBusTrace(items, {
    expectedRequests: publicInput.expectedLookupRequests,
    minTraceLength: publicInput.traceLength
  })
  if (logLookup.publicInput.traceLength !== publicInput.traceLength) {
    throw new Error('Lookup-linked HMAC-SHA256 log trace length mismatch')
  }
  const digest = method2LookupLinkedHmacSha256PublicInputDigest(publicInput)
  const hashChallenges = deriveHashChallenges(digest)
  const rows = new Array<FieldElement[]>(publicInput.traceLength)
  for (let rowIndex = 0; rowIndex < publicInput.traceLength; rowIndex++) {
    const row = new Array<FieldElement>(
      METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.width
    ).fill(0n)
    const scheduleRow = schedule.rows[rowIndex]
    if (scheduleRow.compactSourceRow >= 0) {
      const compactRow = compact.rows[scheduleRow.compactSourceRow]
      copyInto(row, METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compact, compactRow)
      row[METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compactHash0] =
        compactRowHash(compactRow, hashChallenges.gammaPowers0)
      row[METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compactHash1] =
        compactRowHash(compactRow, hashChallenges.gammaPowers1)
    }
    copyInto(row, METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.logLookup, logLookup.rows[rowIndex])
    row[METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compactRegionActive] =
      scheduleRow.compactRegionActive
    row[METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compactHoldActive] =
      scheduleRow.compactHoldActive
    row[METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compactTransitionActive] =
      scheduleRow.compactTransitionActive
    writeLinkSelectors(row, scheduleRow.linkCode, scheduleRow.nibble)
    rows[rowIndex] = row
  }
  const trace = {
    publicInput,
    key: key.slice(),
    rows,
    layout: METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT,
    compact
  }
  validateMethod2LookupLinkedHmacSha256Trace(trace)
  return trace
}

export function method2LookupLinkedHmacSha256PublicInput (
  invoice: number[],
  linkage: number[],
  options: { minTraceLength?: number } = {}
): Method2LookupLinkedHmacSha256PublicInput {
  const compact = method2CompactHmacSha256PublicInput(invoice, linkage)
  const expectedLookupRequests = compact.totalBlocks * SHA_ROUNDS *
    REQUESTS_PER_ROUND
  const compactPhysicalRows = expectedLookupRequests + compact.totalBlocks
  const activeRows = compactPhysicalRows + TABLE_ROWS
  const traceLength = nextPowerOfTwo(Math.max(
    activeRows + 1,
    options.minTraceLength ?? 0
  ))
  return {
    relation: 'lookup-linked-hmac-sha256',
    invoice: invoice.slice(),
    linkage: linkage.slice(),
    innerBlocks: compact.innerBlocks,
    outerBlocks: compact.outerBlocks,
    totalBlocks: compact.totalBlocks,
    compactActiveRows: compact.activeRows,
    compactTraceLength: compact.traceLength,
    activeRows,
    traceLength,
    expectedLookupRequests,
    lookupTableRows: TABLE_ROWS,
    tableDigest: method2LookupShaHmacTableDigest()
  }
}

export function buildMethod2LookupLinkedHmacSha256Air (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): AirDefinition {
  validateMethod2LookupLinkedHmacSha256PublicInput(publicInput)
  const compactPublicInput = compactPublicInputFromLinked(publicInput)
  const compactAir = buildMethod2CompactHmacSha256Air(compactPublicInput)
  const schedule = buildLinkedSchedule(publicInput)
  const logAir = {
    ...schedule.logPublicInput,
    scheduleRows: schedule.rows.map(row => row.logSchedule)
  }
  const logChallenges = deriveLogLookupChallenges(
    logLookupBusPublicInputDigest(logAir)
  )
  const digest = method2LookupLinkedHmacSha256PublicInputDigest(publicInput)
  const hashChallenges = deriveHashChallenges(digest)
  return {
    traceWidth: METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.width,
    transitionDegree: 10,
    publicInputDigest: digest,
    boundaryConstraints: [
      ...remapCompactBoundaryConstraints(
        compactAir.boundaryConstraints,
        schedule
      ),
      ...logBoundaryConstraints(publicInput)
    ],
    fullBoundaryColumns: [
      ...remapCompactFullBoundaryColumns(
        compactAir.fullBoundaryColumns ?? [],
        schedule,
        publicInput.traceLength
      ),
      ...linkedScheduleFullBoundaryColumns(schedule),
      ...logFullBoundaryColumns(schedule)
    ],
    evaluateTransition: (current, next) =>
      evaluateLookupLinkedHmacTransition(
        current,
        next,
        hashChallenges,
        logChallenges
      )
  }
}

export function proveMethod2LookupLinkedHmacSha256 (
  trace: Method2LookupLinkedHmacSha256Trace,
  options: StarkProverOptions = {}
): StarkProof {
  validateMethod2LookupLinkedHmacSha256Trace(trace)
  const air = buildMethod2LookupLinkedHmacSha256Air(trace.publicInput)
  return proveStark(air, trace.rows, {
    ...METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS,
    ...options,
    publicInputDigest: air.publicInputDigest,
    transcriptDomain: METHOD2_LOOKUP_LINKED_HMAC_SHA256_TRANSCRIPT_DOMAIN
  })
}

export function verifyMethod2LookupLinkedHmacSha256 (
  publicInput: Method2LookupLinkedHmacSha256PublicInput,
  proof: StarkProof
): boolean {
  try {
    if (!lookupLinkedHmacProofMeetsMinimumProfile(proof)) return false
    const air = buildMethod2LookupLinkedHmacSha256Air(publicInput)
    return verifyStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset,
      traceDegreeBound: proof.traceDegreeBound,
      compositionDegreeBound: proof.compositionDegreeBound,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: proofTranscriptDomain(proof)
    })
  } catch {
    return false
  }
}

export function evaluateLookupLinkedHmacTransition (
  current: FieldElement[],
  next: FieldElement[],
  hashChallenges: HashChallenges,
  logChallenges: Parameters<typeof evaluateLogLookupTransition>[2]
): FieldElement[] {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  const compactCurrent = current.slice(
    layout.compact,
    layout.compact + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
  )
  const compactNext = next.slice(
    layout.compact,
    layout.compact + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
  )
  const logCurrent = current.slice(
    layout.logLookup,
    layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.width
  )
  const logNext = next.slice(
    layout.logLookup,
    layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.width
  )
  const constraints = evaluateLogLookupTransition(
    logCurrent,
    logNext,
    logChallenges
  )
  const regionActive = current[layout.compactRegionActive]
  const holdActive = current[layout.compactHoldActive]
  const transitionActive = current[layout.compactTransitionActive]
  constraints.push(booleanConstraint(regionActive))
  constraints.push(booleanConstraint(holdActive))
  constraints.push(booleanConstraint(transitionActive))
  constraints.push(F.mul(
    regionActive,
    F.sub(
      current[layout.compactHash0],
      compactRowHash(compactCurrent, hashChallenges.gammaPowers0)
    )
  ))
  constraints.push(F.mul(
    regionActive,
    F.sub(
      current[layout.compactHash1],
      compactRowHash(compactCurrent, hashChallenges.gammaPowers1)
    )
  ))
  constraints.push(F.mul(
    holdActive,
    F.sub(next[layout.compactHash0], current[layout.compactHash0])
  ))
  constraints.push(F.mul(
    holdActive,
    F.sub(next[layout.compactHash1], current[layout.compactHash1])
  ))
  constraints.push(...gated(
    transitionActive,
    evaluateMethod2CompactHmacSha256Transition(
      compactCurrent,
      compactNext,
      METHOD2_COMPACT_HMAC_SHA256_LAYOUT
    )
  ))
  constraints.push(...lookupLinkConstraints(current))
  return constraints
}

export function method2LookupLinkedHmacSha256Metrics (
  trace: Method2LookupLinkedHmacSha256Trace,
  proof?: StarkProof
): Method2LookupLinkedHmacSha256Metrics {
  return {
    invoiceLength: trace.publicInput.invoice.length,
    innerBlocks: trace.publicInput.innerBlocks,
    outerBlocks: trace.publicInput.outerBlocks,
    totalBlocks: trace.publicInput.totalBlocks,
    activeRows: trace.publicInput.activeRows,
    paddedRows: trace.publicInput.traceLength,
    traceWidth: trace.layout.width,
    compactWidth: METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width,
    lookupWidth: LOG_LOOKUP_BUS_LAYOUT.width,
    lookupRequests: trace.publicInput.expectedLookupRequests,
    lookupTableRows: trace.publicInput.lookupTableRows,
    committedCells: trace.publicInput.traceLength * trace.layout.width,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function method2LookupLinkedHmacSha256KeyForLink (
  trace: Method2LookupLinkedHmacSha256Trace
): number[] {
  validateMethod2LookupLinkedHmacSha256Trace(trace)
  return trace.key.slice()
}

export function method2LookupLinkedHmacSha256PublicInputDigest (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): number[] {
  validateMethod2LookupLinkedHmacSha256PublicInput(publicInput)
  const writer = new Writer()
  writer.write(toArray(METHOD2_LOOKUP_LINKED_HMAC_SHA256_PUBLIC_INPUT_ID, 'utf8'))
  writer.writeVarIntNum(publicInput.invoice.length)
  writer.write(publicInput.invoice)
  writer.writeVarIntNum(publicInput.linkage.length)
  writer.write(publicInput.linkage)
  writer.writeVarIntNum(publicInput.innerBlocks)
  writer.writeVarIntNum(publicInput.outerBlocks)
  writer.writeVarIntNum(publicInput.totalBlocks)
  writer.writeVarIntNum(publicInput.compactActiveRows)
  writer.writeVarIntNum(publicInput.compactTraceLength)
  writer.writeVarIntNum(publicInput.activeRows)
  writer.writeVarIntNum(publicInput.traceLength)
  writer.writeVarIntNum(publicInput.expectedLookupRequests)
  writer.writeVarIntNum(publicInput.lookupTableRows)
  writer.writeVarIntNum(publicInput.tableDigest.length)
  writer.write(publicInput.tableDigest)
  writer.writeVarIntNum(METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.width)
  return sha256(writer.toArray())
}

export function validateMethod2LookupLinkedHmacSha256Trace (
  trace: Method2LookupLinkedHmacSha256Trace
): void {
  validateMethod2LookupLinkedHmacSha256PublicInput(trace.publicInput)
  assertBytes(trace.key, METHOD2_HMAC_KEY_SIZE, 'HMAC key')
  if (!bytesEqual(hmacSha256(trace.key, trace.publicInput.invoice), trace.publicInput.linkage)) {
    throw new Error('Lookup-linked HMAC-SHA256 trace linkage mismatch')
  }
  if (trace.layout.width !== METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.width) {
    throw new Error('Lookup-linked HMAC-SHA256 layout mismatch')
  }
  if (trace.rows.length !== trace.publicInput.traceLength) {
    throw new Error('Lookup-linked HMAC-SHA256 trace length mismatch')
  }
  for (const row of trace.rows) {
    if (row.length !== trace.layout.width) {
      throw new Error('Lookup-linked HMAC-SHA256 trace row width mismatch')
    }
  }
}

export function validateMethod2LookupLinkedHmacSha256PublicInput (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): void {
  if (publicInput.relation !== 'lookup-linked-hmac-sha256') {
    throw new Error('Lookup-linked HMAC-SHA256 relation mismatch')
  }
  assertBytes(publicInput.invoice, undefined, 'invoice')
  assertBytes(publicInput.linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const expected = method2LookupLinkedHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  if (
    publicInput.innerBlocks !== expected.innerBlocks ||
    publicInput.outerBlocks !== expected.outerBlocks ||
    publicInput.totalBlocks !== expected.totalBlocks ||
    publicInput.compactActiveRows !== expected.compactActiveRows ||
    publicInput.compactTraceLength !== expected.compactTraceLength ||
    publicInput.activeRows !== expected.activeRows ||
    publicInput.expectedLookupRequests !== expected.expectedLookupRequests ||
    publicInput.lookupTableRows !== expected.lookupTableRows
  ) {
    throw new Error('Lookup-linked HMAC-SHA256 public input shape mismatch')
  }
  if (
    !isPowerOfTwo(publicInput.traceLength) ||
    publicInput.traceLength < expected.traceLength
  ) {
    throw new Error('Lookup-linked HMAC-SHA256 trace length mismatch')
  }
  if (!bytesEqual(publicInput.tableDigest, expected.tableDigest)) {
    throw new Error('Lookup-linked HMAC-SHA256 table digest mismatch')
  }
}

function buildLinkedSchedule (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): LinkedSchedule {
  const rows: LinkedScheduleRow[] = []
  const compactFirstPhysicalRow = new Array<number>(
    publicInput.compactActiveRows
  ).fill(-1)
  const compactLastPhysicalRow = new Array<number>(
    publicInput.compactActiveRows
  ).fill(-1)
  for (let compactRow = 0; compactRow < publicInput.compactActiveRows; compactRow++) {
    compactFirstPhysicalRow[compactRow] = rows.length
    if (isCompactRoundRow(compactRow)) {
      const descriptors = roundLinkDescriptors()
      descriptors.forEach((descriptor, index) => {
        rows.push(scheduleRow({
          compactSourceRow: compactRow,
          compactRegionActive: 1n,
          compactHoldActive: index + 1 < descriptors.length ? 1n : 0n,
          compactTransitionActive:
            index + 1 === descriptors.length &&
            compactRow + 1 < publicInput.compactActiveRows
              ? 1n
              : 0n,
          linkCode: descriptor.code,
          nibble: descriptor.nibble,
          logSchedule: {
            kind: LOG_LOOKUP_ROW_KIND.request,
            tag: descriptor.tag,
            publicTuple: zeroTuple()
          }
        }))
      })
    } else {
      rows.push(scheduleRow({
        compactSourceRow: compactRow,
        compactRegionActive: 1n,
        compactHoldActive: 0n,
        compactTransitionActive: compactRow + 1 < publicInput.compactActiveRows
          ? 1n
          : 0n,
        linkCode: LINK_NONE,
        nibble: 0,
        logSchedule: inactiveLogSchedule()
      }))
    }
    compactLastPhysicalRow[compactRow] = rows.length - 1
  }
  for (const tableRow of buildMethod2LookupShaHmacTable()) {
    rows.push(scheduleRow({
      compactSourceRow: -1,
      compactRegionActive: 0n,
      compactHoldActive: 0n,
      compactTransitionActive: 0n,
      linkCode: LINK_NONE,
      nibble: 0,
      logSchedule: {
        kind: LOG_LOOKUP_ROW_KIND.supply,
        tag: tableRow.tag,
        publicTuple: tableRow.values
      }
    }))
  }
  while (rows.length < publicInput.traceLength) {
    rows.push(scheduleRow({
      compactSourceRow: -1,
      compactRegionActive: 0n,
      compactHoldActive: 0n,
      compactTransitionActive: 0n,
      linkCode: LINK_NONE,
      nibble: 0,
      logSchedule: inactiveLogSchedule()
    }))
  }
  if (rows.length !== publicInput.traceLength) {
    throw new Error('Lookup-linked HMAC-SHA256 schedule length mismatch')
  }
  return {
    rows,
    compactFirstPhysicalRow,
    compactLastPhysicalRow,
    logPublicInput: {
      traceLength: publicInput.traceLength,
      expectedRequests: publicInput.expectedLookupRequests,
      scheduleRows: rows.map(row => row.logSchedule)
    }
  }
}

function scheduleRow (row: LinkedScheduleRow): LinkedScheduleRow {
  return row
}

function logItemForLinkedRow (
  schedule: LinkedScheduleRow,
  compactRows: FieldElement[][]
): LogLookupBusItem {
  if (schedule.logSchedule.kind === LOG_LOOKUP_ROW_KIND.request) {
    const compactRow = compactRows[schedule.compactSourceRow]
    return {
      kind: LOG_LOOKUP_ROW_KIND.request,
      tag: schedule.logSchedule.tag,
      values: expectedLookupTuple(compactRow, schedule.linkCode, schedule.nibble),
      multiplicity: 1n
    }
  }
  if (schedule.logSchedule.kind === LOG_LOOKUP_ROW_KIND.supply) {
    return {
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: schedule.logSchedule.tag,
      values: schedule.logSchedule.publicTuple,
      publicValues: schedule.logSchedule.publicTuple,
      multiplicity: 0n
    }
  }
  return {
    kind: LOG_LOOKUP_ROW_KIND.inactive,
    tag: 0n,
    values: zeroTuple(),
    multiplicity: 0n
  }
}

function lookupLinkConstraints (current: FieldElement[]): FieldElement[] {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  const logOffset = layout.logLookup
  const compactRow = current.slice(
    layout.compact,
    layout.compact + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width
  )
  const constraints: FieldElement[] = []
  let linkActive = 0n
  for (let index = 0; index < LINK_SELECTOR_COUNT; index++) {
    const selector = current[layout.linkSelectors + index]
    const code = index + 1
    linkActive = F.add(linkActive, selector)
    for (const value of gated(
      selector,
      tupleEquality(
        current.slice(
          logOffset + LOG_LOOKUP_BUS_LAYOUT.tuple,
          logOffset + LOG_LOOKUP_BUS_LAYOUT.tuple + LOG_LOOKUP_TUPLE_ARITY
        ),
        expectedLookupTuple(compactRow, code, selectedNibble(current))
      )
    )) {
      constraints.push(value)
    }
  }
  constraints.push(F.mul(
    linkActive,
    F.sub(current[logOffset + LOG_LOOKUP_BUS_LAYOUT.kind], LOG_LOOKUP_ROW_KIND.request)
  ))
  return constraints
}

function expectedLookupTuple (
  compactRow: FieldElement[],
  code: number,
  nibble: number
): FieldElement[] {
  const bits = compactBits(compactRow)
  switch (code) {
    case LINK_XOR_SIGMA0_FIRST:
      return xorFirstTuple(
        rotrBits(bits.a, 2),
        rotrBits(bits.a, 13),
        nibble
      )
    case LINK_XOR_SIGMA0_SECOND:
      return xorSecondTuple(
        rotrBits(bits.a, 2),
        rotrBits(bits.a, 13),
        rotrBits(bits.a, 22),
        nibble
      )
    case LINK_XOR_SIGMA1_FIRST:
      return xorFirstTuple(
        rotrBits(bits.e, 6),
        rotrBits(bits.e, 11),
        nibble
      )
    case LINK_XOR_SIGMA1_SECOND:
      return xorSecondTuple(
        rotrBits(bits.e, 6),
        rotrBits(bits.e, 11),
        rotrBits(bits.e, 25),
        nibble
      )
    case LINK_CH_AND_EF:
      return andTuple(bits.e, bits.f, nibble)
    case LINK_CH_AND_NOT_E_G:
      return andTuple(notBits(bits.e), bits.g, nibble)
    case LINK_CH_XOR:
      return xorFirstTuple(andBits(bits.e, bits.f), andBits(notBits(bits.e), bits.g), nibble)
    case LINK_MAJ_AND_AB:
      return andTuple(bits.a, bits.b, nibble)
    case LINK_MAJ_AND_AC:
      return andTuple(bits.a, bits.c, nibble)
    case LINK_MAJ_AND_BC:
      return andTuple(bits.b, bits.c, nibble)
    case LINK_MAJ_XOR_AB_AC:
      return xorFirstTuple(andBits(bits.a, bits.b), andBits(bits.a, bits.c), nibble)
    case LINK_MAJ_XOR_TEMP_BC:
      return xorFirstTuple(
        xorBits(andBits(bits.a, bits.b), andBits(bits.a, bits.c)),
        andBits(bits.b, bits.c),
        nibble
      )
    case LINK_XOR_SMALL0_FIRST:
      return xorFirstTuple(
        rotrBits(bits.schedule1, 7),
        rotrBits(bits.schedule1, 18),
        nibble
      )
    case LINK_XOR_SMALL0_SECOND:
      return xorSecondTuple(
        rotrBits(bits.schedule1, 7),
        rotrBits(bits.schedule1, 18),
        shrBits(bits.schedule1, 3),
        nibble
      )
    case LINK_XOR_SMALL1_FIRST:
      return xorFirstTuple(
        rotrBits(bits.schedule14, 17),
        rotrBits(bits.schedule14, 19),
        nibble
      )
    case LINK_XOR_SMALL1_SECOND:
      return xorSecondTuple(
        rotrBits(bits.schedule14, 17),
        rotrBits(bits.schedule14, 19),
        shrBits(bits.schedule14, 10),
        nibble
      )
    default:
      return zeroTuple()
  }
}

function compactBits (
  row: FieldElement[]
): Record<string, FieldElement[]> {
  const layout = METHOD2_COMPACT_HMAC_SHA256_LAYOUT
  return {
    a: row.slice(layout.aBits, layout.aBits + WORD_BITS),
    b: row.slice(layout.bBits, layout.bBits + WORD_BITS),
    c: row.slice(layout.cBits, layout.cBits + WORD_BITS),
    e: row.slice(layout.eBits, layout.eBits + WORD_BITS),
    f: row.slice(layout.fBits, layout.fBits + WORD_BITS),
    g: row.slice(layout.gBits, layout.gBits + WORD_BITS),
    schedule1: row.slice(layout.schedule1Bits, layout.schedule1Bits + WORD_BITS),
    schedule14: row.slice(layout.schedule14Bits, layout.schedule14Bits + WORD_BITS)
  }
}

function xorFirstTuple (
  left: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  return padTuple([
    nibbleFromBits(left, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(xorBits(left, right), nibble)
  ])
}

function xorSecondTuple (
  left: FieldElement[],
  middle: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  const temp = xorBits(left, middle)
  return padTuple([
    nibbleFromBits(temp, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(xorBits(temp, right), nibble)
  ])
}

function andTuple (
  left: FieldElement[],
  right: FieldElement[],
  nibble: number
): FieldElement[] {
  return padTuple([
    nibbleFromBits(left, nibble),
    nibbleFromBits(right, nibble),
    nibbleFromBits(andBits(left, right), nibble)
  ])
}

function selectedNibble (row: FieldElement[]): number {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  for (let nibble = 0; nibble < NIBBLE_SELECTOR_COUNT; nibble++) {
    if (row[layout.nibbleSelectors + nibble] === 1n) return nibble
  }
  return 0
}

function writeLinkSelectors (
  row: FieldElement[],
  code: number,
  nibble: number
): void {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  if (code !== LINK_NONE) {
    row[layout.linkSelectors + code - 1] = 1n
    row[layout.nibbleSelectors + nibble] = 1n
  }
}

function linkedScheduleFullBoundaryColumns (
  schedule: LinkedSchedule
): AirDefinition['fullBoundaryColumns'] {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  const columns: AirDefinition['fullBoundaryColumns'] = [
    {
      column: layout.compactRegionActive,
      values: schedule.rows.map(row => row.compactRegionActive)
    },
    {
      column: layout.compactHoldActive,
      values: schedule.rows.map(row => row.compactHoldActive)
    },
    {
      column: layout.compactTransitionActive,
      values: schedule.rows.map(row => row.compactTransitionActive)
    }
  ]
  for (let code = 1; code <= LINK_SELECTOR_COUNT; code++) {
    columns.push({
      column: layout.linkSelectors + code - 1,
      values: schedule.rows.map(row => row.linkCode === code ? 1n : 0n)
    })
  }
  for (let nibble = 0; nibble < NIBBLE_SELECTOR_COUNT; nibble++) {
    columns.push({
      column: layout.nibbleSelectors + nibble,
      values: schedule.rows.map(row =>
        row.linkCode !== LINK_NONE && row.nibble === nibble ? 1n : 0n
      )
    })
  }
  return columns
}

function remapCompactFullBoundaryColumns (
  columns: NonNullable<AirDefinition['fullBoundaryColumns']>,
  schedule: LinkedSchedule,
  traceLength: number
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  return columns.map(column => {
    const values = new Array<FieldElement>(traceLength).fill(0n)
    for (let row = 0; row < traceLength; row++) {
      const source = schedule.rows[row].compactSourceRow
      if (source >= 0) values[row] = column.values[source] ?? 0n
    }
    return {
      column: METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compact + column.column,
      values
    }
  })
}

function remapCompactBoundaryConstraints (
  constraints: AirDefinition['boundaryConstraints'],
  schedule: LinkedSchedule
): AirDefinition['boundaryConstraints'] {
  return constraints
    .filter(constraint => constraint.row < schedule.compactFirstPhysicalRow.length)
    .map(constraint => ({
      column: METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT.compact + constraint.column,
      row: schedule.compactFirstPhysicalRow[constraint.row],
      value: constraint.value
    }))
}

function logBoundaryConstraints (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): AirDefinition['boundaryConstraints'] {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  const lastRow = publicInput.traceLength - 1
  return [
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.accumulator0, row: 0, value: 0n },
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.accumulator1, row: 0, value: 0n },
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.requestCount, row: 0, value: 0n },
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.supplyCount, row: 0, value: 0n },
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.accumulator0, row: lastRow, value: 0n },
    { column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.accumulator1, row: lastRow, value: 0n },
    {
      column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.requestCount,
      row: lastRow,
      value: BigInt(publicInput.expectedLookupRequests)
    },
    {
      column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.supplyCount,
      row: lastRow,
      value: BigInt(publicInput.expectedLookupRequests)
    }
  ]
}

function logFullBoundaryColumns (
  schedule: LinkedSchedule
): NonNullable<AirDefinition['fullBoundaryColumns']> {
  const layout = METHOD2_LOOKUP_LINKED_HMAC_SHA256_LAYOUT
  return [
    {
      column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.kind,
      values: schedule.rows.map(row => row.logSchedule.kind)
    },
    {
      column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.tag,
      values: schedule.rows.map(row => row.logSchedule.tag)
    },
    ...Array.from({ length: LOG_LOOKUP_TUPLE_ARITY }, (_, index) => ({
      column: layout.logLookup + LOG_LOOKUP_BUS_LAYOUT.publicTuple + index,
      values: schedule.rows.map(row => row.logSchedule.publicTuple[index])
    }))
  ]
}

function compactPublicInputFromLinked (
  publicInput: Method2LookupLinkedHmacSha256PublicInput
): Method2CompactHmacSha256PublicInput {
  const compact = method2CompactHmacSha256PublicInput(
    publicInput.invoice,
    publicInput.linkage
  )
  validateMethod2CompactHmacSha256PublicInput(compact)
  return compact
}

function roundLinkDescriptors (): LinkDescriptor[] {
  const out: LinkDescriptor[] = []
  appendXor3Descriptors(out, LINK_XOR_SIGMA0_FIRST, LINK_XOR_SIGMA0_SECOND)
  appendXor3Descriptors(out, LINK_XOR_SIGMA1_FIRST, LINK_XOR_SIGMA1_SECOND)
  appendChDescriptors(out)
  appendMajDescriptors(out)
  appendXor3Descriptors(out, LINK_XOR_SMALL0_FIRST, LINK_XOR_SMALL0_SECOND)
  appendXor3Descriptors(out, LINK_XOR_SMALL1_FIRST, LINK_XOR_SMALL1_SECOND)
  return out
}

function appendXor3Descriptors (
  out: LinkDescriptor[],
  first: number,
  second: number
): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: first, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
    out.push({ code: second, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function appendChDescriptors (out: LinkDescriptor[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: LINK_CH_AND_EF, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_CH_AND_NOT_E_G, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_CH_XOR, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function appendMajDescriptors (out: LinkDescriptor[]): void {
  for (let nibble = 0; nibble < NIBBLES_PER_WORD; nibble++) {
    out.push({ code: LINK_MAJ_AND_AB, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_AND_AC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_AND_BC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_AND4 })
    out.push({ code: LINK_MAJ_XOR_AB_AC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
    out.push({ code: LINK_MAJ_XOR_TEMP_BC, nibble, tag: METHOD2_LOOKUP_SHA_TAG_XOR4 })
  }
}

function requestMultiplicities (
  table: ReturnType<typeof buildMethod2LookupShaHmacTable>,
  requests: LogLookupBusItem[]
): number[] {
  const indexByKey = new Map<string, number>()
  table.forEach((row, index) => {
    indexByKey.set(tupleKey(row.tag, row.values), index)
  })
  const out = new Array<number>(table.length).fill(0)
  for (const request of requests) {
    const index = indexByKey.get(tupleKey(request.tag, request.values ?? []))
    if (index === undefined) {
      throw new Error('Lookup-linked HMAC-SHA256 request is missing from table')
    }
    out[index]++
  }
  return out
}

function compactRowHash (
  row: FieldElement[],
  powers: FieldElement[]
): FieldElement {
  let out = 0n
  for (let i = 0; i < METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width; i++) {
    out = F.add(out, F.mul(F.normalize(row[i] ?? 0n), powers[i]))
  }
  return out
}

function deriveHashChallenges (
  publicInputDigest: number[]
): HashChallenges {
  const transcript = new FiatShamirTranscript(
    `${METHOD2_LOOKUP_LINKED_HMAC_SHA256_TRANSCRIPT_DOMAIN}:row-hash`
  )
  transcript.absorb('public-input', publicInputDigest)
  return {
    gammaPowers0: challengePowers(nonZeroChallenge(transcript, 'gamma-0')),
    gammaPowers1: challengePowers(nonZeroChallenge(transcript, 'gamma-1'))
  }
}

function challengePowers (gamma: FieldElement): FieldElement[] {
  const powers = new Array<FieldElement>(METHOD2_COMPACT_HMAC_SHA256_LAYOUT.width)
  let power = F.normalize(gamma)
  for (let i = 0; i < powers.length; i++) {
    powers[i] = power
    power = F.mul(power, gamma)
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
  throw new Error('Lookup-linked HMAC-SHA256 could not derive non-zero challenge')
}

function isCompactRoundRow (row: number): boolean {
  return row % BLOCK_STRIDE < SHA_ROUNDS
}

function lookupLinkedHmacProofMeetsMinimumProfile (proof: StarkProof): boolean {
  return proof.blowupFactor >=
    METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS.blowupFactor &&
    proof.numQueries >=
      METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS.numQueries &&
    proof.maxRemainderSize <=
      METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS.maxRemainderSize &&
    proof.maskDegree >=
      METHOD2_LOOKUP_LINKED_HMAC_SHA256_STARK_OPTIONS.maskDegree &&
    proof.cosetOffset !== 0n
}

function proofTranscriptDomain (proof: StarkProof): string {
  return (proof as StarkProof & { transcriptDomain?: string }).transcriptDomain ??
    METHOD2_LOOKUP_LINKED_HMAC_SHA256_TRANSCRIPT_DOMAIN
}

function tupleEquality (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return Array.from({ length: LOG_LOOKUP_TUPLE_ARITY }, (_, index) =>
    F.sub(left[index] ?? 0n, right[index] ?? 0n)
  )
}

function tupleKey (tag: FieldElement, values: FieldElement[]): string {
  return `${F.normalize(tag).toString()}:${
    values.map(value => F.normalize(value).toString()).join(',')
  }`
}

function rotrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bits[(bit + amount) % WORD_BITS])
}

function shrBits (bits: FieldElement[], amount: number): FieldElement[] {
  return bits.map((_, bit) => bit + amount < WORD_BITS ? bits[bit + amount] : 0n)
}

function xorBits (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((bit, index) => xorBit(bit, right[index]))
}

function andBits (
  left: FieldElement[],
  right: FieldElement[]
): FieldElement[] {
  return left.map((bit, index) => F.mul(bit, right[index]))
}

function notBits (bits: FieldElement[]): FieldElement[] {
  return bits.map(bit => F.sub(1n, bit))
}

function xorBit (left: FieldElement, right: FieldElement): FieldElement {
  return F.sub(F.add(left, right), F.mul(2n, F.mul(left, right)))
}

function nibbleFromBits (
  bits: FieldElement[],
  nibble: number
): FieldElement {
  let out = 0n
  for (let bit = 0; bit < 4; bit++) {
    out = F.add(out, F.mul(bits[nibble * 4 + bit], BigInt(1 << bit)))
  }
  return out
}

function padTuple (values: FieldElement[]): FieldElement[] {
  const out = zeroTuple()
  for (let i = 0; i < values.length; i++) out[i] = F.normalize(values[i])
  return out
}

function zeroTuple (): FieldElement[] {
  return new Array<FieldElement>(LOG_LOOKUP_TUPLE_ARITY).fill(0n)
}

function inactiveLogSchedule (): LogLookupBusScheduleRow {
  return {
    kind: LOG_LOOKUP_ROW_KIND.inactive,
    tag: 0n,
    publicTuple: zeroTuple()
  }
}

function gated (
  selector: FieldElement,
  constraints: FieldElement[]
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function copyInto (
  target: FieldElement[],
  offset: number,
  source: FieldElement[]
): void {
  for (let i = 0; i < source.length; i++) target[offset + i] = source[i]
}

function assertBytes (
  bytes: number[],
  length: number | undefined,
  label: string
): void {
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`Invalid ${label} length`)
  }
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid ${label} byte`)
    }
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  if (left.length !== right.length) return false
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]
  return diff === 0
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function isPowerOfTwo (value: number): boolean {
  return Number.isSafeInteger(value) && value > 0 && (value & (value - 1)) === 0
}
