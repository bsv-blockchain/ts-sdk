import {
  AirDefinition,
  F,
  FieldElement,
  StarkProverOptions,
  StarkProof,
  evaluateAirTrace,
  proveStark,
  serializeStarkProof,
  verifyStark
} from '../stark/index.js'
import { sha256 } from '../../../primitives/Hash.js'
import { Writer, toArray } from '../../../primitives/utils.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  METHOD2_V2_PROFILE,
  METHOD2_V2_STARK_BLOWUP_FACTOR,
  METHOD2_V2_STARK_COSET_OFFSET,
  METHOD2_V2_STARK_MAX_REMAINDER_SIZE,
  METHOD2_V2_STARK_NUM_QUERIES,
  Method2V2AccumulationRow,
  Method2V2SelectionRow,
  Method2V2Trace,
  method2V2Metrics
} from './Method2V2.js'

export const BRC69_METHOD2_V2_SCALAR_CORE_TRANSCRIPT_DOMAIN =
  'BRC69_METHOD2_V2_SCALAR_CORE_AIR_V1'

export interface Method2V2ScalarCoreLayout {
  isSelect: number
  isAccumulate: number
  isPadding: number
  firstInWindow: number
  lastInWindow: number
  window: number
  windowWeight: number
  candidate: number
  selector: number
  selectorSum: number
  selectedDigit: number
  candidateG: number
  candidateB: number
  selectedG: number
  selectedB: number
  accScalarBefore: number
  accScalarAfter: number
  accGBefore: number
  accBBefore: number
  accGAfter: number
  accBAfter: number
  width: number
}

export interface Method2V2ScalarCoreTrace {
  rows: FieldElement[][]
  activeRows: number
  paddedRows: number
  layout: Method2V2ScalarCoreLayout
}

export interface Method2V2ScalarCoreFeasibility {
  activeRows: number
  paddedRows: number
  traceWidth: number
  privateCommittedWidth: number
  publicPreprocessedWidth: number
  ldeRows: number
  estimatedTraceArea: number
  invoiceLength: number
  proofBytes?: number
}

export const METHOD2_V2_SCALAR_CORE_LAYOUT: Method2V2ScalarCoreLayout = {
  isSelect: 0,
  isAccumulate: 1,
  isPadding: 2,
  firstInWindow: 3,
  lastInWindow: 4,
  window: 5,
  windowWeight: 6,
  candidate: 7,
  selector: 8,
  selectorSum: 9,
  selectedDigit: 10,
  candidateG: 11,
  candidateB: 12,
  selectedG: 13,
  selectedB: 14,
  accScalarBefore: 15,
  accScalarAfter: 16,
  accGBefore: 17,
  accBBefore: 18,
  accGAfter: 19,
  accBAfter: 20,
  width: 21
}

const INFINITY_FINGERPRINT = pointFingerprint({ x: 0n, y: 0n, infinity: true })

export function buildMethod2V2ScalarCoreTrace (
  trace: Method2V2Trace
): Method2V2ScalarCoreTrace {
  const layout = METHOD2_V2_SCALAR_CORE_LAYOUT
  const activeRows = trace.rows.length
  const paddedRows = nextPowerOfTwo(activeRows)
  const rows = new Array<FieldElement[]>(paddedRows)
    .fill([])
    .map(() => new Array<FieldElement>(layout.width).fill(0n))
  let rowIndex = 0
  let accScalar = 0n
  let runningSelectedDigit = 0n
  let accGFingerprint = INFINITY_FINGERPRINT
  let accBFingerprint = INFINITY_FINGERPRINT
  for (const source of trace.rows) {
    const row = rows[rowIndex]
    if (source.phase === 'select') {
      if (source.digit === 0) runningSelectedDigit = 0n
      runningSelectedDigit = F.add(
        runningSelectedDigit,
        F.mul(BigInt(source.selector), BigInt(source.digit))
      )
      writeSelectionRow(
        row,
        source,
        accScalar,
        runningSelectedDigit,
        accGFingerprint,
        accBFingerprint
      )
    } else {
      const weight = windowWeight(source.window)
      writeAccumulationRow(row, source, accScalar, F.add(
        accScalar,
        F.mul(BigInt(source.digit), weight)
      ))
      accScalar = row[layout.accScalarAfter]
      accGFingerprint = row[layout.accGAfter]
      accBFingerprint = row[layout.accBAfter]
    }
    rowIndex++
  }
  for (; rowIndex < paddedRows; rowIndex++) {
    rows[rowIndex][layout.isPadding] = 1n
  }
  return {
    rows,
    activeRows,
    paddedRows,
    layout
  }
}

export function buildMethod2V2ScalarCoreAir (
  trace: Method2V2Trace,
  publicInputDigest: number[] = []
): AirDefinition {
  const coreTrace = buildMethod2V2ScalarCoreTrace(trace)
  const layout = coreTrace.layout
  const finalAccRow = coreTrace.activeRows - 1
  return {
    traceWidth: layout.width,
    transitionDegree: 4,
    publicInputDigest,
    blowupFactor: METHOD2_V2_STARK_BLOWUP_FACTOR,
    numQueries: METHOD2_V2_STARK_NUM_QUERIES,
    maxRemainderSize: METHOD2_V2_STARK_MAX_REMAINDER_SIZE,
    cosetOffset: METHOD2_V2_STARK_COSET_OFFSET,
    boundaryConstraints: [
      {
        column: layout.accGAfter,
        row: finalAccRow,
        value: pointFingerprint(trace.publicA)
      },
      {
        column: layout.accBAfter,
        row: finalAccRow,
        value: pointFingerprint(trace.sharedS)
      }
    ],
    fullBoundaryColumns: publicScheduleBoundaryColumns(coreTrace.rows, layout),
    evaluateTransition: (current, next) =>
      evaluateMethod2V2ScalarCoreTransition(current, next, layout)
  }
}

export function evaluateMethod2V2ScalarCoreTransition (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2ScalarCoreLayout = METHOD2_V2_SCALAR_CORE_LAYOUT
): FieldElement[] {
  const constraints: FieldElement[] = [
    booleanConstraint(current[layout.isSelect]),
    booleanConstraint(current[layout.isAccumulate]),
    booleanConstraint(current[layout.isPadding]),
    F.sub(
      F.add(
        F.add(current[layout.isSelect], current[layout.isAccumulate]),
        current[layout.isPadding]
      ),
      1n
    ),
    F.mul(
      current[layout.isSelect],
      booleanConstraint(current[layout.selector])
    )
  ]

  constraints.push(...gateConstraints(
    firstSelectionConstraints(current, layout),
    F.mul(current[layout.isSelect], current[layout.firstInWindow])
  ))
  constraints.push(...gateConstraints(
    nextSelectionConstraints(current, next, layout),
    F.mul(current[layout.isSelect], F.sub(1n, current[layout.lastInWindow]))
  ))
  constraints.push(...gateConstraints(
    selectionToAccumulationConstraints(current, next, layout),
    F.mul(current[layout.isSelect], current[layout.lastInWindow])
  ))
  constraints.push(...gateConstraints(
    accumulationConstraints(current, layout),
    current[layout.isAccumulate]
  ))
  constraints.push(...gateConstraints(
    accumulationToSelectionConstraints(current, next, layout),
    F.mul(current[layout.isAccumulate], next[layout.isSelect])
  ))
  constraints.push(...gateConstraints(
    paddingConstraints(current, next, layout),
    current[layout.isPadding]
  ))
  return constraints
}

export function proveMethod2V2ScalarCore (
  trace: Method2V2Trace,
  options: StarkProverOptions = {}
): StarkProof {
  const coreTrace = buildMethod2V2ScalarCoreTrace(trace)
  const air = buildMethod2V2ScalarCoreAir(
    trace,
    options.publicInputDigest ?? method2V2ScalarCoreDigest(trace)
  )
  return proveStark(air, coreTrace.rows, {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 16,
    maskDegree: 1,
    cosetOffset: 3n,
    transcriptDomain: BRC69_METHOD2_V2_SCALAR_CORE_TRANSCRIPT_DOMAIN,
    ...options,
    publicInputDigest: air.publicInputDigest
  })
}

export function verifyMethod2V2ScalarCore (
  trace: Method2V2Trace,
  proof: StarkProof
): boolean {
  const air = buildMethod2V2ScalarCoreAir(trace, proof.publicInputDigest)
  return verifyStark(air, proof, {
    blowupFactor: proof.blowupFactor,
    numQueries: proof.numQueries,
    maxRemainderSize: proof.maxRemainderSize,
    maskDegree: proof.maskDegree,
    cosetOffset: proof.cosetOffset,
    traceDegreeBound: proof.traceDegreeBound,
    compositionDegreeBound: proof.compositionDegreeBound,
    publicInputDigest: proof.publicInputDigest,
    transcriptDomain: BRC69_METHOD2_V2_SCALAR_CORE_TRANSCRIPT_DOMAIN
  })
}

export function method2V2ScalarCoreFeasibility (
  trace: Method2V2Trace,
  proof?: StarkProof
): Method2V2ScalarCoreFeasibility {
  const coreTrace = buildMethod2V2ScalarCoreTrace(trace)
  const metrics = method2V2Metrics(trace)
  return {
    activeRows: coreTrace.activeRows,
    paddedRows: coreTrace.paddedRows,
    traceWidth: coreTrace.layout.width,
    privateCommittedWidth: coreTrace.layout.width,
    publicPreprocessedWidth: 9,
    ldeRows: coreTrace.paddedRows * METHOD2_V2_STARK_BLOWUP_FACTOR,
    estimatedTraceArea: coreTrace.paddedRows *
      METHOD2_V2_STARK_BLOWUP_FACTOR *
      coreTrace.layout.width,
    invoiceLength: metrics.invoiceLength,
    proofBytes: proof === undefined ? undefined : serializeStarkProof(proof).length
  }
}

export function assertMethod2V2ScalarCoreAirTrace (
  trace: Method2V2Trace
): void {
  const coreTrace = buildMethod2V2ScalarCoreTrace(trace)
  const air = buildMethod2V2ScalarCoreAir(trace, method2V2ScalarCoreDigest(trace))
  const result = evaluateAirTrace(air, coreTrace.rows)
  if (!result.valid) {
    const transition = result.transitionFailures[0]
    if (transition !== undefined) {
      throw new Error(
        `Method 2 V2 scalar-core transition ${transition.constraint} failed at step ${transition.step}`
      )
    }
    throw new Error('Method 2 V2 scalar-core boundary constraint failed')
  }
}

export function method2V2ScalarCoreDigest (trace: Method2V2Trace): number[] {
  const writer = new Writer()
  writer.write(toArray(BRC69_METHOD2_V2_SCALAR_CORE_TRANSCRIPT_DOMAIN, 'utf8'))
  writer.write(toArray(METHOD2_V2_PROFILE.airId, 'utf8'))
  writer.writeVarIntNum(trace.activeRows)
  writer.writeVarIntNum(METHOD2_V2_SCALAR_CORE_LAYOUT.width)
  writer.writeVarIntNum(trace.invoiceBytes.length)
  return sha256(writer.toArray())
}

export function pointFingerprint (point: SecpPoint): FieldElement {
  const writer = new Writer()
  if (point.infinity === true) {
    writer.writeUInt8(0)
    writer.write(new Array(64).fill(0))
  } else {
    writer.writeUInt8(1)
    writeBigIntFixed(writer, point.x, 32)
    writeBigIntFixed(writer, point.y, 32)
  }
  const digest = sha256(writer.toArray())
  let value = 0n
  for (const byte of digest) {
    value = ((value << 8n) + BigInt(byte)) % F.p
  }
  return value
}

function writeSelectionRow (
  row: FieldElement[],
  source: Method2V2SelectionRow,
  accScalar: FieldElement,
  runningSelectedDigit: FieldElement,
  accGFingerprint: FieldElement,
  accBFingerprint: FieldElement
): void {
  const layout = METHOD2_V2_SCALAR_CORE_LAYOUT
  row[layout.isSelect] = 1n
  row[layout.firstInWindow] = source.digit === 0 ? 1n : 0n
  row[layout.lastInWindow] = source.digit === (1 << windowBits(source.window)) - 1
    ? 1n
    : 0n
  row[layout.window] = BigInt(source.window)
  row[layout.windowWeight] = windowWeight(source.window)
  row[layout.candidate] = BigInt(source.digit)
  row[layout.selector] = BigInt(source.selector)
  row[layout.selectorSum] = BigInt(source.selectorSum)
  row[layout.selectedDigit] = runningSelectedDigit
  row[layout.candidateG] = pointFingerprint(source.candidateG)
  row[layout.candidateB] = pointFingerprint(source.candidateB)
  row[layout.selectedG] = pointFingerprint(source.selectedG)
  row[layout.selectedB] = pointFingerprint(source.selectedB)
  row[layout.accScalarBefore] = accScalar
  row[layout.accScalarAfter] = accScalar
  row[layout.accGBefore] = accGFingerprint
  row[layout.accBBefore] = accBFingerprint
  row[layout.accGAfter] = accGFingerprint
  row[layout.accBAfter] = accBFingerprint
}

function writeAccumulationRow (
  row: FieldElement[],
  source: Method2V2AccumulationRow,
  accScalarBefore: FieldElement,
  accScalarAfter: FieldElement
): void {
  const layout = METHOD2_V2_SCALAR_CORE_LAYOUT
  row[layout.isAccumulate] = 1n
  row[layout.window] = BigInt(source.window)
  row[layout.windowWeight] = windowWeight(source.window)
  row[layout.candidate] = BigInt(source.digit)
  row[layout.selectorSum] = 1n
  row[layout.selectedDigit] = BigInt(source.digit)
  row[layout.candidateG] = pointFingerprint(source.selectedG)
  row[layout.candidateB] = pointFingerprint(source.selectedB)
  row[layout.selectedG] = pointFingerprint(source.selectedG)
  row[layout.selectedB] = pointFingerprint(source.selectedB)
  row[layout.accScalarBefore] = accScalarBefore
  row[layout.accScalarAfter] = accScalarAfter
  row[layout.accGBefore] = pointFingerprint(source.accGBefore)
  row[layout.accBBefore] = pointFingerprint(source.accBBefore)
  row[layout.accGAfter] = pointFingerprint(source.accGAfter)
  row[layout.accBAfter] = pointFingerprint(source.accBAfter)
}

function publicScheduleBoundaryColumns (
  rows: FieldElement[][],
  layout: Method2V2ScalarCoreLayout
): Array<{ column: number, values: FieldElement[] }> {
  return [
    layout.isSelect,
    layout.isAccumulate,
    layout.isPadding,
    layout.firstInWindow,
    layout.lastInWindow,
    layout.window,
    layout.windowWeight,
    layout.candidate,
    layout.candidateG,
    layout.candidateB
  ].map(column => ({
    column,
    values: rows.map(row => row[column])
  }))
}

function firstSelectionConstraints (
  row: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [
    F.sub(row[layout.selectorSum], row[layout.selector]),
    row[layout.selectedDigit],
    F.sub(row[layout.selectedG], INFINITY_FINGERPRINT),
    F.sub(row[layout.selectedB], INFINITY_FINGERPRINT)
  ]
}

function nextSelectionConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [
    F.sub(next[layout.isSelect], 1n),
    F.sub(next[layout.window], current[layout.window]),
    F.sub(next[layout.selectorSum], F.add(
      current[layout.selectorSum],
      next[layout.selector]
    )),
    F.sub(next[layout.selectedDigit], F.add(
      current[layout.selectedDigit],
      F.mul(next[layout.selector], next[layout.candidate])
    )),
    F.sub(next[layout.selectedG], selectFingerprint(
      current[layout.selectedG],
      next[layout.candidateG],
      next[layout.selector]
    )),
    F.sub(next[layout.selectedB], selectFingerprint(
      current[layout.selectedB],
      next[layout.candidateB],
      next[layout.selector]
    )),
    F.sub(next[layout.accScalarBefore], current[layout.accScalarBefore]),
    F.sub(next[layout.accScalarAfter], current[layout.accScalarAfter])
  ]
}

function selectionToAccumulationConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [
    F.sub(current[layout.selectorSum], 1n),
    F.sub(next[layout.isAccumulate], 1n),
    F.sub(next[layout.window], current[layout.window]),
    F.sub(next[layout.selectedDigit], current[layout.selectedDigit]),
    F.sub(next[layout.selectedG], current[layout.selectedG]),
    F.sub(next[layout.selectedB], current[layout.selectedB]),
    F.sub(next[layout.accScalarBefore], current[layout.accScalarBefore])
  ]
}

function accumulationConstraints (
  row: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [
    F.sub(row[layout.selectorSum], 1n),
    F.sub(row[layout.accScalarAfter], F.add(
      row[layout.accScalarBefore],
      F.mul(row[layout.selectedDigit], row[layout.windowWeight])
    ))
  ]
}

function accumulationToSelectionConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [
    F.sub(next[layout.firstInWindow], 1n),
    F.sub(next[layout.accScalarBefore], current[layout.accScalarAfter]),
    F.sub(next[layout.accScalarAfter], current[layout.accScalarAfter]),
    F.sub(next[layout.accGBefore], current[layout.accGAfter]),
    F.sub(next[layout.accBBefore], current[layout.accBAfter])
  ]
}

function paddingConstraints (
  current: FieldElement[],
  next: FieldElement[],
  layout: Method2V2ScalarCoreLayout
): FieldElement[] {
  return [F.sub(next[layout.isPadding], 1n)]
}

function gateConstraints (
  constraints: FieldElement[],
  selector: FieldElement
): FieldElement[] {
  return constraints.map(constraint => F.mul(selector, constraint))
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function selectFingerprint (
  previous: FieldElement,
  candidate: FieldElement,
  selector: FieldElement
): FieldElement {
  return F.add(previous, F.mul(selector, F.sub(candidate, previous)))
}

function windowBits (window: number): number {
  return window === METHOD2_V2_PROFILE.windowCount - 1
    ? METHOD2_V2_PROFILE.finalWindowBits
    : METHOD2_V2_PROFILE.windowBits
}

function windowWeight (window: number): FieldElement {
  return F.pow(2n, BigInt(window * METHOD2_V2_PROFILE.windowBits))
}

function writeBigIntFixed (writer: Writer, value: bigint, length: number): void {
  const bytes = new Array<number>(length)
  let current = value
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(current & 0xffn)
    current >>= 8n
  }
  if (current !== 0n) throw new Error('Integer does not fit fixed encoding')
  writer.write(bytes)
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}
