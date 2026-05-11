import {
  SECP256K1_G,
  SECP256K1_P,
  isOnCurve,
  pointAdd,
  pointDouble,
  scalarMultiply,
  validateScalar
} from '../circuit/Secp256k1.js'
import { SecpPoint } from '../circuit/Types.js'
import { FieldElement } from './Field.js'
import {
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
  LOOKUP_BUS_TUPLE_ARITY,
  LookupBusMetrics,
  LookupBusTableRow,
  LookupBusTrace,
  buildLookupBusTrace,
  lookupBusFixedTableItems,
  lookupBusLookupRequestItems,
  lookupBusMetrics,
  proveLookupBus,
  verifyLookupBusProof
} from './LookupBus.js'
import {
  MultiTraceStarkProof,
  StarkProverOptions,
  StarkVerifierOptions
} from './Stark.js'

export const DUAL_BASE_SIGNED_WINDOW_BITS = 11
export const DUAL_BASE_WINDOW_COUNT = 24
export const DUAL_BASE_POINT_LIMB_BITS = 52
export const DUAL_BASE_POINT_LIMBS = 5
export const DUAL_BASE_POSITIVE_SIGN = 0
export const DUAL_BASE_NEGATIVE_SIGN = 1
export const DUAL_BASE_TUPLE_PREFIX_FIELDS = 3

export interface DualBaseLookupParameters {
  windowBits?: number
  windowCount?: number
  pointLimbBits?: number
  pointLimbs?: number
  minTraceLength?: number
}

export interface DualBaseLookupConfig {
  windowBits: number
  windowCount: number
  maxMagnitude: number
  pointLimbBits: number
  pointLimbs: number
}

export interface DualBaseSignedDigit {
  window: number
  digit: bigint
  sign: 0 | 1
  magnitude: number
  tableIndex: number
}

export interface DualBasePointPairTableRow extends LookupBusTableRow {
  index: number
  window: number
  sign: 0 | 1
  magnitude: number
  g: SecpPoint
  b: SecpPoint
}

export interface DualBaseDecodedPointPair {
  window: number
  sign: 0 | 1
  magnitude: number
  g: SecpPoint
  b: SecpPoint
}

export interface DualBaseAccumulatedPointPairs {
  g: SecpPoint
  b: SecpPoint
}

export interface DualBaseLookupPrototype {
  config: DualBaseLookupConfig
  scalar: bigint
  baseG: SecpPoint
  baseB: SecpPoint
  digits: DualBaseSignedDigit[]
  table: DualBasePointPairTableRow[]
  selectedIndexes: number[]
  trace: LookupBusTrace
}

export interface DualBaseLookupMetrics extends LookupBusMetrics {
  windowBits: number
  windowCount: number
  maxMagnitude: number
  rowsPerWindow: number
  tableRows: number
  selectedRows: number
  pointLimbBits: number
  pointLimbs: number
  tupleArity: number
  committedWidth: number
  lookupRows: number
  activeCells: number
  paddedCells: number
  overheadRowsPerLookup: number
  proofBytesPerLookup?: number
}

export interface DualBaseLookupMetricsCase {
  name: string
  scalar: bigint
  baseB: SecpPoint
  parameters?: DualBaseLookupParameters
  baseG?: SecpPoint
  prove?: boolean
  proofOptions?: StarkProverOptions
}

export interface DualBaseLookupMetricsSweepOptions {
  cases: DualBaseLookupMetricsCase[]
  prove?: boolean
  maxProveTableRows?: number
  proofOptions?: StarkProverOptions
  now?: () => number
}

export interface DualBaseLookupMetricsResult extends DualBaseLookupMetrics {
  name: string
  buildMs: number
  proveMs?: number
  verifyMs?: number
  verified?: boolean
  estimatedOnly: boolean
}

export interface DualBaseLookupMetricsEstimateResult extends DualBaseLookupMetrics {
  name: string
  estimatedOnly: true
}

export const DUAL_BASE_LOOKUP_DEFAULT_CONFIG: DualBaseLookupConfig = {
  windowBits: DUAL_BASE_SIGNED_WINDOW_BITS,
  windowCount: DUAL_BASE_WINDOW_COUNT,
  maxMagnitude: 1 << (DUAL_BASE_SIGNED_WINDOW_BITS - 1),
  pointLimbBits: DUAL_BASE_POINT_LIMB_BITS,
  pointLimbs: DUAL_BASE_POINT_LIMBS
}

export function decomposeDualBaseSignedDigits (
  scalar: bigint,
  parameters: DualBaseLookupParameters = {}
): DualBaseSignedDigit[] {
  validateScalar(scalar)
  const config = normalizeDualBaseLookupConfig(parameters)
  const radix = 1n << BigInt(config.windowBits)
  const halfRadix = radix >> 1n
  let remaining = scalar
  const digits: DualBaseSignedDigit[] = []

  for (let window = 0; window < config.windowCount; window++) {
    const raw = remaining % radix
    const digit = raw >= halfRadix ? raw - radix : raw
    const sign = digit < 0n
      ? DUAL_BASE_NEGATIVE_SIGN
      : DUAL_BASE_POSITIVE_SIGN
    const magnitude = Number(digit < 0n ? -digit : digit)
    const tableIndex = dualBaseSignedDigitTableIndex(
      window,
      sign,
      magnitude,
      config
    )
    digits.push({
      window,
      digit,
      sign,
      magnitude,
      tableIndex
    })
    remaining = (remaining - digit) / radix
  }

  if (remaining !== 0n) {
    throw new Error('Scalar does not fit in the signed-window configuration')
  }
  if (reconstructDualBaseSignedScalar(digits, config) !== scalar) {
    throw new Error('Signed-window scalar decomposition mismatch')
  }
  return digits
}

export function reconstructDualBaseSignedScalar (
  digits: DualBaseSignedDigit[],
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): bigint {
  const config = normalizeDualBaseLookupConfig(parameters)
  const radix = 1n << BigInt(config.windowBits)
  let weight = 1n
  let scalar = 0n
  for (let window = 0; window < digits.length; window++) {
    const digit = digits[window]
    if (digit.window !== window) {
      throw new Error('Signed-window digits are not in window order')
    }
    scalar += digit.digit * weight
    weight *= radix
  }
  return scalar
}

export function buildDualBasePointPairTable (
  baseB: SecpPoint,
  parameters: DualBaseLookupParameters = {},
  baseG: SecpPoint = SECP256K1_G
): DualBasePointPairTableRow[] {
  const config = normalizeDualBaseLookupConfig(parameters)
  validatePublicBase(baseG, 'G')
  validatePublicBase(baseB, 'B')

  const table: DualBasePointPairTableRow[] = []
  let gWindowBase = baseG
  let bWindowBase = baseB

  for (let window = 0; window < config.windowCount; window++) {
    const positiveRows: DualBasePointPairTableRow[] = []
    const negativeRows: DualBasePointPairTableRow[] = []
    const windowBaseIndex = table.length
    let gMultiple = infinityPoint()
    let bMultiple = infinityPoint()

    positiveRows.push(makeDualBaseTableRow(
      windowBaseIndex,
      window,
      DUAL_BASE_POSITIVE_SIGN,
      0,
      infinityPoint(),
      infinityPoint(),
      config
    ))

    for (let magnitude = 1; magnitude <= config.maxMagnitude; magnitude++) {
      gMultiple = pointAdd(gMultiple, gWindowBase)
      bMultiple = pointAdd(bMultiple, bWindowBase)
      if (magnitude < config.maxMagnitude) {
        positiveRows.push(makeDualBaseTableRow(
          windowBaseIndex + positiveRows.length,
          window,
          DUAL_BASE_POSITIVE_SIGN,
          magnitude,
          gMultiple,
          bMultiple,
          config
        ))
      }
      negativeRows.push(makeDualBaseTableRow(
        windowBaseIndex + config.maxMagnitude + negativeRows.length,
        window,
        DUAL_BASE_NEGATIVE_SIGN,
        magnitude,
        negatePoint(gMultiple),
        negatePoint(bMultiple),
        config
      ))
    }

    table.push(...positiveRows, ...negativeRows)
    for (let i = 0; i < config.windowBits; i++) {
      gWindowBase = pointDouble(gWindowBase)
      bWindowBase = pointDouble(bWindowBase)
    }
  }

  return table
}

export function buildDualBaseLookupPrototype (
  scalar: bigint,
  baseB: SecpPoint,
  parameters: DualBaseLookupParameters = {},
  baseG: SecpPoint = SECP256K1_G
): DualBaseLookupPrototype {
  const config = normalizeDualBaseLookupConfig(parameters)
  const digits = decomposeDualBaseSignedDigits(scalar, config)
  const table = buildDualBasePointPairTable(baseB, config, baseG)
  const selectedIndexes = digits.map(digit => digit.tableIndex)
  const multiplicities = lookupMultiplicities(selectedIndexes)
  const trace = buildLookupBusTrace([
    ...lookupBusFixedTableItems(table, multiplicities),
    ...lookupBusLookupRequestItems(table, selectedIndexes)
  ], { minTraceLength: parameters.minTraceLength })

  return {
    config,
    scalar,
    baseG,
    baseB,
    digits,
    table,
    selectedIndexes,
    trace
  }
}

export function proveDualBaseLookupPrototype (
  prototype: DualBaseLookupPrototype,
  options: StarkProverOptions = {}
): MultiTraceStarkProof {
  return proveLookupBus(prototype.trace, options)
}

export function verifyDualBaseLookupPrototypeProof (
  prototype: DualBaseLookupPrototype,
  proof: MultiTraceStarkProof,
  options: StarkVerifierOptions = {}
): boolean {
  return verifyLookupBusProof(prototype.trace.publicInput, proof, options)
}

export function dualBaseLookupMetrics (
  prototype: DualBaseLookupPrototype,
  proof?: MultiTraceStarkProof
): DualBaseLookupMetrics {
  const metrics = lookupBusMetrics(prototype.trace, proof)
  const shape = dualBaseLookupShape(prototype.config)
  const proofBytes = proof === undefined ? undefined : metrics.proofBytes
  return {
    ...metrics,
    ...shape,
    ...dualBaseLookupOverhead(
      metrics.paddedRows,
      metrics.traceWidth,
      shape.tableRows,
      shape.selectedRows,
      proofBytes
    )
  }
}

export function estimateDualBaseLookupMetrics (
  parameters: DualBaseLookupParameters = {}
): DualBaseLookupMetrics {
  const config = normalizeDualBaseLookupConfig(parameters)
  const shape = dualBaseLookupShape(config)
  const activeRows = shape.tableRows + config.windowCount
  const paddedRows = nextPowerOfTwo(Math.max(
    2,
    parameters.minTraceLength ?? 0,
    activeRows + 1
  ))
  return {
    activeRows,
    paddedRows,
    traceWidth: LOOKUP_BUS_LAYOUT.width,
    fixedTableRows: shape.tableRows,
    lookupRequests: config.windowCount,
    lookupSupplies: config.windowCount,
    fixedLookups: config.windowCount,
    equalityRows: 0,
    ...shape,
    ...dualBaseLookupOverhead(
      paddedRows,
      LOOKUP_BUS_LAYOUT.width,
      shape.tableRows,
      shape.selectedRows
    )
  }
}

export function estimateDualBaseLookupMetricsCase (
  name: string,
  parameters: DualBaseLookupParameters = {}
): DualBaseLookupMetricsEstimateResult {
  return {
    name,
    estimatedOnly: true,
    ...estimateDualBaseLookupMetrics(parameters)
  }
}

export function runDualBaseLookupMetricsSweep (
  options: DualBaseLookupMetricsSweepOptions
): DualBaseLookupMetricsResult[] {
  const now = options.now ?? defaultNow
  const maxProveTableRows = options.maxProveTableRows ?? 4096
  const results: DualBaseLookupMetricsResult[] = []

  for (const item of options.cases) {
    const parameters = item.parameters ?? {}
    const estimated = estimateDualBaseLookupMetrics(parameters)
    const shouldProve = item.prove ?? options.prove ?? false
    if (!shouldProve || estimated.tableRows > maxProveTableRows) {
      results.push({
        name: item.name,
        ...estimated,
        buildMs: 0,
        estimatedOnly: true
      })
      continue
    }

    const buildStart = now()
    const prototype = buildDualBaseLookupPrototype(
      item.scalar,
      item.baseB,
      parameters,
      item.baseG
    )
    validateDualBaseLookupPrototype(prototype)
    const buildMs = now() - buildStart

    const proveStart = now()
    const proof = proveDualBaseLookupPrototype(prototype, {
      ...options.proofOptions,
      ...item.proofOptions
    })
    const proveMs = now() - proveStart

    const verifyStart = now()
    const verified = verifyDualBaseLookupPrototypeProof(prototype, proof)
    const verifyMs = now() - verifyStart

    results.push({
      name: item.name,
      ...dualBaseLookupMetrics(prototype, proof),
      buildMs,
      proveMs,
      verifyMs,
      verified,
      estimatedOnly: false
    })
  }

  return results
}

export function dualBaseSignedDigitTableIndex (
  window: number,
  sign: 0 | 1,
  magnitude: number,
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): number {
  const config = normalizeDualBaseLookupConfig(parameters)
  validateWindow(window, config)
  validateSignMagnitude(sign, magnitude, config)

  let rowOffset = 0
  if (sign === DUAL_BASE_POSITIVE_SIGN) {
    rowOffset = magnitude
  } else {
    rowOffset = config.maxMagnitude - 1 + magnitude
  }
  return window * dualBaseRowsPerWindow(config) + rowOffset
}

export function dualBaseRowsPerWindow (
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): number {
  const config = normalizeDualBaseLookupConfig(parameters)
  return 2 * config.maxMagnitude
}

export function dualBasePointToLimbs (
  point: SecpPoint,
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): FieldElement[] {
  const config = normalizeDualBaseLookupConfig(parameters)
  if (point.infinity === true) {
    return new Array<FieldElement>(config.pointLimbs * 2).fill(0n)
  }
  validatePublicBase(point, 'point')
  return [
    ...bigintToDualBaseLimbs(point.x, config),
    ...bigintToDualBaseLimbs(point.y, config)
  ]
}

export function dualBasePointFromLimbs (
  limbs: FieldElement[],
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): SecpPoint {
  const config = normalizeDualBaseLookupConfig(parameters)
  if (limbs.length !== config.pointLimbs * 2) {
    throw new Error('Dual-base point coordinate limb count mismatch')
  }
  const x = dualBaseLimbsToBigint(limbs.slice(0, config.pointLimbs), config)
  const y = dualBaseLimbsToBigint(limbs.slice(config.pointLimbs), config)
  if (x === 0n && y === 0n) return infinityPoint()
  const point = { x, y }
  validatePublicBase(point, 'decoded point')
  return point
}

export function bigintToDualBaseLimbs (
  value: bigint,
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): FieldElement[] {
  const config = normalizeDualBaseLookupConfig(parameters)
  if (value < 0n || value >= SECP256K1_P) {
    throw new Error('Dual-base point limb value is outside secp256k1 field')
  }
  const mask = (1n << BigInt(config.pointLimbBits)) - 1n
  const limbs = new Array<FieldElement>(config.pointLimbs)
  let remaining = value
  for (let i = 0; i < config.pointLimbs; i++) {
    limbs[i] = remaining & mask
    remaining >>= BigInt(config.pointLimbBits)
  }
  if (remaining !== 0n) {
    throw new Error('Dual-base point limb configuration is too small')
  }
  return limbs
}

export function dualBaseLimbsToBigint (
  limbs: FieldElement[],
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): bigint {
  const config = normalizeDualBaseLookupConfig(parameters)
  if (limbs.length !== config.pointLimbs) {
    throw new Error('Dual-base point limb count mismatch')
  }
  const limbBound = 1n << BigInt(config.pointLimbBits)
  let value = 0n
  for (let i = limbs.length - 1; i >= 0; i--) {
    if (limbs[i] < 0n || limbs[i] >= limbBound) {
      throw new Error('Dual-base point limb is outside configured range')
    }
    value <<= BigInt(config.pointLimbBits)
    value += limbs[i]
  }
  return value
}

export function dualBasePointPairFromTuple (
  values: FieldElement[],
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): DualBaseDecodedPointPair {
  const config = normalizeDualBaseLookupConfig(parameters)
  if (values.length !== LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('Dual-base point-pair tuple arity mismatch')
  }
  const window = Number(values[0])
  const sign = Number(values[1]) as 0 | 1
  const magnitude = Number(values[2])
  validateWindow(window, config)
  validateSignMagnitude(sign, magnitude, config)
  const pointWidth = config.pointLimbs * 2
  const gStart = DUAL_BASE_TUPLE_PREFIX_FIELDS
  const bStart = gStart + pointWidth
  return {
    window,
    sign,
    magnitude,
    g: dualBasePointFromLimbs(values.slice(gStart, bStart), config),
    b: dualBasePointFromLimbs(values.slice(bStart, bStart + pointWidth), config)
  }
}

export function selectedDualBasePointPairs (
  prototype: DualBaseLookupPrototype
): DualBasePointPairTableRow[] {
  return prototype.selectedIndexes.map(index => {
    const row = prototype.table[index]
    if (row === undefined) {
      throw new Error('Dual-base selected point-pair index is missing')
    }
    return row
  })
}

export function accumulateDualBasePointPairs (
  pairs: Array<Pick<DualBaseDecodedPointPair, 'g' | 'b'>>
): DualBaseAccumulatedPointPairs {
  let g = infinityPoint()
  let b = infinityPoint()
  for (const pair of pairs) {
    g = pointAdd(g, pair.g)
    b = pointAdd(b, pair.b)
  }
  return { g, b }
}

export function validateDualBaseLookupPrototype (
  prototype: DualBaseLookupPrototype
): void {
  const reconstructed = reconstructDualBaseSignedScalar(
    prototype.digits,
    prototype.config
  )
  if (reconstructed !== prototype.scalar) {
    throw new Error('Dual-base lookup scalar reconstruction mismatch')
  }

  const selectedRows = selectedDualBasePointPairs(prototype)
  if (selectedRows.length !== prototype.digits.length) {
    throw new Error('Dual-base lookup selected row count mismatch')
  }

  for (let i = 0; i < prototype.digits.length; i++) {
    const digit = prototype.digits[i]
    const row = selectedRows[i]
    if (
      row.index !== digit.tableIndex ||
      row.window !== digit.window ||
      row.sign !== digit.sign ||
      row.magnitude !== digit.magnitude
    ) {
      throw new Error('Dual-base lookup digit does not match selected table row')
    }
    const decoded = dualBasePointPairFromTuple(row.values, prototype.config)
    if (
      decoded.window !== row.window ||
      decoded.sign !== row.sign ||
      decoded.magnitude !== row.magnitude ||
      !dualBasePointsEqual(decoded.g, row.g) ||
      !dualBasePointsEqual(decoded.b, row.b)
    ) {
      throw new Error('Dual-base lookup table tuple does not decode to its row')
    }
  }

  const accumulated = accumulateDualBasePointPairs(selectedRows)
  const expectedG = scalarMultiply(prototype.scalar, prototype.baseG)
  const expectedB = scalarMultiply(prototype.scalar, prototype.baseB)
  if (
    !dualBasePointsEqual(accumulated.g, expectedG) ||
    !dualBasePointsEqual(accumulated.b, expectedB)
  ) {
    throw new Error('Dual-base lookup selected point pairs do not match scalar products')
  }
}

export function dualBasePointsEqual (
  left: SecpPoint,
  right: SecpPoint
): boolean {
  if (left.infinity === true || right.infinity === true) {
    return left.infinity === true && right.infinity === true
  }
  return left.x === right.x && left.y === right.y
}

export function normalizeDualBaseLookupConfig (
  parameters: DualBaseLookupParameters | DualBaseLookupConfig = {}
): DualBaseLookupConfig {
  const windowBits = parameters.windowBits ?? DUAL_BASE_SIGNED_WINDOW_BITS
  const windowCount = parameters.windowCount ?? DUAL_BASE_WINDOW_COUNT
  const pointLimbBits = parameters.pointLimbBits ?? DUAL_BASE_POINT_LIMB_BITS
  const pointLimbs = parameters.pointLimbs ?? DUAL_BASE_POINT_LIMBS
  if (
    !Number.isSafeInteger(windowBits) ||
    windowBits < 2 ||
    windowBits > 20
  ) {
    throw new Error('Dual-base signed window size is invalid')
  }
  if (!Number.isSafeInteger(windowCount) || windowCount < 1) {
    throw new Error('Dual-base window count is invalid')
  }
  if (
    !Number.isSafeInteger(pointLimbBits) ||
    pointLimbBits < 1 ||
    pointLimbBits > 52
  ) {
    throw new Error('Dual-base point limb size is invalid')
  }
  if (!Number.isSafeInteger(pointLimbs) || pointLimbs < 1) {
    throw new Error('Dual-base point limb count is invalid')
  }
  if (pointLimbBits * pointLimbs < 256) {
    throw new Error('Dual-base point limb configuration is too small')
  }
  const maxMagnitude = 1 << (windowBits - 1)
  if (3 + pointLimbs * 4 !== LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('Lookup bus tuple arity does not match dual-base point limbs')
  }
  return {
    windowBits,
    windowCount,
    maxMagnitude,
    pointLimbBits,
    pointLimbs
  }
}

function dualBaseLookupShape (
  config: DualBaseLookupConfig
): Omit<
  DualBaseLookupMetrics,
  'activeRows' |
  'paddedRows' |
  'traceWidth' |
  'fixedTableRows' |
  'lookupRequests' |
  'lookupSupplies' |
  'fixedLookups' |
  'equalityRows' |
  'proofBytes' |
  'committedWidth' |
  'lookupRows' |
  'activeCells' |
  'paddedCells' |
  'overheadRowsPerLookup' |
  'proofBytesPerLookup'
  > {
  const rowsPerWindow = dualBaseRowsPerWindow(config)
  return {
    windowBits: config.windowBits,
    windowCount: config.windowCount,
    maxMagnitude: config.maxMagnitude,
    rowsPerWindow,
    tableRows: rowsPerWindow * config.windowCount,
    selectedRows: config.windowCount,
    pointLimbBits: config.pointLimbBits,
    pointLimbs: config.pointLimbs,
    tupleArity: LOOKUP_BUS_TUPLE_ARITY
  }
}

function dualBaseLookupOverhead (
  paddedRows: number,
  traceWidth: number,
  tableRows: number,
  selectedRows: number,
  proofBytes?: number
): Pick<
  DualBaseLookupMetrics,
  'committedWidth' |
  'lookupRows' |
  'activeCells' |
  'paddedCells' |
  'overheadRowsPerLookup' |
  'proofBytesPerLookup'
  > {
  const lookupRows = tableRows + selectedRows
  return {
    committedWidth: traceWidth,
    lookupRows,
    activeCells: lookupRows * traceWidth,
    paddedCells: paddedRows * traceWidth,
    overheadRowsPerLookup: selectedRows === 0 ? 0 : tableRows / selectedRows,
    proofBytesPerLookup: proofBytes === undefined || selectedRows === 0
      ? undefined
      : proofBytes / selectedRows
  }
}

function makeDualBaseTableRow (
  index: number,
  window: number,
  sign: 0 | 1,
  magnitude: number,
  g: SecpPoint,
  b: SecpPoint,
  config: DualBaseLookupConfig
): DualBasePointPairTableRow {
  const values = [
    BigInt(window),
    BigInt(sign),
    BigInt(magnitude),
    ...dualBasePointToLimbs(g, config),
    ...dualBasePointToLimbs(b, config)
  ]
  if (values.length !== LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('Dual-base point-pair tuple arity mismatch')
  }
  return {
    index,
    window,
    sign,
    magnitude,
    g,
    b,
    tag: LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
    values
  }
}

function validatePublicBase (point: SecpPoint, name: string): void {
  if (point.infinity === true || !isOnCurve(point)) {
    throw new Error(`Dual-base lookup ${name} base is not a valid public point`)
  }
}

function validateWindow (
  window: number,
  config: DualBaseLookupConfig
): void {
  if (
    !Number.isSafeInteger(window) ||
    window < 0 ||
    window >= config.windowCount
  ) {
    throw new Error('Dual-base lookup window is invalid')
  }
}

function validateSignMagnitude (
  sign: 0 | 1,
  magnitude: number,
  config: DualBaseLookupConfig
): void {
  if (sign !== DUAL_BASE_POSITIVE_SIGN && sign !== DUAL_BASE_NEGATIVE_SIGN) {
    throw new Error('Dual-base lookup sign is invalid')
  }
  if (
    !Number.isSafeInteger(magnitude) ||
    magnitude < 0 ||
    magnitude > config.maxMagnitude
  ) {
    throw new Error('Dual-base lookup magnitude is invalid')
  }
  if (sign === DUAL_BASE_POSITIVE_SIGN && magnitude === config.maxMagnitude) {
    throw new Error('Positive signed-window digit exceeds allowed range')
  }
  if (sign === DUAL_BASE_NEGATIVE_SIGN && magnitude === 0) {
    throw new Error('Negative zero is not a canonical signed-window digit')
  }
}

function lookupMultiplicities (indexes: number[]): Record<number, number> {
  const multiplicities: Record<number, number> = {}
  for (const index of indexes) {
    multiplicities[index] = (multiplicities[index] ?? 0) + 1
  }
  return multiplicities
}

function negatePoint (point: SecpPoint): SecpPoint {
  if (point.infinity === true) return point
  return {
    x: point.x,
    y: point.y === 0n ? 0n : SECP256K1_P - point.y
  }
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function defaultNow (): number {
  return Date.now()
}
