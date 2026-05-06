import { sha256 } from '../../../primitives/Hash.js'
import {
  SECP256K1_G,
  SECP256K1_P,
  pointDouble
} from '../circuit/Secp256k1.js'
import { SecpPoint } from '../circuit/Types.js'
import {
  DualBaseLookupParameters,
  DualBaseSignedDigit,
  bigintToDualBaseLimbs,
  decomposeDualBaseSignedDigits
} from './DualBaseLookup.js'
import {
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
  LOOKUP_BUS_TUPLE_ARITY,
  LookupBusTableRow,
  LookupBusTrace,
  buildLookupBusTrace,
  lookupBusFixedTableItems,
  lookupBusLookupRequestItems,
  lookupBusMetrics,
  proveLookupBus,
  verifyLookupBusProof
} from './LookupBus.js'
import { buildMerkleTree } from './Merkle.js'
import { serializeFieldElements } from './Polynomial.js'
import { StarkProof, StarkProverOptions } from './Stark.js'

export const BRC69_RADIX11_WINDOW_BITS = 11
export const BRC69_RADIX11_WINDOW_COUNT = 24
export const BRC69_RADIX11_FULL_WINDOWS = 23
export const BRC69_RADIX11_MAX_MAGNITUDE = 1024
export const BRC69_RADIX11_FINAL_MAX_MAGNITUDE = 8
export const BRC69_RADIX11_POINT_LIMB_BITS = 52
export const BRC69_RADIX11_POINT_LIMBS = 5
export const BRC69_RADIX11_TABLE_ROWS =
  BRC69_RADIX11_FULL_WINDOWS * (BRC69_RADIX11_MAX_MAGNITUDE + 1) +
  BRC69_RADIX11_FINAL_MAX_MAGNITUDE + 1

const PRODUCTION_RADIX11_POINT_PAIR_TABLE_CACHE =
  new Map<string, ProductionRadix11PointPairRow[]>()

export interface ProductionRadix11PointPairRow extends LookupBusTableRow {
  index: number
  window: number
  magnitude: number
  isZero: 0 | 1
  g: SecpPoint
  b: SecpPoint
}

export interface ProductionRadix11LookupPrototype {
  scalar: bigint
  baseB: SecpPoint
  digits: DualBaseSignedDigit[]
  table: ProductionRadix11PointPairRow[]
  selectedIndexes: number[]
  trace: LookupBusTrace
  tableRoot: number[]
}

export interface ProductionRadix11LookupMetrics {
  activeRows: number
  paddedRows: number
  traceWidth: number
  committedWidth: number
  committedCells: number
  ldeRows: number
  ldeCells: number
  tableRows: number
  selectedRows: number
  fullWindows: number
  finalWindowRows: number
  maxMagnitude: number
  finalMaxMagnitude: number
  tupleArity: number
  proofBytes?: number
  proofBytesPerLookup?: number
  overheadRowsPerLookup: number
}

interface JacobianPoint {
  x: bigint
  y: bigint
  z: bigint
  infinity?: boolean
}

export function buildProductionRadix11PointPairTable (
  baseB: SecpPoint,
  baseG: SecpPoint = SECP256K1_G
): ProductionRadix11PointPairRow[] {
  const cacheKey = `${pointCacheKey(baseG)}:${pointCacheKey(baseB)}`
  const cached = PRODUCTION_RADIX11_POINT_PAIR_TABLE_CACHE.get(cacheKey)
  if (cached !== undefined) return cached

  const table: ProductionRadix11PointPairRow[] = []
  let gWindowBase = baseG
  let bWindowBase = baseB

  for (let window = 0; window < BRC69_RADIX11_WINDOW_COUNT; window++) {
    const maxMagnitude = radix11WindowMaxMagnitude(window)
    const gMultiples = fixedBaseWindowMultiples(gWindowBase, maxMagnitude)
    const bMultiples = fixedBaseWindowMultiples(bWindowBase, maxMagnitude)
    for (let magnitude = 0; magnitude <= maxMagnitude; magnitude++) {
      table.push(makeProductionRadix11Row(
        table.length,
        window,
        magnitude,
        gMultiples[magnitude],
        bMultiples[magnitude]
      ))
    }
    gWindowBase = multiplyByRadix(gWindowBase)
    bWindowBase = multiplyByRadix(bWindowBase)
  }

  if (table.length !== BRC69_RADIX11_TABLE_ROWS) {
    throw new Error('Production radix-11 table row count mismatch')
  }
  PRODUCTION_RADIX11_POINT_PAIR_TABLE_CACHE.set(cacheKey, table)
  return table
}

export function buildProductionRadix11LookupPrototype (
  scalar: bigint,
  baseB: SecpPoint,
  options: { minTraceLength?: number } = {}
): ProductionRadix11LookupPrototype {
  const digits = decomposeDualBaseSignedDigits(scalar, radix11Parameters())
  validateFinalWindowMagnitude(digits)
  const table = buildProductionRadix11PointPairTable(baseB)
  const selectedIndexes = digits.map(digit =>
    productionRadix11TableIndex(digit.window, digit.magnitude)
  )
  const multiplicities = selectedIndexes.reduce<Record<number, number>>(
    (out, index) => {
      out[index] = (out[index] ?? 0) + 1
      return out
    },
    {}
  )
  const trace = buildLookupBusTrace([
    ...lookupBusFixedTableItems(table, multiplicities),
    ...lookupBusLookupRequestItems(table, selectedIndexes)
  ], {
    expectedLookupRequests: BRC69_RADIX11_WINDOW_COUNT,
    minTraceLength: options.minTraceLength
  })
  return {
    scalar,
    baseB,
    digits,
    table,
    selectedIndexes,
    trace,
    tableRoot: productionRadix11TableRoot(table)
  }
}

export function proveProductionRadix11Lookup (
  prototype: ProductionRadix11LookupPrototype,
  options: StarkProverOptions = {}
): StarkProof {
  return proveLookupBus(prototype.trace, options)
}

export function verifyProductionRadix11Lookup (
  prototype: ProductionRadix11LookupPrototype,
  proof: StarkProof
): boolean {
  return verifyLookupBusProof(prototype.trace.publicInput, proof)
}

export function productionRadix11LookupMetrics (
  prototype?: ProductionRadix11LookupPrototype,
  proof?: StarkProof,
  blowupFactor: number = 16
): ProductionRadix11LookupMetrics {
  const activeRows = BRC69_RADIX11_TABLE_ROWS + BRC69_RADIX11_WINDOW_COUNT
  const paddedRows = nextPowerOfTwo(Math.max(
    2,
    prototype?.trace.publicInput.traceLength ?? 0,
    activeRows + 1
  ))
  const proofBytes = proof === undefined
    ? undefined
    : lookupBusMetrics(prototypeOrThrow(prototype).trace, proof).proofBytes
  return {
    activeRows,
    paddedRows,
    traceWidth: LOOKUP_BUS_LAYOUT.width,
    committedWidth: LOOKUP_BUS_LAYOUT.width,
    committedCells: paddedRows * LOOKUP_BUS_LAYOUT.width,
    ldeRows: paddedRows * blowupFactor,
    ldeCells: paddedRows * blowupFactor * LOOKUP_BUS_LAYOUT.width,
    tableRows: BRC69_RADIX11_TABLE_ROWS,
    selectedRows: BRC69_RADIX11_WINDOW_COUNT,
    fullWindows: BRC69_RADIX11_FULL_WINDOWS,
    finalWindowRows: BRC69_RADIX11_FINAL_MAX_MAGNITUDE + 1,
    maxMagnitude: BRC69_RADIX11_MAX_MAGNITUDE,
    finalMaxMagnitude: BRC69_RADIX11_FINAL_MAX_MAGNITUDE,
    tupleArity: LOOKUP_BUS_TUPLE_ARITY,
    proofBytes,
    proofBytesPerLookup: proofBytes === undefined
      ? undefined
      : proofBytes / BRC69_RADIX11_WINDOW_COUNT,
    overheadRowsPerLookup:
      BRC69_RADIX11_TABLE_ROWS / BRC69_RADIX11_WINDOW_COUNT
  }
}

export function productionRadix11TableRoot (
  table: ProductionRadix11PointPairRow[]
): number[] {
  const tree = buildMerkleTree(table.map(row => serializeFieldElements([
    row.tag,
    ...row.values
  ])))
  return sha256(tree.root)
}

export function productionRadix11TableIndex (
  window: number,
  magnitude: number
): number {
  if (
    !Number.isSafeInteger(window) ||
    window < 0 ||
    window >= BRC69_RADIX11_WINDOW_COUNT
  ) {
    throw new Error('Production radix-11 window is invalid')
  }
  const maxMagnitude = radix11WindowMaxMagnitude(window)
  if (
    !Number.isSafeInteger(magnitude) ||
    magnitude < 0 ||
    magnitude > maxMagnitude
  ) {
    throw new Error('Production radix-11 magnitude is invalid')
  }
  if (window < BRC69_RADIX11_FULL_WINDOWS) {
    return window * (BRC69_RADIX11_MAX_MAGNITUDE + 1) + magnitude
  }
  return BRC69_RADIX11_FULL_WINDOWS *
    (BRC69_RADIX11_MAX_MAGNITUDE + 1) +
    magnitude
}

export function radix11Parameters (): DualBaseLookupParameters {
  return {
    windowBits: BRC69_RADIX11_WINDOW_BITS,
    windowCount: BRC69_RADIX11_WINDOW_COUNT,
    pointLimbBits: BRC69_RADIX11_POINT_LIMB_BITS,
    pointLimbs: BRC69_RADIX11_POINT_LIMBS
  }
}

function makeProductionRadix11Row (
  index: number,
  window: number,
  magnitude: number,
  g: SecpPoint,
  b: SecpPoint
): ProductionRadix11PointPairRow {
  const values = [
    BigInt(window),
    BigInt(magnitude),
    magnitude === 0 ? 1n : 0n,
    ...pointLimbs(g),
    ...pointLimbs(b)
  ]
  if (values.length !== LOOKUP_BUS_TUPLE_ARITY) {
    throw new Error('Production radix-11 tuple arity mismatch')
  }
  return {
    index,
    window,
    magnitude,
    isZero: magnitude === 0 ? 1 : 0,
    g,
    b,
    tag: LOOKUP_BUS_TAG_DUAL_BASE_POINT_PAIR,
    values
  }
}

function pointLimbs (point: SecpPoint): bigint[] {
  if (point.infinity === true) {
    return new Array<bigint>(BRC69_RADIX11_POINT_LIMBS * 2).fill(0n)
  }
  return [
    ...bigintToDualBaseLimbs(point.x, radix11Parameters()),
    ...bigintToDualBaseLimbs(point.y, radix11Parameters())
  ]
}

function validateFinalWindowMagnitude (digits: DualBaseSignedDigit[]): void {
  const final = digits[BRC69_RADIX11_WINDOW_COUNT - 1]
  if (
    final === undefined ||
    final.magnitude > BRC69_RADIX11_FINAL_MAX_MAGNITUDE
  ) {
    throw new Error('Production radix-11 final magnitude exceeds target')
  }
}

function radix11WindowMaxMagnitude (window: number): number {
  return window < BRC69_RADIX11_FULL_WINDOWS
    ? BRC69_RADIX11_MAX_MAGNITUDE
    : BRC69_RADIX11_FINAL_MAX_MAGNITUDE
}

function multiplyByRadix (point: SecpPoint): SecpPoint {
  let out = point
  for (let i = 0; i < BRC69_RADIX11_WINDOW_BITS; i++) {
    out = pointDouble(out)
  }
  return out
}

function fixedBaseWindowMultiples (
  base: SecpPoint,
  maxMagnitude: number
): SecpPoint[] {
  const jacobians: JacobianPoint[] = [infinityJacobian()]
  let current: JacobianPoint = infinityJacobian()
  for (let magnitude = 1; magnitude <= maxMagnitude; magnitude++) {
    current = jacobianMixedAdd(current, base)
    jacobians.push(current)
  }
  return batchNormalizeJacobian(jacobians)
}

function jacobianMixedAdd (
  left: JacobianPoint,
  right: SecpPoint
): JacobianPoint {
  if (right.infinity === true) return left
  if (left.infinity === true) return affineToJacobian(right)
  const z1z1 = modP(left.z * left.z)
  const u2 = modP(right.x * z1z1)
  const s2 = modP(right.y * left.z * z1z1)
  const h = modP(u2 - left.x)
  const r = modP(2n * (s2 - left.y))
  if (h === 0n) {
    if (r === 0n) return jacobianDouble(left)
    return infinityJacobian()
  }
  const hh = modP(h * h)
  const i = modP(4n * hh)
  const j = modP(h * i)
  const v = modP(left.x * i)
  const x = modP(r * r - j - 2n * v)
  const y = modP(r * (v - x) - 2n * left.y * j)
  const z = modP((left.z + h) * (left.z + h) - z1z1 - hh)
  return { x, y, z }
}

function jacobianDouble (point: JacobianPoint): JacobianPoint {
  if (point.infinity === true || point.y === 0n) return infinityJacobian()
  const yy = modP(point.y * point.y)
  const yyyy = modP(yy * yy)
  const s = modP(4n * point.x * yy)
  const m = modP(3n * point.x * point.x)
  const x = modP(m * m - 2n * s)
  const y = modP(m * (s - x) - 8n * yyyy)
  const z = modP(2n * point.y * point.z)
  return { x, y, z }
}

function batchNormalizeJacobian (points: JacobianPoint[]): SecpPoint[] {
  const prefix = new Array<bigint>(points.length)
  let accumulator = 1n
  for (let i = 0; i < points.length; i++) {
    prefix[i] = accumulator
    if (points[i].infinity !== true) {
      accumulator = modP(accumulator * points[i].z)
    }
  }
  let inverse = accumulator === 1n ? 1n : modInvP(accumulator)
  const out = new Array<SecpPoint>(points.length)
  for (let i = points.length - 1; i >= 0; i--) {
    const point = points[i]
    if (point.infinity === true) {
      out[i] = infinityPoint()
      continue
    }
    const zInv = modP(inverse * prefix[i])
    inverse = modP(inverse * point.z)
    const zInv2 = modP(zInv * zInv)
    const zInv3 = modP(zInv2 * zInv)
    out[i] = {
      x: modP(point.x * zInv2),
      y: modP(point.y * zInv3)
    }
  }
  return out
}

function affineToJacobian (point: SecpPoint): JacobianPoint {
  if (point.infinity === true) return infinityJacobian()
  return { x: point.x, y: point.y, z: 1n }
}

function infinityJacobian (): JacobianPoint {
  return { x: 0n, y: 0n, z: 0n, infinity: true }
}

function modP (value: bigint): bigint {
  const out = value % SECP256K1_P
  return out < 0n ? out + SECP256K1_P : out
}

function modInvP (value: bigint): bigint {
  let low = modP(value)
  if (low === 0n) throw new Error('Cannot invert zero modulo p')
  let high = SECP256K1_P
  let lm = 1n
  let hm = 0n
  while (low > 1n) {
    const ratio = high / low
    ;[lm, hm] = [hm - lm * ratio, lm]
    ;[low, high] = [high - low * ratio, low]
  }
  return modP(lm)
}

function nextPowerOfTwo (value: number): number {
  let out = 1
  while (out < value) out *= 2
  return out
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}

function pointCacheKey (point: SecpPoint): string {
  if (point.infinity === true) return 'inf'
  return `${point.x.toString(16)}:${point.y.toString(16)}`
}

function prototypeOrThrow (
  prototype: ProductionRadix11LookupPrototype | undefined
): ProductionRadix11LookupPrototype {
  if (prototype === undefined) {
    throw new Error('Production radix-11 prototype is required')
  }
  return prototype
}
