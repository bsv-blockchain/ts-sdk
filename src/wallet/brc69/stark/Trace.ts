import {
  F,
  FieldElement,
  assertPowerOfTwo,
  getPowerOfTwoDomain
} from './Field.js'
import {
  interpolateEvaluations,
  serializeFieldElements
} from './Polynomial.js'
import {
  MerklePathItem,
  MerkleTree,
  buildMerkleTreeFromLeafFactory,
  openMerklePath,
  verifyMerklePath
} from './Merkle.js'
import {
  StarkProgressCallback,
  emitStarkProgress,
  shouldEmitProgress
} from './Progress.js'
import {
  TypedFieldColumn,
  typedFieldColumnValue,
  typedFieldRowBytes,
  typedFieldTraceFromRowsColumnMajor
} from './TypedField.js'
import {
  typedApplyVanishingMask,
  typedEvaluatePolynomialOnCoset,
  typedInterpolateEvaluations
} from './TypedPolynomial.js'

export interface TraceLdeOptions {
  blowupFactor: number
  cosetOffset: FieldElement
  maskCoefficients?: FieldElement[][]
  progress?: StarkProgressCallback
}

export interface TraceCommitment {
  traceLength: number
  traceWidth: number
  ldeSize: number
  blowupFactor: number
  cosetOffset: FieldElement
  columnCoefficients: FieldElement[][]
  ldeColumns: FieldElement[][]
  typedColumnCoefficients?: TypedFieldColumn[]
  typedLdeColumns?: TypedFieldColumn[]
  ldeRows?: FieldElement[][]
  tree: MerkleTree
}

export interface TraceRowOpening {
  rowIndex: number
  row: FieldElement[]
  path: MerklePathItem[]
}

export function traceColumnsFromRows (
  rows: FieldElement[][]
): FieldElement[][] {
  validateTraceRows(rows)
  const width = rows[0].length
  const columns = new Array<FieldElement[]>(width)
  for (let column = 0; column < width; column++) {
    columns[column] = rows.map(row => F.normalize(row[column]))
  }
  return columns
}

export function traceRowsFromColumns (
  columns: FieldElement[][]
): FieldElement[][] {
  if (columns.length === 0) {
    throw new Error('Trace must contain at least one column')
  }
  const length = columns[0].length
  assertPowerOfTwo(length)
  for (const column of columns) {
    if (column.length !== length) {
      throw new Error('Trace columns must have equal lengths')
    }
  }
  const rows = new Array<FieldElement[]>(length)
  for (let row = 0; row < length; row++) {
    rows[row] = columns.map(column => F.normalize(column[row]))
  }
  return rows
}

export function interpolateTraceColumns (
  rows: FieldElement[][]
): FieldElement[][] {
  return traceColumnsFromRows(rows).map(interpolateEvaluations)
}

export function commitTraceLde (
  rows: FieldElement[][],
  options: TraceLdeOptions
): TraceCommitment {
  validateTraceRows(rows)
  assertPowerOfTwo(options.blowupFactor)
  const cosetOffset = F.normalize(options.cosetOffset)
  if (cosetOffset === 0n) {
    throw new Error('Trace LDE coset offset must be non-zero')
  }
  const traceLength = rows.length
  const traceWidth = rows[0].length
  const evaluationSize = traceLength * options.blowupFactor
  const start = Date.now()
  emitStarkProgress(options.progress, {
    phase: 'trace.commit',
    status: 'start',
    traceLength,
    traceWidth,
    ldeSize: evaluationSize
  })
  const sourceTrace = typedFieldTraceFromRowsColumnMajor(rows)
  const typedColumnCoefficients = new Array<TypedFieldColumn>(traceWidth)
  emitStarkProgress(options.progress, {
    phase: 'trace.interpolate',
    status: 'start',
    traceLength,
    traceWidth,
    columns: traceWidth
  })
  for (let column = 0; column < traceWidth; column++) {
    typedColumnCoefficients[column] = typedInterpolateEvaluations(
      sourceTrace.columns[column]
    )
    if (shouldEmitProgress(column, traceWidth)) {
      emitStarkProgress(options.progress, {
        phase: 'trace.interpolate',
        status: 'progress',
        column,
        count: column + 1,
        total: traceWidth
      })
    }
  }
  emitStarkProgress(options.progress, {
    phase: 'trace.interpolate',
    status: 'end',
    columns: traceWidth
  })
  const typedLdeColumns: TypedFieldColumn[] = []

  emitStarkProgress(options.progress, {
    phase: 'trace.lde',
    status: 'start',
    columns: traceWidth,
    ldeSize: evaluationSize
  })
  for (let column = 0; column < traceWidth; column++) {
    const mask = options.maskCoefficients?.[column]
    const coefficients = mask !== undefined && mask.length > 0
      ? typedApplyVanishingMask(
        typedColumnCoefficients[column],
        traceLength,
        mask
      )
      : typedColumnCoefficients[column]
    if (coefficients.lo.length > evaluationSize) {
      throw new Error('Trace mask degree exceeds LDE domain')
    }
    typedLdeColumns.push(
      typedEvaluatePolynomialOnCoset(
        coefficients,
        evaluationSize,
        cosetOffset
      )
    )
    if (shouldEmitProgress(column, traceWidth)) {
      emitStarkProgress(options.progress, {
        phase: 'trace.lde',
        status: 'progress',
        column,
        count: column + 1,
        total: traceWidth
      })
    }
  }
  emitStarkProgress(options.progress, {
    phase: 'trace.lde',
    status: 'end',
    columns: traceWidth,
    ldeSize: evaluationSize
  })

  emitStarkProgress(options.progress, {
    phase: 'trace.leaf-serialization',
    status: 'start',
    rows: evaluationSize
  })
  const tree = buildMerkleTreeFromLeafFactory(
    evaluationSize,
    row => {
      const leaf = typedFieldRowBytes(typedLdeColumns, row)
      if (shouldEmitProgress(row, evaluationSize)) {
        emitStarkProgress(options.progress, {
          phase: 'trace.leaf-serialization',
          status: 'progress',
          row,
          count: row + 1,
          total: evaluationSize
        })
      }
      return leaf
    },
    {
      progress: options.progress,
      phase: 'trace.merkle'
    }
  )
  emitStarkProgress(options.progress, {
    phase: 'trace.leaf-serialization',
    status: 'end',
    rows: evaluationSize
  })

  emitStarkProgress(options.progress, {
    phase: 'trace.commit',
    status: 'end',
    traceLength,
    traceWidth,
    ldeSize: evaluationSize,
    elapsedMs: Date.now() - start
  })
  return {
    traceLength,
    traceWidth,
    ldeSize: evaluationSize,
    blowupFactor: options.blowupFactor,
    cosetOffset,
    columnCoefficients: [],
    ldeColumns: [],
    typedColumnCoefficients,
    typedLdeColumns,
    tree
  }
}

export function openTraceRow (
  commitment: TraceCommitment,
  rowIndex: number
): TraceRowOpening {
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= commitment.ldeSize) {
    throw new Error('Trace row index out of bounds')
  }
  return {
    rowIndex,
    row: traceCommitmentLdeRow(commitment, rowIndex),
    path: openMerklePath(commitment.tree, rowIndex)
  }
}

export function verifyTraceRowOpening (
  root: number[],
  opening: TraceRowOpening,
  rowCount?: number
): boolean {
  return verifyMerklePath(
    serializeFieldElements(opening.row),
    opening.rowIndex,
    root,
    opening.path,
    rowCount
  )
}

export function traceCommitmentLdeRow (
  commitment: TraceCommitment,
  rowIndex: number
): FieldElement[] {
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= commitment.ldeSize) {
    throw new Error('Trace row index out of bounds')
  }
  if (commitment.ldeRows !== undefined) return commitment.ldeRows[rowIndex]
  if (commitment.typedLdeColumns !== undefined) {
    return typedLdeRow(commitment.typedLdeColumns, rowIndex)
  }
  return ldeRow(commitment.ldeColumns, rowIndex)
}

export function writeTraceCommitmentLdeRow (
  commitment: TraceCommitment,
  rowIndex: number,
  out: FieldElement[]
): FieldElement[] {
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= commitment.ldeSize) {
    throw new Error('Trace row index out of bounds')
  }
  if (commitment.ldeRows !== undefined) {
    if (out.length !== commitment.traceWidth) {
      throw new Error('Trace LDE row output width mismatch')
    }
    for (let column = 0; column < out.length; column++) {
      out[column] = F.normalize(commitment.ldeRows[rowIndex][column])
    }
    return out
  }
  if (commitment.typedLdeColumns !== undefined) {
    return writeTypedLdeRow(commitment.typedLdeColumns, rowIndex, out)
  }
  return writeLdeRow(commitment.ldeColumns, rowIndex, out)
}

function typedLdeRow (
  columns: TypedFieldColumn[],
  rowIndex: number
): FieldElement[] {
  if (columns.length === 0) throw new Error('Trace must contain at least one column')
  const rowCount = columns[0].lo.length
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= rowCount) {
    throw new Error('Trace LDE row index out of bounds')
  }
  return columns.map(column => typedFieldColumnValue(column, rowIndex))
}

function writeTypedLdeRow (
  columns: TypedFieldColumn[],
  rowIndex: number,
  out: FieldElement[]
): FieldElement[] {
  if (columns.length === 0) throw new Error('Trace must contain at least one column')
  const rowCount = columns[0].lo.length
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= rowCount) {
    throw new Error('Trace LDE row index out of bounds')
  }
  if (out.length !== columns.length) {
    throw new Error('Trace LDE row output width mismatch')
  }
  for (let column = 0; column < columns.length; column++) {
    const typedColumn = columns[column]
    out[column] =
      (BigInt(typedColumn.hi[rowIndex] >>> 0) << 32n) |
      BigInt(typedColumn.lo[rowIndex] >>> 0)
  }
  return out
}

export function evaluateTraceRowFromColumns (
  columnCoefficients: FieldElement[][],
  point: FieldElement
): FieldElement[] {
  return columnCoefficients.map(coefficients => {
    let result = 0n
    for (let i = coefficients.length - 1; i >= 0; i--) {
      result = F.add(F.mul(result, point), coefficients[i])
    }
    return result
  })
}

export function getTraceDomain (traceLength: number): FieldElement[] {
  return getPowerOfTwoDomain(traceLength)
}

export function ldeRow (
  columns: FieldElement[][],
  rowIndex: number
): FieldElement[] {
  if (columns.length === 0) throw new Error('Trace must contain at least one column')
  const rowCount = columns[0].length
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= rowCount) {
    throw new Error('Trace LDE row index out of bounds')
  }
  return columns.map(column => F.normalize(column[rowIndex]))
}

export function writeLdeRow (
  columns: FieldElement[][],
  rowIndex: number,
  out: FieldElement[]
): FieldElement[] {
  if (columns.length === 0) throw new Error('Trace must contain at least one column')
  const rowCount = columns[0].length
  if (!Number.isInteger(rowIndex) || rowIndex < 0 || rowIndex >= rowCount) {
    throw new Error('Trace LDE row index out of bounds')
  }
  if (out.length !== columns.length) {
    throw new Error('Trace LDE row output width mismatch')
  }
  for (let column = 0; column < columns.length; column++) {
    out[column] = F.normalize(columns[column][rowIndex])
  }
  return out
}

function validateTraceRows (rows: FieldElement[][]): void {
  if (rows.length === 0) {
    throw new Error('Trace must contain at least one row')
  }
  assertPowerOfTwo(rows.length)
  const width = rows[0].length
  if (width === 0) {
    throw new Error('Trace must contain at least one column')
  }
  for (const row of rows) {
    if (row.length !== width) {
      throw new Error('Trace rows must have equal widths')
    }
  }
}
