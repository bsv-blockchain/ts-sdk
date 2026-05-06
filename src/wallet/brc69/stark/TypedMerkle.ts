import {
  MerkleTree,
  buildMerkleTreeFromLeafFactory,
  hashMerkleLeaf,
  openMerklePath,
  verifyMerklePath
} from './Merkle.js'
import {
  TypedFieldColumn,
  TypedFieldTrace,
  typedFieldElementBytes
} from './TypedField.js'

export function typedFieldLeaf (
  column: TypedFieldColumn,
  index: number
): number[] {
  if (!Number.isInteger(index) || index < 0 || index >= column.lo.length) {
    throw new Error('Typed Merkle field index out of bounds')
  }
  return typedFieldElementBytes({
    lo: column.lo[index],
    hi: column.hi[index]
  })
}

export function typedTraceRowLeaf (
  trace: TypedFieldTrace,
  row: number
): number[] {
  if (!Number.isInteger(row) || row < 0 || row >= trace.length) {
    throw new Error('Typed Merkle trace row out of bounds')
  }
  const out: number[] = []
  for (let column = 0; column < trace.width; column++) {
    out.push(...typedFieldElementBytes({
      lo: trace.columns[column].lo[row],
      hi: trace.columns[column].hi[row]
    }))
  }
  return out
}

export function buildTypedFieldMerkleTree (
  column: TypedFieldColumn
): MerkleTree {
  return buildMerkleTreeFromLeafFactory(
    column.lo.length,
    index => typedFieldLeaf(column, index)
  )
}

export function buildTypedTraceMerkleTree (
  trace: TypedFieldTrace
): MerkleTree {
  return buildMerkleTreeFromLeafFactory(
    trace.length,
    row => typedTraceRowLeaf(trace, row)
  )
}

export {
  hashMerkleLeaf,
  openMerklePath,
  verifyMerklePath
}
