import Script from '../Script.js'
import OP from '../OP.js'
import ScriptChunk from '../ScriptChunk.js'
import BigNumber from '../../primitives/BigNumber.js'
import * as Hash from '../../primitives/Hash.js'
import TransactionSignature from '../../primitives/TransactionSignature.js'
import { maxScriptElementSize, requireMinimalPush } from '../limits.js'
import type { ScriptMacroApplyContext, ScriptMacroDefinition, ScriptMacroMatch } from './types.js'

const MACRO_REVERSE_BYTE_COUNT = 32
const MACRO_REVERSE_SPLITS = MACRO_REVERSE_BYTE_COUNT - 1
const MACRO_HASH256_REVERSE_LENGTH = 1 + (MACRO_REVERSE_SPLITS * 2) + (MACRO_REVERSE_SPLITS * 2)
const MACRO_MIN_SWAP_CAT_RUN = 1
const MACRO_MIN_SPLIT_1X_RUN = 1
const PREAMBLE_GX_HEX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const PREAMBLE_PUBKEY = Object.freeze([2, ...hexToBytes(PREAMBLE_GX_HEX)])
const PREAMBLE_SCOPE = TransactionSignature.SIGHASH_FORKID | TransactionSignature.SIGHASH_ALL

function hexToBytes (hex: string): number[] {
  const bytes: number[] = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  }
  return bytes
}

function compareNumberArrays (a: Readonly<number[]>, b: Readonly<number[]>): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function matchPairSequence (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number,
  repeatCount: number,
  op1: number,
  op2: number
): boolean {
  for (let i = 0; i < repeatCount; i++) {
    const offset = startIndex + i * 2
    if (chunks[offset]?.op !== op1 || chunks[offset + 1]?.op !== op2) {
      return false
    }
  }
  return true
}

function readSmallPush (chunk: ScriptChunk | undefined, max: number = 16): number | null {
  if (chunk == null || typeof chunk.op !== 'number') return null
  if (chunk.op >= OP.OP_1 && chunk.op <= OP.OP_16) {
    const value = chunk.op - (OP.OP_1 - 1)
    return value <= max ? value : null
  }
  if (chunk.op < 0 || chunk.op > OP.OP_PUSHDATA4) return null
  const data = Array.isArray(chunk.data) ? chunk.data : []
  let value: bigint
  try {
    value = BigNumber.fromScriptNum(data, requireMinimalPush).toBigInt()
  } catch {
    return null
  }
  if (value < 0n || value > BigInt(max)) return null
  return Number(value)
}

function matchHash256Reverse32 (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_HASH256) return null
  const endIndex = startIndex + MACRO_HASH256_REVERSE_LENGTH
  if (endIndex > chunks.length) return null
  const splitStart = startIndex + 1
  if (!matchPairSequence(chunks, splitStart, MACRO_REVERSE_SPLITS, OP.OP_1, OP.OP_SPLIT)) return null
  const swapCatStart = splitStart + MACRO_REVERSE_SPLITS * 2
  if (!matchPairSequence(chunks, swapCatStart, MACRO_REVERSE_SPLITS, OP.OP_SWAP, OP.OP_CAT)) return null
  return { length: MACRO_HASH256_REVERSE_LENGTH }
}

function isPreamblePubkeyPush (chunk: ScriptChunk | undefined): boolean {
  if (chunk == null || !Array.isArray(chunk.data)) return false
  if (chunk.data.length !== PREAMBLE_PUBKEY.length) return false
  return compareNumberArrays(chunk.data, PREAMBLE_PUBKEY)
}

function matchCompilablePreamble (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (startIndex !== 0) return null
  if (chunks[startIndex]?.op !== OP.OP_DUP) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_TOALTSTACK) return null
  const hashStart = startIndex + 2
  const hashMatch = matchHash256Reverse32(chunks, hashStart)
  if (hashMatch == null) return null
  const scanStart = hashStart + hashMatch.length
  for (let i = scanStart + 1; i < chunks.length; i++) {
    if (chunks[i]?.op === OP.OP_CHECKSIGVERIFY && isPreamblePubkeyPush(chunks[i - 1])) {
      return { length: i - startIndex + 1 }
    }
  }
  return null
}

function matchSwapCatRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (chunks[index]?.op === OP.OP_SWAP && chunks[index + 1]?.op === OP.OP_CAT) {
    count++
    index += 2
  }
  if (count < MACRO_MIN_SWAP_CAT_RUN) return null
  return { length: count * 2, meta: { count } }
}

function matchSplit1xRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (readSmallPush(chunks[index], 1) === 1 && chunks[index + 1]?.op === OP.OP_SPLIT) {
    count++
    index += 2
  }
  if (count < MACRO_MIN_SPLIT_1X_RUN) return null
  return { length: count * 2, meta: { count } }
}

function matchFromAltStackRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (chunks[index]?.op === OP.OP_FROMALTSTACK) {
    count++
    index++
  }
  if (count < 2) return null
  return { length: count, meta: { count } }
}

function matchSwapToAltStackRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (chunks[index]?.op === OP.OP_SWAP && chunks[index + 1]?.op === OP.OP_TOALTSTACK) {
    count++
    index += 2
  }
  if (count < 1) return null
  return { length: count * 2, meta: { count } }
}

function matchSplitDrop (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_SPLIT || chunks[startIndex + 1]?.op !== OP.OP_DROP) return null
  return { length: 2 }
}

function matchSplitNip (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_SPLIT || chunks[startIndex + 1]?.op !== OP.OP_NIP) return null
  return { length: 2 }
}

function matchConstSplitDrop (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  const count = readSmallPush(chunks[startIndex], 16)
  if (count == null) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_SPLIT || chunks[startIndex + 2]?.op !== OP.OP_DROP) return null
  return { length: 3, meta: { count } }
}

function matchConstSplitNip (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  const count = readSmallPush(chunks[startIndex], 16)
  if (count == null) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_SPLIT || chunks[startIndex + 2]?.op !== OP.OP_NIP) return null
  return { length: 3, meta: { count } }
}

function matchDepthPushSub1SubPick (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_DEPTH) return null
  const pushChunk = chunks[startIndex + 1]
  if (pushChunk == null || pushChunk.op < 0 || pushChunk.op > OP.OP_PUSHDATA4) return null
  const data = Array.isArray(pushChunk.data) ? pushChunk.data : []
  let indexBigInt: bigint
  try {
    indexBigInt = BigNumber.fromScriptNum(data, requireMinimalPush).toBigInt()
  } catch {
    return null
  }
  if (indexBigInt < 0n || indexBigInt > BigInt(Number.MAX_SAFE_INTEGER)) return null
  if (chunks[startIndex + 2]?.op !== OP.OP_SUB) return null
  if (chunks[startIndex + 3]?.op !== OP.OP_1SUB) return null
  if (chunks[startIndex + 4]?.op !== OP.OP_PICK) return null
  return { length: 5, meta: { index: Number(indexBigInt), pushLen: data.length } }
}

function match2DropRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (chunks[index]?.op === OP.OP_2DROP) {
    count++
    index++
  }
  if (count < 2) return null
  return { length: count, meta: { count } }
}

function matchCatSwap (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_CAT) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_SWAP) return null
  return { length: 2 }
}

function matchDropPush0 (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_DROP) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_0) return null
  return { length: 2 }
}

function matchCatCat (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  if (chunks[startIndex]?.op !== OP.OP_CAT) return null
  if (chunks[startIndex + 1]?.op !== OP.OP_CAT) return null
  return { length: 2 }
}

function matchDropRun (
  chunks: ReadonlyArray<ScriptChunk>,
  startIndex: number
): ScriptMacroMatch | null {
  let count = 0
  let index = startIndex
  while (chunks[index]?.op === OP.OP_DROP) {
    count++
    index++
  }
  if (count < 2) return null
  return { length: count, meta: { count } }
}

function applyHash256Reverse32 (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 1) return false
  const buf = spend.stack[spend.stack.length - 1]
  if (!Array.isArray(buf)) return false
  const nextMem = spend.stackMem - buf.length + MACRO_REVERSE_BYTE_COUNT
  if (nextMem > spend.memoryLimit) return false

  spend.stack.pop()
  spend.stackMem -= buf.length
  const hashResult = Hash.hash256(buf)
  hashResult.reverse()
  spend.stack.push(hashResult)
  spend.stackMem += hashResult.length
  return true
}

function applyCompilablePreamble (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 1) return false
  const preimage = spend.stack[spend.stack.length - 1]
  if (!Array.isArray(preimage)) return false
  if (spend.stackMem + preimage.length > spend.memoryLimit) return false
  if (spend.altStackMem + preimage.length > spend.memoryLimit) return false

  const scriptForChecksig = spend.context === 'UnlockingScript' ? spend.unlockingScript : spend.lockingScript
  const codeStart = spend.lastCodeSeparator === null ? 0 : spend.lastCodeSeparator + 1
  const scriptCodeChunks = scriptForChecksig.chunks.slice(codeStart)
  const subscript = new Script(scriptCodeChunks)

  const expectedPreimage = TransactionSignature.formatBytes({
    sourceTXID: spend.sourceTXID,
    sourceOutputIndex: spend.sourceOutputIndex,
    sourceSatoshis: spend.sourceSatoshis,
    transactionVersion: spend.transactionVersion,
    otherInputs: spend.otherInputs,
    outputs: spend.outputs,
    inputIndex: spend.inputIndex,
    subscript,
    inputSequence: spend.inputSequence,
    lockTime: spend.lockTime,
    scope: PREAMBLE_SCOPE,
    cache: spend.getSignatureHashCache()
  })

  const expectedHash = Hash.hash256(expectedPreimage)
  const providedHash = Hash.hash256(preimage)
  if (!compareNumberArrays(expectedHash, providedHash)) return false

  spend.altStack.push(preimage.slice())
  spend.altStackMem += preimage.length
  spend.stack.pop()
  spend.stackMem -= preimage.length
  return true
}

function applySplit1xRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  if (spend.stack.length < 1) return false
  if (spend.stackMem + 1 > spend.memoryLimit) return false
  const buf = spend.stack[spend.stack.length - 1]
  if (!Array.isArray(buf) || buf.length < count) return false

  spend.stack.pop()
  spend.stackMem -= buf.length

  const items = new Array(count + 1)
  for (let i = 0; i < count; i++) {
    items[i] = [buf[i]]
  }
  items[count] = buf.slice(count)

  spend.stack.push(...items)
  spend.stackMem += buf.length
  return true
}

function applySwapCatRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  const itemCount = count + 1
  if (spend.stack.length < itemCount) return false
  const start = spend.stack.length - itemCount
  const items = spend.stack.slice(start)
  let totalLen = 0
  for (let i = 0; i < items.length; i++) {
    totalLen += items[i].length
    if (totalLen > maxScriptElementSize) return false
  }

  const result = new Array(totalLen)
  let offset = 0
  for (let i = items.length - 1; i >= 0; i--) {
    const item = items[i]
    for (let k = 0; k < item.length; k++) {
      result[offset++] = item[k]
    }
  }

  spend.stack.length = start
  spend.stackMem -= totalLen
  spend.stack.push(result)
  spend.stackMem += totalLen
  return true
}

function applyFromAltStackRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  if (spend.altStack.length < count) return false

  const start = spend.altStack.length - count
  const items = spend.altStack.slice(start)
  let totalLen = 0
  for (let i = 0; i < items.length; i++) {
    totalLen += items[i].length
  }
  if (spend.stackMem + totalLen > spend.memoryLimit) return false

  spend.altStack.length = start
  spend.altStackMem -= totalLen

  for (let i = items.length - 1; i >= 0; i--) {
    spend.stack.push(items[i])
  }
  spend.stackMem += totalLen
  return true
}

function applySwapToAltStackRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  if (spend.stack.length < count + 1) return false

  const start = spend.stack.length - count - 1
  const items = spend.stack.slice(start, start + count)
  let totalLen = 0
  for (let i = 0; i < items.length; i++) {
    totalLen += items[i].length
  }
  if (spend.altStackMem + totalLen > spend.memoryLimit) return false

  spend.stack.splice(start, count)
  spend.stackMem -= totalLen

  for (let i = items.length - 1; i >= 0; i--) {
    spend.altStack.push(items[i])
  }
  spend.altStackMem += totalLen
  return true
}

function applySplitDrop (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 2) return false
  const posBuf = spend.stack[spend.stack.length - 1]
  const dataToSplit = spend.stack[spend.stack.length - 2]
  if (!Array.isArray(posBuf) || !Array.isArray(dataToSplit)) return false

  let splitIndexBigInt: bigint
  try {
    splitIndexBigInt = BigNumber.fromScriptNum(posBuf, requireMinimalPush).toBigInt()
  } catch {
    return false
  }
  if (splitIndexBigInt < 0n || splitIndexBigInt > BigInt(dataToSplit.length)) return false
  const splitIndex = Number(splitIndexBigInt)
  const left = dataToSplit.slice(0, splitIndex)

  spend.stack.pop()
  spend.stack.pop()
  spend.stackMem -= posBuf.length + dataToSplit.length
  spend.stack.push(left)
  spend.stackMem += left.length
  return true
}

function applySplitNip (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 2) return false
  const posBuf = spend.stack[spend.stack.length - 1]
  const dataToSplit = spend.stack[spend.stack.length - 2]
  if (!Array.isArray(posBuf) || !Array.isArray(dataToSplit)) return false

  let splitIndexBigInt: bigint
  try {
    splitIndexBigInt = BigNumber.fromScriptNum(posBuf, requireMinimalPush).toBigInt()
  } catch {
    return false
  }
  if (splitIndexBigInt < 0n || splitIndexBigInt > BigInt(dataToSplit.length)) return false
  const splitIndex = Number(splitIndexBigInt)
  const right = dataToSplit.slice(splitIndex)

  spend.stack.pop()
  spend.stack.pop()
  spend.stackMem -= posBuf.length + dataToSplit.length
  spend.stack.push(right)
  spend.stackMem += right.length
  return true
}

function applyConstSplitDrop (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 0) return false
  if (spend.stack.length < 1) return false
  if (spend.stackMem + 1 > spend.memoryLimit) return false

  const dataToSplit = spend.stack[spend.stack.length - 1]
  if (!Array.isArray(dataToSplit) || dataToSplit.length < count) return false

  const left = dataToSplit.slice(0, count)
  spend.stack.pop()
  spend.stackMem -= dataToSplit.length
  spend.stack.push(left)
  spend.stackMem += left.length
  return true
}

function applyConstSplitNip (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 0) return false
  if (spend.stack.length < 1) return false
  if (spend.stackMem + 1 > spend.memoryLimit) return false

  const dataToSplit = spend.stack[spend.stack.length - 1]
  if (!Array.isArray(dataToSplit) || dataToSplit.length < count) return false

  const right = dataToSplit.slice(count)
  spend.stack.pop()
  spend.stackMem -= dataToSplit.length
  spend.stack.push(right)
  spend.stackMem += right.length
  return true
}

function applyDepthPushSub1SubPick (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const index = typeof match.meta?.index === 'number' ? match.meta.index : -1
  const pushLen = typeof match.meta?.pushLen === 'number' ? match.meta.pushLen : 0
  if (!Number.isInteger(index) || index < 0 || index >= spend.stack.length) return false

  const depthBytes = new BigNumber(spend.stack.length).toScriptNum()
  if (spend.stackMem + depthBytes.length + pushLen > spend.memoryLimit) return false

  const item = spend.stack[index]
  if (!Array.isArray(item)) return false
  if (spend.stackMem + item.length > spend.memoryLimit) return false

  spend.stack.push(item.slice())
  spend.stackMem += item.length
  return true
}

function apply2DropRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  const dropItems = count * 2
  if (spend.stack.length < dropItems) return false

  const start = spend.stack.length - dropItems
  const items = spend.stack.slice(start)
  let totalLen = 0
  for (let i = 0; i < items.length; i++) {
    totalLen += items[i].length
  }

  spend.stack.length = start
  spend.stackMem -= totalLen
  return true
}

function applyCatSwap (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 3) return false
  const top = spend.stack[spend.stack.length - 1]
  const second = spend.stack[spend.stack.length - 2]
  if (!Array.isArray(top) || !Array.isArray(second)) return false
  const catLen = top.length + second.length
  if (catLen > maxScriptElementSize) return false
  if (spend.stackMem - top.length - second.length + catLen > spend.memoryLimit) return false

  const c = spend.stack.pop() as number[]
  const b = spend.stack.pop() as number[]
  const a = spend.stack.pop() as number[]
  spend.stackMem -= a.length + b.length + c.length

  const cat = new Array(catLen)
  for (let i = 0; i < b.length; i++) cat[i] = b[i]
  for (let i = 0; i < c.length; i++) cat[b.length + i] = c[i]

  spend.stack.push(cat)
  spend.stack.push(a)
  spend.stackMem += cat.length + a.length
  return true
}

function applyDropPush0 (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 1) return false
  const item = spend.stack.pop() as number[]
  spend.stackMem -= item.length
  if (spend.stackMem + 1 > spend.memoryLimit) return false
  spend.stack.push([])
  return true
}

function applyCatCat (spend: ScriptMacroApplyContext): boolean {
  if (spend.stack.length < 3) return false
  const top = spend.stack[spend.stack.length - 1]
  const second = spend.stack[spend.stack.length - 2]
  const third = spend.stack[spend.stack.length - 3]
  if (!Array.isArray(top) || !Array.isArray(second) || !Array.isArray(third)) return false
  const catLen = top.length + second.length + third.length
  if (catLen > maxScriptElementSize) return false
  if (spend.stackMem - top.length - second.length - third.length + catLen > spend.memoryLimit) return false

  const c = spend.stack.pop() as number[]
  const b = spend.stack.pop() as number[]
  const a = spend.stack.pop() as number[]
  spend.stackMem -= a.length + b.length + c.length

  const cat = new Array(catLen)
  let offset = 0
  for (let i = 0; i < a.length; i++) cat[offset++] = a[i]
  for (let i = 0; i < b.length; i++) cat[offset++] = b[i]
  for (let i = 0; i < c.length; i++) cat[offset++] = c[i]

  spend.stack.push(cat)
  spend.stackMem += cat.length
  return true
}

function applyDropRun (spend: ScriptMacroApplyContext, match: ScriptMacroMatch): boolean {
  const count = typeof match.meta?.count === 'number' ? match.meta.count : 0
  if (!Number.isInteger(count) || count < 1) return false
  if (spend.stack.length < count) return false

  const start = spend.stack.length - count
  const items = spend.stack.slice(start)
  let totalLen = 0
  for (let i = 0; i < items.length; i++) {
    totalLen += items[i].length
  }

  spend.stack.length = start
  spend.stackMem -= totalLen
  return true
}

export const DEFAULT_MACROS: ReadonlyArray<ScriptMacroDefinition> = Object.freeze([
  Object.freeze({
    name: 'compilable-preamble',
    match: matchCompilablePreamble,
    apply: (spend: ScriptMacroApplyContext) => applyCompilablePreamble(spend),
    skipWhenNotExecuting: false,
    pattern: 'OP_DUP OP_TOALTSTACK <hash256 reverse> ... <G pubkey> OP_CHECKSIGVERIFY',
    description: 'Fast-paths the Compilable preamble by validating the preimage hash and moving it to alt stack.'
  }),
  Object.freeze({
    name: 'hash256-reverse32',
    match: matchHash256Reverse32,
    apply: (spend: ScriptMacroApplyContext) => applyHash256Reverse32(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_HASH256 (OP_1 OP_SPLIT)x31 (OP_SWAP OP_CAT)x31',
    description: 'Hashes the top stack item with HASH256 then reverses 32 bytes into little endian.'
  }),
  Object.freeze({
    name: 'split-1x-run',
    match: matchSplit1xRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applySplit1xRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: '(OP_1 OP_SPLIT)xN',
    description: 'Splits a byte array into N single-byte items plus the remaining tail.'
  }),
  Object.freeze({
    name: 'swap-cat-run',
    match: matchSwapCatRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applySwapCatRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: '(OP_SWAP OP_CAT)xN',
    description: 'Concatenates N+1 stack items in reverse order.'
  }),
  Object.freeze({
    name: 'fromaltstack-run',
    match: matchFromAltStackRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applyFromAltStackRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_FROMALTSTACK x N',
    description: 'Moves N items from alt stack to stack.'
  }),
  Object.freeze({
    name: 'swap-toaltstack-run',
    match: matchSwapToAltStackRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applySwapToAltStackRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: '(OP_SWAP OP_TOALTSTACK)xN',
    description: 'Moves N stack items (below top) onto the alt stack.'
  }),
  Object.freeze({
    name: 'split-drop',
    match: matchSplitDrop,
    apply: (spend: ScriptMacroApplyContext) => applySplitDrop(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_SPLIT OP_DROP',
    description: 'Splits a byte array and keeps the left slice.'
  }),
  Object.freeze({
    name: 'split-nip',
    match: matchSplitNip,
    apply: (spend: ScriptMacroApplyContext) => applySplitNip(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_SPLIT OP_NIP',
    description: 'Splits a byte array and keeps the right slice.'
  }),
  Object.freeze({
    name: 'const-split-drop',
    match: matchConstSplitDrop,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applyConstSplitDrop(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_1..OP_16 OP_SPLIT OP_DROP',
    description: 'Splits with a constant index and keeps the left slice.'
  }),
  Object.freeze({
    name: 'const-split-nip',
    match: matchConstSplitNip,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applyConstSplitNip(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_1..OP_16 OP_SPLIT OP_NIP',
    description: 'Splits with a constant index and keeps the right slice.'
  }),
  Object.freeze({
    name: 'depth-push-sub-1sub-pick',
    match: matchDepthPushSub1SubPick,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applyDepthPushSub1SubPick(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_DEPTH <push n> OP_SUB OP_1SUB OP_PICK',
    description: 'Duplicates the stack item at depth n (0-based from bottom).'
  }),
  Object.freeze({
    name: '2drop-run',
    match: match2DropRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => apply2DropRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_2DROP x N',
    description: 'Drops N pairs of stack items.'
  }),
  Object.freeze({
    name: 'drop-run',
    match: matchDropRun,
    apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => applyDropRun(spend, match),
    skipWhenNotExecuting: true,
    pattern: 'OP_DROP x N',
    description: 'Drops N stack items.'
  }),
  Object.freeze({
    name: 'cat-swap',
    match: matchCatSwap,
    apply: (spend: ScriptMacroApplyContext) => applyCatSwap(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_CAT OP_SWAP',
    description: 'Concatenates the top two stack items and swaps with the next item.'
  }),
  Object.freeze({
    name: 'drop-push0',
    match: matchDropPush0,
    apply: (spend: ScriptMacroApplyContext) => applyDropPush0(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_DROP OP_0',
    description: 'Drops the top stack item and pushes an empty array.'
  }),
  Object.freeze({
    name: 'cat-cat',
    match: matchCatCat,
    apply: (spend: ScriptMacroApplyContext) => applyCatCat(spend),
    skipWhenNotExecuting: true,
    pattern: 'OP_CAT OP_CAT',
    description: 'Concatenates the top three stack items in order.'
  })
])
