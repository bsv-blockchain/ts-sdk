import type Script from '../Script.js'
import type ScriptChunk from '../ScriptChunk.js'
import type TransactionInput from '../../transaction/TransactionInput.js'
import type TransactionOutput from '../../transaction/TransactionOutput.js'
import type { SignatureHashCache } from '../../primitives/TransactionSignature.js'

export interface ScriptMacroMatch {
  length: number
  meta?: Record<string, unknown>
}

export interface ScriptMacroApplyContext {
  context: 'UnlockingScript' | 'LockingScript'
  unlockingScript: Script
  lockingScript: Script
  lastCodeSeparator: number | null
  stack: number[][]
  altStack: number[][]
  stackMem: number
  altStackMem: number
  memoryLimit: number
  sourceTXID: string
  sourceOutputIndex: number
  sourceSatoshis: number
  transactionVersion: number
  otherInputs: TransactionInput[]
  outputs: TransactionOutput[]
  inputIndex: number
  inputSequence: number
  lockTime: number
  getSignatureHashCache: () => SignatureHashCache
}

export interface ScriptMacroDefinition {
  name: string
  match: (chunks: ReadonlyArray<ScriptChunk>, startIndex: number) => ScriptMacroMatch | null
  apply: (spend: ScriptMacroApplyContext, match: ScriptMacroMatch) => boolean
  skipWhenNotExecuting?: boolean
  pattern?: string
  description?: string
}
