/**
 * A representation of a chunk of a script, which includes an opcode. For push operations, the associated data to push onto the stack is also included.
 */
export interface ScriptMacroTag {
  name: string
  length: number
  role: 'start' | 'body'
  index: number
  ownerId?: number
  meta?: Record<string, unknown>
}

export default interface ScriptChunk {
  op: number
  data?: number[]
  macro?: ScriptMacroTag
}
