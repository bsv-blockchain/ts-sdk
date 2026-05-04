/**
 * A representation of a chunk of a script, which includes an opcode. For push operations, the associated data to push onto the stack is also included.
 */
export default interface ScriptChunk {
  op: number
  data?: number[]
  invalidLength?: boolean
}
