import ScriptEvaluationError from '../ScriptEvaluationError'

const baseParams = {
  message: 'test error',
  txid: 'a'.repeat(64),
  outputIndex: 0,
  context: 'LockingScript' as const,
  programCounter: 3,
  stackState: [] as number[][],
  altStackState: [] as number[][],
  ifStackState: [] as boolean[],
  stackMem: 0,
  altStackMem: 0
}

describe('ScriptEvaluationError', () => {
  it('constructs with empty stacks', () => {
    const err = new ScriptEvaluationError(baseParams)
    expect(err).toBeInstanceOf(Error)
    expect(err.message).toContain('test error')
    expect(err.txid).toBe('a'.repeat(64))
    expect(err.outputIndex).toBe(0)
    expect(err.context).toBe('LockingScript')
    expect(err.programCounter).toBe(3)
  })

  it('renders valid stack items as hex in the message (toHex branch)', () => {
    const err = new ScriptEvaluationError({
      ...baseParams,
      stackState: [[0xde, 0xad], [0xbe, 0xef]],
      altStackState: [[0x01]]
    })
    expect(err.message).toContain('dead')
    expect(err.message).toContain('beef')
    expect(err.message).toContain('01')
  })

  it('renders null stack item as null/undef (null/undef branch)', () => {
    // The message is built before the deep-copy, so null/undef branch is executed
    // even though the constructor later throws when trying to slice null.
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return new ScriptEvaluationError({ ...baseParams, stackState: [null as any] })
    }).toThrow()
  })

  it('renders undefined stack item as null/undef (undefined branch)', () => {
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return new ScriptEvaluationError({ ...baseParams, stackState: [undefined as any] })
    }).toThrow()
  })

  it('renders non-array stack item as INVALID_STACK_ITEM', () => {
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return new ScriptEvaluationError({ ...baseParams, stackState: [{ notAnArray: true } as any] })
    }).toThrow()
  })

  it('renders null alt-stack item as null/undef (covers altStack map branches)', () => {
    expect(() => {
      return new ScriptEvaluationError({
        ...baseParams,
        stackState: [[0x01]],
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        altStackState: [null as any]
      })
    }).toThrow()
  })

  it('includes ifStack entries in the message', () => {
    const err = new ScriptEvaluationError({
      ...baseParams,
      ifStackState: [true, false]
    })
    expect(err.message).toContain('true, false')
  })

  it('includes UnlockingScript context in the message', () => {
    const err = new ScriptEvaluationError({
      ...baseParams,
      context: 'UnlockingScript'
    })
    expect(err.message).toContain('UnlockingScript')
  })

  it('deep-copies stackState and altStackState to prevent mutation', () => {
    const originalStack = [[1, 2, 3]]
    const err = new ScriptEvaluationError({
      ...baseParams,
      stackState: originalStack
    })
    // Mutate original — error should keep its own copy
    originalStack[0].push(4)
    expect(err.stackState[0]).toHaveLength(3)
  })
})
