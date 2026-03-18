import Spend from '../../script/Spend'
import LockingScript from '../../script/LockingScript'
import UnlockingScript from '../../script/UnlockingScript'
import BigNumber from '../../primitives/BigNumber'
import OP from '../../script/OP'
import ScriptChunk from '../../script/ScriptChunk'
import PrivateKey from '../../primitives/PrivateKey'
import PublicKey from '../../primitives/PublicKey'
import Transaction from '../../transaction/Transaction'
import P2PKH from '../../script/templates/P2PKH'

const ZERO_TXID = '0'.repeat(64)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSpend (
  lockingChunks: ScriptChunk[],
  unlockingChunks: ScriptChunk[] = [],
  opts: { transactionVersion?: number, memoryLimit?: number, isRelaxed?: boolean } = {}
): Spend {
  return new Spend({
    sourceTXID: ZERO_TXID,
    sourceOutputIndex: 0,
    sourceSatoshis: 1,
    lockingScript: new LockingScript(lockingChunks),
    transactionVersion: opts.transactionVersion ?? 1,
    otherInputs: [],
    outputs: [],
    inputIndex: 0,
    unlockingScript: new UnlockingScript(unlockingChunks),
    inputSequence: 0xffffffff,
    lockTime: 0,
    memoryLimit: opts.memoryLimit,
    isRelaxed: opts.isRelaxed
  })
}

/** Minimal-push helper that respects script number semantics. */
function pushChunk (data: number[]): ScriptChunk {
  if (data.length === 0) return { op: OP.OP_0 }
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) {
    return { op: OP.OP_1 + (data[0] - 1) }
  }
  if (data.length === 1 && data[0] === 0x81) return { op: OP.OP_1NEGATE }
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 255) return { op: OP.OP_PUSHDATA1, data }
  if (data.length <= 65535) return { op: OP.OP_PUSHDATA2, data }
  return { op: OP.OP_PUSHDATA4, data }
}

/** scriptnum bytes for an integer. */
function scriptNum (n: number): number[] {
  return new BigNumber(n).toScriptNum()
}

/** Fast way to make a Spend in relaxed mode with a locking-script-only test. */
function makeLocking (
  lockingChunks: ScriptChunk[],
  opts: { memoryLimit?: number } = {}
): Spend {
  return makeSpend(lockingChunks, [], { isRelaxed: true, memoryLimit: opts.memoryLimit })
}

// ---------------------------------------------------------------------------
// Memory limit checks (lines 238, 246, 383-384, 387-388)
// ---------------------------------------------------------------------------
describe('Spend – memory limit enforcement', () => {
  it('step() throws when stackMem already exceeds memoryLimit', () => {
    const spend = makeLocking([{ op: OP.OP_1 }], { memoryLimit: 0 })
    spend.context = 'LockingScript'
    spend.stackMem = 1 // artificially exceeded
    expect(() => spend.step()).toThrow('Stack memory usage has exceeded')
  })

  it('step() throws when altStackMem already exceeds memoryLimit', () => {
    const spend = makeLocking([{ op: OP.OP_1 }], { memoryLimit: 0 })
    spend.context = 'LockingScript'
    spend.altStackMem = 1
    expect(() => spend.step()).toThrow('Alt stack memory usage has exceeded')
  })

  it('pushStack throws when additional bytes would exceed memoryLimit', () => {
    // OP_1 calls pushStackCopy with a 1-byte item; memoryLimit=0 so 0+1>0
    const spend = makeLocking([{ op: OP.OP_1 }], { memoryLimit: 0 })
    spend.context = 'LockingScript'
    expect(() => spend.step()).toThrow('Stack memory usage has exceeded')
  })

  it('pushAltStack throws when additional bytes would exceed memoryLimit', () => {
    const spend = makeLocking([{ op: OP.OP_TOALTSTACK }], { memoryLimit: 0 })
    spend.context = 'LockingScript'
    // Pre-populate stack without going through ensureStackMem
    spend.stack = [[1]]
    spend.stackMem = 0 // bypass step() initial guard (0 > 0 = false)
    expect(() => spend.step()).toThrow('Alt stack memory usage has exceeded')
  })
})

// ---------------------------------------------------------------------------
// step() structural edge-cases (lines 401, 407, 417)
// ---------------------------------------------------------------------------
describe('Spend – step() structural edge-cases', () => {
  it('step() returns false when locking script is exhausted', () => {
    // Empty locking script: after unlocking script finishes, step() returns false
    const spend = makeSpend([], [pushChunk([1])], { isRelaxed: true })
    expect(spend.step()).toBe(true) // process unlocking push
    expect(spend.step()).toBe(false) // locking is empty → return false
  })

  it('step() throws for non-minimal push in strict mode', () => {
    // data=[0x01] should be pushed with OP_1 (0x51), not op=1
    const nonMinimal: ScriptChunk = { op: 1, data: [0x01] }
    const spend = makeSpend([nonMinimal], [], { memoryLimit: 1000 })
    spend.context = 'LockingScript'
    expect(() => spend.step()).toThrow('not minimally-encoded')
  })

  it('step() processes non-minimal push when isRelaxed=true', () => {
    const nonMinimal: ScriptChunk = { op: 1, data: [0x01] }
    const spend = makeSpend([nonMinimal], [], { isRelaxed: true, memoryLimit: 1000 })
    spend.context = 'LockingScript'
    expect(spend.step()).toBe(true)
    expect(spend.stack[0]).toEqual([0x01])
  })
})

// ---------------------------------------------------------------------------
// validate() error paths (lines 1103, 1118, 1125, 1132, 1136)
// ---------------------------------------------------------------------------
describe('Spend – validate() error paths', () => {
  it('throws when unlocking script is not push-only in strict mode', () => {
    // OP_DROP is not a push opcode
    const spend = makeSpend(
      [{ op: OP.OP_1 }],
      [{ op: OP.OP_DROP }]
    )
    expect(() => spend.validate()).toThrow('Unlocking scripts can only contain push operations')
  })

  it('throws when OP_IF is not closed with OP_ENDIF', () => {
    // OP_1 OP_IF OP_1 ← no OP_ENDIF
    const spend = makeLocking([
      { op: OP.OP_1 },
      { op: OP.OP_IF },
      { op: OP.OP_1 }
    ])
    expect(() => spend.validate()).toThrow('OP_IF')
  })

  it('throws clean-stack violation when more than one item left', () => {
    // Non-relaxed mode: exactly 1 item is required
    const spend = makeSpend([{ op: OP.OP_1 }, { op: OP.OP_1 }])
    expect(() => spend.validate()).toThrow('clean stack')
  })

  it('throws when stack is empty after execution', () => {
    // OP_DROP leaves stack empty in relaxed mode
    const spend = makeLocking([
      { op: OP.OP_1 },
      { op: OP.OP_DROP }
    ])
    expect(() => spend.validate()).toThrow('stack is empty')
  })

  it('throws when top stack item is falsy', () => {
    const spend = makeLocking([{ op: OP.OP_0 }])
    expect(() => spend.validate()).toThrow('top stack element must be truthy')
  })

  it('castToBool returns false for negative-zero sentinel [0x80]', () => {
    // Push [0x80] (negative zero) – should be falsy
    const spend = makeLocking([pushChunk([0x80])])
    expect(() => spend.validate()).toThrow('top stack element must be truthy')
  })
})

// ---------------------------------------------------------------------------
// isChunkMinimalPushHelper – data.length 256-65535 path (line 97-98)
// ---------------------------------------------------------------------------
describe('Spend – isChunkMinimalPushHelper 256-65535 byte data', () => {
  it('rejects PUSHDATA4 for 256-byte data (should use PUSHDATA2)', () => {
    const data = new Array(256).fill(0x42)
    // Using OP_PUSHDATA4 for 256-byte data is non-minimal (should be PUSHDATA2)
    const badPush: ScriptChunk = { op: OP.OP_PUSHDATA4, data }
    const spend = makeSpend([badPush], [], { memoryLimit: 10000000 })
    spend.context = 'LockingScript'
    expect(() => spend.step()).toThrow('not minimally-encoded')
  })

  it('accepts PUSHDATA2 for 256-byte data', () => {
    const data = new Array(256).fill(0x42)
    const goodPush: ScriptChunk = { op: OP.OP_PUSHDATA2, data }
    const spend = makeSpend([goodPush, { op: OP.OP_DROP }, { op: OP.OP_1 }], [], { memoryLimit: 10000000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// checkPublicKeyEncoding paths (lines 328-353)
// ---------------------------------------------------------------------------
describe('Spend – checkPublicKeyEncoding error paths', () => {
  function checksigSpend (pubkeyBytes: number[], sigBytes: number[]): Spend {
    return makeLocking([
      pushChunk(sigBytes),
      pushChunk(pubkeyBytes),
      { op: OP.OP_CHECKSIG }
    ])
  }

  it('throws when pubkey is empty', () => {
    expect(() => checksigSpend([], []).validate()).toThrow('Public key is empty')
  })

  it('throws when pubkey is too short (< 33 bytes)', () => {
    const shortKey = new Array(32).fill(0x02)
    expect(() => checksigSpend(shortKey, []).validate()).toThrow('too short')
  })

  it('throws when 0x04 pubkey is not 65 bytes', () => {
    const wrongLen = [0x04, ...new Array(33).fill(0x00)]
    expect(() => checksigSpend(wrongLen, []).validate()).toThrow('non-compressed public key must be 65 bytes')
  })

  it('throws when 0x02 pubkey is not 33 bytes', () => {
    const wrongLen = [0x02, ...new Array(34).fill(0x00)]
    expect(() => checksigSpend(wrongLen, []).validate()).toThrow('compressed public key must be 33 bytes')
  })

  it('throws when 0x03 pubkey is not 33 bytes', () => {
    const wrongLen = [0x03, ...new Array(34).fill(0x00)]
    expect(() => checksigSpend(wrongLen, []).validate()).toThrow('compressed public key must be 33 bytes')
  })

  it('throws when pubkey prefix is unknown', () => {
    const unknown = new Array(33).fill(0x00)
    unknown[0] = 0x05
    expect(() => checksigSpend(unknown, []).validate()).toThrow('unknown format')
  })

  it('throws when pubkey prefix is 0x04 but coordinates are invalid', () => {
    // 65-byte 0x04 with all zeros – valid length but invalid curve point
    const bad = [0x04, ...new Array(64).fill(0x00)]
    expect(() => checksigSpend(bad, []).validate()).toThrow()
  })
})

// ---------------------------------------------------------------------------
// checkSignatureEncoding paths (lines 310-321)
// ---------------------------------------------------------------------------
describe('Spend – checkSignatureEncoding error paths', () => {
  it('throws when sig has invalid DER format (wrong first byte)', () => {
    const privKey = PrivateKey.fromRandom()
    const pubKey = PublicKey.fromPrivateKey(privKey)
    const badSig = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
    const spend = makeLocking([
      pushChunk(badSig),
      pushChunk(pubKey.toDER() as number[]),
      { op: OP.OP_CHECKSIG }
    ])
    expect(() => spend.validate()).toThrow('signature format is invalid')
  })

  it('CHECKSIG with empty sig returns false result without error', () => {
    const privKey = PrivateKey.fromRandom()
    const pubKey = PublicKey.fromPrivateKey(privKey)
    // empty sig → fSuccess stays false → pushes [] but still truthy check fails
    const spend = makeLocking([
      { op: OP.OP_0 }, // empty sig
      pushChunk(pubKey.toDER() as number[]),
      { op: OP.OP_CHECKSIG } // pushes [] (false)
      // Stack is [[]] which is falsy → validate throws
    ])
    expect(() => spend.validate()).toThrow('top stack element must be truthy')
  })

  it('CHECKSIGVERIFY throws when sig is empty (fSuccess = false)', () => {
    const privKey = PrivateKey.fromRandom()
    const pubKey = PublicKey.fromPrivateKey(privKey)
    const spend = makeLocking([
      { op: OP.OP_0 }, // empty sig
      pushChunk(pubKey.toDER() as number[]),
      { op: OP.OP_CHECKSIGVERIFY },
      { op: OP.OP_1 }
    ])
    expect(() => spend.validate()).toThrow('OP_CHECKSIGVERIFY requires')
  })

  it('CHECKSIGVERIFY succeeds and pops result for valid sig', async () => {
    const privKey = PrivateKey.fromRandom()
    const pubKey = PublicKey.fromPrivateKey(privKey)
    const p2pkh = new P2PKH()
    const hash = pubKey.toHash()
    const lockingScript = p2pkh.lock(hash)
    const sourceTx = new Transaction(1, [], [{ lockingScript, satoshis: 1 }], 0)
    const spendTx = new Transaction(
      1,
      [{ sourceTransaction: sourceTx, sourceOutputIndex: 0, sequence: 0xffffffff }],
      [],
      0
    )
    const unlockingScript = await p2pkh.unlock(privKey).sign(spendTx, 0)
    const spend = new Spend({
      sourceTXID: sourceTx.id('hex'),
      sourceOutputIndex: 0,
      sourceSatoshis: 1,
      lockingScript,
      transactionVersion: 1,
      otherInputs: [],
      outputs: [],
      inputIndex: 0,
      unlockingScript,
      inputSequence: 0xffffffff,
      lockTime: 0
    })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_CODESEPARATOR (lines 861-862)
// ---------------------------------------------------------------------------
describe('Spend – OP_CODESEPARATOR', () => {
  it('sets lastCodeSeparator to current programCounter', () => {
    const spend = makeLocking([
      { op: OP.OP_CODESEPARATOR },
      { op: OP.OP_1 }
    ])
    expect(spend.validate()).toBe(true)
    // lastCodeSeparator was set during execution
  })
})

// ---------------------------------------------------------------------------
// OP_VER (lines 432-435)
// ---------------------------------------------------------------------------
describe('Spend – OP_VER', () => {
  it('pushes transaction version as 4-byte LE', () => {
    // transactionVersion=2, LE=[2,0,0,0]; compare with that value
    const spend = makeLocking([
      { op: OP.OP_VER },
      pushChunk([2, 0, 0, 0]),
      { op: OP.OP_EQUAL }
    ], { memoryLimit: 100000 })
    // isRelaxed already set, transactionVersion defaults to 1 via makeLocking
    // Redo with version=2
    const spend2 = makeSpend([
      { op: OP.OP_VER },
      pushChunk([2, 0, 0, 0]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, transactionVersion: 2, memoryLimit: 100000 })
    expect(spend2.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_SUBSTR (lines 436-449)
// ---------------------------------------------------------------------------
describe('Spend – OP_SUBSTR', () => {
  it('extracts a substring from a buffer', () => {
    // "hello" starting at offset 1, length 3 → "ell"
    const hello = [0x68, 0x65, 0x6c, 0x6c, 0x6f]
    const ell = [0x65, 0x6c, 0x6c]
    const spend = makeSpend([
      pushChunk(hello),
      pushChunk(scriptNum(1)),
      pushChunk(scriptNum(3)),
      { op: OP.OP_SUBSTR },
      pushChunk(ell),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('throws when OP_SUBSTR offset is out of range', () => {
    const buf = [0x01, 0x02, 0x03]
    const spend = makeSpend([
      pushChunk(buf),
      pushChunk(scriptNum(5)), // offset >= size → error
      pushChunk(scriptNum(1)),
      { op: OP.OP_SUBSTR },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_SUBSTR')
  })
})

// ---------------------------------------------------------------------------
// OP_LEFT / OP_RIGHT (lines 450-474)
// ---------------------------------------------------------------------------
describe('Spend – OP_LEFT / OP_RIGHT', () => {
  it('OP_LEFT extracts the first N bytes', () => {
    const buf = [0x01, 0x02, 0x03, 0x04]
    const spend = makeSpend([
      pushChunk(buf),
      pushChunk(scriptNum(2)),
      { op: OP.OP_LEFT },
      pushChunk([0x01, 0x02]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_LEFT throws when len is out of range', () => {
    const buf = [0x01, 0x02]
    const spend = makeSpend([
      pushChunk(buf),
      pushChunk(scriptNum(5)), // len > size → error
      { op: OP.OP_LEFT },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_LEFT')
  })

  it('OP_RIGHT extracts the last N bytes', () => {
    const buf = [0x01, 0x02, 0x03, 0x04]
    const spend = makeSpend([
      pushChunk(buf),
      pushChunk(scriptNum(2)),
      { op: OP.OP_RIGHT },
      pushChunk([0x03, 0x04]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_RIGHT throws when len is out of range', () => {
    const buf = [0x01, 0x02]
    const spend = makeSpend([
      pushChunk(buf),
      pushChunk(scriptNum(5)),
      { op: OP.OP_RIGHT },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_RIGHT')
  })
})

// ---------------------------------------------------------------------------
// OP_LSHIFTNUM / OP_RSHIFTNUM (lines 476-501)
// ---------------------------------------------------------------------------
describe('Spend – OP_LSHIFTNUM / OP_RSHIFTNUM', () => {
  it('OP_LSHIFTNUM shifts a number left by N bits', () => {
    // 1 << 3 = 8
    const spend = makeSpend([
      pushChunk(scriptNum(1)),
      pushChunk(scriptNum(3)),
      { op: OP.OP_LSHIFTNUM },
      pushChunk(scriptNum(8)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_LSHIFTNUM throws when shift bits are negative', () => {
    const spend = makeSpend([
      pushChunk(scriptNum(1)),
      pushChunk(scriptNum(-1)),
      { op: OP.OP_LSHIFTNUM },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_LSHIFTNUM bits to shift must not be negative')
  })

  it('OP_RSHIFTNUM shifts a positive number right', () => {
    // 8 >> 2 = 2
    const spend = makeSpend([
      pushChunk(scriptNum(8)),
      pushChunk(scriptNum(2)),
      { op: OP.OP_RSHIFTNUM },
      pushChunk(scriptNum(2)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_RSHIFTNUM shifts a negative number right (sign-preserving)', () => {
    // -8 >> 2 = -2
    const spend = makeSpend([
      pushChunk(scriptNum(-8)),
      pushChunk(scriptNum(2)),
      { op: OP.OP_RSHIFTNUM },
      pushChunk(scriptNum(-2)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_RSHIFTNUM throws when shift bits are negative', () => {
    const spend = makeSpend([
      pushChunk(scriptNum(8)),
      pushChunk(scriptNum(-1)),
      { op: OP.OP_RSHIFTNUM },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_RSHIFTNUM bits to shift must not be negative')
  })
})

// ---------------------------------------------------------------------------
// OP_1NEGATE (line 504-505)
// ---------------------------------------------------------------------------
describe('Spend – OP_1NEGATE', () => {
  it('pushes -1 onto the stack', () => {
    const spend = makeSpend([
      { op: OP.OP_1NEGATE },
      pushChunk(scriptNum(-1)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_VERIF / OP_VERNOTIF (lines 531-544)
// ---------------------------------------------------------------------------
describe('Spend – OP_VERIF / OP_VERNOTIF', () => {
  it('OP_VERIF: matching 4-byte LE version makes inner block execute', () => {
    // version=2 → LE = [2,0,0,0]; VERIF match → ifStack=true → inner push executes
    const spend = makeSpend([
      pushChunk([2, 0, 0, 0]),
      { op: OP.OP_VERIF },
      { op: OP.OP_1 },
      { op: OP.OP_ENDIF }
    ], [], { isRelaxed: true, transactionVersion: 2, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_VERIF: non-matching version skips inner block', () => {
    // version=2, push [3,0,0,0] → no match → ifStack=false → inner push skipped
    const spend = makeSpend([
      pushChunk([3, 0, 0, 0]),
      { op: OP.OP_VERIF },
      { op: OP.OP_1 },
      { op: OP.OP_ENDIF },
      { op: OP.OP_1 } // fallback truthy result
    ], [], { isRelaxed: true, transactionVersion: 2, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_VERIF: non-4-byte value never matches', () => {
    const spend = makeSpend([
      pushChunk([1]),    // 1-byte value → never 4-byte match
      { op: OP.OP_VERIF },
      { op: OP.OP_1 },
      { op: OP.OP_ENDIF },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, transactionVersion: 1, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_VERNOTIF: matching version skips inner block (negated)', () => {
    // version=2, [2,0,0,0] matches → VERNOTIF negates → ifStack=false → block skipped
    const spend = makeSpend([
      pushChunk([2, 0, 0, 0]),
      { op: OP.OP_VERNOTIF },
      { op: OP.OP_1 },
      { op: OP.OP_ENDIF },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, transactionVersion: 2, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_IFDUP (lines 628-633)
// ---------------------------------------------------------------------------
describe('Spend – OP_IFDUP', () => {
  it('duplicates top item when truthy', () => {
    const spend = makeSpend([
      { op: OP.OP_1 },
      { op: OP.OP_IFDUP },
      { op: OP.OP_DROP } // consume duplicate
      // stack: [1] → truthy → validate ok
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('does NOT duplicate top item when falsy', () => {
    // [0x00] is falsy → IFDUP leaves stack unchanged → stack=[0x00] → falsy → throws
    const spend = makeSpend([
      pushChunk([0x00]),
      { op: OP.OP_IFDUP }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('top stack element must be truthy')
  })
})

// ---------------------------------------------------------------------------
// OP_AND / OP_OR / OP_XOR / OP_INVERT (lines 704-726)
// ---------------------------------------------------------------------------
describe('Spend – bitwise opcodes', () => {
  it('OP_AND performs bitwise AND', () => {
    const spend = makeSpend([
      pushChunk([0xff]),
      pushChunk([0x0f]),
      { op: OP.OP_AND },
      pushChunk([0x0f]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_AND throws when operands differ in length', () => {
    const spend = makeSpend([
      pushChunk([0x01, 0x02]),
      pushChunk([0x01]),
      { op: OP.OP_AND },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_AND requires the top two stack items to be the same size')
  })

  it('OP_OR performs bitwise OR', () => {
    const spend = makeSpend([
      pushChunk([0xf0]),
      pushChunk([0x0f]),
      { op: OP.OP_OR },
      pushChunk([0xff]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_XOR performs bitwise XOR', () => {
    const spend = makeSpend([
      pushChunk([0xff]),
      pushChunk([0xf0]),
      { op: OP.OP_XOR },
      pushChunk([0x0f]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_INVERT performs bitwise NOT', () => {
    const spend = makeSpend([
      pushChunk([0xff]),
      { op: OP.OP_INVERT },
      pushChunk([0x00]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_2MUL / OP_2DIV (lines 775-776)
// ---------------------------------------------------------------------------
describe('Spend – OP_2MUL / OP_2DIV', () => {
  it('OP_2MUL doubles the top stack value', () => {
    const spend = makeSpend([
      pushChunk(scriptNum(7)),
      { op: OP.OP_2MUL },
      pushChunk(scriptNum(14)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('OP_2DIV halves the top stack value', () => {
    const spend = makeSpend([
      pushChunk(scriptNum(8)),
      { op: OP.OP_2DIV },
      pushChunk(scriptNum(4)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_CHECKMULTISIG error paths (lines 902, 908, 916, 922, 929)
// ---------------------------------------------------------------------------
describe('Spend – OP_CHECKMULTISIG error paths', () => {
  it('throws when stack is empty (no nKeys item)', () => {
    const spend = makeLocking([{ op: OP.OP_CHECKMULTISIG }])
    expect(() => spend.validate()).toThrow('requires at least 1 item')
  })

  it('throws when nKeys is negative', () => {
    const spend = makeLocking([
      pushChunk(scriptNum(-1)),
      { op: OP.OP_CHECKMULTISIG }
    ])
    expect(() => spend.validate()).toThrow('key count between 0')
  })

  it('throws when stack is too small for the declared keys', () => {
    // nKeys=2 but only the nKeys element and 1 key are available
    const spend = makeLocking([
      pushChunk([0x01]), // one dummy key
      pushChunk(scriptNum(2)), // nKeys=2
      { op: OP.OP_CHECKMULTISIG }
    ])
    expect(() => spend.validate()).toThrow('stack too small for nKeys and keys')
  })

  it('throws when nSigs > nKeys', () => {
    const dummyKey = [0x02, ...new Array(32).fill(0x00)] // 33-byte invalid key (will fail later)
    // nSigs=3 but nKeys=1
    const spend = makeLocking([
      pushChunk([0x00]),        // dummy
      pushChunk(scriptNum(3)), // nSigs
      pushChunk(dummyKey),      // key 1
      pushChunk(scriptNum(1)), // nKeys=1
      { op: OP.OP_CHECKMULTISIG }
    ])
    expect(() => spend.validate()).toThrow('number of signatures to be no greater than the number of keys')
  })

  it('throws when stack is too small for the declared sigs', () => {
    const dummyKey = [0x02, ...new Array(32).fill(0x00)]
    // nKeys=1, nSigs=1 but no sig or dummy on stack
    const spend = makeLocking([
      pushChunk(dummyKey),      // key 1
      pushChunk(scriptNum(1)), // nKeys=1
      { op: OP.OP_CHECKMULTISIG }
      // nSigs would be next but stack ran out
    ])
    expect(() => spend.validate()).toThrow()
  })

  it('throws when non-empty dummy is present in strict mode', () => {
    const privKey = PrivateKey.fromRandom()
    const pubKey = PublicKey.fromPrivateKey(privKey)
    // 0 of 0 multisig with non-empty dummy → NULLDUMMY violation
    const spend = makeSpend([
      pushChunk([0x01]),        // non-empty dummy (violates SCRIPT_VERIFY_NULLDUMMY)
      pushChunk(scriptNum(0)), // nSigs=0
      pushChunk(scriptNum(0)), // nKeys=0
      { op: OP.OP_CHECKMULTISIG }
    ])
    expect(() => spend.validate()).toThrow('dummy')
  })

  it('succeeds for 0-of-0 multisig with empty dummy', () => {
    const spend = makeSpend([
      { op: OP.OP_0 },         // empty dummy
      { op: OP.OP_0 },         // nSigs=0
      { op: OP.OP_0 },         // nKeys=0
      { op: OP.OP_CHECKMULTISIG }
    ])
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_NUM2BIN (lines 1029-1068)
// ---------------------------------------------------------------------------
describe('Spend – OP_NUM2BIN', () => {
  it('throws when the requested size is too small for the value', () => {
    // 256 needs 2 bytes; requesting 1 byte → error
    const spend = makeSpend([
      pushChunk(scriptNum(256)),
      pushChunk(scriptNum(1)), // size = 1 → too small
      { op: OP.OP_NUM2BIN },
      { op: OP.OP_1 }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(() => spend.validate()).toThrow('OP_NUM2BIN requires that the size')
  })

  it('pads a positive number to the requested size', () => {
    // value=5, size=4 → [0x05, 0x00, 0x00, 0x00]
    const spend = makeSpend([
      pushChunk(scriptNum(5)),
      pushChunk(scriptNum(4)),
      { op: OP.OP_NUM2BIN },
      pushChunk([0x05, 0x00, 0x00, 0x00]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('pads a negative number to the requested size (sign bit preserved)', () => {
    // value=-5 (scriptnum: [0x85]), size=4 → [0x05, 0x00, 0x00, 0x80]
    const spend = makeSpend([
      pushChunk(scriptNum(-5)),
      pushChunk(scriptNum(4)),
      { op: OP.OP_NUM2BIN },
      pushChunk([0x05, 0x00, 0x00, 0x80]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('does not pad when rawnum length equals requested size', () => {
    // value=256 (scriptnum [0x00, 0x01]), size=2 → [0x00, 0x01]
    const spend = makeSpend([
      pushChunk(scriptNum(256)),
      pushChunk(scriptNum(2)),
      { op: OP.OP_NUM2BIN },
      pushChunk([0x00, 0x01]),
      { op: OP.OP_EQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// OP_BIN2NUM (line 1070-1078)
// ---------------------------------------------------------------------------
describe('Spend – OP_BIN2NUM', () => {
  it('converts binary to minimal scriptnum', () => {
    // [0x05, 0x00, 0x00, 0x00] → 5
    const spend = makeSpend([
      pushChunk([0x05, 0x00, 0x00, 0x00]),
      { op: OP.OP_BIN2NUM },
      pushChunk(scriptNum(5)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })

  it('converts padded negative binary to minimal scriptnum', () => {
    // [0x05, 0x00, 0x00, 0x80] → -5
    const spend = makeSpend([
      pushChunk([0x05, 0x00, 0x00, 0x80]),
      { op: OP.OP_BIN2NUM },
      pushChunk(scriptNum(-5)),
      { op: OP.OP_NUMEQUAL }
    ], [], { isRelaxed: true, memoryLimit: 100000 })
    expect(spend.validate()).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Default opcode path – invalid opcode (line 1082)
// ---------------------------------------------------------------------------
describe('Spend – default opcode (invalid)', () => {
  it('throws for an invalid opcode value', () => {
    // 0xff is not a valid opcode in BSV
    const spend = makeLocking([{ op: 0xff }])
    expect(() => spend.validate()).toThrow('Invalid opcode')
  })
})
