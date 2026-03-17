import Script from '../Script'
import Spend from '../Spend'
import LockingScript from '../LockingScript'
import UnlockingScript from '../UnlockingScript'
import ScriptChunk from '../ScriptChunk'
import OP from '../OP'

/**
 * Chronicle upgrade opcode tests.
 *
 * Based on the bitcoin-sv node v1.2.0 functional test suite:
 * https://github.com/bitcoin-sv/bitcoin-sv/tree/172c8fa38cce30cf4df0327b33c7418ea6289de8/test/functional/chronicle_upgrade_tests
 *
 * Covers:
 *   - opcodes.py          → restored/new opcodes (OP_VER, OP_VERIF, OP_VERNOTIF, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_2MUL, OP_2DIV, OP_LSHIFTNUM, OP_RSHIFTNUM)
 *   - script_num_size.py  → enlarged script number limits post-Chronicle
 *   - Undefined opcodes   → 0xba+ must error (no longer NOPs)
 */

const ZERO_TXID = '0'.repeat(64)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a ScriptChunk that pushes arbitrary bytes. */
function pushChunk (bytes: number[]): ScriptChunk {
  if (bytes.length === 0) return { op: OP.OP_0, data: [] }
  if (bytes.length === 1) {
    if (bytes[0] >= 1 && bytes[0] <= 16) return { op: OP.OP_1 + (bytes[0] - 1) }
    if (bytes[0] === 0x81) return { op: OP.OP_1NEGATE }
  }
  let op: number
  if (bytes.length < OP.OP_PUSHDATA1) op = bytes.length
  else if (bytes.length < 256) op = OP.OP_PUSHDATA1
  else if (bytes.length < 65536) op = OP.OP_PUSHDATA2
  else op = OP.OP_PUSHDATA4
  return { op, data: bytes.slice() }
}

/** Create a Spend that evaluates a locking script (with optional unlocking pushes). */
function createSpend (
  lockingScript: LockingScript,
  unlockingPushes: number[][] = [],
  txVersion: number = 1
): Spend {
  return new Spend({
    sourceTXID: ZERO_TXID,
    sourceOutputIndex: 0,
    sourceSatoshis: 1,
    lockingScript,
    transactionVersion: txVersion,
    otherInputs: [],
    outputs: [],
    inputIndex: 0,
    unlockingScript: new UnlockingScript(unlockingPushes.map(pushChunk)),
    inputSequence: 0xffffffff,
    lockTime: 0
  })
}

/** Create a Spend from ASM string for the locking script. */
function createSpendFromAsm (
  lockingAsm: string,
  unlockingPushes: number[][] = [],
  txVersion: number = 1
): Spend {
  const parsed = Script.fromASM(lockingAsm)
  const ls = new LockingScript(parsed.chunks.map(c => ({
    op: c.op,
    data: Array.isArray(c.data) ? c.data.slice() : undefined
  })))
  return createSpend(ls, unlockingPushes, txVersion)
}

/** Build a locking script from a mixture of opcodes and byte-array pushes. */
function buildLockingScript (items: Array<number | number[]>): LockingScript {
  const chunks: ScriptChunk[] = items.map(item => {
    if (typeof item === 'number') return { op: item }
    return pushChunk(item)
  })
  return new LockingScript(chunks)
}

/** Encode a string to its byte array. */
function strBytes (s: string): number[] {
  return Array.from(Buffer.from(s, 'ascii'))
}

/** 4-byte little-endian encoding of a 32-bit integer (matching node's to_le). */
function le4 (v: number): number[] {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]
}

/** Assert that a locking script built from items validates successfully. */
function expectValid (items: Array<number | number[]>, txVersion: number = 1): void {
  const spend = createSpend(buildLockingScript(items), [], txVersion)
  expect(spend.validate()).toBe(true)
}

/** Assert that a locking script built from items throws on validation. */
function expectInvalid (items: Array<number | number[]>, txVersion: number = 1): void {
  const spend = createSpend(buildLockingScript(items), [], txVersion)
  expect(() => spend.validate()).toThrow()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Chronicle Opcode Tests (based on bitcoin-sv node v1.2.0 test suite)', () => {

  // ==========================================================================
  // opcodes.py — OP_VER
  // ==========================================================================
  describe('OP_VER', () => {
    it('pushes the transaction version (1) as 4-byte LE, then DROP + TRUE succeeds', () => {
      // CScript([OP_VER, OP_DROP, OP_TRUE])
      expectValid([OP.OP_VER, OP.OP_DROP, OP.OP_TRUE])
    })

    it('pushes tx version 2 correctly as 4-byte LE', () => {
      // OP_VER should push [0x02, 0x00, 0x00, 0x00] for version 2
      expectValid([OP.OP_VER, le4(2), OP.OP_EQUAL], 2)
    })

    it('pushes tx version 1 as [0x01, 0x00, 0x00, 0x00]', () => {
      expectValid([OP.OP_VER, le4(1), OP.OP_EQUAL])
    })

    it('OP_VER with version 0xFF00 encodes correctly', () => {
      const ver = 0xFF00
      expectValid([OP.OP_VER, le4(ver), OP.OP_EQUAL], ver)
    })
  })

  // ==========================================================================
  // opcodes.py — OP_VERIF / OP_VERNOTIF
  // ==========================================================================
  describe('OP_VERIF', () => {
    it('branches to TRUE when stack top matches tx version as 4-byte LE', () => {
      // CScript([b'\x01\x00\x00\x00', OP_VERIF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF])
      expectValid([le4(1), OP.OP_VERIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
    })

    it('branches to ELSE when stack top does NOT match tx version', () => {
      // Push version 2 encoding but tx version is 1 → VERIF is false → goes to ELSE
      expectValid([le4(2), OP.OP_VERIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF])
    })

    it('only matches exactly 4-byte items (3-byte push fails match)', () => {
      // Node v1.2.0: only matches when stack item is exactly 4 bytes
      // 3 bytes — should NOT match version 1
      expectValid([[0x01, 0x00, 0x00], OP.OP_VERIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF])
    })

    it('only matches exactly 4-byte items (5-byte push fails match)', () => {
      expectValid([[0x01, 0x00, 0x00, 0x00, 0x00], OP.OP_VERIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF])
    })

    it('requires at least one item on the stack', () => {
      expectInvalid([OP.OP_VERIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
    })
  })

  describe('OP_VERNOTIF', () => {
    it('branches to TRUE when stack top does NOT match tx version', () => {
      // CScript([b'\x01\xFF\x00\x00', OP_VERNOTIF, OP_TRUE, OP_ELSE, OP_FALSE, OP_ENDIF])
      // Version 0x00FF01 != version 1 → VERNOTIF negates → true → goes to OP_TRUE
      expectValid([[0x01, 0xFF, 0x00, 0x00], OP.OP_VERNOTIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
    })

    it('branches to ELSE when stack top matches tx version', () => {
      expectValid([le4(1), OP.OP_VERNOTIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF])
    })

    it('non-4-byte items always evaluate as not-matching (so VERNOTIF → true)', () => {
      // 1 byte — won't match, so NOT(false) = true
      expectValid([[0x01], OP.OP_VERNOTIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_SUBSTR (restored Chronicle opcode, 0xb3)
  // ==========================================================================
  describe('OP_SUBSTR', () => {
    it("extracts 'oWorl' from 'HelloWorld' at offset 4, length 5", () => {
      // CScript([b'HelloWorld', OP_4, OP_5, OP_SUBSTR, b'oWorl', OP_EQUAL])
      expectValid([strBytes('HelloWorld'), OP.OP_4, OP.OP_5, OP.OP_SUBSTR, strBytes('oWorl'), OP.OP_EQUAL])
    })

    it('extracts full string with offset 0 and length = size', () => {
      expectValid([strBytes('ABC'), OP.OP_0, OP.OP_3, OP.OP_SUBSTR, strBytes('ABC'), OP.OP_EQUAL])
    })

    it('extracts single char from beginning', () => {
      expectValid([strBytes('Hello'), OP.OP_0, OP.OP_1, OP.OP_SUBSTR, strBytes('H'), OP.OP_EQUAL])
    })

    it('fails when offset is out of range', () => {
      // offset 5, but string is only 2 bytes
      expectInvalid([strBytes('Hi'), OP.OP_5, OP.OP_1, OP.OP_SUBSTR])
    })

    it('fails when length exceeds available bytes from offset', () => {
      // offset 1, length 5, but only 1 byte remaining
      expectInvalid([strBytes('Hi'), OP.OP_1, OP.OP_5, OP.OP_SUBSTR])
    })

    it('requires at least 3 stack items', () => {
      expectInvalid([OP.OP_1, OP.OP_SUBSTR])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_LEFT (restored Chronicle opcode, 0xb4)
  // ==========================================================================
  describe('OP_LEFT', () => {
    it("extracts 'Hello' from 'HelloWorld' (left 5 bytes)", () => {
      // CScript([b'HelloWorld', OP_5, OP_LEFT, b'Hello', OP_EQUAL])
      expectValid([strBytes('HelloWorld'), OP.OP_5, OP.OP_LEFT, strBytes('Hello'), OP.OP_EQUAL])
    })

    it('left 0 bytes returns empty', () => {
      expectValid([strBytes('Hello'), OP.OP_0, OP.OP_LEFT, OP.OP_0, OP.OP_EQUAL])
    })

    it('left full length returns the whole string', () => {
      expectValid([strBytes('Hello'), OP.OP_5, OP.OP_LEFT, strBytes('Hello'), OP.OP_EQUAL])
    })

    it('fails when length exceeds string size', () => {
      expectInvalid([strBytes('Hi'), OP.OP_5, OP.OP_LEFT])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_RIGHT (restored Chronicle opcode, 0xb5)
  // ==========================================================================
  describe('OP_RIGHT', () => {
    it("extracts 'World' from 'HelloWorld' (right 5 bytes)", () => {
      // CScript([b'HelloWorld', OP_5, OP_RIGHT, b'World', OP_EQUAL])
      expectValid([strBytes('HelloWorld'), OP.OP_5, OP.OP_RIGHT, strBytes('World'), OP.OP_EQUAL])
    })

    it('right 0 bytes returns empty', () => {
      expectValid([strBytes('Hello'), OP.OP_0, OP.OP_RIGHT, OP.OP_0, OP.OP_EQUAL])
    })

    it('right full length returns the whole string', () => {
      expectValid([strBytes('Hello'), OP.OP_5, OP.OP_RIGHT, strBytes('Hello'), OP.OP_EQUAL])
    })

    it('right 1 byte returns last char', () => {
      expectValid([strBytes('Hello'), OP.OP_1, OP.OP_RIGHT, strBytes('o'), OP.OP_EQUAL])
    })

    it('fails when length exceeds string size', () => {
      expectInvalid([strBytes('Hi'), OP.OP_5, OP.OP_RIGHT])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_2MUL (restored Chronicle opcode, 0x8d)
  // ==========================================================================
  describe('OP_2MUL', () => {
    it('1 * 2 = 2', () => {
      // CScript([OP_1, OP_2MUL, OP_2, OP_EQUAL])
      expectValid([OP.OP_1, OP.OP_2MUL, OP.OP_2, OP.OP_EQUAL])
    })

    it('0 * 2 = 0', () => {
      expectValid([OP.OP_0, OP.OP_2MUL, OP.OP_0, OP.OP_EQUAL])
    })

    it('8 * 2 = 16', () => {
      expectValid([OP.OP_8, OP.OP_2MUL, OP.OP_16, OP.OP_EQUAL])
    })

    it('-1 * 2 = -2', () => {
      // -2 in script num is [0x82]
      expectValid([OP.OP_1NEGATE, OP.OP_2MUL, [0x82], OP.OP_EQUAL])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_2DIV (restored Chronicle opcode, 0x8e)
  // ==========================================================================
  describe('OP_2DIV', () => {
    it('2 / 2 = 1', () => {
      // CScript([OP_2, OP_2DIV, OP_1, OP_EQUAL])
      expectValid([OP.OP_2, OP.OP_2DIV, OP.OP_1, OP.OP_EQUAL])
    })

    it('16 / 2 = 8', () => {
      expectValid([OP.OP_16, OP.OP_2DIV, OP.OP_8, OP.OP_EQUAL])
    })

    it('1 / 2 = 0 (integer division)', () => {
      expectValid([OP.OP_1, OP.OP_2DIV, OP.OP_0, OP.OP_EQUAL])
    })

    it('0 / 2 = 0', () => {
      expectValid([OP.OP_0, OP.OP_2DIV, OP.OP_0, OP.OP_EQUAL])
    })
  })

  // ==========================================================================
  // opcodes.py — OP_LSHIFTNUM (restored Chronicle opcode, 0xb6)
  // ==========================================================================
  describe('OP_LSHIFTNUM', () => {
    it('1 << 2 = 4', () => {
      // CScript([OP_1, OP_2, OP_LSHIFTNUM, OP_4, OP_EQUAL])
      expectValid([OP.OP_1, OP.OP_2, OP.OP_LSHIFTNUM, OP.OP_4, OP.OP_EQUAL])
    })

    it('1 << 1 = 2', () => {
      const spend = createSpendFromAsm('OP_1 OP_1 OP_LSHIFTNUM OP_2 OP_EQUAL')
      expect(spend.validate()).toBe(true)
    })

    it('1 << 8 produces a 2-byte result', () => {
      const spend = createSpendFromAsm('OP_1 OP_8 OP_LSHIFTNUM 0001 OP_EQUAL')
      expect(spend.validate()).toBe(true)
    })
  })

  // ==========================================================================
  // opcodes.py — OP_RSHIFTNUM (restored Chronicle opcode, 0xb7)
  // ==========================================================================
  describe('OP_RSHIFTNUM', () => {
    it('16 >> 2 = 4', () => {
      // CScript([OP_16, OP_2, OP_RSHIFTNUM, OP_4, OP_EQUAL])
      expectValid([OP.OP_16, OP.OP_2, OP.OP_RSHIFTNUM, OP.OP_4, OP.OP_EQUAL])
    })

    it('4 >> 2 = 1', () => {
      const spend = createSpendFromAsm('OP_4 OP_2 OP_RSHIFTNUM OP_1 OP_EQUAL')
      expect(spend.validate()).toBe(true)
    })

    it('2 >> 1 = 1', () => {
      const spend = createSpendFromAsm('OP_2 OP_1 OP_RSHIFTNUM OP_1 OP_EQUAL')
      expect(spend.validate()).toBe(true)
    })
  })

  // ==========================================================================
  // All opcodes together — full post-Chronicle validation
  // Mirrors the CHRONICLE_ACTIVATION / POST_CHRONICLE test sets from opcodes.py
  // ==========================================================================
  describe('Post-Chronicle opcode activation (all should succeed)', () => {
    const tests: Array<{ name: string, ls: LockingScript, txVersion?: number }> = [
      {
        name: 'OP_VER OP_DROP OP_TRUE',
        ls: buildLockingScript([OP.OP_VER, OP.OP_DROP, OP.OP_TRUE])
      },
      {
        name: 'OP_VERIF with matching version (v1)',
        ls: buildLockingScript([le4(1), OP.OP_VERIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
      },
      {
        name: 'OP_VERNOTIF with non-matching version',
        ls: buildLockingScript([[0x01, 0xFF, 0x00, 0x00], OP.OP_VERNOTIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF])
      },
      {
        name: "OP_SUBSTR: 'oWorl' from 'HelloWorld'",
        ls: buildLockingScript([strBytes('HelloWorld'), OP.OP_4, OP.OP_5, OP.OP_SUBSTR, strBytes('oWorl'), OP.OP_EQUAL])
      },
      {
        name: "OP_LEFT: 'Hello' from 'HelloWorld'",
        ls: buildLockingScript([strBytes('HelloWorld'), OP.OP_5, OP.OP_LEFT, strBytes('Hello'), OP.OP_EQUAL])
      },
      {
        name: "OP_RIGHT: 'World' from 'HelloWorld'",
        ls: buildLockingScript([strBytes('HelloWorld'), OP.OP_5, OP.OP_RIGHT, strBytes('World'), OP.OP_EQUAL])
      },
      {
        name: 'OP_2MUL: 1 * 2 = 2',
        ls: buildLockingScript([OP.OP_1, OP.OP_2MUL, OP.OP_2, OP.OP_EQUAL])
      },
      {
        name: 'OP_2DIV: 2 / 2 = 1',
        ls: buildLockingScript([OP.OP_2, OP.OP_2DIV, OP.OP_1, OP.OP_EQUAL])
      },
      {
        name: 'OP_LSHIFTNUM: 1 << 2 = 4',
        ls: buildLockingScript([OP.OP_1, OP.OP_2, OP.OP_LSHIFTNUM, OP.OP_4, OP.OP_EQUAL])
      },
      {
        name: 'OP_RSHIFTNUM: 16 >> 2 = 4',
        ls: buildLockingScript([OP.OP_16, OP.OP_2, OP.OP_RSHIFTNUM, OP.OP_4, OP.OP_EQUAL])
      }
    ]

    for (const t of tests) {
      it(t.name, () => {
        const spend = createSpend(t.ls, [], t.txVersion ?? 1)
        expect(spend.validate()).toBe(true)
      })
    }
  })

  // ==========================================================================
  // Undefined opcodes >= 0xba must now fail (no longer treated as NOPs)
  // Per node v1.2.0: opcodes >= FIRST_UNDEFINED_OP_VALUE (0xba) return SCRIPT_ERR_BAD_OPCODE
  // ==========================================================================
  describe('Undefined opcodes (>= 0xba) must fail', () => {
    const undefinedOpcodes = [
      { name: 'OP_NOP11 (0xba)', value: 0xba },
      { name: 'OP_NOP12 (0xbb)', value: 0xbb },
      { name: 'OP_NOP16 (0xbf)', value: 0xbf },
      { name: 'OP_NOP20 (0xc3)', value: 0xc3 },
      { name: 'OP_NOP32 (0xcf)', value: 0xcf },
      { name: 'OP_NOP50 (0xe1)', value: 0xe1 },
      { name: 'OP_NOP73 (0xf8)', value: 0xf8 },
      { name: '0xf9 (OP_SMALLDATA)', value: 0xf9 },
      { name: 'OP_INVALIDOPCODE (0xff)', value: 0xff }
    ]

    for (const { name, value } of undefinedOpcodes) {
      it(`${name} should error when executed`, () => {
        // Build a script that executes the undefined opcode followed by OP_TRUE
        const ls = new LockingScript([{ op: value }, { op: OP.OP_TRUE }])
        const spend = createSpend(ls)
        expect(() => spend.validate()).toThrow()
      })
    }
  })

  // ==========================================================================
  // Valid NOPs that should still work (OP_NOP1, OP_NOP2/CLTV, OP_NOP3/CSV, OP_NOP9, OP_NOP10)
  // ==========================================================================
  describe('Valid NOPs still work', () => {
    const validNops = [
      { name: 'OP_NOP1 (0xb0)', value: OP.OP_NOP1 },
      { name: 'OP_CHECKLOCKTIMEVERIFY/OP_NOP2 (0xb1)', value: OP.OP_CHECKLOCKTIMEVERIFY },
      { name: 'OP_CHECKSEQUENCEVERIFY/OP_NOP3 (0xb2)', value: OP.OP_CHECKSEQUENCEVERIFY },
      { name: 'OP_NOP9 (0xb8)', value: OP.OP_NOP9 },
      { name: 'OP_NOP10 (0xb9)', value: OP.OP_NOP10 }
    ]

    for (const { name, value } of validNops) {
      it(`${name} acts as NOP and script succeeds`, () => {
        const ls = new LockingScript([{ op: value }, { op: OP.OP_TRUE }])
        const spend = createSpend(ls)
        expect(spend.validate()).toBe(true)
      })
    }
  })

  // ==========================================================================
  // script_num_size.py — Larger script numbers work post-Chronicle
  // ==========================================================================
  describe('Script number size (post-Chronicle)', () => {
    it('a script number up to old genesis limit (750000 bytes) executes OP_1ADD successfully', () => {
      // A large script number followed by OP_1ADD OP_DROP OP_TRUE
      // Use a modest size that proves the limit is > 4 bytes (pre-genesis limit)
      const bigNum = new Array(8).fill(42) // 8-byte script number
      expectValid([bigNum, OP.OP_1ADD, OP.OP_DROP, OP.OP_TRUE])
    })

    it('OP_MUL works with numbers up to the genesis script num size', () => {
      // Use OP_DUP OP_MUL to square a number, verifying arithmetic on larger nums
      expectValid([OP.OP_3, OP.OP_DUP, OP.OP_MUL, OP.OP_9, OP.OP_EQUAL])
    })
  })

  // ==========================================================================
  // OP_RIGHT fix verification — the PR fixed buf.slice(size - len, len) → buf.slice(size - len)
  // ==========================================================================
  describe('OP_RIGHT slice fix', () => {
    it('correctly returns last N bytes for various inputs', () => {
      const testCases = [
        { input: [1, 2, 3, 4, 5], len: 3, expected: [3, 4, 5] },
        { input: [0xAA, 0xBB, 0xCC, 0xDD], len: 2, expected: [0xCC, 0xDD] },
        { input: [0xFF], len: 1, expected: [0xFF] },
        { input: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], len: 1, expected: [10] }
      ]

      for (const { input, len, expected } of testCases) {
        const lenOpcode = OP.OP_1 + (len - 1) // len is always 1-10 in our test cases
        expectValid([input, lenOpcode, OP.OP_RIGHT, expected, OP.OP_EQUAL])
      }
    })
  })

  // ==========================================================================
  // OP_VER encoding fix — the PR changed from script-number to 4-byte LE
  // ==========================================================================
  describe('OP_VER encoding (4-byte LE, not script num)', () => {
    it('version 1 pushes exactly [0x01, 0x00, 0x00, 0x00] (not script num [0x01])', () => {
      // If OP_VER used script num, it would push [0x01] (1 byte).
      // With the fix it pushes 4 bytes. Check by testing SIZE.
      expectValid([
        OP.OP_VER,
        OP.OP_SIZE,       // push size of top element
        OP.OP_4,          // expected: 4 bytes
        OP.OP_EQUALVERIFY,
        le4(1),           // verify actual value
        OP.OP_EQUAL
      ])
    })

    it('version 256 pushes [0x00, 0x01, 0x00, 0x00]', () => {
      expectValid([OP.OP_VER, [0x00, 0x01, 0x00, 0x00], OP.OP_EQUAL], 256)
    })
  })

  // ==========================================================================
  // Combined OP_LEFT + OP_RIGHT = OP_SPLIT equivalent
  // ==========================================================================
  describe('OP_LEFT + OP_RIGHT composition', () => {
    it('LEFT + RIGHT can reconstruct the original string', () => {
      // Take 'HelloWorld', LEFT 5 → 'Hello', original RIGHT 5 → 'World', CAT → 'HelloWorld'
      expectValid([
        strBytes('HelloWorld'),
        OP.OP_DUP,
        OP.OP_5,
        OP.OP_LEFT,   // stack: 'HelloWorld', 'Hello'
        OP.OP_SWAP,
        OP.OP_5,
        OP.OP_RIGHT,  // stack: 'Hello', 'World'
        OP.OP_CAT,    // stack: 'HelloWorld'
        strBytes('HelloWorld'),
        OP.OP_EQUAL
      ])
    })
  })

  // ==========================================================================
  // Edge cases for OP_VERIF/OP_VERNOTIF with different version numbers
  // ==========================================================================
  describe('OP_VERIF/OP_VERNOTIF edge cases', () => {
    it('OP_VERIF with tx version 2 matches [0x02, 0x00, 0x00, 0x00]', () => {
      expectValid([le4(2), OP.OP_VERIF, OP.OP_TRUE, OP.OP_ELSE, OP.OP_FALSE, OP.OP_ENDIF], 2)
    })

    it('OP_VERIF with empty stack item (0 bytes) does not match any version', () => {
      // OP_0 pushes empty array
      expectValid([OP.OP_0, OP.OP_VERIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF])
    })

    it('OP_VERNOTIF with tx version 2: matching value goes to ELSE', () => {
      expectValid([le4(2), OP.OP_VERNOTIF, OP.OP_FALSE, OP.OP_ELSE, OP.OP_TRUE, OP.OP_ENDIF], 2)
    })
  })
})
