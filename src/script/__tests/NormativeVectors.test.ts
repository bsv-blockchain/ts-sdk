import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { join } from 'path'
import BigNumber from '../../primitives/BigNumber'
import { hash160, hash256 } from '../../primitives/Hash'
import TransactionSignature from '../../primitives/TransactionSignature'
import { toArray, toHex } from '../../primitives/utils'
import Transaction from '../../transaction/Transaction'
import LockingScript from '../LockingScript'
import OP from '../OP'
import Script from '../Script'
import ScriptChunk from '../ScriptChunk'
import Spend from '../Spend'
import UnlockingScript from '../UnlockingScript'

type JsonValue = string | number | JsonValue[]

const errorSummary = (e: unknown): string => String((e as Error).message ?? e).split('\n')[0]
const amountFromJSON = (amount: JsonValue): number => Math.round(Number(amount) * 100000000)

interface ScriptVector {
  source: string
  index: number
  amount: number
  txVersion: number
  scriptSig: string
  scriptPubKey: string
  flags: string
  expected: string
  comment: string
}

interface TxVector {
  source: string
  index: number
  prevouts: Array<[string, number, string, number?]>
  txHex: string
  flags: string[]
}

interface SighashVector {
  source: string
  index: number
  txHex: string
  scriptHex: string
  inputIndex: number
  hashType: number
  regularHash: string
  originalHash: string
}

const ZERO_TXID = '0'.repeat(64)
const FIXTURE_ROOT = join(process.cwd(), 'src/script/__tests/fixtures')

const fixtureSources = [
  {
    name: 'bitcoin-sv',
    path: 'bitcoin-sv',
    shas: {
      'script_tests.json': 'a77f8b94412ef61e9ee59980ebc682a64212b47a16f06d87f809d91770ba496d',
      'sighash.json': '9c1afcaf81e8482f818345efa8a3f0610f6541b975023b58550d50ad2a557f63',
      'tx_invalid.json': '536a533f00714374d15fb24f601b989a87f9447a7a414a6532380e41c09c4fbe',
      'tx_valid.json': '20e42308ead38db645454c4def763288e8cef2e5c47a4d9088e53dc7fc01419d'
    }
  },
  {
    name: 'teranode',
    path: 'teranode',
    shas: {
      'script_tests.json': '3577a2e6e71e3356c5ec06eaa5fffb243e563eeef3946bd9b0285a54f0ad87f9',
      'sighash.json': 'ca2d6449c7cb98b8a83f3e18dc994d8227001d87adedd907b5e9a235114e283f',
      'tx_invalid.json': '536a533f00714374d15fb24f601b989a87f9447a7a414a6532380e41c09c4fbe',
      'tx_valid.json': '20e42308ead38db645454c4def763288e8cef2e5c47a4d9088e53dc7fc01419d'
    }
  }
]

function readFixture<T = JsonValue[]> (source: string, file: string): T {
  return JSON.parse(readFileSync(join(FIXTURE_ROOT, source, file), 'utf8')) as T
}

function sha256File (source: string, file: string): string {
  return createHash('sha256')
    .update(readFileSync(join(FIXTURE_ROOT, source, file)))
    .digest('hex')
}

function scriptNumBytes (value: bigint): number[] {
  if (value === 0n) return []
  const negative = value < 0n
  let absValue = negative ? -value : value
  const bytes: number[] = []
  while (absValue > 0n) {
    bytes.push(Number(absValue & 0xffn))
    absValue >>= 8n
  }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) {
    bytes.push(negative ? 0x80 : 0)
  } else if (negative) {
    bytes[bytes.length - 1] |= 0x80
  }
  return bytes
}

function writePush (bytes: number[], out: number[]): void {
  if (bytes.length === 0) {
    out.push(OP.OP_0)
  } else if (bytes.length === 1 && bytes[0] >= 1 && bytes[0] <= 16) {
    out.push(OP.OP_1 + bytes[0] - 1)
  } else if (bytes.length === 1 && bytes[0] === 0x81) {
    out.push(OP.OP_1NEGATE)
  } else if (bytes.length < OP.OP_PUSHDATA1) {
    out.push(bytes.length, ...bytes)
  } else if (bytes.length <= 0xff) {
    out.push(OP.OP_PUSHDATA1, bytes.length, ...bytes)
  } else if (bytes.length <= 0xffff) {
    out.push(OP.OP_PUSHDATA2, bytes.length & 0xff, (bytes.length >> 8) & 0xff, ...bytes)
  } else {
    out.push(
      OP.OP_PUSHDATA4,
      bytes.length & 0xff,
      (bytes.length >> 8) & 0xff,
      (bytes.length >> 16) & 0xff,
      (bytes.length >> 24) & 0xff,
      ...bytes
    )
  }
}

function tokenToOpcode (token: string): number | undefined {
  if (token === 'TRUE') return OP.OP_TRUE
  if (token === 'FALSE') return OP.OP_FALSE
  const opToken = token.startsWith('OP_') ? token : `OP_${token}`
  const opcode = (OP as Record<string, number>)[opToken]
  return typeof opcode === 'number' ? opcode : undefined
}

function tokenizeAsm (asm: string): string[] {
  return asm.match(/'[^']*'|\S+/g) ?? []
}

function parseNodeAsm (asm: string): number[] {
  const out: number[] = []
  for (const token of tokenizeAsm(asm)) {
    if (token.startsWith('0x')) {
      out.push(...toArray(token.slice(2), 'hex'))
      continue
    }

    if (token.startsWith("'") && token.endsWith("'")) {
      writePush(Array.from(Buffer.from(token.slice(1, -1), 'utf8')), out)
      continue
    }

    if (/^-?\d+$/.test(token)) {
      writePush(scriptNumBytes(BigInt(token)), out)
      continue
    }

    const opcode = tokenToOpcode(token)
    if (opcode === undefined) throw new Error(`Unsupported script token: ${token}`)
    out.push(opcode)
  }
  return out
}

function toLockingScript (asm: string): LockingScript {
  return new LockingScript(Script.fromBinary(parseNodeAsm(asm)).chunks.map(cloneChunk))
}

function toUnlockingScript (asm: string): UnlockingScript {
  return new UnlockingScript(Script.fromBinary(parseNodeAsm(asm)).chunks.map(cloneChunk))
}

function cloneChunk (chunk: ScriptChunk): ScriptChunk {
  return {
    op: chunk.op,
    data: Array.isArray(chunk.data) ? chunk.data.slice() : undefined,
    invalidLength: chunk.invalidLength
  }
}

function buildCreditingTransaction (lockingScript: LockingScript, amount: number): Transaction {
  return new Transaction(
    1,
    [{
      sourceTXID: ZERO_TXID,
      sourceOutputIndex: 0xffffffff,
      unlockingScript: new UnlockingScript([{ op: OP.OP_0 }, { op: OP.OP_0 }]),
      sequence: 0xffffffff
    }],
    [{ lockingScript, satoshis: amount }],
    0
  )
}

function buildScriptSpend (vector: ScriptVector): Spend {
  const lockingScript = toLockingScript(vector.scriptPubKey)
  const creditTx = buildCreditingTransaction(lockingScript, vector.amount)
  return new Spend({
    sourceTXID: creditTx.id('hex'),
    sourceOutputIndex: 0,
    sourceSatoshis: vector.amount,
    lockingScript,
    transactionVersion: vector.txVersion,
    otherInputs: [],
    outputs: [{ lockingScript: new LockingScript(), satoshis: vector.amount }],
    inputIndex: 0,
    unlockingScript: toUnlockingScript(vector.scriptSig),
    inputSequence: 0xffffffff,
    lockTime: 0,
    verifyFlags: vector.flags
  })
}

function parseScriptVectors (source: string): ScriptVector[] {
  const raw = readFixture<JsonValue[]>(source, 'script_tests.json')
  const vectors: ScriptVector[] = []
  raw.forEach((entry, index) => {
    if (!Array.isArray(entry) || entry.length <= 1) return
    if (source === 'bitcoin-sv') {
      let offset = 0
      let amount = 0
      if (Array.isArray(entry[0])) {
        amount = amountFromJSON(entry[0][0])
        offset = 1
      }
      vectors.push({
        source,
        index,
        amount,
        txVersion: Number(entry[offset]),
        scriptSig: String(entry[offset + 1]),
        scriptPubKey: String(entry[offset + 2]),
        flags: String(entry[offset + 3]),
        expected: String(entry[offset + 4]),
        comment: entry[offset + 5] === undefined ? '' : String(entry[offset + 5])
      })
      return
    }

    let offset = 0
    let amount = 0
    if (Array.isArray(entry[0])) {
      amount = amountFromJSON(entry[0][0])
      offset = 1
    }
    vectors.push({
      source,
      index,
      amount,
      txVersion: 1,
      scriptSig: String(entry[offset]),
      scriptPubKey: String(entry[offset + 1]),
      flags: String(entry[offset + 2]),
      expected: String(entry[offset + 3]),
      comment: entry[offset + 4] === undefined ? '' : String(entry[offset + 4])
    })
  })
  return vectors
}

function parseTxVectors (source: string, file: string): TxVector[] {
  const raw = readFixture<JsonValue[]>(source, file)
  const vectors: TxVector[] = []
  raw.forEach((entry, index) => {
    if (!Array.isArray(entry) || entry.length <= 1) return
    const flags = Array.isArray(entry[2]) ? entry[2].map(String) : [String(entry[2])]
    vectors.push({
      source,
      index,
      prevouts: entry[0] as Array<[string, number, string, number?]>,
      txHex: String(entry[1]),
      flags
    })
  })
  return vectors
}

function parseSighashVectors (source: string): SighashVector[] {
  const raw = readFixture<JsonValue[]>(source, 'sighash.json')
  const vectors: SighashVector[] = []
  raw.forEach((entry, index) => {
    if (!Array.isArray(entry) || entry.length <= 1) return
    vectors.push({
      source,
      index,
      txHex: String(entry[0]),
      scriptHex: String(entry[1]),
      inputIndex: Number(entry[2]),
      hashType: Number(entry[3]),
      regularHash: String(entry[4]),
      originalHash: String(entry[5])
    })
  })
  return vectors
}

function validateTxVectorInput (vector: TxVector, flags: string, inputIndex: number): boolean {
  const tx = Transaction.fromHex(vector.txHex)
  const input = tx.inputs[inputIndex]
  const prevout = vector.prevouts.find(([txid, vout]) =>
    txid === input.sourceTXID && (vout >>> 0) === input.sourceOutputIndex
  )
  if (prevout === undefined || input.unlockingScript === undefined) {
    throw new Error(`Missing prevout fixture for input ${inputIndex}`)
  }

  const otherInputs = [...tx.inputs]
  otherInputs.splice(inputIndex, 1)
  const spend = new Spend({
    sourceTXID: input.sourceTXID ?? '',
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: prevout[3] ?? 0,
    lockingScript: toLockingScript(prevout[2]),
    transactionVersion: tx.version,
    otherInputs,
    outputs: tx.outputs,
    inputIndex,
    unlockingScript: input.unlockingScript,
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
    verifyFlags: flags
  })
  return spend.validate()
}

function computeSignatureHashes (vector: SighashVector): { regular: string, original: string } {
  const tx = Transaction.fromHex(vector.txHex)
  const input = tx.inputs[vector.inputIndex]
  const otherInputs = [...tx.inputs]
  otherInputs.splice(vector.inputIndex, 1)
  const params = {
    sourceTXID: input.sourceTXID ?? '',
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis: 0,
    transactionVersion: tx.version,
    otherInputs,
    outputs: tx.outputs,
    inputIndex: vector.inputIndex,
    subscript: Script.fromHex(vector.scriptHex),
    inputSequence: input.sequence ?? 0xffffffff,
    lockTime: tx.lockTime,
    scope: vector.hashType
  }
  // Teranode's go-bt-derived vectors route FORKID signatures through the
  // forkid digest even when the Chronicle bit is present. bitcoin-sv keeps
  // the Chronicle bit as an OTDA selector, which remains the SDK default.
  const regular = hash256(TransactionSignature.format({
    ...params,
    ignoreChronicle: vector.source === 'teranode'
  })).reverse()
  const original = hash256(TransactionSignature.formatOTDA(params)).reverse()
  return {
    regular: toHex(regular),
    original: toHex(original)
  }
}

describe('Normative BSV node script fixtures', () => {
  it('authenticates fixture checksums', () => {
    for (const source of fixtureSources) {
      for (const [file, sha] of Object.entries(source.shas)) {
        expect(sha256File(source.path, file)).toBe(sha)
      }
    }
  })

  for (const source of fixtureSources) {
    describe(`${source.name} script_tests.json`, () => {
      const vectors = parseScriptVectors(source.path)
      it(`executes all ${vectors.length} script vectors with expected boolean result`, () => {
        const failures: string[] = []
        for (const vector of vectors) {
          const run = (): boolean => buildScriptSpend(vector).validate()
          const label = `${vector.source}#${vector.index} ${vector.expected} ${vector.flags} ${vector.comment}`
          try {
            if (vector.expected === 'OK') {
              if (run() !== true) failures.push(`${label}: returned false`)
            } else {
              run()
              failures.push(`${label}: accepted invalid script`)
            }
          } catch (e) {
            if (vector.expected === 'OK') {
              failures.push(`${label}: ${errorSummary(e)}`)
            }
          }
        }
        expect(failures).toEqual([])
      })
    })

    describe(`${source.name} tx_valid.json`, () => {
      const vectors = parseTxVectors(source.path, 'tx_valid.json')
      it(`validates all script spends in ${vectors.length} valid transaction vectors`, () => {
        const failures: string[] = []
        for (const vector of vectors) {
          const tx = Transaction.fromHex(vector.txHex)
          expect(toHex(tx.toBinary())).toBe(vector.txHex)
          for (const flags of vector.flags) {
            for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
              const label = `${vector.source} tx_valid#${vector.index} input ${inputIndex} flags ${flags}`
              try {
                if (validateTxVectorInput(vector, flags, inputIndex) !== true) failures.push(`${label}: returned false`)
              } catch (e) {
                failures.push(`${label}: ${errorSummary(e)}`)
              }
            }
          }
        }
        expect(failures).toEqual([])
      })
    })

    describe(`${source.name} tx_invalid.json`, () => {
      const vectors = parseTxVectors(source.path, 'tx_invalid.json')
      it(`executes all parseable invalid transaction script spends across ${vectors.length} entries`, () => {
        let evaluatedSpendCases = 0
        let rejectedSpendCases = 0
        for (const vector of vectors) {
          let tx: Transaction
          try {
            tx = Transaction.fromHex(vector.txHex)
            expect(toHex(tx.toBinary())).toBe(vector.txHex)
          } catch (e) {
            expect(e).toBeInstanceOf(Error)
            continue
          }

          for (const flags of vector.flags) {
            for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
              evaluatedSpendCases++
              try {
                if (validateTxVectorInput(vector, flags, inputIndex) !== true) rejectedSpendCases++
              } catch (e) {
                rejectedSpendCases++
              }
            }
          }
        }
        expect(evaluatedSpendCases).toBeGreaterThan(0)
        expect(rejectedSpendCases).toBeGreaterThan(0)
      })
    })

    describe(`${source.name} sighash.json`, () => {
      const vectors = parseSighashVectors(source.path)
      it(`matches all ${vectors.length} regular and original signature hash vectors`, () => {
        const failures: string[] = []
        for (const vector of vectors) {
          const actual = computeSignatureHashes(vector)
          const label = `${vector.source} sighash#${vector.index}`
          if (actual.regular !== vector.regularHash) {
            failures.push(`${label} regular: expected ${vector.regularHash}, received ${actual.regular}`)
          }
          if (actual.original !== vector.originalHash) {
            failures.push(`${label} original: expected ${vector.originalHash}, received ${actual.original}`)
          }
        }
        expect(failures).toEqual([])
      })
    })
  }
})
