import { toHex } from "../../primitives/utils"
import Script from "../Script"
import Spend from "../Spend"

describe('lrshiftnum tests', () => {
    jest.setTimeout(99999999)

    test('0 valid OP_LSHIFTNUM Scripts', async () => {
      for (const [script, stack] of lshiftnumValidScripts) {
        const result = executeScriptCode(script, stack)
        expect(result).toBe(true)
      }
    })

    test('1 invalid OP_LSHIFTNUM Scripts', async () => {
      for (const [script, stack] of lshiftnumInvalidScripts) {
        try {
          // An invalid script should throw...
          const result = executeScriptCode(script, stack)
          expect(true).toBe(false)
        } catch (e) {
          expect(e).toBeTruthy()
        }
      }
    })

    test('2 valid OP_RSHIFTNUM Scripts', async () => {
      for (const [script, stack] of rshiftnumValidScripts) {
        const result = executeScriptCode(script, stack)
        expect(result).toBe(true)
      }
    })

    test('3 invalid OP_RSHIFTNUM Scripts', async () => {
      for (const [script, stack] of rshiftnumInvalidScripts) {
        try {
          // An invalid script should throw...
          const result = executeScriptCode(script, stack)
          expect(true).toBe(false)
        } catch (e) {
          expect(e).toBeTruthy()
        }
      }
    })
})

const lshiftnumInvalidScripts: [string, string[]][] = [
  ['OP_LSHIFTNUM',
    ['']],
  ['OP_1 OP_LSHIFTNUM',
    ['']],
  ['OP_2, OP_1NEGATE, OP_LSHIFTNUM',
    ['']],
]

const lshiftnumValidScripts: [string, string[]][] = [
  ['010203 OP_16 OP_LSHIFTNUM', // shift 2 bytes
    ['0000010203']
  ]
  ,
  ['OP_0 OP_1 OP_LSHIFTNUM',  // empty input data
    ['']
  ],
  ['OP_1 OP_0 OP_LSHIFTNUM',  // shift by 0
    ['01']
  ],

  ['OP_1 OP_8 OP_LSHIFTNUM',  // shift by size of stack element (or greater)
    ['0001']
  ],

  ['0102 OP_8 OP_LSHIFTNUM', // shift 1 byte
    ['000102']
  ],

  ['010203 OP_16 OP_LSHIFTNUM', // shift 2 bytes
    ['0000010203']
  ],

  ['OP_1 OP_1 OP_LSHIFTNUM', // shift by 1 bit
    ['02']
  ],

  ['OP_1 OP_2 OP_LSHIFTNUM', // shift by 2 bits
    ['04']
  ],

  ['OP_1 OP_7 OP_LSHIFTNUM',
    ['8000']
  ],

  ['0102 OP_9 OP_LSHIFTNUM', // shift by bits and bytes
    ['000204']
  ],

  // Negative numbers
  ['OP_1NEGATE OP_7 OP_LSHIFTNUM', // shift into the sign bit
    ['8080']
  ],

  ['0180 OP_7 OP_LSHIFTNUM', // shift into the sign bit
    ['8080']
  ],
]

const rshiftnumInvalidScripts: [string, string[]][] = [
  ['OP_RSHIFTNUM',
    ['']],
  ['OP_1 OP_RSHIFTNUM',
    ['']],
  ['OP_2 OP_1NEGATE OP_RSHIFTNUM',
    ['']],
]

const rshiftnumValidScripts: [string, string[]][] = [
  ['OP_0 OP_1 OP_RSHIFTNUM',  // empty input data
    ['']],

  ['OP_1 OP_0 OP_RSHIFTNUM',  // shift by 0
    ['01']],

  ['0102 OP_8 OP_RSHIFTNUM', // shift 1 byte
    ['02']],

  ['010203 OP_16 OP_RSHIFTNUM', // shift 2 bytes
    ['03']],

  ['OP_2 OP_1 OP_RSHIFTNUM', // shift by 1 bit
    ['01']],

  ['OP_4 OP_2 OP_RSHIFTNUM', // shift by 2 bits
    ['01']],

  ['0001 OP_1 OP_RSHIFTNUM', // 256 >> 1 -> 128
    ['8000']],

  ['0081 OP_1 OP_RSHIFTNUM', // -256 >> 1 -> -128
    ['8080']],

  ['010204 OP_9 OP_RSHIFTNUM', // shift by bits and bytes
    ['0102']],

  // round to 0
  ['OP_1 OP_1 OP_RSHIFTNUM', // 1 >> 1 -> 0
    ['']],

  ['OP_1NEGATE OP_1 OP_RSHIFTNUM', // -1 >> 1 -> -1    THIS IS DIFFERENT FROM C++ IMPLEMENTATION WHICH MAY YIELD 0
    ['81']], // Note: Changes size of the data
]

function executeScriptCode(script: Script | string, expectedStack: string[]): boolean {
  if (typeof script === 'string')
    script = Script.fromASM(script)
  const spend = new Spend({
    sourceTXID: '',
    sourceOutputIndex: 0,
    sourceSatoshis: 0,
    lockingScript: script,
    transactionVersion: 0,
    otherInputs: [],
    outputs: [],
    unlockingScript: new Script(),
    inputSequence: 0,
    inputIndex: 0,
    lockTime: 0,
    memoryLimit: undefined,
    isRelaxed: true
  })
  for (let i = 0; i < script.chunks.length; i++)
    spend.step()
  const stack = spend.stack
  if (stack.length !== expectedStack.length) {
    console.log(`script ${script.toASM()} expected stack length ${expectedStack.length} but got ${stack.length}`)
    return false
  }
  for (let i = 0; i < expectedStack.length; i++) {
    const expected = expectedStack[i]
    const actual = toHex(stack[i])
    if (expected !== actual) {
      console.log(`script ${script.toASM()} expected stack[${i}] ${expected} but got ${actual}`)
      return false
    }
  }
  return true
}