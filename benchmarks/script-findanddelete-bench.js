import Script from '../dist/esm/src/script/Script.js'
import OP from '../dist/esm/src/script/OP.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function makeBytes (seed, length) {
  let x = seed | 0
  const out = new Array(length)
  for (let i = 0; i < length; i++) {
    x ^= x << 13
    x ^= x >>> 17
    x ^= x << 5
    out[i] = x & 0xff
  }
  return out
}

function makePushChunk (data) {
  const len = data.length
  let op
  if (len === 0) {
    op = OP.OP_0
  } else if (len < OP.OP_PUSHDATA1) {
    op = len
  } else if (len < 0x100) {
    op = OP.OP_PUSHDATA1
  } else if (len < 0x10000) {
    op = OP.OP_PUSHDATA2
  } else if (len < 0x100000000) {
    op = OP.OP_PUSHDATA4
  } else {
    throw new Error('Chunk data too large')
  }
  return {
    op,
    data: len > 0 ? data : undefined
  }
}

const totalChunks = 8000
const matchEvery = 20
const payloadLength = 72

const targetData = makeBytes(0xdeadbeef, payloadLength)
const targetChunk = makePushChunk(targetData)
const targetScript = new Script([targetChunk])

const baseChunks = new Array(totalChunks)
for (let i = 0; i < totalChunks; i++) {
  if (i % matchEvery === 0) {
    baseChunks[i] = targetChunk
  } else {
    baseChunks[i] = makePushChunk(makeBytes(i + 1, payloadLength))
  }
}

function makeScript () {
  return new Script(baseChunks.slice())
}

async function main () {
  await runBenchmark('findAndDelete big script (8000 chunks, 5% matches)', () => {
    const script = makeScript()
    script.findAndDelete(targetScript)
  }, {
    minSampleMs: 600,
    samples: 10,
    minIterations: 10
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
