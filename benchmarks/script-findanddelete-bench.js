import Script from '../dist/esm/src/script/Script.js'
import OP from '../dist/esm/src/script/OP.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function makeRng (seed) {
  let x = seed | 0
  return () => {
    x ^= x << 13
    x ^= x >>> 17
    x ^= x << 5
    return x >>> 0
  }
}

function makeBytes (rng, length) {
  const out = new Array(length)
  for (let i = 0; i < length; i++) {
    out[i] = rng() & 0xff
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

function makeOpChunk (op) {
  return { op }
}

function makeScenario ({
  name,
  totalChunks,
  matchRatio,
  payloadBytes,
  opRatio,
  opReturnRatio,
  seed
}) {
  const rng = makeRng(seed)
  const targetData = makeBytes(rng, payloadBytes)
  const targetChunk = makePushChunk(targetData)
  const targetScript = new Script([targetChunk])

  const chunks = new Array(totalChunks)
  for (let i = 0; i < totalChunks; i++) {
    const roll = rng() / 0xffffffff
    if (roll < matchRatio) {
      chunks[i] = targetChunk
      continue
    }
    if (roll < matchRatio + opReturnRatio) {
      chunks[i] = {
        op: OP.OP_RETURN,
        data: makeBytes(rng, payloadBytes)
      }
      continue
    }
    if (roll < matchRatio + opReturnRatio + opRatio) {
      chunks[i] = makeOpChunk(OP.OP_1 + (rng() % 16))
      continue
    }
    chunks[i] = makePushChunk(makeBytes(rng, payloadBytes))
  }

  return {
    name,
    targetScript,
    makeScript: () => new Script(chunks.slice())
  }
}

const scenarios = [
  makeScenario({
    name: 'findAndDelete mixed script (4000 chunks, 2% matches, 64B data)',
    totalChunks: 4000,
    matchRatio: 0.02,
    payloadBytes: 64,
    opRatio: 0.15,
    opReturnRatio: 0.05,
    seed: 0x12345678
  }),
  makeScenario({
    name: 'findAndDelete mixed script (8000 chunks, 5% matches, 72B data)',
    totalChunks: 8000,
    matchRatio: 0.05,
    payloadBytes: 72,
    opRatio: 0.1,
    opReturnRatio: 0.05,
    seed: 0x9e3779b9
  }),
  makeScenario({
    name: 'findAndDelete mixed script (8000 chunks, 20% matches, 72B data)',
    totalChunks: 8000,
    matchRatio: 0.2,
    payloadBytes: 72,
    opRatio: 0.1,
    opReturnRatio: 0.05,
    seed: 0xdeadbeef
  }),
  makeScenario({
    name: 'findAndDelete mixed script (2000 chunks, 5% matches, 300B data)',
    totalChunks: 2000,
    matchRatio: 0.05,
    payloadBytes: 300,
    opRatio: 0.1,
    opReturnRatio: 0.05,
    seed: 0xa5a5a5a5
  }),
  makeScenario({
    name: 'findAndDelete mixed script (12000 chunks, 1% matches, 32B data)',
    totalChunks: 12000,
    matchRatio: 0.01,
    payloadBytes: 32,
    opRatio: 0.2,
    opReturnRatio: 0.05,
    seed: 0x0f1e2d3c
  })
]

async function main () {
  for (const scenario of scenarios) {
    await runBenchmark(scenario.name, () => {
      const script = scenario.makeScript()
      script.findAndDelete(scenario.targetScript)
    }, {
      minSampleMs: 600,
      samples: 9,
      minIterations: 10
    })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
