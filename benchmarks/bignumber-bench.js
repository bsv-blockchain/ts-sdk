import BigNumber from '../dist/esm/src/primitives/BigNumber.js'
import { runBenchmark } from './lib/benchmark-runner.js'

const digits = Number(process.argv[2] ?? 20000)
const mulIterations = Number(process.argv[3] ?? 5)
const addIterations = Number(process.argv[4] ?? 1000)
const largeHex = 'f'.repeat(digits)
const a = new BigNumber(largeHex, 16)
const b = new BigNumber(largeHex, 16)

async function main () {
  await runBenchmark('mul large numbers', () => {
    for (let i = 0; i < mulIterations; i++) {
      a.mul(b)
    }
  }, {
    minSampleMs: 500,
    samples: 10
  })

  await runBenchmark('add large numbers', () => {
    for (let i = 0; i < addIterations; i++) {
      a.add(b)
    }
  }, {
    minSampleMs: 400,
    samples: 10
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
