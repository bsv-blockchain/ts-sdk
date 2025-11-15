import BigNumber from '../dist/esm/src/primitives/BigNumber.js'
import { runBenchmark } from './lib/benchmark-runner.js'

const digits = Number(process.argv[2] ?? 200000)
const iterations = Number(process.argv[3] ?? 1)
const largeHex = 'f'.repeat(digits)
const bn = new BigNumber(largeHex, 16)
const little = bn.toSm('little')
const big = bn.toSm('big')

async function main () {
  const options = { minSampleMs: 400, samples: 8 }

  await runBenchmark('toSm big', () => {
    for (let i = 0; i < iterations; i++) bn.toSm('big')
  }, options)

  await runBenchmark('toSm little', () => {
    for (let i = 0; i < iterations; i++) bn.toSm('little')
  }, options)

  await runBenchmark('fromSm big', () => {
    for (let i = 0; i < iterations; i++) BigNumber.fromSm(big)
  }, options)

  await runBenchmark('fromSm little', () => {
    for (let i = 0; i < iterations; i++) BigNumber.fromSm(little, 'little')
  }, options)

  await runBenchmark('fromScriptNum', () => {
    for (let i = 0; i < iterations; i++) BigNumber.fromScriptNum(little)
  }, options)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
