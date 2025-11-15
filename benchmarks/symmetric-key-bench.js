import { randomBytes, randomFillSync } from 'crypto'
// Provide browser-like crypto for Random
globalThis.self = { crypto: { getRandomValues: (arr) => randomFillSync(arr) } }
import SymmetricKey from '../dist/esm/src/primitives/SymmetricKey.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function rand (n) {
  return [...randomBytes(n)]
}

const key = SymmetricKey.fromRandom()
const largeMsg = rand(2 * 1024 * 1024)
const smallMsgs = Array.from({ length: 50 }, () => rand(100))
const mediumMsgs = Array.from({ length: 200 }, () => rand(1024))

let enc
const encSmall = smallMsgs.map(m => key.encrypt(m))
const encMedium = mediumMsgs.map(m => key.encrypt(m))

async function main () {
  const heavyOptions = { minSampleMs: 250, samples: 5, warmupIterations: 1 }
  const lightOptions = { minSampleMs: 250, samples: 9, warmupIterations: 1 }
  await runBenchmark('encrypt large 2MB', () => {
    enc = key.encrypt(largeMsg)
  }, heavyOptions)

  await runBenchmark('decrypt large 2MB', () => {
    key.decrypt(enc)
  }, heavyOptions)

  await runBenchmark('encrypt 50 small', () => {
    for (const m of smallMsgs) key.encrypt(m)
  }, lightOptions)

  await runBenchmark('decrypt 50 small', () => {
    for (const m of encSmall) key.decrypt(m)
  }, lightOptions)

  await runBenchmark('encrypt 200 medium', () => {
    for (const m of mediumMsgs) key.encrypt(m)
  }, lightOptions)

  await runBenchmark('decrypt 200 medium', () => {
    for (const m of encMedium) key.decrypt(m)
  }, lightOptions)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
