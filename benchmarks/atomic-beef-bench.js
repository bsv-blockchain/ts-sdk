import { performance } from 'perf_hooks'
import Transaction from '../dist/esm/src/transaction/Transaction.js'
import PrivateKey from '../dist/esm/src/primitives/PrivateKey.js'
import P2PKH from '../dist/esm/src/script/templates/P2PKH.js'

async function buildChain (depth) {
  const privateKey = new PrivateKey(1)
  const publicKeyHash = privateKey.toPublicKey().toHash()
  const p2pkh = new P2PKH()

  const baseTx = new Transaction()
  baseTx.addOutput({
    lockingScript: p2pkh.lock(publicKeyHash),
    satoshis: 100000
  })

  let currentTx = baseTx

  for (let i = 1; i < depth; i++) {
    const nextTx = new Transaction()
    nextTx.addInput({
      sourceTransaction: currentTx,
      sourceOutputIndex: 0,
      unlockingScriptTemplate: p2pkh.unlock(privateKey),
      sequence: 0xffffffff
    })
    nextTx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 100000 - i
    })
    await nextTx.sign()
    currentTx = nextTx
  }

  return currentTx
}

async function measure (fn, iterations = 5) {
  const times = []
  for (let i = 0; i < iterations; i++) {
    const start = performance.now()
    const result = fn()
    if (result instanceof Promise) {
      await result
    }
    const end = performance.now()
    times.push(end - start)
  }
  const total = times.reduce((sum, t) => sum + t, 0)
  return {
    average: total / times.length,
    min: Math.min(...times),
    max: Math.max(...times)
  }
}

async function run () {
  const depth = Number.parseInt(process.argv[2] ?? '200', 10)
  const iterations = Number.parseInt(process.argv[3] ?? '5', 10)
  console.log(`Building transaction chain with depth ${depth} ...`)
  const finalTx = await buildChain(depth)

  console.log('Warming up serializers/deserializers ...')
  const initialSerialized = finalTx.toAtomicBEEF()
  Transaction.fromAtomicBEEF(initialSerialized)

  const toStats = await measure(() => finalTx.toAtomicBEEF(), iterations)
  const serialized = finalTx.toAtomicBEEF()
  const fromStats = await measure(() => Transaction.fromAtomicBEEF(serialized), iterations)

  console.log(`Transaction.toAtomicBEEF avg: ${toStats.average.toFixed(2)}ms (min ${toStats.min.toFixed(2)}ms, max ${toStats.max.toFixed(2)}ms)`) 
  console.log(`Transaction.fromAtomicBEEF avg: ${fromStats.average.toFixed(2)}ms (min ${fromStats.min.toFixed(2)}ms, max ${fromStats.max.toFixed(2)}ms)`) 
}

run().catch((err) => {
  console.error(err)
  process.exit(1)
})
