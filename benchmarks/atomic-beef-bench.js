import Transaction from '../dist/esm/src/transaction/Transaction.js'
import PrivateKey from '../dist/esm/src/primitives/PrivateKey.js'
import P2PKH from '../dist/esm/src/script/templates/P2PKH.js'
import { runBenchmark } from './lib/benchmark-runner.js'

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
async function run () {
  const depth = Number.parseInt(process.argv[2] ?? '200', 10)
  const iterations = Number.parseInt(process.argv[3] ?? '5', 10)
  console.log(`Building transaction chain with depth ${depth} ...`)
  const finalTx = await buildChain(depth)

  console.log('Warming up serializers/deserializers ...')
  const initialSerialized = finalTx.toAtomicBEEF()
  Transaction.fromAtomicBEEF(initialSerialized)

  const serialized = finalTx.toAtomicBEEF()
  await runBenchmark('Transaction.toAtomicBEEF', () => finalTx.toAtomicBEEF(), {
    minSampleMs: 200,
    samples: Math.max(5, iterations)
  })
  await runBenchmark('Transaction.fromAtomicBEEF', () => Transaction.fromAtomicBEEF(serialized), {
    minSampleMs: 200,
    samples: Math.max(5, iterations)
  })
}

run().catch((err) => {
  console.error(err)
  process.exit(1)
})
