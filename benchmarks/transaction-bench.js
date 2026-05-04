import Transaction from '../dist/esm/src/transaction/Transaction.js'
import PrivateKey from '../dist/esm/src/primitives/PrivateKey.js'
import P2PKH from '../dist/esm/src/script/templates/P2PKH.js'
import MerklePath from '../dist/esm/src/transaction/MerklePath.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function randomHash () {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function buildFullBlockPath (count) {
  const txids = []
  const leaves = []
  for (let i = 0; i < count; i++) {
    const hash = randomHash()
    txids.push(hash)
    leaves.push({ offset: i, hash, txid: true })
  }
  if (count % 2 === 1) leaves.push({ offset: count, duplicate: true })
  return {
    mp: new MerklePath(1, [leaves]),
    txids
  }
}

function pickRandom (arr, n) {
  const copy = [...arr]
  const result = []
  for (let i = 0; i < n && copy.length > 0; i++) {
    const index = Math.floor(Math.random() * copy.length)
    result.push(copy.splice(index, 1)[0])
  }
  return result
}

function merkleExtractCase (path, extractCount) {
  const targets = pickRandom(path.txids, extractCount)
  const extracted = path.mp.extract(targets)
  for (const txid of targets) {
    if (extracted.computeRoot(txid) !== path.mp.computeRoot(txid)) {
      throw new Error('MerklePath.extract produced an invalid root')
    }
  }
}

async function deepInputChain () {
  const privateKey = new PrivateKey(1)
  const publicKey = privateKey.toPublicKey()
  const publicKeyHash = publicKey.toHash()
  const p2pkh = new P2PKH()

  const depth = 100
  let tx = new Transaction()
  tx.addOutput({
    lockingScript: p2pkh.lock(publicKeyHash),
    satoshis: 100000
  })
  const blockHeight = 1631619
  const txid = tx.hash('hex')
  const path = [
    [
      { offset: 0, hash: txid, txid: true, duplicate: false },
      { offset: 1, hash: 'aa'.repeat(32), txid: false, duplicate: false }
    ],
    [{ offset: 1, hash: 'bb'.repeat(32), txid: false, duplicate: false }]
  ]
  const merklePath = new MerklePath(blockHeight, path)
  tx.merklePath = merklePath

  for (let i = 1; i < depth + 1; i++) {
    const newTx = new Transaction()
    newTx.addInput({
      sourceTransaction: tx,
      sourceOutputIndex: 0,
      unlockingScriptTemplate: p2pkh.unlock(privateKey),
      sequence: 0xffffffff
    })
    newTx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 100000 - i * 10
    })
    await newTx.sign()
    tx = newTx
  }

  await tx.verify('scripts only')
}

async function wideInputSet () {
  const privateKey = new PrivateKey(1)
  const publicKeyHash = privateKey.toPublicKey().toHash()
  const p2pkh = new P2PKH()

  const inputCount = 100
  const sourceTxs = []
  for (let i = 0; i < inputCount; i++) {
    const sourceTx = new Transaction()
    sourceTx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 1000
    })
    const blockHeight = 1631619
    const txid = sourceTx.hash('hex')
    const path = [
      [
        { offset: 0, hash: txid, txid: true, duplicate: false },
        { offset: 1, hash: 'aa'.repeat(32), txid: false, duplicate: false }
      ],
      [{ offset: 1, hash: 'bb'.repeat(32), txid: false, duplicate: false }]
    ]
    const merklePath = new MerklePath(blockHeight, path)
    sourceTx.merklePath = merklePath
    sourceTxs.push(sourceTx)
  }

  const tx = new Transaction()
  for (let i = 0; i < inputCount; i++) {
    tx.addInput({
      sourceTransaction: sourceTxs[i],
      sourceOutputIndex: 0,
      unlockingScriptTemplate: p2pkh.unlock(privateKey),
      sequence: 0xffffffff
    })
  }
  tx.addOutput({
    lockingScript: p2pkh.lock(publicKeyHash),
    satoshis: inputCount * 1000 - 1000
  })
  await tx.sign()
  await tx.verify('scripts only')
}

async function largeInputsOutputs () {
  const privateKey = new PrivateKey(1)
  const publicKeyHash = privateKey.toPublicKey().toHash()
  const p2pkh = new P2PKH()

  const inputCount = 50
  const outputCount = 50
  const sourceTxs = []
  for (let i = 0; i < inputCount; i++) {
    const sourceTx = new Transaction()
    sourceTx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 2000
    })
    const blockHeight = 1631619
    const txid = sourceTx.hash('hex')
    const path = [
      [
        { offset: 0, hash: txid, txid: true, duplicate: false },
        { offset: 1, hash: 'aa'.repeat(32), txid: false, duplicate: false }
      ],
      [{ offset: 1, hash: 'bb'.repeat(32), txid: false, duplicate: false }]
    ]
    const merklePath = new MerklePath(blockHeight, path)
    sourceTx.merklePath = merklePath
    sourceTxs.push(sourceTx)
  }

  const tx = new Transaction()
  for (let i = 0; i < inputCount; i++) {
    tx.addInput({
      sourceTransaction: sourceTxs[i],
      sourceOutputIndex: 0,
      unlockingScriptTemplate: p2pkh.unlock(privateKey),
      sequence: 0xffffffff
    })
  }
  for (let i = 0; i < outputCount; i++) {
    tx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 1000
    })
  }
  await tx.sign()
  await tx.verify('scripts only')
}

async function nestedInputs () {
  const privateKey = new PrivateKey(1)
  const publicKeyHash = privateKey.toPublicKey().toHash()
  const p2pkh = new P2PKH()

  const depth = 5
  const fanOut = 3
  let txs = []

  for (let i = 0; i < fanOut; i++) {
    const baseTx = new Transaction()
    baseTx.addOutput({
      lockingScript: p2pkh.lock(publicKeyHash),
      satoshis: 100000
    })
    const blockHeight = 1631619
    const txid = baseTx.hash('hex')
    const path = [
      [
        { offset: 0, hash: txid, txid: true, duplicate: false },
        { offset: 1, hash: 'aa'.repeat(32), txid: false, duplicate: false }
      ],
      [{ offset: 1, hash: 'bb'.repeat(32), txid: false, duplicate: false }]
    ]
    const merklePath = new MerklePath(blockHeight, path)
    baseTx.merklePath = merklePath
    txs.push(baseTx)
  }

  for (let d = 0; d < depth; d++) {
    const newTxs = []
    for (const tx of txs) {
      const newTx = new Transaction()
      for (let i = 0; i < fanOut; i++) {
        newTx.addInput({
          sourceTransaction: tx,
          sourceOutputIndex: 0,
          unlockingScriptTemplate: p2pkh.unlock(privateKey),
          sequence: 0xffffffff
        })
      }
      newTx.addOutput({
        lockingScript: p2pkh.lock(publicKeyHash),
        satoshis: (tx.outputs[0]?.satoshis ?? 0) - 1000 * fanOut
      })
      await newTx.sign()
      newTxs.push(newTx)
    }
    txs = newTxs
  }

  const finalTx = txs[0]
  await finalTx.verify('scripts only')
}

async function main () {
  const options = { samples: 3, minSampleMs: 150, warmupIterations: 1 }
  const merklePath101 = buildFullBlockPath(101)
  const merklePath501 = buildFullBlockPath(501)
  const merklePath999 = buildFullBlockPath(999)

  await runBenchmark('deep chain verify', () => deepInputChain(), options)
  await runBenchmark('wide transaction verify', () => wideInputSet(), options)
  await runBenchmark('large tx verify', () => largeInputsOutputs(), options)
  await runBenchmark('nested inputs verify', () => nestedInputs(), options)
  await runBenchmark('MerklePath.extract 101 txids / 1 target', () => {
    merkleExtractCase(merklePath101, 1)
  }, { samples: 5, minSampleMs: 100, warmupIterations: 1 })
  await runBenchmark('MerklePath.extract 101 txids / 10 targets', () => {
    merkleExtractCase(merklePath101, 10)
  }, { samples: 5, minSampleMs: 100, warmupIterations: 1 })
  await runBenchmark('MerklePath.extract 501 txids / 10 targets', () => {
    merkleExtractCase(merklePath501, 10)
  }, { samples: 5, minSampleMs: 100, warmupIterations: 1 })
  await runBenchmark('MerklePath.extract 999 txids / 50 targets', () => {
    merkleExtractCase(merklePath999, 50)
  }, { samples: 5, minSampleMs: 100, warmupIterations: 1 })
  await runBenchmark('MerklePath.extract 999 txids / 100 targets', () => {
    merkleExtractCase(merklePath999, 100)
  }, { samples: 3, minSampleMs: 100, warmupIterations: 1 })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
