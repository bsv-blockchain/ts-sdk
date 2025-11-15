import { Writer, Reader } from '../dist/esm/src/primitives/utils.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function data (len, start = 0) {
  const arr = new Array(len)
  for (let i = 0; i < len; i++) arr[i] = (start + i) & 0xff
  return arr
}

const largePayloads = [data(2 * 1024 * 1024, 0), data(2 * 1024 * 1024, 1), data(2 * 1024 * 1024, 2)]
const smallPayloads = Array.from({ length: 3000 }, (_, i) => data(100, i))
const mediumPayloads = Array.from({ length: 400 }, (_, i) => data(10 * 1024, i))

function mixedOps () {
  const writer = new Writer()
  for (let i = 0; i < 1000; i++) {
    writer.writeUInt32LE(i)
    writer.writeInt16BE(-i)
    writer.writeUInt8(i & 0xff)
    writer.writeVarIntNum(i)
    writer.writeVarIntNum(i % 10)
    writer.write(data(i % 10))
  }
  const arr = writer.toArray()
  const reader = new Reader(arr)
  while (!reader.eof()) {
    reader.readUInt32LE()
    reader.readInt16BE()
    reader.readUInt8()
    reader.readVarIntNum()
    const len = reader.readVarIntNum()
    reader.read(len)
  }
}

function rwLarge () {
  const writer = new Writer()
  for (const p of largePayloads) {
    writer.writeVarIntNum(p.length)
    writer.write(p)
  }
  const arr = writer.toArray()
  const reader = new Reader(arr)
  for (let i = 0; i < largePayloads.length; i++) {
    const len = reader.readVarIntNum()
    reader.read(len)
  }
}

function rwSmall () {
  const writer = new Writer()
  for (const p of smallPayloads) {
    writer.writeVarIntNum(p.length)
    writer.write(p)
  }
  const arr = writer.toArray()
  const reader = new Reader(arr)
  for (let i = 0; i < smallPayloads.length; i++) {
    const len = reader.readVarIntNum()
    reader.read(len)
  }
}

function rwMedium () {
  const writer = new Writer()
  for (const p of mediumPayloads) {
    writer.writeVarIntNum(p.length)
    writer.write(p)
  }
  const arr = writer.toArray()
  const reader = new Reader(arr)
  for (let i = 0; i < mediumPayloads.length; i++) {
    const len = reader.readVarIntNum()
    reader.read(len)
  }
}

async function main () {
  const options = { minSampleMs: 300, samples: 9 }
  await runBenchmark('mixed ops', mixedOps, options)
  await runBenchmark('large payloads', rwLarge, options)
  await runBenchmark('3000 small payloads', rwSmall, options)
  await runBenchmark('400 medium payloads', rwMedium, options)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
