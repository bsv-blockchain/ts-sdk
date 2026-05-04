import {
  buildMethod2V2Trace,
  buildMethod2V2FieldMulTrace,
  compressPoint,
  computeInvoiceNumber,
  hmacSha256,
  method2V2FieldMulMetrics,
  method2V2Metrics,
  proveMethod2V2FieldMul,
  scalarMultiply
} from '../dist/esm/src/wallet/brc97/index.js'
import { runBenchmark } from './lib/benchmark-runner.js'

function ascii (value) {
  return Array.from(value, char => char.charCodeAt(0))
}

function statementCase (protocolName, keyID) {
  const scalar = 7n
  const counterpartyScalar = 11n
  const protocolID = [0, protocolName]
  const invoice = ascii(computeInvoiceNumber(protocolID, keyID))
  const publicA = scalarMultiply(scalar)
  const counterpartyB = scalarMultiply(counterpartyScalar)
  const shared = scalarMultiply(scalar, counterpartyB)
  const linkage = hmacSha256(compressPoint(shared), invoice)
  return {
    scalar,
    publicA,
    counterpartyB,
    invoice,
    linkage
  }
}

function buildAndReport (name, fixture) {
  const start = performance.now()
  const trace = buildMethod2V2Trace(
    fixture.scalar,
    fixture.publicA,
    fixture.counterpartyB,
    fixture.invoice,
    fixture.linkage
  )
  const elapsed = performance.now() - start
  const metrics = method2V2Metrics(trace)
  console.log(`${name}: ${JSON.stringify({
    ...metrics,
    buildMs: Number(elapsed.toFixed(2))
  })}`)
}

function fieldMulAndReport () {
  const a = scalarMultiply(7n).x
  const b = scalarMultiply(11n).x
  const trace = buildMethod2V2FieldMulTrace(a, b)
  const start = performance.now()
  const proof = proveMethod2V2FieldMul(trace, {
    blowupFactor: 4,
    numQueries: 4,
    maxRemainderSize: 16,
    maskDegree: 1,
    cosetOffset: 3n,
    maskSeed: ascii('method2-v2-field-mul-mask')
  })
  const elapsed = performance.now() - start
  console.log(`fieldMul: ${JSON.stringify({
    ...method2V2FieldMulMetrics(proof),
    proveMs: Number(elapsed.toFixed(2))
  })}`)
}

async function main () {
  const typical = statementCase('testprotocol', 'key-1')
  const ordinaryMax = statementCase('a'.repeat(400), 'k'.repeat(800))
  const absoluteMax = statementCase(
    `specific linkage revelation ${'a'.repeat(402)}`,
    'k'.repeat(800)
  )

  await runBenchmark('Method2 V2 trace typical invoice', () => {
    buildAndReport('typical', typical)
  }, { samples: 3, minSampleMs: 100, warmupIterations: 1 })

  await runBenchmark('Method2 V2 trace ordinary max invoice', () => {
    buildAndReport('ordinaryMax', ordinaryMax)
  }, { samples: 3, minSampleMs: 100, warmupIterations: 1 })

  await runBenchmark('Method2 V2 trace absolute max invoice', () => {
    buildAndReport('absoluteMax', absoluteMax)
  }, { samples: 3, minSampleMs: 100, warmupIterations: 1 })

  await runBenchmark('Method2 V2 field mul proof', () => {
    fieldMulAndReport()
  }, { samples: 3, minSampleMs: 100, warmupIterations: 1 })
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
