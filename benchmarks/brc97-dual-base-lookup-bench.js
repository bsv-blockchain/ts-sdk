import {
  estimateDualBaseLookupMetricsCase,
  runDualBaseLookupMetricsSweep,
  scalarMultiply
} from '../dist/esm/src/wallet/brc97/index.js'

function ascii (value) {
  return Array.from(value, char => char.charCodeAt(0))
}

function printResult (result) {
  console.log(`${result.name}: ${JSON.stringify({
    estimatedOnly: result.estimatedOnly,
    windowBits: result.windowBits,
    windowCount: result.windowCount,
    tableRows: result.tableRows,
    selectedRows: result.selectedRows,
    activeRows: result.activeRows,
    paddedRows: result.paddedRows,
    traceWidth: result.traceWidth,
    lookupRows: result.lookupRows,
    overheadRowsPerLookup: result.overheadRowsPerLookup,
    proofBytes: result.proofBytes,
    proofBytesPerLookup: result.proofBytesPerLookup,
    buildMs: result.buildMs,
    proveMs: result.proveMs,
    verifyMs: result.verifyMs,
    verified: result.verified
  })}`)
}

async function main () {
  const baseB = scalarMultiply(11n)
  const scalar = 0x1f8n

  console.log('default-shape:', JSON.stringify(
    estimateDualBaseLookupMetricsCase('radix-11-default')
  ))

  const results = runDualBaseLookupMetricsSweep({
    prove: true,
    maxProveTableRows: Number(process.env.BRC97_LOOKUP_MAX_PROVE_TABLE_ROWS ?? 4096),
    proofOptions: { maskSeed: ascii('brc97-dual-base-lookup-bench-mask') },
    cases: [
      {
        name: 'radix-4-windows-4',
        scalar,
        baseB,
        parameters: { windowBits: 4, windowCount: 4, minTraceLength: 128 }
      },
      {
        name: 'radix-5-windows-5',
        scalar,
        baseB,
        parameters: { windowBits: 5, windowCount: 5, minTraceLength: 256 }
      },
      {
        name: 'radix-6-windows-6',
        scalar,
        baseB,
        parameters: { windowBits: 6, windowCount: 6, minTraceLength: 512 }
      },
      {
        name: 'radix-11-default',
        scalar,
        baseB
      }
    ]
  })

  for (const result of results) printResult(result)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
