import { runBenchmark } from './lib/benchmark-runner.js'

import Curve from '../dist/esm/src/primitives/Curve.js'
import BigNumber from '../dist/esm/src/primitives/BigNumber.js'
import * as ECDSA from '../dist/esm/src/primitives/ECDSA.js'

const curve = new Curve()

const scalar = new BigNumber(
  '1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5',
  16
)

const msg = new BigNumber('deadbeefcafebabe', 16)

const priv = new BigNumber(
  '8a2f85e08360a04c8a36b7c22c5e9e9a0d3bcf2f95c97db2b8bd90fc5f5ff66a',
  16
)

const pub = curve.g.mul(priv)

async function main () {
  const options = {
    minSampleMs: 400,
    samples: 8
  }

  await runBenchmark(
    'Point.mul (WNAF)',
    () => {
      curve.g.mul(scalar)
    },
    options
  )

  await runBenchmark(
    'Point.mulCT (constant-time)',
    () => {
      curve.g.mulCT(scalar)
    },
    options
  )

  await runBenchmark(
    'ECDSA.sign',
    () => {
      ECDSA.sign(msg, priv)
    },
    options
  )

  await runBenchmark(
    'ECDSA.verify',
    () => {
      const sig = ECDSA.sign(msg, priv)
      ECDSA.verify(msg, sig, pub)
    },
    options
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
