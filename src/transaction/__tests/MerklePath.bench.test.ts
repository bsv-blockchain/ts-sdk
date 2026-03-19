import MerklePath from '../../transaction/MerklePath'

/**
 * Generate a random 32-byte hex hash.
 */
function randomHash (): string {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Build a full-block compound MerklePath with `count` transactions at level 0.
 * All leaves are txid: true; if count is odd the last leaf gets duplicate: true.
 */
function buildFullBlockPath (count: number): { mp: MerklePath, txids: string[] } {
  const txids: string[] = []
  const leaves: Array<{ offset: number, hash?: string, txid?: boolean, duplicate?: boolean }> = []
  for (let i = 0; i < count; i++) {
    const h = randomHash()
    txids.push(h)
    leaves.push({ offset: i, hash: h, txid: true })
  }
  if (count % 2 === 1) {
    leaves.push({ offset: count, duplicate: true })
  }
  const mp = new MerklePath(1, [leaves])
  return { mp, txids }
}

/**
 * Pick `n` random items from `arr` without replacement.
 */
function pickRandom<T> (arr: T[], n: number): T[] {
  const copy = [...arr]
  const result: T[] = []
  for (let i = 0; i < n && copy.length > 0; i++) {
    const idx = Math.floor(Math.random() * copy.length)
    result.push(copy.splice(idx, 1)[0])
  }
  return result
}

describe('MerklePath.extract() benchmarks', () => {
  // Pre-build paths once so construction time is excluded from extract timing.
  let path101: { mp: MerklePath, txids: string[] }
  let path501: { mp: MerklePath, txids: string[] }
  let path999: { mp: MerklePath, txids: string[] }

  beforeAll(() => {
    path101 = buildFullBlockPath(101)
    path501 = buildFullBlockPath(501)
    path999 = buildFullBlockPath(999)
  })

  const runBench = (
    label: string,
    getPath: () => { mp: MerklePath, txids: string[] },
    extractCount: number,
    iterations: number = 5
  ): void => {
    it(label, () => {
      const { mp, txids } = getPath()
      const targets = pickRandom(txids, extractCount)

      const times: number[] = []
      for (let i = 0; i < iterations; i++) {
        const start = performance.now()
        const extracted = mp.extract(targets)
        const elapsed = performance.now() - start
        times.push(elapsed)
        // Correctness check on every iteration
        for (const txid of targets) {
          expect(extracted.computeRoot(txid)).toBe(mp.computeRoot(txid))
        }
      }

      const avg = times.reduce((a, b) => a + b, 0) / times.length
      const min = Math.min(...times)
      const max = Math.max(...times)
      console.log(
        `[${label}] avg=${avg.toFixed(1)}ms  min=${min.toFixed(1)}ms  max=${max.toFixed(1)}ms  (${iterations} runs)`
      )
    })
  }

  // --- 101 txids ---
  runBench('101 txids, extract 1', () => path101, 1)
  runBench('101 txids, extract 5', () => path101, 5)
  runBench('101 txids, extract 10', () => path101, 10)
  runBench('101 txids, extract 50', () => path101, 50)

  // --- 501 txids ---
  runBench('501 txids, extract 1', () => path501, 1)
  runBench('501 txids, extract 5', () => path501, 5)
  runBench('501 txids, extract 10', () => path501, 10)
  runBench('501 txids, extract 50', () => path501, 50)

  // --- 999 txids ---
  runBench('999 txids, extract 1', () => path999, 1)
  runBench('999 txids, extract 5', () => path999, 5)
  runBench('999 txids, extract 10', () => path999, 10)
  runBench('999 txids, extract 50', () => path999, 50)
  runBench('999 txids, extract 100', () => path999, 100, 3)
})
