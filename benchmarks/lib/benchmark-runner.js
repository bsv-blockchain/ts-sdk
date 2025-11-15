import { performance } from 'perf_hooks'

function numberFromEnv (key, fallback) {
  const value = Number(process.env[key])
  return Number.isFinite(value) && value > 0 ? value : fallback
}

const DEFAULTS = {
  warmupIterations: numberFromEnv('BENCH_WARMUP', 2),
  samples: numberFromEnv('BENCH_SAMPLES', 8),
  minSampleMs: numberFromEnv('BENCH_MIN_SAMPLE_MS', 250),
  minIterations: numberFromEnv('BENCH_MIN_ITERATIONS', 1)
}

async function maybeAwait (result) {
  if (result != null && typeof result.then === 'function') {
    await result
  }
}

async function measureSample (fn, minSampleMs, minIterations) {
  let iterations = 0
  let elapsed = 0
  do {
    const start = performance.now()
    await maybeAwait(fn())
    elapsed += performance.now() - start
    iterations++
  } while (elapsed < minSampleMs || iterations < minIterations)

  return {
    average: elapsed / iterations,
    iterations,
    elapsed
  }
}

function computeStats (values) {
  const total = values.reduce((sum, value) => sum + value, 0)
  const average = total / values.length
  const min = Math.min(...values)
  const max = Math.max(...values)
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + Math.pow(value - average, 2), 0) / values.length
    : 0
  return {
    average,
    min,
    max,
    stddev: Math.sqrt(variance),
    samples: values.length
  }
}

function logStats (name, stats, iterations) {
  const avgIterations = iterations.reduce((sum, value) => sum + value, 0) / iterations.length
  console.log(
    `${name}: ${stats.average.toFixed(2)}ms avg (min ${stats.min.toFixed(2)}ms, max ${stats.max.toFixed(2)}ms, ` +
    `±${stats.stddev.toFixed(2)}ms, ~${avgIterations.toFixed(1)} runs/sample)`
  )
}

export async function runBenchmark (name, fn, options = {}) {
  const warmupIterations = Math.max(0, Math.floor(options.warmupIterations ?? DEFAULTS.warmupIterations))
  const samples = Math.max(1, Math.floor(options.samples ?? DEFAULTS.samples))
  const minSampleMs = Math.max(1, options.minSampleMs ?? DEFAULTS.minSampleMs)
  const minIterations = Math.max(1, Math.floor(options.minIterations ?? DEFAULTS.minIterations))

  for (let i = 0; i < warmupIterations; i++) {
    await maybeAwait(fn())
  }

  const sampleValues = []
  const sampleIterations = []
  for (let i = 0; i < samples; i++) {
    const { average, iterations } = await measureSample(fn, minSampleMs, minIterations)
    sampleValues.push(average)
    sampleIterations.push(iterations)
  }

  const stats = computeStats(sampleValues)
  logStats(name, stats, sampleIterations)
  return {
    ...stats,
    sampleIterations
  }
}
