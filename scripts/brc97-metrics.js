#!/usr/bin/env node
import { execFileSync } from 'child_process'
import { cpus } from 'os'
import { writeFile } from 'fs/promises'
import {
  appendFileSync,
  mkdirSync,
  writeFileSync
} from 'fs'
import path from 'path'
import {
  assertBRC97ActualSegmentsVerified,
  assertBRC97ProductionAcceptanceGate,
  collectBRC97ProductionMetrics,
  formatBRC97ProductionMetrics
} from '../dist/esm/src/wallet/brc97/index.js'

function parseArgs () {
  const args = process.argv.slice(2)
  const options = {
    mode: 'full',
    json: null,
    markdown: null,
    progressJsonl: null,
    partialJson: null,
    proofJson: null,
    diagnosticJson: null,
    progress: true,
    sampleColumns: undefined,
    maxSampleTraceLength: undefined,
    prove: undefined,
    proveSegments: false,
    proveEc: undefined
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--fast') {
      options.mode = 'fast'
      options.prove = false
    } else if (arg === '--no-prove') {
      options.prove = false
    } else if (arg === '--prove') {
      options.prove = true
    } else if (arg === '--segments') {
      options.proveSegments = true
    } else if (arg === '--prove-ec') {
      options.proveEc = true
    } else if (arg === '--proof-json' && args[i + 1] != null) {
      options.proofJson = path.resolve(args[++i])
    } else if (arg === '--diagnostic-json' && args[i + 1] != null) {
      options.diagnosticJson = path.resolve(args[++i])
    } else if (arg === '--json' && args[i + 1] != null) {
      options.json = path.resolve(args[++i])
    } else if (arg === '--markdown' && args[i + 1] != null) {
      options.markdown = path.resolve(args[++i])
    } else if (arg === '--progress-jsonl' && args[i + 1] != null) {
      options.progressJsonl = path.resolve(args[++i])
    } else if (arg === '--partial-json' && args[i + 1] != null) {
      options.partialJson = path.resolve(args[++i])
    } else if (arg === '--no-progress') {
      options.progress = false
    } else if (arg === '--sample-columns' && args[i + 1] != null) {
      options.sampleColumns = Number(args[++i])
    } else if (arg === '--max-sample-trace-length' && args[i + 1] != null) {
      options.maxSampleTraceLength = Number(args[++i])
    }
  }

  return options
}

function gitCommit () {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim()
  } catch {
    return undefined
  }
}

async function main () {
  const options = parseArgs()
  const progressPaths = resolveProgressPaths(options)
  const progress = options.progress === false
    ? undefined
    : createProgressRecorder(options, progressPaths)
  progress?.({
    phase: 'brc97.metrics.cli',
    status: 'start',
    detail: 'starting BRC97 production metrics command'
  })
  const report = collectBRC97ProductionMetrics({
    mode: options.mode,
    prove: options.prove,
    proveSegments: options.proveSegments,
    proveEc: options.proveEc,
    sampleColumns: options.sampleColumns,
    maxSampleTraceLength: options.maxSampleTraceLength,
    gitCommit: gitCommit(),
    cpuCount: cpus().length,
    progress,
    onWholeStatementProof: artifact => {
      if (progressPaths.proofJson != null) {
        writeJsonFile(progressPaths.proofJson, artifact)
      }
      if (progressPaths.diagnosticJson != null) {
        writeJsonFile(progressPaths.diagnosticJson, artifact.diagnostic)
      }
    }
  })
  progress?.({
    phase: 'brc97.metrics.cli.report-format',
    status: 'start'
  })
  const markdown = formatBRC97ProductionMetrics(report)
  const json = JSON.stringify(report, bigintJson, 2)

  if (options.markdown != null) await writeFile(options.markdown, markdown)
  if (options.json != null) await writeFile(options.json, json)
  progress?.({
    phase: 'brc97.metrics.cli.report-format',
    status: 'end'
  })

  if (options.markdown == null && options.json == null) {
    process.stdout.write(`${markdown}\n\n`)
    process.stdout.write('```json\n')
    process.stdout.write(json)
    process.stdout.write('\n```\n')
  }

  assertBRC97ActualSegmentsVerified(report)
  if (options.mode === 'full' && options.prove !== false) {
    assertBRC97ProductionAcceptanceGate(report)
  }
  progress?.({
    phase: 'brc97.metrics.cli',
    status: 'end',
    detail: 'completed BRC97 production metrics command'
  })
  writePartial(progressPaths.partialJson, {
    status: 'completed',
    updatedAt: new Date().toISOString(),
    eventCount: progress?.state?.eventCount,
    latestEvent: progress?.state?.latestEvent,
    artifacts: progressPaths,
    report: {
      json: options.json,
      markdown: options.markdown
    }
  })
}

function bigintJson (_key, value) {
  return typeof value === 'bigint' ? value.toString() : value
}

main().catch(err => {
  const options = parseArgs()
  const progressPaths = resolveProgressPaths(options)
  if (options.progress !== false) {
    writePartial(progressPaths.partialJson, {
      status: 'error',
      updatedAt: new Date().toISOString(),
      artifacts: progressPaths,
      error: err instanceof Error ? err.message : String(err)
    })
  }
  console.error(err)
  process.exit(1)
})

function resolveProgressPaths (options) {
  const base = options.json ?? options.markdown
  return {
    progressJsonl: options.progressJsonl ??
      (base == null ? null : sidecarPath(base, 'progress.jsonl')),
    partialJson: options.partialJson ??
      (base == null ? null : sidecarPath(base, 'partial.json')),
    proofJson: options.proofJson ??
      (base == null ? null : sidecarPath(base, 'whole-proof.json')),
    diagnosticJson: options.diagnosticJson ??
      (base == null ? null : sidecarPath(base, 'diagnostic.json'))
  }
}

function sidecarPath (target, suffix) {
  const parsed = path.parse(target)
  const baseName = parsed.ext === ''
    ? parsed.base
    : parsed.base.slice(0, -parsed.ext.length)
  return path.join(parsed.dir, `${baseName}.${suffix}`)
}

function createProgressRecorder (options, paths) {
  if (paths.progressJsonl == null && paths.partialJson == null) return undefined
  const startedAtMs = Date.now()
  const startedAt = new Date(startedAtMs).toISOString()
  const state = {
    eventCount: 0,
    latestEvent: undefined
  }
  if (paths.progressJsonl != null) {
    mkdirSync(path.dirname(paths.progressJsonl), { recursive: true })
    writeFileSync(paths.progressJsonl, '')
  }
  if (paths.partialJson != null) {
    mkdirSync(path.dirname(paths.partialJson), { recursive: true })
    writePartial(paths.partialJson, {
      status: 'running',
      startedAt,
      updatedAt: startedAt,
      eventCount: state.eventCount,
      artifacts: paths,
      command: {
        mode: options.mode,
        json: options.json,
        markdown: options.markdown
      }
    })
  }

  const record = event => {
    state.eventCount++
    state.latestEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      elapsedMs: Date.now() - startedAtMs,
      memory: process.memoryUsage()
    }
    if (paths.progressJsonl != null) {
      appendFileSync(
        paths.progressJsonl,
        `${JSON.stringify(state.latestEvent, bigintJson)}\n`
      )
    }
    if (paths.partialJson != null) {
      writePartial(paths.partialJson, {
        status: 'running',
        startedAt,
        updatedAt: state.latestEvent.timestamp,
        eventCount: state.eventCount,
        latestEvent: state.latestEvent,
        artifacts: paths,
        command: {
          mode: options.mode,
          json: options.json,
          markdown: options.markdown
        }
      })
    }
    if (event.status !== 'progress') {
      const label = [
        `${Math.round(state.latestEvent.elapsedMs / 1000)}s`,
        event.status,
        event.metricSegment,
        event.segment,
        event.crossConstraint,
        event.phase
      ].filter(Boolean).join(' ')
      console.error(`[brc97:metrics] ${label}`)
    }
  }
  record.state = state
  return record
}

function writePartial (filePath, payload) {
  if (filePath == null) return
  mkdirSync(path.dirname(filePath), { recursive: true })
  writeFileSync(filePath, JSON.stringify(payload, bigintJson, 2))
}

function writeJsonFile (filePath, payload) {
  mkdirSync(path.dirname(filePath), { recursive: true })
  writeFileSync(filePath, JSON.stringify(payload, bigintJson, 2))
}
