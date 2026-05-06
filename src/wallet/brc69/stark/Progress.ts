export type StarkProgressEventStatus = 'start' | 'progress' | 'end' | 'error'

export interface StarkProgressEvent {
  phase: string
  status: StarkProgressEventStatus
  metricSegment?: string
  segment?: string
  crossConstraint?: string
  detail?: string
  traceLength?: number
  traceWidth?: number
  ldeSize?: number
  rows?: number
  columns?: number
  row?: number
  column?: number
  layer?: number
  layerSize?: number
  count?: number
  total?: number
  elapsedMs?: number
  error?: string
}

export type StarkProgressCallback = (event: StarkProgressEvent) => void

export function emitStarkProgress (
  progress: StarkProgressCallback | undefined,
  event: StarkProgressEvent
): void {
  progress?.(event)
}

export function withStarkProgressContext (
  progress: StarkProgressCallback | undefined,
  context: Partial<Pick<
  StarkProgressEvent,
  'metricSegment' | 'segment' | 'crossConstraint'
  >>
): StarkProgressCallback | undefined {
  if (progress === undefined) return undefined
  return event => progress({
    ...context,
    ...event,
    metricSegment: event.metricSegment ?? context.metricSegment,
    segment: event.segment ?? context.segment,
    crossConstraint: event.crossConstraint ?? context.crossConstraint
  })
}

export function progressInterval (total: number): number {
  if (!Number.isFinite(total) || total <= 0) return 1
  return Math.max(1, Math.floor(total / 32))
}

export function shouldEmitProgress (
  index: number,
  total: number
): boolean {
  if (total <= 0) return false
  return index === 0 ||
    index === total - 1 ||
    ((index + 1) % progressInterval(total)) === 0
}
