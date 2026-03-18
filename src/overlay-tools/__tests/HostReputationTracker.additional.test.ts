import { HostReputationTracker } from '../HostReputationTracker'

// ---- helpers ----------------------------------------------------------------

function makeStore (initial: Record<string, string> = {}): {
  store: Map<string, string>
  get: (key: string) => string | null
  set: (key: string, value: string) => void
} {
  const store = new Map<string, string>(Object.entries(initial))
  return {
    store,
    get: (key: string) => store.get(key) ?? null,
    set: (key: string, value: string) => { store.set(key, value) }
  }
}

// ---- suite ------------------------------------------------------------------

describe('HostReputationTracker – additional coverage', () => {
  // -----------------------------------------------------------------------
  // snapshot
  // -----------------------------------------------------------------------

  describe('snapshot', () => {
    it('returns undefined for an unknown host', () => {
      const t = new HostReputationTracker()
      expect(t.snapshot('https://unknown.host')).toBeUndefined()
    })

    it('returns a copy of the entry for a known host', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://known.host', 100)
      const snap = t.snapshot('https://known.host')
      expect(snap).toBeDefined()
      expect(snap!.host).toBe('https://known.host')
      expect(snap!.totalSuccesses).toBe(1)

      // Verify it is a copy — mutating the snapshot does not affect the tracker
      snap!.totalSuccesses = 999
      const snap2 = t.snapshot('https://known.host')
      expect(snap2!.totalSuccesses).toBe(1)
    })
  })

  // -----------------------------------------------------------------------
  // reset
  // -----------------------------------------------------------------------

  describe('reset', () => {
    it('clears all stats', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://a.com', 50)
      t.recordSuccess('https://b.com', 80)
      t.reset()
      expect(t.snapshot('https://a.com')).toBeUndefined()
      expect(t.snapshot('https://b.com')).toBeUndefined()
    })
  })

  // -----------------------------------------------------------------------
  // recordSuccess – latency EWMA
  // -----------------------------------------------------------------------

  describe('recordSuccess', () => {
    it('sets avgLatencyMs to safeLatency on first success', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', 200)
      const snap = t.snapshot('https://host.com')!
      expect(snap.avgLatencyMs).toBe(200)
      expect(snap.lastLatencyMs).toBe(200)
      expect(snap.totalSuccesses).toBe(1)
      expect(snap.consecutiveFailures).toBe(0)
      expect(snap.backoffUntil).toBe(0)
    })

    it('applies EWMA on subsequent successes', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', 100)
      t.recordSuccess('https://host.com', 500)
      const snap = t.snapshot('https://host.com')!
      // avg = (1 - 0.25) * 100 + 0.25 * 500 = 75 + 125 = 200
      expect(snap.avgLatencyMs).toBeCloseTo(200)
      expect(snap.lastLatencyMs).toBe(500)
    })

    it('treats negative latency as DEFAULT_LATENCY_MS (1500)', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', -1)
      const snap = t.snapshot('https://host.com')!
      expect(snap.avgLatencyMs).toBe(1500)
    })

    it('treats NaN latency as DEFAULT_LATENCY_MS (1500)', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', NaN)
      const snap = t.snapshot('https://host.com')!
      expect(snap.avgLatencyMs).toBe(1500)
    })

    it('treats Infinity latency as DEFAULT_LATENCY_MS (1500)', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', Infinity)
      const snap = t.snapshot('https://host.com')!
      expect(snap.avgLatencyMs).toBe(1500)
    })

    it('clears lastError on success', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'some error')
      t.recordSuccess('https://host.com', 100)
      const snap = t.snapshot('https://host.com')!
      expect(snap.lastError).toBeUndefined()
    })
  })

  // -----------------------------------------------------------------------
  // recordFailure – backoff logic
  // -----------------------------------------------------------------------

  describe('recordFailure', () => {
    it('does not backoff on first two failures (grace period)', () => {
      const t = new HostReputationTracker()
      // FAILURE_BACKOFF_GRACE = 2, so first 2 failures have penaltyLevel 0
      t.recordFailure('https://host.com', 'transient')
      t.recordFailure('https://host.com', 'transient')
      const snap = t.snapshot('https://host.com')!
      expect(snap.backoffUntil).toBe(0)
    })

    it('starts backing off after grace period failures', () => {
      const t = new HostReputationTracker()
      const before = Date.now()
      t.recordFailure('https://host.com', 'e')
      t.recordFailure('https://host.com', 'e')
      t.recordFailure('https://host.com', 'e') // penaltyLevel = 1 => backoff = 1000 ms
      const snap = t.snapshot('https://host.com')!
      expect(snap.backoffUntil).toBeGreaterThan(before)
      expect(snap.backoffUntil).toBeLessThanOrEqual(Date.now() + 1001)
    })

    it('caps backoff at MAX_BACKOFF_MS (60000)', () => {
      const t = new HostReputationTracker()
      // After many failures the backoff should cap at 60000 ms
      for (let i = 0; i < 20; i++) {
        t.recordFailure('https://host.com', 'offline')
      }
      const snap = t.snapshot('https://host.com')!
      const maxBackoff = 60_000
      expect(snap.backoffUntil).toBeLessThanOrEqual(Date.now() + maxBackoff + 10)
    })

    it('sets lastError to string reason', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'timeout')
      const snap = t.snapshot('https://host.com')!
      expect(snap.lastError).toBe('timeout')
    })

    it('sets lastError to Error message', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', new Error('connection refused'))
      const snap = t.snapshot('https://host.com')!
      expect(snap.lastError).toBe('connection refused')
    })

    it('sets lastError to undefined for non-string, non-Error reason', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', { some: 'object' })
      const snap = t.snapshot('https://host.com')!
      expect(snap.lastError).toBeUndefined()
    })

    it('sets lastError to undefined when reason is undefined', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com')
      const snap = t.snapshot('https://host.com')!
      expect(snap.lastError).toBeUndefined()
    })

    // Immediate backoff triggers (ERR_NAME_NOT_RESOLVED, ENOTFOUND, etc.)
    it('immediately escalates consecutiveFailures for ERR_NAME_NOT_RESOLVED', () => {
      const t = new HostReputationTracker()
      // First failure with DNS error should skip grace period
      t.recordFailure('https://host.com', 'ERR_NAME_NOT_RESOLVED: dns error')
      const snap = t.snapshot('https://host.com')!
      // consecutiveFailures should be >= FAILURE_BACKOFF_GRACE + 1 = 3
      expect(snap.consecutiveFailures).toBeGreaterThanOrEqual(3)
      expect(snap.backoffUntil).toBeGreaterThan(0)
    })

    it('immediately escalates consecutiveFailures for ENOTFOUND', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'ENOTFOUND host.invalid')
      const snap = t.snapshot('https://host.com')!
      expect(snap.consecutiveFailures).toBeGreaterThanOrEqual(3)
      expect(snap.backoffUntil).toBeGreaterThan(0)
    })

    it('immediately escalates consecutiveFailures for getaddrinfo errors', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'getaddrinfo ENOTFOUND')
      const snap = t.snapshot('https://host.com')!
      expect(snap.consecutiveFailures).toBeGreaterThanOrEqual(3)
      expect(snap.backoffUntil).toBeGreaterThan(0)
    })

    it('immediately escalates consecutiveFailures for "Failed to fetch"', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'Failed to fetch')
      const snap = t.snapshot('https://host.com')!
      expect(snap.consecutiveFailures).toBeGreaterThanOrEqual(3)
      expect(snap.backoffUntil).toBeGreaterThan(0)
    })

    it('immediately escalates for Error with ENOTFOUND message', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', new Error('ENOTFOUND myhost'))
      const snap = t.snapshot('https://host.com')!
      expect(snap.consecutiveFailures).toBeGreaterThanOrEqual(3)
    })

    it('does NOT immediately escalate when consecutiveFailures already exceeds grace+1', () => {
      const t = new HostReputationTracker()
      // Get into deep failure first
      for (let i = 0; i < 5; i++) t.recordFailure('https://host.com', 'normal')
      const snapBefore = t.snapshot('https://host.com')!
      const cfBefore = snapBefore.consecutiveFailures

      // Now a DNS-type error shouldn't change consecutiveFailures (it's already above threshold)
      t.recordFailure('https://host.com', 'ENOTFOUND deephost')
      const snapAfter = t.snapshot('https://host.com')!
      // consecutive failures should still increment by 1 from the regular path
      expect(snapAfter.consecutiveFailures).toBe(cfBefore + 1)
    })

    it('resets consecutive failures to zero on success after failures', () => {
      const t = new HostReputationTracker()
      t.recordFailure('https://host.com', 'err')
      t.recordFailure('https://host.com', 'err')
      t.recordFailure('https://host.com', 'err')
      t.recordSuccess('https://host.com', 50)
      const snap = t.snapshot('https://host.com')!
      expect(snap.consecutiveFailures).toBe(0)
      expect(snap.backoffUntil).toBe(0)
    })
  })

  // -----------------------------------------------------------------------
  // rankHosts
  // -----------------------------------------------------------------------

  describe('rankHosts', () => {
    it('returns empty array for empty input', () => {
      const t = new HostReputationTracker()
      expect(t.rankHosts([])).toEqual([])
    })

    it('deduplicates hosts keeping first occurrence order', () => {
      const t = new HostReputationTracker()
      const ranked = t.rankHosts([
        'https://a.com',
        'https://b.com',
        'https://a.com',  // duplicate
        'https://c.com'
      ])
      const hosts = ranked.map(r => r.host)
      expect(hosts.filter(h => h === 'https://a.com')).toHaveLength(1)
      expect(hosts).toHaveLength(3)
    })

    it('ignores empty string and non-string entries', () => {
      const t = new HostReputationTracker()
      const ranked = t.rankHosts([
        'https://valid.com',
        '',                       // empty string – skipped
        'https://also.valid.com'
      ])
      const hosts = ranked.map(r => r.host)
      expect(hosts).not.toContain('')
      expect(hosts).toHaveLength(2)
    })

    it('sorts hosts in backoff to the end', () => {
      const t = new HostReputationTracker()
      // Put https://bad.com in backoff
      for (let i = 0; i < 5; i++) t.recordFailure('https://bad.com', 'err')
      t.recordSuccess('https://good.com', 50)

      const ranked = t.rankHosts(['https://bad.com', 'https://good.com'])
      expect(ranked[0].host).toBe('https://good.com')
      expect(ranked[1].host).toBe('https://bad.com')
    })

    it('sorts by score (lower is better) when no backoff', () => {
      const t = new HostReputationTracker()
      // high latency host
      for (let i = 0; i < 3; i++) t.recordSuccess('https://slow.com', 3000)
      // low latency host
      for (let i = 0; i < 3; i++) t.recordSuccess('https://fast.com', 50)

      const ranked = t.rankHosts(['https://slow.com', 'https://fast.com'])
      expect(ranked[0].host).toBe('https://fast.com')
    })

    it('prefers host with more successes when score is equal', () => {
      const t = new HostReputationTracker()
      // Same latency
      t.recordSuccess('https://few.com', 100)
      for (let i = 0; i < 5; i++) t.recordSuccess('https://many.com', 100)

      const ranked = t.rankHosts(['https://few.com', 'https://many.com'])
      expect(ranked[0].host).toBe('https://many.com')
    })

    it('preserves original insertion order for hosts with identical scores and successes', () => {
      const t = new HostReputationTracker()
      // Brand new hosts with no history – equal scores
      const ranked = t.rankHosts(['https://first.com', 'https://second.com', 'https://third.com'])
      const hosts = ranked.map(r => r.host)
      expect(hosts).toEqual(['https://first.com', 'https://second.com', 'https://third.com'])
    })

    it('includes score field in returned entries', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://host.com', 200)
      const ranked = t.rankHosts(['https://host.com'])
      expect(typeof ranked[0].score).toBe('number')
    })
  })

  // -----------------------------------------------------------------------
  // computeScore
  // -----------------------------------------------------------------------

  describe('computeScore (via rankHosts)', () => {
    it('caps successBonus at latency/2', () => {
      const t = new HostReputationTracker()
      // Many successes with very low latency
      for (let i = 0; i < 1000; i++) t.recordSuccess('https://host.com', 10)
      const ranked = t.rankHosts(['https://host.com'])
      // score should be >= 0 (bonus capped at latency/2)
      expect(ranked[0].score).toBeGreaterThanOrEqual(0)
    })

    it('adds backoff penalty when host is in backoff', () => {
      const t = new HostReputationTracker()
      const before = Date.now()

      t.recordSuccess('https://host.com', 100) // baseline
      const normalScore = t.rankHosts(['https://host.com'])[0].score

      // Force backoff
      for (let i = 0; i < 5; i++) t.recordFailure('https://host.com', 'err')
      const backedOffScore = t.rankHosts(['https://host.com'])[0].score

      expect(backedOffScore).toBeGreaterThan(normalScore)
    })
  })

  // -----------------------------------------------------------------------
  // Storage – loadFromStorage / saveToStorage
  // -----------------------------------------------------------------------

  describe('storage', () => {
    it('persists and restores data via a custom store', () => {
      const kv = makeStore()
      const t1 = new HostReputationTracker(kv)
      t1.recordSuccess('https://persist.com', 200)
      t1.recordFailure('https://persist.com', 'oops')

      // A new tracker with the same store should load the persisted data
      const t2 = new HostReputationTracker(kv)
      const snap = t2.snapshot('https://persist.com')
      expect(snap).toBeDefined()
      expect(snap!.totalSuccesses).toBe(1)
      expect(snap!.totalFailures).toBe(1)
    })

    it('handles corrupt JSON in storage gracefully', () => {
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: 'not-json{' })
      expect(() => new HostReputationTracker(kv)).not.toThrow()
    })

    it('handles non-object JSON in storage gracefully', () => {
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: '"just a string"' })
      expect(() => new HostReputationTracker(kv)).not.toThrow()
    })

    it('handles null JSON value in storage gracefully', () => {
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: 'null' })
      expect(() => new HostReputationTracker(kv)).not.toThrow()
    })

    it('handles empty string storage gracefully (no-op)', () => {
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: '' })
      expect(() => new HostReputationTracker(kv)).not.toThrow()
    })

    it('handles storage entries with missing fields by defaulting them', () => {
      const partial = JSON.stringify({
        'https://partial.com': {
          host: 'https://partial.com'
          // missing all numeric fields
        }
      })
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: partial })
      const t = new HostReputationTracker(kv)
      const snap = t.snapshot('https://partial.com')
      expect(snap).toBeDefined()
      expect(snap!.totalSuccesses).toBe(0)
      expect(snap!.totalFailures).toBe(0)
      expect(snap!.avgLatencyMs).toBeNull()
    })

    it('handles avgLatencyMs: null in stored data', () => {
      const data = JSON.stringify({
        'https://host.com': {
          host: 'https://host.com',
          totalSuccesses: 0,
          totalFailures: 0,
          consecutiveFailures: 0,
          avgLatencyMs: null,
          lastLatencyMs: null,
          backoffUntil: 0,
          lastUpdatedAt: 0
        }
      })
      const kv = makeStore({ bsvsdk_overlay_host_reputation_v1: data })
      const t = new HostReputationTracker(kv)
      const snap = t.snapshot('https://host.com')
      expect(snap!.avgLatencyMs).toBeNull()
      expect(snap!.lastLatencyMs).toBeNull()
    })

    it('handles storage.get throwing by returning undefined', () => {
      const kv = {
        get: (_key: string): string | null => { throw new Error('get error') },
        set: (_key: string, _value: string): void => {}
      }
      // Should not throw during construction
      expect(() => new HostReputationTracker(kv)).not.toThrow()
    })

    it('handles storage.set throwing gracefully', () => {
      const kv = {
        get: (_key: string): null => null,
        set: (_key: string, _value: string): void => { throw new Error('set error') }
      }
      const t = new HostReputationTracker(kv)
      // Should not throw when saving
      expect(() => t.recordSuccess('https://host.com', 100)).not.toThrow()
    })

    it('constructs without store when no store is provided and no localStorage', () => {
      // In Jest/Node environment, globalThis.localStorage is not defined
      const t = new HostReputationTracker(undefined)
      expect(t).toBeInstanceOf(HostReputationTracker)
      // Should work without persistence
      t.recordSuccess('https://no-storage.com', 100)
      expect(t.snapshot('https://no-storage.com')).toBeDefined()
    })
  })

  // -----------------------------------------------------------------------
  // localStorage adapter (via mock globalThis)
  // -----------------------------------------------------------------------

  describe('localStorage adapter', () => {
    let originalLocalStorage: any

    beforeEach(() => {
      originalLocalStorage = (globalThis as any).localStorage
    })

    afterEach(() => {
      if (originalLocalStorage === undefined) {
        delete (globalThis as any).localStorage
      } else {
        (globalThis as any).localStorage = originalLocalStorage
      }
    })

    it('uses globalThis.localStorage when available', () => {
      const mockStore = new Map<string, string>()
      ;(globalThis as any).localStorage = {
        getItem: (key: string): string | null => mockStore.get(key) ?? null,
        setItem: (key: string, value: string): void => { mockStore.set(key, value) }
      }

      const t = new HostReputationTracker()
      t.recordSuccess('https://ls-test.com', 300)

      // Data should have been persisted to the mock localStorage
      expect(mockStore.has('bsvsdk_overlay_host_reputation_v1')).toBe(true)
      const stored = JSON.parse(mockStore.get('bsvsdk_overlay_host_reputation_v1')!)
      expect(stored['https://ls-test.com']).toBeDefined()
    })

    it('handles localStorage.getItem throwing', () => {
      ;(globalThis as any).localStorage = {
        getItem: (_key: string): never => { throw new Error('security error') },
        setItem: (_key: string, _value: string): void => {}
      }

      // Construction should not throw even if getItem throws
      expect(() => new HostReputationTracker()).not.toThrow()
    })

    it('handles localStorage.setItem throwing', () => {
      ;(globalThis as any).localStorage = {
        getItem: (_key: string): null => null,
        setItem: (_key: string, _value: string): never => { throw new Error('quota exceeded') }
      }

      const t = new HostReputationTracker()
      expect(() => t.recordSuccess('https://ls-quota.com', 100)).not.toThrow()
    })
  })

  // -----------------------------------------------------------------------
  // Integration: multiple calls
  // -----------------------------------------------------------------------

  describe('integration', () => {
    it('tracks multiple hosts independently', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://alpha.com', 100)
      t.recordSuccess('https://alpha.com', 150)
      t.recordFailure('https://beta.com', 'timeout')
      t.recordFailure('https://beta.com', 'timeout')
      t.recordFailure('https://beta.com', 'timeout')

      const alpha = t.snapshot('https://alpha.com')!
      const beta = t.snapshot('https://beta.com')!

      expect(alpha.totalSuccesses).toBe(2)
      expect(alpha.totalFailures).toBe(0)
      expect(beta.totalSuccesses).toBe(0)
      expect(beta.totalFailures).toBe(3)
      expect(beta.backoffUntil).toBeGreaterThan(0)
    })

    it('returns correct ranking with mixed host states', () => {
      const t = new HostReputationTracker()
      t.recordSuccess('https://mid.com', 500)
      t.recordSuccess('https://fast.com', 50)
      for (let i = 0; i < 4; i++) t.recordFailure('https://down.com', 'err')

      const ranked = t.rankHosts([
        'https://down.com',
        'https://mid.com',
        'https://fast.com'
      ])

      // fast should come first, down should be last (in backoff)
      expect(ranked[0].host).toBe('https://fast.com')
      expect(ranked[ranked.length - 1].host).toBe('https://down.com')
    })
  })
})
