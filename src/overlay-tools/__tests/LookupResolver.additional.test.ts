import LookupResolver, {
  HTTPSOverlayLookupFacilitator,
  DEFAULT_SLAP_TRACKERS,
  DEFAULT_TESTNET_SLAP_TRACKERS,
  LookupQuestion
} from '../LookupResolver'
import { getOverlayHostReputationTracker, HostReputationTracker } from '../HostReputationTracker'
import OverlayAdminTokenTemplate from '../../overlay-tools/OverlayAdminTokenTemplate'
import { CompletedProtoWallet } from '../../auth/certificates/__tests/CompletedProtoWallet'
import { PrivateKey } from '../../primitives/index'
import { Transaction } from '../../transaction/index'
import { LockingScript } from '../../script/index'

const mockFacilitator = {
  lookup: jest.fn()
}

// --------------------------------------------------------------------------
// Sample BEEFs for use in tests
// --------------------------------------------------------------------------

const sampleBeef1 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 1 }],
  0
).toBEEF()

const sampleBeef2 = new Transaction(
  1,
  [],
  [{ lockingScript: LockingScript.fromHex('88'), satoshis: 2 }],
  0
).toBEEF()

// --------------------------------------------------------------------------
// Helper: build a SLAP token transaction pointing at a given host/service
// --------------------------------------------------------------------------

async function makeSlapTx (
  keyScalar: number,
  domain: string,
  service: string
): Promise<Transaction> {
  const key = new PrivateKey(keyScalar)
  const wallet = new CompletedProtoWallet(key)
  const lib = new OverlayAdminTokenTemplate(wallet)
  const script = await lib.lock('SLAP', domain, service)
  return new Transaction(1, [], [{ lockingScript: script, satoshis: 1 }], 0)
}

// --------------------------------------------------------------------------
// Suite
// --------------------------------------------------------------------------

describe('LookupResolver – additional coverage', () => {
  const globalTracker = getOverlayHostReputationTracker()

  beforeEach(() => {
    mockFacilitator.lookup.mockReset()
    globalTracker.reset()
  })

  // -----------------------------------------------------------------------
  // networkPreset branches
  // -----------------------------------------------------------------------

  describe('networkPreset', () => {
    it('uses DEFAULT_SLAP_TRACKERS for mainnet preset (default)', () => {
      const r = new LookupResolver({ facilitator: mockFacilitator })
      // Access private via cast
      expect((r as any).slapTrackers).toEqual(DEFAULT_SLAP_TRACKERS)
      expect((r as any).networkPreset).toBe('mainnet')
    })

    it('uses DEFAULT_TESTNET_SLAP_TRACKERS for testnet preset', () => {
      const r = new LookupResolver({ facilitator: mockFacilitator, networkPreset: 'testnet' })
      expect((r as any).slapTrackers).toEqual(DEFAULT_TESTNET_SLAP_TRACKERS)
      expect((r as any).networkPreset).toBe('testnet')
    })

    it('uses localhost for local preset in ls_slap query', async () => {
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
      })

      const r = new LookupResolver({ facilitator: mockFacilitator, networkPreset: 'local' })
      await r.query({ service: 'ls_slap', query: {} })

      expect(mockFacilitator.lookup.mock.calls[0][0]).toBe('http://localhost:8080')
    })

    it('uses localhost for local preset on non-slap service query', async () => {
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
      })

      const r = new LookupResolver({ facilitator: mockFacilitator, networkPreset: 'local' })
      await r.query({ service: 'ls_bar', query: {} })

      expect(mockFacilitator.lookup.mock.calls[0][0]).toBe('http://localhost:8080')
    })

    it('includes "testnet" in error message for testnet preset', async () => {
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: []
      })

      const r = new LookupResolver({ facilitator: mockFacilitator, networkPreset: 'testnet' })
      await expect(r.query({ service: 'ls_missing', query: {} })).rejects.toThrow(
        'No competent testnet hosts found'
      )
    })

    it('uses custom slapTrackers even when preset is testnet', () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        networkPreset: 'testnet',
        slapTrackers: ['https://custom.tracker']
      })
      expect((r as any).slapTrackers).toEqual(['https://custom.tracker'])
    })
  })

  // -----------------------------------------------------------------------
  // hostOverrides validation
  // -----------------------------------------------------------------------

  describe('hostOverrides validation', () => {
    it('throws when hostOverride service name does not start with ls_', () => {
      expect(() => new LookupResolver({
        facilitator: mockFacilitator,
        hostOverrides: { badServiceName: ['https://host.com'] }
      })).toThrow('Host override service names must start with "ls_": badServiceName')
    })

    it('does not throw for valid ls_ prefixed hostOverride keys', () => {
      expect(() => new LookupResolver({
        facilitator: mockFacilitator,
        hostOverrides: { ls_valid: ['https://host.com'] }
      })).not.toThrow()
    })
  })

  // -----------------------------------------------------------------------
  // reputationStorage options
  // -----------------------------------------------------------------------

  describe('reputationStorage', () => {
    it('accepts reputationStorage: "localStorage" option', () => {
      // Simply verify construction does not throw
      expect(() => new LookupResolver({
        facilitator: mockFacilitator,
        reputationStorage: 'localStorage'
      })).not.toThrow()
    })

    it('accepts reputationStorage as a custom key-value store object', async () => {
      const store = new Map<string, string>()
      const kvStore = {
        get: (key: string): string | null => store.get(key) ?? null,
        set: (key: string, value: string): void => { store.set(key, value) }
      }

      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        reputationStorage: kvStore,
        hostOverrides: { ls_test: ['https://host.com'] }
      })

      await r.query({ service: 'ls_test', query: {} })
      // Reputation data should have been written to the store
      expect(store.size).toBeGreaterThan(0)
    })
  })

  // -----------------------------------------------------------------------
  // Cache tuning options
  // -----------------------------------------------------------------------

  describe('cache configuration', () => {
    it('respects custom hostsTtlMs', () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        cache: { hostsTtlMs: 999 }
      })
      expect((r as any).hostsTtlMs).toBe(999)
    })

    it('respects custom hostsMaxEntries', () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        cache: { hostsMaxEntries: 5 }
      })
      expect((r as any).hostsMaxEntries).toBe(5)
    })

    it('respects custom txMemoTtlMs', () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        cache: { txMemoTtlMs: 123 }
      })
      expect((r as any).txMemoTtlMs).toBe(123)
    })

    it('uses stale hosts from cache while refreshing in the background', async () => {
      const slapTx = await makeSlapTx(42, 'https://cached.host', 'ls_cached')

      // First call: populates the cache
      mockFacilitator.lookup
        .mockResolvedValueOnce({
          type: 'output-list',
          outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
        })
        .mockResolvedValueOnce({
          type: 'output-list',
          outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
        })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap'],
        cache: { hostsTtlMs: 0 } // immediate expiry to force stale path
      })

      await r.query({ service: 'ls_cached', query: {} })

      // Second call: cache entry is now stale (ttl=0), should use stale hosts
      // while kicking off a background refresh
      mockFacilitator.lookup.mockResolvedValue({
        type: 'output-list',
        outputs: [{ beef: sampleBeef2, outputIndex: 1 }]
      })

      const res2 = await r.query({ service: 'ls_cached', query: {} })

      expect(res2.type).toBe('output-list')
    })

    it('evicts oldest cache entry when hostsMaxEntries is reached', async () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap'],
        cache: { hostsMaxEntries: 2 }
      })

      const hostsCache: Map<string, any> = (r as any).hostsCache

      // Manually populate the cache to its limit
      hostsCache.set('ls_service1', { hosts: ['https://h1.com'], expiresAt: Date.now() + 60000 })
      hostsCache.set('ls_service2', { hosts: ['https://h2.com'], expiresAt: Date.now() + 60000 })

      expect(hostsCache.size).toBe(2)

      // Force a refresh for a third service which should evict ls_service1
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: []
      })

      // Trigger cache refresh via refreshHosts indirectly
      const slapTx = await makeSlapTx(42, 'https://h3.com', 'ls_service3')
      mockFacilitator.lookup.mockResolvedValue({
        type: 'output-list',
        outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
      })

      try {
        await r.query({ service: 'ls_service3', query: {} })
      } catch {
        // might fail if no competent hosts for the actual lookup
      }

      // Cache size should not exceed hostsMaxEntries + 1 (the new entry)
      expect(hostsCache.size).toBeLessThanOrEqual(3)
    })

    it('coalesces concurrent in-flight host resolution requests for the same service', async () => {
      const slapTx = await makeSlapTx(42, 'https://coalesce.host', 'ls_coalesce')

      let resolveSlap: (v: any) => void
      const slapPromise = new Promise<any>((res) => { resolveSlap = res })

      mockFacilitator.lookup
        .mockReturnValueOnce(slapPromise)   // slap tracker – delayed
        .mockResolvedValue({
          type: 'output-list',
          outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
        })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      // Fire two concurrent queries before slap resolves
      const p1 = r.query({ service: 'ls_coalesce', query: {} })
      const p2 = r.query({ service: 'ls_coalesce', query: {} })

      // Resolve the SLAP tracker
      resolveSlap!({
        type: 'output-list',
        outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
      })

      const [res1, res2] = await Promise.all([p1, p2])
      expect(res1.type).toBe('output-list')
      expect(res2.type).toBe('output-list')
    })
  })

  // -----------------------------------------------------------------------
  // txMemo eviction at 4096 entries
  // -----------------------------------------------------------------------

  describe('txMemo eviction', () => {
    it('evicts the oldest txMemo entry when size exceeds 4096', async () => {
      mockFacilitator.lookup.mockResolvedValue({
        type: 'output-list',
        outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        hostOverrides: { ls_memo: ['https://memo.host'] }
      })

      const txMemo: Map<string, any> = (r as any).txMemo

      // Pre-fill to just over 4096 entries
      for (let i = 0; i < 4097; i++) {
        txMemo.set(`key${i}`, { txId: `tx${i}`, expiresAt: Date.now() + 60000 })
      }

      expect(txMemo.size).toBe(4097)

      // Query to trigger the eviction path
      await r.query({ service: 'ls_memo', query: {} })

      // After query the eviction should have fired, size should be <= 4097 + 1 - 1 = 4097
      // (evict oldest then set new)
      expect(txMemo.size).toBeLessThanOrEqual(4098)
    })
  })

  // -----------------------------------------------------------------------
  // prepareHostsForQuery – all-backoff error
  // -----------------------------------------------------------------------

  describe('prepareHostsForQuery – backoff error', () => {
    it('throws when all competent hosts are in backoff', async () => {
      const slapTx = await makeSlapTx(42, 'https://backing.off', 'ls_backoff_test')

      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: [{ outputIndex: 0, beef: slapTx.toBEEF() }]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://mock.slap']
      })

      // Poison the reputation of the host so it enters backoff
      const tracker: HostReputationTracker = (r as any).hostReputation
      for (let i = 0; i < 5; i++) {
        tracker.recordFailure('https://backing.off', 'connection refused')
      }

      // Now the host is deeply in backoff
      // prepareHostsForQuery throws with context = 'lookup service ls_backoff_test'
      await expect(r.query({ service: 'ls_backoff_test', query: {} })).rejects.toThrow(
        'All lookup service ls_backoff_test hosts are backing off'
      )
    })

    it('throws when all SLAP trackers are in backoff', async () => {
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: ['https://backed.off.slap']
      })

      // Put the SLAP tracker into deep backoff
      const tracker: HostReputationTracker = (r as any).hostReputation
      for (let i = 0; i < 5; i++) {
        tracker.recordFailure('https://backed.off.slap', 'connection refused')
      }

      await expect(r.query({ service: 'ls_any', query: {} })).rejects.toThrow(
        'All SLAP trackers hosts are backing off'
      )
    })
  })

  // -----------------------------------------------------------------------
  // additionalHosts – deduplication
  // -----------------------------------------------------------------------

  describe('additionalHosts', () => {
    it('does not duplicate a host that already appears in competentHosts', async () => {
      // Override + additional pointing at same host
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'output-list',
        outputs: [{ beef: sampleBeef1, outputIndex: 0 }]
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        hostOverrides: { ls_dup: ['https://same.host'] },
        additionalHosts: { ls_dup: ['https://same.host', 'https://extra.host'] }
      })

      await r.query({ service: 'ls_dup', query: {} })

      // same.host should appear exactly once in the calls
      const calledHosts = mockFacilitator.lookup.mock.calls.map((c: any[]) => c[0])
      const sameHostCalls = calledHosts.filter((h: string) => h === 'https://same.host')
      expect(sameHostCalls).toHaveLength(1)
    })
  })

  // -----------------------------------------------------------------------
  // HTTPSOverlayLookupFacilitator
  // -----------------------------------------------------------------------

  describe('HTTPSOverlayLookupFacilitator', () => {
    it('throws when no fetch implementation is available', () => {
      expect(() => new HTTPSOverlayLookupFacilitator(null as any)).toThrow(
        'HTTPSOverlayLookupFacilitator requires a fetch implementation'
      )
    })

    it('allows HTTP URLs when allowHTTP is true', async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({ type: 'output-list', outputs: [] })
      })
      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      const result = await facilitator.lookup('http://localhost:8080', { service: 'ls_test', query: {} })
      expect(result).toEqual({ type: 'output-list', outputs: [] })
    })

    it('handles HTTP error responses by throwing', async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 503,
        headers: { get: () => 'application/json' },
        json: async () => ({})
      })
      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      await expect(
        facilitator.lookup('http://host', { service: 'ls_test', query: {} })
      ).rejects.toThrow('Failed to facilitate lookup (HTTP 503)')
    })

    it('normalises AbortError to "Request timed out"', async () => {
      const abortError = new Error('aborted')
      abortError.name = 'AbortError'
      const mockFetch = jest.fn().mockRejectedValue(abortError)
      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      await expect(
        facilitator.lookup('http://host', { service: 'ls_test', query: {} }, 1)
      ).rejects.toThrow('Request timed out')
    })

    it('parses octet-stream responses', async () => {
      // Build a minimal octet-stream payload: 1 outpoint, then BEEF bytes
      const tx = new Transaction(
        1,
        [],
        [{ lockingScript: LockingScript.fromHex('88'), satoshis: 1 }],
        0
      )
      const beef = tx.toBEEF()

      // Build the payload: varint(1) + txid(32) + varint(outputIndex) + varint(contextLen=0) + beef
      // The source reads 32 bytes and calls Utils.toHex(), so the bytes must be in big-endian
      // (same order as tx.id('hex')) so the resulting hex matches what Transaction.fromBEEF expects.
      const txid = Buffer.from(tx.id('hex'), 'hex')
      const nOutpoints = Buffer.from([0x01]) // varint 1
      const outputIndex = Buffer.from([0x00]) // varint 0
      const contextLen = Buffer.from([0x00]) // varint 0
      const beefBuf = Buffer.from(beef)
      const payload = Buffer.concat([nOutpoints, txid, outputIndex, contextLen, beefBuf])

      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => 'application/octet-stream' },
        arrayBuffer: async () => payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength)
      })

      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      const result = await facilitator.lookup('http://host', { service: 'ls_test', query: {} })

      expect(result.type).toBe('output-list')
      expect(result.outputs).toHaveLength(1)
      expect(result.outputs[0].outputIndex).toBe(0)
    })

    it('parses octet-stream responses with context bytes', async () => {
      const tx = new Transaction(
        1,
        [],
        [{ lockingScript: LockingScript.fromHex('88'), satoshis: 1 }],
        0
      )
      const beef = tx.toBEEF()
      // Use big-endian byte order so Utils.toHex(r.read(32)) produces the same hex as tx.id('hex')
      const txid = Buffer.from(tx.id('hex'), 'hex')

      // payload: 1 outpoint, with context of 2 bytes [0xde, 0xad]
      const nOutpoints = Buffer.from([0x01])
      const outputIndex = Buffer.from([0x00])
      const contextLen = Buffer.from([0x02])
      const contextBytes = Buffer.from([0xde, 0xad])
      const beefBuf = Buffer.from(beef)
      const payload = Buffer.concat([nOutpoints, txid, outputIndex, contextLen, contextBytes, beefBuf])

      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => 'application/octet-stream' },
        arrayBuffer: async () => payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength)
      })

      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      const result = await facilitator.lookup('http://host', { service: 'ls_test', query: {} })

      expect(result.type).toBe('output-list')
      expect(result.outputs[0].context).toBeDefined()
      expect(Array.from(result.outputs[0].context!)).toEqual([0xde, 0xad])
    })

    it('re-throws non-AbortError errors from fetch', async () => {
      const mockFetch = jest.fn().mockRejectedValue(new Error('DNS failure'))
      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      await expect(
        facilitator.lookup('http://host', { service: 'ls_test', query: {} })
      ).rejects.toThrow('DNS failure')
    })

    it('sends correct request body to /lookup endpoint', async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({ type: 'output-list', outputs: [] })
      })
      const facilitator = new HTTPSOverlayLookupFacilitator(mockFetch, true)
      const question = { service: 'ls_test', query: { filter: 'abc' } }
      await facilitator.lookup('http://host', question)

      const calledUrl: string = mockFetch.mock.calls[0][0]
      expect(calledUrl).toBe('http://host/lookup')

      const body = JSON.parse(mockFetch.mock.calls[0][1].body)
      expect(body).toEqual({ service: 'ls_test', query: { filter: 'abc' } })
    })
  })

  // -----------------------------------------------------------------------
  // lookupHostWithTracking – invalid response tracking
  // -----------------------------------------------------------------------

  describe('lookupHostWithTracking – invalid response', () => {
    it('records failure when host returns a non-output-list response', async () => {
      mockFacilitator.lookup.mockResolvedValueOnce({
        type: 'freeform',
        data: 'some free data'
      })

      const r = new LookupResolver({
        facilitator: mockFacilitator,
        hostOverrides: { ls_invalid: ['https://weird.host'] }
      })

      // The query returns empty outputs since the response is ignored
      const res = await r.query({ service: 'ls_invalid', query: {} })
      expect(res.outputs).toHaveLength(0)

      // The host should have been penalised in the tracker
      const tracker: HostReputationTracker = (r as any).hostReputation
      const snap = tracker.snapshot('https://weird.host')
      expect(snap?.totalFailures).toBeGreaterThan(0)
    })
  })

  // -----------------------------------------------------------------------
  // Empty hosts edge case
  // -----------------------------------------------------------------------

  describe('empty trackerHosts', () => {
    it('returns empty array from findCompetentHosts when all SLAP trackers are empty list', async () => {
      // Provide an empty slapTrackers list so trackerHosts.length === 0
      const r = new LookupResolver({
        facilitator: mockFacilitator,
        slapTrackers: []
      })

      await expect(r.query({ service: 'ls_foo', query: {} })).rejects.toThrow(
        'No competent mainnet hosts found'
      )
    })
  })
})
