import ARC from '../../../transaction/broadcasters/ARC'
import Transaction from '../../../transaction/Transaction'
import { FetchHttpClient } from '../../../transaction/http/FetchHttpClient'
import { NodejsHttpClient } from '../../../transaction/http/NodejsHttpClient'
import { HttpClientRequestOptions } from '../../http'
import { RequestOptions } from 'https'

// Mock Transaction
jest.mock('../../../transaction/Transaction', () => {
  class MockTransaction {
    toHex (): string {
      return 'mocked_transaction_hex'
    }

    toHexEF (): string {
      return 'mocked_transaction_hexEF'
    }
  }
  return { __esModule: true, default: MockTransaction }
})

// ---- helpers ----------------------------------------------------------------

function mockedFetch (response: { status: number, data: any }): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    statusText: response.status === 200 ? 'OK' : 'Bad request',
    headers: {
      get: (key: string): string | undefined => {
        if (key === 'Content-Type') return 'application/json; charset=UTF-8'
        return undefined
      }
    },
    json: async () => response.data
  })
}

function mockedHttps (response: { status: number, data: any }): {
  request: (
    url: string,
    options: RequestOptions,
    callback: (res: {
      statusCode: number
      statusMessage: string
      headers: { 'content-type': string }
      on: (event: string, handler: (chunk?: any) => void) => void
    }) => void
  ) => { on: jest.Mock, write: jest.Mock, end: jest.Mock }
} {
  const https = {
    request: (
      url: string,
      options: RequestOptions,
      callback: (res: any) => void
    ) => {
      const mockResponse = {
        statusCode: response.status,
        statusMessage: response.status === 200 ? 'OK' : 'Bad request',
        headers: { 'content-type': 'application/json; charset=UTF-8' },
        on (event: string, handler: (chunk?: any) => void) {
          if (event === 'data') handler(JSON.stringify(response.data))
          if (event === 'end') handler()
        }
      }
      process.nextTick(() => callback(mockResponse))
      return { on: jest.fn(), write: jest.fn(), end: jest.fn() }
    }
  }
  jest.mock('https', () => https)
  return https
}

// ---- suite ------------------------------------------------------------------

describe('ARC Broadcaster – additional coverage', () => {
  const URL = 'https://arc.example.com'
  let transaction: Transaction

  beforeEach(() => {
    transaction = new Transaction()
  })

  // --------------------------------------------------------------------------
  // Constructor branches
  // --------------------------------------------------------------------------

  describe('constructor', () => {
    it('sets callbackUrl and callbackToken on headers when provided via config', async () => {
      const mockFetch = mockedFetch({ status: 200, data: { txid: 'abc', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' } })
      const broadcaster = new ARC(URL, {
        callbackUrl: 'https://my.callback.url',
        callbackToken: 'my-secret-token',
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcast(transaction)

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers['X-CallbackUrl']).toBe('https://my.callback.url')
      expect(headers['X-CallbackToken']).toBe('my-secret-token')
    })

    it('does not add X-CallbackUrl header when callbackUrl is empty string', async () => {
      const mockFetch = mockedFetch({ status: 200, data: { txid: 'abc', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' } })
      const broadcaster = new ARC(URL, {
        callbackUrl: '',
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcast(transaction)

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers['X-CallbackUrl']).toBeUndefined()
    })

    it('does not add X-CallbackToken header when callbackToken is empty string', async () => {
      const mockFetch = mockedFetch({ status: 200, data: { txid: 'abc', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' } })
      const broadcaster = new ARC(URL, {
        callbackToken: '',
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcast(transaction)

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers['X-CallbackToken']).toBeUndefined()
    })

    it('merges custom headers into request headers', async () => {
      const mockFetch = mockedFetch({ status: 200, data: { txid: 'abc', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' } })
      const broadcaster = new ARC(URL, {
        headers: { 'X-Custom-Header': 'custom-value', 'X-Another': 'another' },
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcast(transaction)

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers['X-Custom-Header']).toBe('custom-value')
      expect(headers['X-Another']).toBe('another')
      // Standard headers still present
      expect(headers['Content-Type']).toBe('application/json')
    })

    it('does not add Authorization header when apiKey is empty string', async () => {
      const mockFetch = mockedFetch({ status: 200, data: { txid: 'abc', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' } })
      const broadcaster = new ARC(URL, {
        apiKey: '',
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcast(transaction)

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers.Authorization).toBeUndefined()
    })

    it('accepts config with no httpClient (uses default)', () => {
      // Just verify construction does not throw
      expect(() => new ARC(URL, {})).not.toThrow()
    })
  })

  // --------------------------------------------------------------------------
  // broadcast – error txStatus branches
  // --------------------------------------------------------------------------

  describe('broadcast – HTTP 200 error statuses', () => {
    it('returns error for INVALID txStatus', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'txid1', txStatus: 'INVALID', extraInfo: 'script error' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('INVALID')
        expect(response.description).toContain('INVALID')
        expect(response.description).toContain('script error')
        expect(response.txid).toBe('txid1')
        expect(response.more).toBeUndefined()
      }
    })

    it('returns error for MALFORMED txStatus', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'txid2', txStatus: 'MALFORMED', extraInfo: 'bad format' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('MALFORMED')
      }
    })

    it('returns error for MINED_IN_STALE_BLOCK txStatus', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'txid3', txStatus: 'MINED_IN_STALE_BLOCK', extraInfo: '' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('MINED_IN_STALE_BLOCK')
      }
    })

    it('returns error when txStatus itself contains ORPHAN', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'orphanTxid', txStatus: 'SEEN_IN_ORPHAN_MEMPOOL', extraInfo: '' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('SEEN_IN_ORPHAN_MEMPOOL')
        expect(response.txid).toBe('orphanTxid')
      }
    })

    it('includes competingTxs in failure when present on error txStatus', async () => {
      const competingTxs = ['competingTx1', 'competingTx2']
      const mockFetch = mockedFetch({
        status: 200,
        data: {
          txid: 'txid4',
          txStatus: 'REJECTED',
          extraInfo: '',
          competingTxs
        }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.more).toEqual({ competingTxs })
      }
    })

    it('includes competingTxs on successful broadcast when present', async () => {
      const competingTxs = ['competingTx1']
      const mockFetch = mockedFetch({
        status: 200,
        data: {
          txid: 'successTxid',
          txStatus: 'SEEN_ON_NETWORK',
          extraInfo: 'ok',
          competingTxs
        }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('success')
      if (response.status === 'success') {
        expect(response.competingTxs).toEqual(competingTxs)
        expect(response.txid).toBe('successTxid')
      }
    })

    it('handles missing txStatus and extraInfo on successful response', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'minimalTxid' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      // No txStatus means no error status match – should succeed
      expect(response.status).toBe('success')
      if (response.status === 'success') {
        expect(response.txid).toBe('minimalTxid')
        // message should be 'undefined undefined' trimmed or similar
        expect(typeof response.message).toBe('string')
      }
    })
  })

  // --------------------------------------------------------------------------
  // broadcast – non-ok HTTP responses
  // --------------------------------------------------------------------------

  describe('broadcast – non-ok HTTP responses', () => {
    it('handles non-ok response with object data containing txid and detail', async () => {
      const mockFetch = mockedFetch({
        status: 422,
        data: {
          txid: 'failedTxid',
          detail: 'Unprocessable entity'
        }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('422')
        expect(response.txid).toBe('failedTxid')
        expect(response.description).toBe('Unprocessable entity')
        expect(response.more).toEqual({ txid: 'failedTxid', detail: 'Unprocessable entity' })
      }
    })

    it('handles non-ok response with object data but no txid or detail', async () => {
      const mockFetch = mockedFetch({
        status: 500,
        data: { someOtherField: 'value' }
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('500')
        expect(response.description).toBe('Unknown error')
        expect(response.more).toEqual({ someOtherField: 'value' })
        expect(response.txid).toBeUndefined()
      }
    })

    it('handles non-ok response with null data', async () => {
      const mockFetch = mockedFetch({ status: 503, data: null })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('503')
        expect(response.description).toBe('Unknown error')
      }
    })

    it('handles non-ok response with string data that is valid JSON', async () => {
      const mockFetch = mockedFetch({
        status: 400,
        data: JSON.stringify({ detail: 'parsed from string', txid: 'parsedTxid' })
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.description).toBe('parsed from string')
        expect(response.txid).toBe('parsedTxid')
      }
    })

    it('handles non-ok response with string data that is invalid JSON', async () => {
      const mockFetch = mockedFetch({
        status: 400,
        data: 'not-valid-json-{'
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      // Should remain as 'Unknown error' since JSON parse fails
      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('400')
        expect(response.description).toBe('Unknown error')
      }
    })

    it('handles non-ok response where status type is neither number nor string', async () => {
      // Craft a special mock that returns a non-string, non-number status
      const mockFetch = jest.fn().mockResolvedValue({
        ok: false,
        status: undefined,
        statusText: 'Unknown',
        headers: { get: () => 'application/json' },
        json: async () => null
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('ERR_UNKNOWN')
      }
    })
  })

  // --------------------------------------------------------------------------
  // broadcast – EF format fallback
  // --------------------------------------------------------------------------

  describe('broadcast – EF serialization fallback', () => {
    it('falls back to toHex when toHexEF throws the expected EF error', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: { txid: 'efFallbackTxid', txStatus: 'SEEN_ON_NETWORK', extraInfo: '' }
      })

      // Override the mock transaction to throw the EF error
      const mockTx = {
        toHexEF: () => {
          throw new Error('All inputs must have source transactions when serializing to EF format')
        },
        toHex: () => 'fallback_hex'
      } as unknown as Transaction

      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(mockTx)

      expect(response.status).toBe('success')
      // Verify that the fallback hex was sent (not EF)
      // FetchHttpClient serializes data into body via JSON.stringify, so parse it back
      const sentData = JSON.parse((mockFetch.mock.calls[0][1] as any)?.body)
      expect(sentData).toEqual({ rawTx: 'fallback_hex' })
    })

    it('re-throws non-EF errors from toHexEF', async () => {
      const mockFetch = mockedFetch({ status: 200, data: {} })
      const mockTx = {
        toHexEF: () => {
          throw new Error('Some other unexpected error')
        },
        toHex: () => 'fallback_hex'
      } as unknown as Transaction

      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      await expect(broadcaster.broadcast(mockTx)).rejects.toThrow('Some other unexpected error')
    })
  })

  // --------------------------------------------------------------------------
  // broadcast – catch block (network error)
  // --------------------------------------------------------------------------

  describe('broadcast – network-level errors', () => {
    it('handles thrown error with non-string message', async () => {
      const mockFetch = jest.fn().mockRejectedValue({ message: 42, toString: () => '42' })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const response = await broadcaster.broadcast(transaction)

      expect(response.status).toBe('error')
      if (response.status === 'error') {
        expect(response.code).toBe('500')
        expect(response.description).toBe('Internal Server Error')
      }
    })
  })

  // --------------------------------------------------------------------------
  // broadcastMany
  // --------------------------------------------------------------------------

  describe('broadcastMany', () => {
    it('broadcasts multiple transactions successfully', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: [
          { txid: 'txid1', txStatus: 'SEEN_ON_NETWORK' },
          { txid: 'txid2', txStatus: 'SEEN_ON_NETWORK' }
        ]
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })

      const tx1 = new Transaction()
      const tx2 = new Transaction()
      const responses = await broadcaster.broadcastMany([tx1, tx2])

      expect(mockFetch).toHaveBeenCalled()
      expect(Array.isArray(responses)).toBe(true)
      // Verify the URL used was /v1/txs
      const calledUrl: string = mockFetch.mock.calls[0][0]
      expect(calledUrl).toContain('/v1/txs')
    })

    it('sends array of rawTx objects to /v1/txs', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: [{ txid: 'txid1' }]
      })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      await broadcaster.broadcastMany([new Transaction()])

      // FetchHttpClient serializes data into body via JSON.stringify, so parse it back
      const sentData = JSON.parse((mockFetch.mock.calls[0][1] as any)?.body)
      expect(Array.isArray(sentData)).toBe(true)
      expect(sentData[0]).toHaveProperty('rawTx')
    })

    it('falls back to toHex for broadcastMany when toHexEF throws EF error', async () => {
      const mockFetch = mockedFetch({
        status: 200,
        data: [{ txid: 'txid_ef_fallback' }]
      })
      const mockTx = {
        toHexEF: () => {
          throw new Error('All inputs must have source transactions when serializing to EF format')
        },
        toHex: () => 'non_ef_hex'
      } as unknown as Transaction

      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      const responses = await broadcaster.broadcastMany([mockTx])

      // FetchHttpClient serializes data into body via JSON.stringify, so parse it back
      const sentData = JSON.parse((mockFetch.mock.calls[0][1] as any)?.body) as any[]
      expect(sentData[0]).toEqual({ rawTx: 'non_ef_hex' })
      expect(Array.isArray(responses)).toBe(true)
    })

    it('re-throws non-EF errors from toHexEF in broadcastMany', async () => {
      const mockFetch = mockedFetch({ status: 200, data: [] })
      const mockTx = {
        toHexEF: () => {
          throw new Error('Unexpected serialization error')
        },
        toHex: () => 'fallback'
      } as unknown as Transaction

      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })
      await expect(broadcaster.broadcastMany([mockTx])).rejects.toThrow('Unexpected serialization error')
    })

    it('returns error objects for all transactions when HTTP request throws', async () => {
      const mockFetch = jest.fn().mockRejectedValue(new Error('Connection refused'))
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })

      const tx1 = new Transaction()
      const tx2 = new Transaction()
      const responses = await broadcaster.broadcastMany([tx1, tx2])

      expect(responses).toHaveLength(2)
      for (const r of responses) {
        const err = r as any
        expect(err.status).toBe('error')
        expect(err.code).toBe('500')
        expect(err.description).toBe('Connection refused')
      }
    })

    it('handles non-string error message in broadcastMany catch block', async () => {
      const mockFetch = jest.fn().mockRejectedValue({ message: undefined })
      const broadcaster = new ARC(URL, { httpClient: new FetchHttpClient(mockFetch) })

      const responses = await broadcaster.broadcastMany([new Transaction()])
      const err = responses[0] as any
      expect(err.status).toBe('error')
      expect(err.description).toBe('Internal Server Error')
    })

    it('sends correct request headers in broadcastMany', async () => {
      const mockFetch = mockedFetch({ status: 200, data: [] })
      const apiKey = 'test-api-key'
      const broadcaster = new ARC(URL, {
        apiKey,
        httpClient: new FetchHttpClient(mockFetch)
      })
      await broadcaster.broadcastMany([new Transaction()])

      const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}
      expect(headers.Authorization).toBe(`Bearer ${apiKey}`)
      expect(headers['Content-Type']).toBe('application/json')
      expect(headers['XDeployment-ID']).toMatch(/ts-sdk-.*/)
    })
  })

  // --------------------------------------------------------------------------
  // Node.js https path for broadcastMany
  // --------------------------------------------------------------------------

  describe('broadcastMany – Node.js https', () => {
    it('broadcasts multiple transactions using NodejsHttpClient', async () => {
      const mockHttps = mockedHttps({
        status: 200,
        data: [{ txid: 'txid1' }, { txid: 'txid2' }]
      })
      const broadcaster = new ARC(URL, {
        httpClient: new NodejsHttpClient(mockHttps)
      })

      const responses = await broadcaster.broadcastMany([new Transaction(), new Transaction()])
      expect(Array.isArray(responses)).toBe(true)
    })
  })
})
