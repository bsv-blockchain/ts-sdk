import { BlockHeadersService } from '../../../transaction/chaintrackers/BlockHeadersService'

describe('BlockHeadersService', () => {
  const baseUrl = 'https://headers.spv.money'
  const apiKey = 'test-api-key-12345'
  const merkleRoot = 'abc123merkleroot'
  const blockHeight = 800000

  function makeHttpClient (response: { ok: boolean, status: number, data: any }): { request: jest.Mock } {
    return {
      request: jest.fn().mockResolvedValue(response)
    }
  }

  describe('constructor', () => {
    it('sets baseUrl from first argument', () => {
      const httpClient = makeHttpClient({ ok: true, status: 200, data: {} })
      const tracker = new BlockHeadersService(baseUrl, { httpClient })
      expect((tracker as any).baseUrl).toBe(baseUrl)
    })

    it('sets apiKey from config', () => {
      const httpClient = makeHttpClient({ ok: true, status: 200, data: {} })
      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      expect((tracker as any).apiKey).toBe(apiKey)
    })

    it('uses empty string for apiKey when not provided', () => {
      const httpClient = makeHttpClient({ ok: true, status: 200, data: {} })
      const tracker = new BlockHeadersService(baseUrl, { httpClient })
      expect((tracker as any).apiKey).toBe('')
    })

    it('uses provided httpClient', () => {
      const httpClient = makeHttpClient({ ok: true, status: 200, data: {} })
      const tracker = new BlockHeadersService(baseUrl, { httpClient })
      expect((tracker as any).httpClient).toBe(httpClient)
    })

    it('falls back to defaultHttpClient when no httpClient provided', () => {
      const tracker = new BlockHeadersService(baseUrl, { apiKey })
      // The httpClient should be set (not undefined) – it comes from defaultHttpClient()
      expect((tracker as any).httpClient).toBeDefined()
    })
  })

  describe('isValidRootForHeight', () => {
    it('returns true when confirmationState is CONFIRMED', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: {
          confirmationState: 'CONFIRMED',
          confirmations: [
            {
              blockHash: 'hash123',
              blockHeight,
              merkleRoot,
              confirmation: 'CONFIRMED'
            }
          ]
        }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      const result = await tracker.isValidRootForHeight(merkleRoot, blockHeight)
      expect(result).toBe(true)
    })

    it('returns false when confirmationState is UNCONFIRMED', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: {
          confirmationState: 'UNCONFIRMED',
          confirmations: []
        }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      const result = await tracker.isValidRootForHeight(merkleRoot, blockHeight)
      expect(result).toBe(false)
    })

    it('throws on non-ok HTTP response', async () => {
      const httpClient = makeHttpClient({
        ok: false,
        status: 400,
        data: { error: 'Bad Request' }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.isValidRootForHeight(merkleRoot, blockHeight)).rejects.toThrow(
        `Failed to verify merkleroot for height ${blockHeight} because of an error:`
      )
    })

    it('throws when httpClient.request rejects', async () => {
      const httpClient = {
        request: jest.fn().mockRejectedValue(new Error('Network failure'))
      }

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.isValidRootForHeight(merkleRoot, blockHeight)).rejects.toThrow(
        'Failed to verify merkleroot for height'
      )
    })

    it('sends correct POST body with blockHeight and merkleRoot', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { confirmationState: 'CONFIRMED', confirmations: [] }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await tracker.isValidRootForHeight(merkleRoot, blockHeight)

      expect(httpClient.request).toHaveBeenCalledTimes(1)
      const [url, options] = httpClient.request.mock.calls[0]
      expect(url).toBe(`${baseUrl}/api/v1/chain/merkleroot/verify`)
      expect(options.method).toBe('POST')
      expect(options.data).toEqual([
        {
          blockHeight,
          merkleRoot
        }
      ])
    })

    it('sets Authorization header with Bearer token from apiKey', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { confirmationState: 'CONFIRMED', confirmations: [] }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await tracker.isValidRootForHeight(merkleRoot, blockHeight)

      const [, options] = httpClient.request.mock.calls[0]
      expect(options.headers['Authorization']).toBe(`Bearer ${apiKey}`)
    })

    it('sets Content-Type and Accept headers', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { confirmationState: 'CONFIRMED', confirmations: [] }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await tracker.isValidRootForHeight(merkleRoot, blockHeight)

      const [, options] = httpClient.request.mock.calls[0]
      expect(options.headers['Content-Type']).toBe('application/json')
      expect(options.headers['Accept']).toBe('application/json')
    })
  })

  describe('currentHeight', () => {
    it('returns height from response data', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { height: 875904 }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      const result = await tracker.currentHeight()
      expect(result).toBe(875904)
    })

    it('sends GET request to correct URL', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { height: 100 }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await tracker.currentHeight()

      const [url, options] = httpClient.request.mock.calls[0]
      expect(url).toBe(`${baseUrl}/api/v1/chain/tip/longest`)
      expect(options.method).toBe('GET')
    })

    it('sets Authorization header with Bearer token for currentHeight', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { height: 100 }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await tracker.currentHeight()

      const [, options] = httpClient.request.mock.calls[0]
      expect(options.headers['Authorization']).toBe(`Bearer ${apiKey}`)
    })

    it('throws on non-ok response', async () => {
      const httpClient = makeHttpClient({
        ok: false,
        status: 500,
        data: { error: 'Internal Server Error' }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.currentHeight()).rejects.toThrow(
        'Failed to get current height because of an error:'
      )
    })

    it('throws when response.data.height is not a number', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: { height: 'not-a-number' }
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.currentHeight()).rejects.toThrow(
        'Failed to get current height because of an error:'
      )
    })

    it('throws when response.data is missing height field', async () => {
      const httpClient = makeHttpClient({
        ok: true,
        status: 200,
        data: {}
      })

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.currentHeight()).rejects.toThrow(
        'Failed to get current height because of an error:'
      )
    })

    it('throws when httpClient.request rejects', async () => {
      const httpClient = {
        request: jest.fn().mockRejectedValue(new Error('Connection refused'))
      }

      const tracker = new BlockHeadersService(baseUrl, { apiKey, httpClient })
      await expect(tracker.currentHeight()).rejects.toThrow(
        'Failed to get current height because of an error: Connection refused'
      )
    })
  })
})
