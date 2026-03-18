import WhatsOnChain from '../../../transaction/chaintrackers/WhatsOnChain'
import { FetchHttpClient } from '../../../transaction/http/FetchHttpClient'

// These tests cover the branches that are missing from WhatsOnChainChainTracker.test.ts:
//   Line 80-85  — currentHeight() non-ok response branch (throws)
//   Line 84     — currentHeight() catch block re-throws with formatted message
//   Line 97     — getHttpHeaders() sets Authorization header when apiKey is non-empty

describe('WhatsOnChain — additional coverage', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  // -------------------------------------------------------------------------
  // currentHeight() — non-ok response (lines 80-83)
  // -------------------------------------------------------------------------

  it('throws when currentHeight receives a non-ok HTTP response', async () => {
    const mockFetch = mockedFetch({ status: 503, data: { error: 'Service Unavailable' } })

    const tracker = new WhatsOnChain('main', {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(tracker.currentHeight()).rejects.toThrow(
      /Failed to get current height because of an error:/
    )
  })

  it('includes the serialised response data in the thrown message for non-ok currentHeight', async () => {
    const mockFetch = mockedFetch({ status: 429, data: { code: 'RATE_LIMITED' } })

    const tracker = new WhatsOnChain('main', {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(tracker.currentHeight()).rejects.toThrow(
      /RATE_LIMITED/
    )
  })

  // -------------------------------------------------------------------------
  // currentHeight() — catch block (lines 84-87)
  // The outer try/catch in currentHeight() wraps everything, including the
  // non-ok branch.  A network-level rejection also exercises lines 84-87.
  // -------------------------------------------------------------------------

  it('wraps network errors in a formatted message via the catch block', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('connection refused'))

    const tracker = new WhatsOnChain('main', {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(tracker.currentHeight()).rejects.toThrow(
      'Failed to get current height because of an error: connection refused'
    )
  })

  it('handles non-Error thrown values in the catch block', async () => {
    const mockHttpClient = {
      request: jest.fn().mockRejectedValue('raw string rejection')
    }

    const tracker = new WhatsOnChain('main', { httpClient: mockHttpClient })

    await expect(tracker.currentHeight()).rejects.toThrow(
      'Failed to get current height because of an error: raw string rejection'
    )
  })

  // -------------------------------------------------------------------------
  // getHttpHeaders() — Authorization header when apiKey is set (line 97)
  // -------------------------------------------------------------------------

  it('includes Authorization header in requests when apiKey is provided', async () => {
    const apiKey = 'my-test-api-key'
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'root123' } })

    const tracker = new WhatsOnChain('main', {
      apiKey,
      httpClient: new FetchHttpClient(mockFetch)
    })

    await tracker.isValidRootForHeight('root123', 100)

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers?.Authorization).toBe(apiKey)
  })

  it('does NOT include Authorization header when apiKey is an empty string', async () => {
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'root456' } })

    const tracker = new WhatsOnChain('main', {
      apiKey: '',
      httpClient: new FetchHttpClient(mockFetch)
    })

    await tracker.isValidRootForHeight('root456', 200)

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers?.Authorization).toBeUndefined()
  })

  it('does NOT include Authorization header when apiKey is only whitespace', async () => {
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'root789' } })

    const tracker = new WhatsOnChain('main', {
      apiKey: '   ',
      httpClient: new FetchHttpClient(mockFetch)
    })

    await tracker.isValidRootForHeight('root789', 300)

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers?.Authorization).toBeUndefined()
  })

  it('always includes Accept: application/json regardless of apiKey', async () => {
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'rAny' } })

    const tracker = new WhatsOnChain('main', {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await tracker.isValidRootForHeight('rAny', 1)

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers?.Accept).toBe('application/json')
  })

  it('sends Authorization header to currentHeight endpoint when apiKey is set', async () => {
    const apiKey = 'another-key'
    const mockFetch = mockedFetch({
      status: 200,
      data: [{ height: 999999 }]
    })

    const tracker = new WhatsOnChain('test', {
      apiKey,
      httpClient: new FetchHttpClient(mockFetch)
    })

    await tracker.currentHeight()

    const [, fetchOptions] = mockFetch.mock.calls[0]
    expect(fetchOptions.headers?.Authorization).toBe(apiKey)
  })

  // -------------------------------------------------------------------------
  // Constructor — network variants
  // -------------------------------------------------------------------------

  it('builds the correct URL for the "test" network', async () => {
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'testroot' } })

    const tracker = new WhatsOnChain('test', { httpClient: new FetchHttpClient(mockFetch) })
    await tracker.isValidRootForHeight('testroot', 10)

    const [calledUrl] = mockFetch.mock.calls[0]
    expect(calledUrl).toContain('bsv/test')
  })

  it('builds the correct URL for the "stn" network', async () => {
    const mockFetch = mockedFetch({ status: 200, data: { merkleroot: 'stnroot' } })

    const tracker = new WhatsOnChain('stn', { httpClient: new FetchHttpClient(mockFetch) })
    await tracker.isValidRootForHeight('stnroot', 20)

    const [calledUrl] = mockFetch.mock.calls[0]
    expect(calledUrl).toContain('bsv/stn')
  })

  // -------------------------------------------------------------------------
  // Helper
  // -------------------------------------------------------------------------

  function mockedFetch (response: { status: number, data: any }): jest.Mock {
    return jest.fn().mockResolvedValue({
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Error',
      headers: {
        get (key: string): string | undefined {
          if (key === 'Content-Type') return 'application/json'
          return undefined
        }
      },
      json: async () => response.data
    })
  }
})
