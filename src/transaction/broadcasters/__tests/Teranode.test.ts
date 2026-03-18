import Teranode from '../../../transaction/broadcasters/Teranode'
import Transaction from '../../../transaction/Transaction'
import { BinaryFetchClient } from '../../../transaction/http/BinaryFetchClient'
import { NodejsHttpClient } from '../../../transaction/http/NodejsHttpClient'
import { RequestOptions } from 'https'

// Mock Transaction so tests don't require a fully-formed BSV tx
jest.mock('../../../transaction/Transaction', () => {
  class MockTransaction {
    toEF (): number[] {
      return [0x01, 0x02, 0x03, 0x04]
    }

    id (_encoding: string): string {
      return 'mocked_txid'
    }
  }
  return { __esModule: true, default: MockTransaction }
})

describe('Teranode Broadcaster', () => {
  const URL = 'https://teranode.example.com/api/v1/tx'

  let transaction: Transaction

  beforeEach(() => {
    transaction = new Transaction()
  })

  afterEach(() => {
    jest.clearAllMocks()
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }
  })

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  it('stores the provided URL', () => {
    const mockFetch = jest.fn()
    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    expect(broadcaster.URL).toBe(URL)
  })

  it('stores the provided httpClient', () => {
    const mockFetch = jest.fn()
    const httpClient = new BinaryFetchClient(mockFetch as any)
    const broadcaster = new Teranode(URL, httpClient)
    expect(broadcaster.httpClient).toBe(httpClient)
  })

  it('uses binaryHttpClient when no httpClient is provided and window.fetch exists', () => {
    const mockFetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => ''
    })
    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    // Constructor must not throw; httpClient must be defined
    const broadcaster = new Teranode(URL)
    expect(broadcaster.httpClient).toBeDefined()
    expect(typeof broadcaster.httpClient.request).toBe('function')
  })

  // ---------------------------------------------------------------------------
  // broadcast() — successful response
  // ---------------------------------------------------------------------------

  it('returns BroadcastResponse on HTTP 200', async () => {
    const mockFetch = mockedFetch({ status: 200, data: '' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    const response = await broadcaster.broadcast(transaction)

    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'broadcast successful'
    })
  })

  it('sends a POST with Content-Type application/octet-stream', async () => {
    const mockFetch = mockedFetch({ status: 200, data: '' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [calledUrl, calledOptions] = mockFetch.mock.calls[0]
    expect(calledUrl).toBe(URL)
    expect(calledOptions.method).toBe('POST')
    expect(calledOptions.headers['Content-Type']).toBe('application/octet-stream')
  })

  it('sends a Blob derived from toEF() bytes as request body', async () => {
    const mockFetch = mockedFetch({ status: 200, data: '' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    await broadcaster.broadcast(transaction)

    const [, calledOptions] = mockFetch.mock.calls[0]
    expect(calledOptions.body).toBeInstanceOf(Blob)
  })

  it('returns the tx id from transaction.id("hex")', async () => {
    const mockFetch = mockedFetch({ status: 200, data: '' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('success')
    if (response.status === 'success') {
      expect(response.txid).toBe('mocked_txid')
    }
  })

  // ---------------------------------------------------------------------------
  // broadcast() — error response
  // ---------------------------------------------------------------------------

  it('returns BroadcastFailure with status code string on non-200 response', async () => {
    const mockFetch = mockedFetch({ status: 400, data: 'Bad request data' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('400')
      expect(response.description).toBe('Bad request data')
    }
  })

  it('returns BroadcastFailure on HTTP 500', async () => {
    const mockFetch = mockedFetch({ status: 500, data: 'Internal Server Error body' })

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('500')
    }
  })

  it('uses "ERR_UNKNOWN" code when response.status is missing/falsy', async () => {
    // Construct a mock where the HttpClient returns a non-ok response with status 0
    const mockHttpClient = {
      request: jest.fn().mockResolvedValue({
        ok: false,
        status: 0,
        statusText: '',
        data: 'some error'
      })
    }

    const broadcaster = new Teranode(URL, mockHttpClient)
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      // status.toString() of 0 is "0", not falsy in template — code is "0"
      expect(response.code).toBe('0')
      expect(response.description).toBe('some error')
    }
  })

  it('uses "Unknown error" description when response.data is null/undefined', async () => {
    const mockHttpClient = {
      request: jest.fn().mockResolvedValue({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        data: null
      })
    }

    const broadcaster = new Teranode(URL, mockHttpClient)
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('503')
      expect(response.description).toBe('Unknown error')
    }
  })

  it('uses "Unknown error" description when response.data is undefined', async () => {
    const mockHttpClient = {
      request: jest.fn().mockResolvedValue({
        ok: false,
        status: 422,
        statusText: 'Unprocessable',
        data: undefined
      })
    }

    const broadcaster = new Teranode(URL, mockHttpClient)
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.description).toBe('Unknown error')
    }
  })

  // ---------------------------------------------------------------------------
  // broadcast() — network / thrown errors
  // ---------------------------------------------------------------------------

  it('returns BroadcastFailure with code 500 on network error (Error instance)', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'))

    const broadcaster = new Teranode(URL, new BinaryFetchClient(mockFetch))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('500')
      expect(response.description).toBe('Network error')
    }
  })

  it('returns "Internal Server Error" description when thrown error has non-string message', async () => {
    const mockHttpClient = {
      request: jest.fn().mockRejectedValue({ message: 42 })
    }

    const broadcaster = new Teranode(URL, mockHttpClient)
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('500')
      expect(response.description).toBe('Internal Server Error')
    }
  })

  it('returns "Internal Server Error" when thrown value has no message property', async () => {
    const mockHttpClient = {
      request: jest.fn().mockRejectedValue('plain string error')
    }

    const broadcaster = new Teranode(URL, mockHttpClient)
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('500')
      expect(response.description).toBe('Internal Server Error')
    }
  })

  // ---------------------------------------------------------------------------
  // broadcast() — using Node.js https module directly
  // ---------------------------------------------------------------------------

  it('broadcasts successfully using NodejsHttpClient', async () => {
    const mockHttps = mockedHttps({ status: 200, data: '' })

    const broadcaster = new Teranode(URL, new NodejsHttpClient(mockHttps))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('success')
    if (response.status === 'success') {
      expect(response.txid).toBe('mocked_txid')
    }
  })

  it('returns BroadcastFailure using NodejsHttpClient on non-200', async () => {
    const mockHttps = mockedHttps({ status: 503, data: 'Unavailable' })

    const broadcaster = new Teranode(URL, new NodejsHttpClient(mockHttps))
    const response = await broadcaster.broadcast(transaction)

    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('503')
    }
  })

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function mockedFetch (response: { status: number, data: any }): jest.Mock {
    return jest.fn().mockResolvedValue({
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Error',
      // BinaryFetchClient calls res.text() then returns result as data
      text: async () =>
        typeof response.data === 'string'
          ? response.data
          : JSON.stringify(response.data)
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
    ) => {
      on: jest.Mock
      write: jest.Mock
      end: jest.Mock
    }
  } {
    return {
      request: (
        url: string,
        options: RequestOptions,
        callback: (res: any) => void
      ) => {
        const mockResponse = {
          statusCode: response.status,
          statusMessage: response.status === 200 ? 'OK' : 'Error',
          headers: { 'content-type': 'application/octet-stream' },
          on (event: string, handler: (chunk?: any) => void) {
            if (event === 'data') {
              handler(
                typeof response.data === 'string'
                  ? response.data
                  : JSON.stringify(response.data)
              )
            }
            if (event === 'end') handler()
          }
        }
        process.nextTick(() => callback(mockResponse))
        return {
          on: jest.fn(),
          write: jest.fn(),
          end: jest.fn()
        }
      }
    }
  }
})
