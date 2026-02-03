import ARC from '../../../transaction/broadcasters/ARC'
import Transaction from '../../../transaction/Transaction'
import { NodejsHttpClient } from '../../../transaction/http/NodejsHttpClient'
import { FetchHttpClient } from '../../../transaction/http/FetchHttpClient'
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

describe('ARC Broadcaster', () => {
  const URL = 'https://example.com'
  const successResponse = {
    status: 200,
    data: {
      txid: 'mocked_txid',
      txStatus: 'success',
      extraInfo: 'received'
    }
  }

  let transaction: Transaction

  beforeEach(() => {
    transaction = new Transaction()
  })

  it('should broadcast successfully using window.fetch', async () => {
    // Mocking window.fetch
    const mockFetch = mockedFetch(successResponse)
    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const broadcaster = new ARC(URL)
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'success received'
    })
  })

  it('should broadcast successfully using Node.js https', async () => {
    // Mocking Node.js https module
    mockedHttps(successResponse)
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window // ✅ Explicit property check
    }

    const broadcaster = new ARC(URL)
    const response = await broadcaster.broadcast(transaction)

    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'success received'
    })
  })

  it('should broadcast successfully using provided fetch', async () => {
    const mockFetch = mockedFetch(successResponse)

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'success received'
    })
  })

  it('should broadcast successfully using provided https', async () => {
    const mockHttps = mockedHttps(successResponse)
    const broadcaster = new ARC(URL, {
      httpClient: new NodejsHttpClient(mockHttps)
    })

    const response = await broadcaster.broadcast(transaction)

    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'success received'
    })
  })

  it('should send default request headers when broadcasting', async () => {
    const mockFetch = mockedFetch(successResponse)

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    await broadcaster.broadcast(transaction)

    // Ensure headers exist and cast to the correct type
    const requestOptions = mockFetch.mock.calls[0][1] as HttpClientRequestOptions
    const headers = (requestOptions?.headers ?? {}) // ✅ Proper typing

    expect(headers['Content-Type']).toEqual('application/json')
    expect(headers['XDeployment-ID']).toBeDefined()
    expect(headers['XDeployment-ID']).toMatch(/ts-sdk-.*/)
    expect(headers.Authorization).toBeUndefined()
  })

  it('should send authorization header when api key is provided', async () => {
    const mockFetch = mockedFetch(successResponse)
    const apiKey = 'mainnet_1234567890'

    const broadcaster = new ARC(URL, {
      apiKey,
      httpClient: new FetchHttpClient(mockFetch)
    })
    await broadcaster.broadcast(transaction)

    // Extract and properly type headers
    const requestOptions = mockFetch.mock.calls[0][1] as HttpClientRequestOptions
    const headers = (requestOptions?.headers ?? {}) // ✅ Correct typing

    expect(headers['XDeployment-ID']).toBeDefined()
    expect(headers['XDeployment-ID']).toMatch(/ts-sdk-.*/)
    expect(headers.Authorization).toEqual(`Bearer ${apiKey}`) // ✅ Now properly typed
  })

  it('should handle api key as second argument', async () => {
    const mockFetch = mockedFetch(successResponse)
    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const apiKey = 'mainnet_1234567890'

    const broadcaster = new ARC(URL, apiKey)
    await broadcaster.broadcast(transaction)

    // Ensure headers is always defined
    const headers = (mockFetch.mock.calls[0][1] as HttpClientRequestOptions)?.headers ?? {}

    expect(headers.Authorization).toEqual(`Bearer ${apiKey}`)
  })

  it('should send provided deployment id', async () => {
    const mockFetch = mockedFetch(successResponse)
    const deploymentId = 'custom_deployment_id'

    const broadcaster = new ARC(URL, {
      deploymentId,
      httpClient: new FetchHttpClient(mockFetch)
    })
    await broadcaster.broadcast(transaction)

    // Ensure headers is always defined
    const headers =
    (mockFetch.mock.calls[0]?.[1]?.headers) ?? {}

    expect(headers['XDeployment-ID']).toEqual(deploymentId)
  })

  it('should handle network errors', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'))
    global.window = { fetch: mockFetch } as unknown as Window & typeof globalThis

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'error',
      code: '500',
      description: 'Network error'
    })
  })

  it('should handle non-200 responses', async () => {
    const mockFetch = mockedFetch({
      status: 400,
      data: JSON.stringify({
        detail: 'Bad request'
      })
    })

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'error',
      code: '400',
      description: 'Bad request',
      more: {
        detail: 'Bad request'
      }
    })
  })

  it('handles error 460', async () => {
    // Mock the fetch response to simulate the error 460 response
    const mockFetch = mockedFetch({
      status: 460,
      data: {
        status: 460,
        detail: 'Transaction is not in extended format, missing input scripts',
        txid: 'd21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43'
      }
    })

    // Initialize the ARC broadcaster with the mocked fetch client
    const URL = 'https://arc.gorillapool.io'
    const apiKey = 'mock_api_key' // Example API key
    const broadcaster = new ARC(URL, {
      apiKey,
      httpClient: new FetchHttpClient(mockFetch)
    })

    // Simulate broadcasting the transaction
    const response = await broadcaster.broadcast(transaction)

    // Check if the response is an error as expected
    if (response.status === 'error') {
      // Validate the BroadcastFailure response properties
      expect(response.status).toBe('error')
      expect(response.code).toBe('460')
      expect(response.description).toBe(
        'Transaction is not in extended format, missing input scripts'
      )
      expect(response.txid).toBe(
        'd21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43'
      )
      expect(response.more).toBeTruthy() // Validate the presence of additional error details
    } else {
      // Fail the test if the response is not an error
      fail('Expected a BroadcastFailure but got a BroadcastResponse')
    }
  })

  it('should return error for DOUBLE_SPEND_ATTEMPTED even with HTTP 200', async () => {
    const mockFetch = mockedFetch({
      status: 200,
      data: {
        txid: '89100426fc13a55260fa65e621e7591f8b01007af62480e818d0da518723bfd3',
        txStatus: 'DOUBLE_SPEND_ATTEMPTED',
        extraInfo: '',
        competingTxs: ['5e58f06a83343011f77d9109aab08dcc38d89e8cc7bd55da16affa948281d7ed']
      }
    })

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('DOUBLE_SPEND_ATTEMPTED')
      expect(response.txid).toBe('89100426fc13a55260fa65e621e7591f8b01007af62480e818d0da518723bfd3')
      expect(response.more).toEqual({
        competingTxs: ['5e58f06a83343011f77d9109aab08dcc38d89e8cc7bd55da16affa948281d7ed']
      })
    }
  })

  it('should return error for SEEN_IN_ORPHAN_MEMPOOL even with HTTP 200', async () => {
    const mockFetch = mockedFetch({
      status: 200,
      data: {
        txid: 'b06cb1059c2bf3debee1e65dc90d0815653325c7cf2584763b90c761c09919db',
        txStatus: 'success',
        extraInfo: 'SEEN_IN_ORPHAN_MEMPOOL'
      }
    })

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('success')
      expect(response.txid).toBe('b06cb1059c2bf3debee1e65dc90d0815653325c7cf2584763b90c761c09919db')
      expect(response.description).toContain('ORPHAN')
    }
  })

  it('should return error for REJECTED status even with HTTP 200', async () => {
    const mockFetch = mockedFetch({
      status: 200,
      data: {
        txid: 'abc123',
        txStatus: 'REJECTED',
        extraInfo: 'Transaction rejected by network'
      }
    })

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response.status).toBe('error')
    if (response.status === 'error') {
      expect(response.code).toBe('REJECTED')
      expect(response.description).toContain('REJECTED')
      expect(response.description).toContain('Transaction rejected by network')
    }
  })

  it('should still return success for valid txStatus values', async () => {
    const mockFetch = mockedFetch({
      status: 200,
      data: {
        txid: 'valid_txid',
        txStatus: 'SEEN_ON_NETWORK',
        extraInfo: 'Transaction accepted'
      }
    })

    const broadcaster = new ARC(URL, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response.status).toBe('success')
    if (response.status === 'success') {
      expect(response.txid).toBe('valid_txid')
      expect(response.message).toBe('SEEN_ON_NETWORK Transaction accepted')
    }
  })

  function mockedFetch (response: { status: number, data: any }): jest.Mock {
    return jest.fn().mockResolvedValue({
      ok: response.status === 200,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Bad request',
      headers: {
        get: (key: string): string | undefined => {
          if (key === 'Content-Type') {
            return 'application/json; charset=UTF-8'
          }
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
    ) => {
      on: jest.Mock
      write: jest.Mock
      end: jest.Mock
    }
  } {
    const https = {
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
        const mockResponse = {
          statusCode: response.status,
          statusMessage: response.status === 200 ? 'OK' : 'Bad request',
          headers: {
            'content-type': 'application/json; charset=UTF-8'
          },
          on (event: string, handler: (chunk?: any) => void) {
            if (event === 'data') handler(JSON.stringify(response.data))
            if (event === 'end') handler()
          }
        }

        // ✅ Call the callback asynchronously to match Node.js behavior
        process.nextTick(() => callback(mockResponse))

        return {
          on: jest.fn(),
          write: jest.fn(),
          end: jest.fn()
        }
      }
    }

    jest.mock('https', () => https)
    return https
  }
})
