import Transaction from '../../../transaction/Transaction'
import { NodejsHttpClient, HttpsNodejs } from '../../../transaction/http/NodejsHttpClient'
import WhatsOnChainBroadcaster from '../../../transaction/broadcasters/WhatsOnChainBroadcaster'
import { FetchHttpClient } from '../../../transaction/http/FetchHttpClient'

// Mock Transaction
jest.mock('../../../transaction/Transaction', () => {
  class MockTransaction {
    toHex (): String {
      return 'mocked_transaction_hex'
    }

    toHexEF (): String {
      return 'mocked_transaction_hexEF'
    }
  }
  return { __esModule: true, default: MockTransaction }
})

describe('WhatsOnChainBroadcaster', () => {
  const network = 'main'
  const successResponse = {
    status: 200,
    data: 'mocked_txid'
  }

  let transaction: Transaction

  beforeEach(() => {
    transaction = new Transaction()
  })

  async function withoutGlobalFetch<T> (callback: () => Promise<T>): Promise<T> {
    const originalFetchDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'fetch')
    Object.defineProperty(globalThis, 'fetch', {
      configurable: true,
      writable: true,
      value: undefined
    })
    try {
      return await callback()
    } finally {
      if (originalFetchDescriptor !== undefined) {
        Object.defineProperty(globalThis, 'fetch', originalFetchDescriptor)
      } else {
        delete (globalThis as { fetch?: unknown }).fetch
      }
    }
  }

  it('should broadcast successfully using window.fetch', async () => {
    // Mocking window.fetch
    const mockFetch = mockedFetch(successResponse)
    global.window = { fetch: mockFetch } as any

    const response = await withoutGlobalFetch(async () => {
      const broadcaster = new WhatsOnChainBroadcaster(network)
      return await broadcaster.broadcast(transaction)
    })

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'broadcast successful'
    })
  })

  it('should broadcast successfully using Node.js https', async () => {
    // Mocking Node.js https module
    mockedHttps(successResponse)
    global.window = {} as any

    const response = await withoutGlobalFetch(async () => {
      const broadcaster = new WhatsOnChainBroadcaster(network)
      return await broadcaster.broadcast(transaction)
    })

    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'broadcast successful'
    })
  })

  it('should broadcast successfully using provided fetch', async () => {
    const mockFetch = mockedFetch(successResponse)

    const broadcaster = new WhatsOnChainBroadcaster(
      network,
      new FetchHttpClient(mockFetch)
    )
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'broadcast successful'
    })
  })

  it('should broadcast successfully using provided https', async () => {
    const mockHttps = mockedHttps(successResponse) as unknown as HttpsNodejs
    const broadcaster = new WhatsOnChainBroadcaster(
      network,
      new NodejsHttpClient(mockHttps)
    )

    const response = await broadcaster.broadcast(transaction)

    expect(response).toEqual({
      status: 'success',
      txid: 'mocked_txid',
      message: 'broadcast successful'
    })
  })

  it('should handle network errors', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'))
    global.window = { fetch: mockFetch } as any

    const broadcaster = new WhatsOnChainBroadcaster(network)
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
      data: 'Bad request'
    })
    global.window = { fetch: mockFetch } as any

    const broadcaster = new WhatsOnChainBroadcaster(network)
    const response = await broadcaster.broadcast(transaction)

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual({
      status: 'error',
      code: '400',
      description: 'Bad request'
    })
  })

  function mockedFetch (response: any): jest.Mock<any, any, any> {
    return jest.fn().mockResolvedValue({
      ok: response.status === 200,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Bad request',
      headers: {
        get (key: string) {
          if (key === 'Content-Type') {
            return 'text/plain'
          }
        }
      },
      text: async () => response.data
    })
  }

  function mockedHttps (response: any): { request: Function } {
    const https = {
      request: (url, options, callback) => {
        // eslint-disable-next-line
        callback({
          statusCode: response.status,
          statusMessage: response.status === 200 ? 'OK' : 'Bad request',
          headers: {
            'content-type': 'text/plain'
          },
          on: (event, handler) => {
            if (event === 'data') handler(response.data)
            if (event === 'end') handler()
          }
        })
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
