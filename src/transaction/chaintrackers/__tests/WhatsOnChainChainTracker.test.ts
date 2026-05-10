import { NodejsHttpClient } from '../../../transaction/http/NodejsHttpClient'
import WhatsOnChain from '../../../transaction/chaintrackers/WhatsOnChain'
import { FetchHttpClient } from '../../../transaction/http/FetchHttpClient'

describe('WhatsOnChain ChainTracker', () => {
  const network = 'main'
  const height = 123456
  const merkleroot = 'mocked_merkleroot'

  const successResponse = {
    status: 200,
    data: {
      merkleroot
    }
  }

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

  it('should verify merkleroot successfully using window.fetch', async () => {
    // Mocking window.fetch
    const mockFetch = mockedFetch(successResponse)
    global.window = { fetch: mockFetch } as any

    const response = await withoutGlobalFetch(async () => {
      const chainTracker = new WhatsOnChain(network)
      return await chainTracker.isValidRootForHeight(
        merkleroot,
        height
      )
    })

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual(true)
  })

  it('should verify merkleroot successfully using Node.js https', async () => {
    // Mocking Node.js https module
    mockedHttps(successResponse)
    if (typeof global.window !== 'undefined') global.window = {} as any

    const response = await withoutGlobalFetch(async () => {
      const chainTracker = new WhatsOnChain(network)
      return await chainTracker.isValidRootForHeight(
        merkleroot,
        height
      )
    })

    expect(response).toEqual(true)
  })

  it('should verify merkleroot successfully using provided window.fetch', async () => {
    const mockFetch = mockedFetch(successResponse)

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await chainTracker.isValidRootForHeight(
      merkleroot,
      height
    )

    expect(mockFetch).toHaveBeenCalled()
    expect(response).toEqual(true)
  })

  it('should verify merkleroot successfully using provided Node.js https', async () => {
    const mockHttps = mockedHttps(successResponse)

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new NodejsHttpClient(mockHttps)
    })
    const response = await chainTracker.isValidRootForHeight(
      merkleroot,
      height
    )

    expect(response).toEqual(true)
  })

  it('should respond with invalid root for height when block for height is not found', async () => {
    const mockFetch = mockedFetch({
      status: 404,
      data: 'not found'
    })

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new FetchHttpClient(mockFetch)
    })
    const response = await chainTracker.isValidRootForHeight(
      merkleroot,
      height
    )

    expect(response).toEqual(false)
  })

  it('should handle network errors', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'))

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(
      chainTracker.isValidRootForHeight(merkleroot, height)
    ).rejects.toThrow('Network error')
  })

  it('should throw error when received error response', async () => {
    const mockFetch = mockedFetch({
      status: 401,
      data: { error: 'Unauthorized' }
    })

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(
      chainTracker.isValidRootForHeight(merkleroot, height)
    ).rejects.toThrow(
      /Failed to verify merkleroot for height \d+ because of an error: .*/
    )
  })

  it('should return the current height', async () => {
    const mockFetch = mockedFetch({
      status: 200,
      data: [
        {
          hash: '00000000000000000af9958a79fd4dbac1b04a553cc00c80e108718561ccb5a5',
          confirmations: 1,
          size: 29605652,
          height: 875904,
          version: 704643072,
          versionHex: '2a000000',
          merkleroot:
            '8af5a2d4325ec30e30103b1f365c303d4b49d11e42d26b0d7e9b6866724392e9',
          time: 1734667612,
          mediantime: 1734663717,
          nonce: 157007350,
          bits: '180f2b74',
          difficulty: 72479484799.59058,
          chainwork:
            '00000000000000000000000000000000000000000160c2f41c8793b90f4500dd',
          previousblockhash:
            '00000000000000000128f312a7c62ef5f9a91a3f845a4464d10cfbaaecd233a0',
          nextblockhash: '',
          nTx: 0,
          num_tx: 167567
        }
      ]
    })

    const chainTracker = new WhatsOnChain(network, {
      httpClient: new FetchHttpClient(mockFetch)
    })

    await expect(await chainTracker.currentHeight()).toBe(875904)
  })

  function mockedFetch (response: { status: number, data: any }): jest.Mock<any, any, any> {
    return jest.fn().mockResolvedValue({
      ok: response.status === 200,
      status: response.status,
      statusText: response.status === 200 ? 'OK' : 'Bad request',
      headers: {
        get (key: string) {
          if (key === 'Content-Type') {
            return 'application/json'
          }
        }
      },
      json: async () => response.data
    })
  }

  function mockedHttps (response: { status: number, data: any }): { request: (url: string, options: any, callback: (res: any) => void) => any } {
    const https = {
      request: (url, options, callback) => {
        // eslint-disable-next-line
        callback({
          statusCode: response.status,
          statusMessage: response.status === 200 ? 'OK' : 'Bad request',
          headers: {
            'content-type': 'application/json'
          },
          on: (event, handler) => {
            if (event === 'data') handler(JSON.stringify(response.data))
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
