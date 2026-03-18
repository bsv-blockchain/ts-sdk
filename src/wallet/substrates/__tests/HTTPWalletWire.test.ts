import HTTPWalletWire from '../HTTPWalletWire'
import WalletWireCalls from '../WalletWireCalls'
import * as Utils from '../../../primitives/utils'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a valid binary message frame for a given call name with an optional
 * originator string and an arbitrary payload.
 *
 * Frame layout (mirrors WalletWireTransceiver.transmit):
 *   [callCode: uint8][originatorLength: uint8][originator: utf8 bytes][payload…]
 */
function buildFrame(
  callName: keyof typeof WalletWireCalls,
  originator = '',
  payload: number[] = []
): number[] {
  const callCode = WalletWireCalls[callName]
  const originatorBytes = Utils.toArray(originator, 'utf8')
  return [callCode, originatorBytes.length, ...originatorBytes, ...payload]
}

/** Resolve an ArrayBuffer from an array of byte values. */
function toArrayBuffer(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer
}

/**
 * Replace the global `fetch` with a jest mock that returns the given bytes.
 * HTTPWalletWire.transmitToWallet calls the *global* fetch, not this.httpClient.
 */
function mockGlobalFetch(responseBytes: number[]): jest.Mock {
  const mock = jest.fn().mockResolvedValue({
    arrayBuffer: () => Promise.resolve(toArrayBuffer(responseBytes)),
  } as unknown as Response)
  global.fetch = mock
  return mock
}

function mockGlobalFetchWithNetworkError(message = 'Network error'): jest.Mock {
  const mock = jest.fn().mockRejectedValue(new Error(message))
  global.fetch = mock
  return mock
}

// Preserve the real fetch so we can restore it between tests.
const realFetch = global.fetch

afterEach(() => {
  global.fetch = realFetch
  jest.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – constructor', () => {
  it('stores the baseUrl', () => {
    const wire = new HTTPWalletWire('example.com', 'http://my-server:9000')
    expect(wire.baseUrl).toBe('http://my-server:9000')
  })

  it('uses http://localhost:3301 as the default baseUrl', () => {
    const wire = new HTTPWalletWire('example.com')
    expect(wire.baseUrl).toBe('http://localhost:3301')
  })

  it('stores the originator', () => {
    const wire = new HTTPWalletWire('wallet.example.com')
    expect(wire.originator).toBe('wallet.example.com')
  })

  it('accepts undefined originator', () => {
    const wire = new HTTPWalletWire(undefined)
    expect(wire.originator).toBeUndefined()
  })

  it('stores a custom httpClient (even though transmitToWallet uses global fetch)', () => {
    const mockFetch = jest.fn()
    const wire = new HTTPWalletWire(
      'example.com',
      'http://localhost:3301',
      mockFetch as unknown as typeof fetch
    )
    expect(wire.httpClient).toBe(mockFetch)
  })
})

// ---------------------------------------------------------------------------
// transmitToWallet – invalid call code
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – transmitToWallet invalid call code', () => {
  it('throws on call code 0 (not in enum)', async () => {
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')
    const invalidMessage = [0] // 0 maps to undefined in the enum
    await expect(wire.transmitToWallet(invalidMessage)).rejects.toThrow('Invalid call code')
  })

  it('throws on call code 255 (out of range)', async () => {
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')
    const invalidMessage = [255]
    await expect(wire.transmitToWallet(invalidMessage)).rejects.toThrow('Invalid call code')
  })
})

// ---------------------------------------------------------------------------
// transmitToWallet – request building
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – transmitToWallet request', () => {
  it('calls global fetch with the correct URL derived from the call name', async () => {
    const mockFetch = mockGlobalFetch([1, 2, 3])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion'))

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('http://localhost:3301/getVersion')
  })

  it('uses POST method', async () => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion'))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(init.method).toBe('POST')
  })

  it('sets Content-Type to application/octet-stream', async () => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion'))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers['Content-Type']).toBe('application/octet-stream')
  })

  it('sets Origin header to the originator encoded in the message frame', async () => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion', 'myapp.example.com'))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers['Origin']).toBe('myapp.example.com')
  })

  it('sets Origin to empty string when frame originator is absent', async () => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion', ''))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(headers['Origin']).toBe('')
  })

  it('sends a Uint8Array body containing the payload bytes', async () => {
    const payload = [0xde, 0xad, 0xbe, 0xef]
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion', '', payload))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(init.body).toBeInstanceOf(Uint8Array)
    const bodyBytes = Array.from(init.body as Uint8Array)
    expect(bodyBytes).toEqual(payload)
  })

  it('sends an empty Uint8Array body when there is no payload', async () => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame('getVersion', ''))

    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(Array.from(init.body as Uint8Array)).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// transmitToWallet – response handling
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – transmitToWallet response', () => {
  it('returns the response body as a number array', async () => {
    const responseBytes = [0xca, 0xfe, 0xba, 0xbe]
    mockGlobalFetch(responseBytes)
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    const result = await wire.transmitToWallet(buildFrame('getVersion'))
    expect(result).toEqual(responseBytes)
  })

  it('returns an empty array when response body is empty', async () => {
    mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    const result = await wire.transmitToWallet(buildFrame('getVersion'))
    expect(result).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// transmitToWallet – network errors
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – network errors', () => {
  it('propagates a fetch rejection', async () => {
    mockGlobalFetchWithNetworkError('Failed to connect')
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await expect(wire.transmitToWallet(buildFrame('getVersion'))).rejects.toThrow('Failed to connect')
  })
})

// ---------------------------------------------------------------------------
// transmitToWallet – call-name routing smoke tests
// ---------------------------------------------------------------------------

describe('HTTPWalletWire – call-name routing', () => {
  const callsToTest: Array<keyof typeof WalletWireCalls> = [
    'createAction',
    'signAction',
    'abortAction',
    'listActions',
    'internalizeAction',
    'listOutputs',
    'relinquishOutput',
    'getPublicKey',
    'encrypt',
    'decrypt',
    'createHmac',
    'verifyHmac',
    'createSignature',
    'verifySignature',
    'acquireCertificate',
    'listCertificates',
    'proveCertificate',
    'relinquishCertificate',
    'discoverByIdentityKey',
    'discoverByAttributes',
    'isAuthenticated',
    'waitForAuthentication',
    'getHeight',
    'getHeaderForHeight',
    'getNetwork',
    'getVersion',
  ]

  it.each(callsToTest)('routes %s to the correct URL segment', async (callName) => {
    const mockFetch = mockGlobalFetch([])
    const wire = new HTTPWalletWire(undefined, 'http://localhost:3301')

    await wire.transmitToWallet(buildFrame(callName))

    const [url] = mockFetch.mock.calls[0] as [string]
    expect(url).toBe(`http://localhost:3301/${callName}`)
  })
})
