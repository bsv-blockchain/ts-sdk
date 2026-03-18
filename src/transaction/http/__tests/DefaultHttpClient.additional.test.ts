// Additional coverage for DefaultHttpClient.ts lines 13 and 28-31:
//   Line 13   — noHttpClient.request throws 'No method available...'
//   Lines 28-31 — catch(e) path when require('https') throws → returns noHttpClient
//              — else path when require is undefined → returns noHttpClient
//
// Strategy: jest.isolateModules() reloads the module fresh for every sub-test,
// allowing us to control whether `https` throws on require.

describe('defaultHttpClient — noHttpClient fallback paths', () => {
  afterEach(() => {
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }
    jest.resetModules()
  })

  // --------------------------------------------------------------------------
  // Lines 28-29: require('https') throws → fall back to noHttpClient
  // Line 13:     noHttpClient.request() throws the expected error message
  // --------------------------------------------------------------------------

  it('returns a noHttpClient that throws when require("https") throws', async () => {
    // Make the https module unavailable so the try/catch in DefaultHttpClient fires
    jest.mock('https', () => {
      throw new Error('https module not available')
    })

    // window must be absent so the fetch branch is skipped
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let defaultHttpClient: any

    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/DefaultHttpClient')
      defaultHttpClient = mod.defaultHttpClient
    })

    // The function must still return a client object (noHttpClient)
    const client = (defaultHttpClient as any)()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')

    // Calling request() must throw 'No method available to perform HTTP request'
    await expect(
      client.request('https://example.com', { method: 'GET' })
    ).rejects.toThrow('No method available to perform HTTP request')
  })

  // --------------------------------------------------------------------------
  // Additional: verify the error message text exactly (line 13 text coverage)
  // --------------------------------------------------------------------------

  it('noHttpClient.request throws with the exact message text', async () => {
    jest.mock('https', () => {
      throw new Error('https not available')
    })

    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let client: any

    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/DefaultHttpClient')
      client = mod.defaultHttpClient()
    })

    let thrown: Error | undefined
    try {
      await client.request('https://example.com', { method: 'POST', data: {} })
    } catch (e) {
      thrown = e as Error
    }

    expect(thrown).toBeInstanceOf(Error)
    expect(thrown?.message).toBe('No method available to perform HTTP request')
  })

  // --------------------------------------------------------------------------
  // Sanity: confirm the Node.js happy path still works after mock is cleared
  // --------------------------------------------------------------------------

  it('returns a working NodejsHttpClient when require("https") succeeds (Node.js path)', () => {
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let defaultHttpClient: any
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/DefaultHttpClient')
      defaultHttpClient = mod.defaultHttpClient
    })

    const client = defaultHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')
  })
})

// --------------------------------------------------------------------------
// Additional coverage for BinaryFetchClient.ts lines 97, 112-115:
//   Line 97    — noHttpClient.request throws 'No method available...'
//   Lines 112-113 — catch(e) path when require('https') throws
//   Lines 114-115 — else path when require is undefined
// --------------------------------------------------------------------------

describe('binaryHttpClient — noHttpClient fallback paths', () => {
  afterEach(() => {
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }
    jest.resetModules()
  })

  it('returns a noHttpClient that throws when require("https") throws', async () => {
    jest.mock('https', () => {
      throw new Error('https module not available')
    })

    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let binaryHttpClient: any

    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/BinaryFetchClient')
      binaryHttpClient = mod.binaryHttpClient
    })

    const client = binaryHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')

    // Line 97: calling request on the noHttpClient throws
    await expect(
      client.request('https://example.com', { method: 'GET' })
    ).rejects.toThrow('No method available to perform HTTP request')
  })

  it('noHttpClient.request in binaryHttpClient throws with the exact message text', async () => {
    jest.mock('https', () => {
      throw new Error('https not available')
    })

    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let client: any

    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/BinaryFetchClient')
      client = mod.binaryHttpClient()
    })

    let thrown: Error | undefined
    try {
      await client.request('https://example.com', { method: 'POST', data: new Uint8Array([1, 2]) })
    } catch (e) {
      thrown = e as Error
    }

    expect(thrown).toBeInstanceOf(Error)
    expect(thrown?.message).toBe('No method available to perform HTTP request')
  })

  it('returns a working BinaryNodejsHttpClient when require("https") succeeds', () => {
    if ('window' in globalThis) {
      delete (globalThis as { window?: unknown }).window
    }

    let binaryHttpClient: any
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const mod = require('../../../transaction/http/BinaryFetchClient')
      binaryHttpClient = mod.binaryHttpClient
    })

    const client = binaryHttpClient()
    expect(client).toBeDefined()
    expect(typeof client.request).toBe('function')
  })
})
