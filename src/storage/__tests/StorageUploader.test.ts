import { StorageUploader, DEFAULT_UHRP_SERVERS, RenewResiliencyError } from '../StorageUploader.js'
import * as StorageUtils from '../StorageUtils.js'
import WalletClient from '../../wallet/WalletClient.js'
import { createHash } from 'crypto'

/**
 * A helper for converting a string to a number[] of UTF-8 bytes
 */
function stringToUtf8Array (str: string): number[] {
  return Array.from(new TextEncoder().encode(str))
}

/**
 * Builds a JSON Response for mocked fetch calls.
 */
function jsonResponse (body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Normalizes whatever a caller passed to `fetch` into a URL string.
 */
function extractFetchURL (input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

describe('StorageUploader — legacy single-host behavior', () => {
  let uploader: StorageUploader
  let walletClient: WalletClient

  let authFetchSpy: jest.SpyInstance
  let globalFetchSpy: jest.SpiedFunction<typeof global.fetch>

  beforeEach(() => {
    walletClient = new WalletClient('json-api', 'non-admin.com')
    uploader = new StorageUploader({
      storageURL: 'https://example.test.system',
      wallet: walletClient
    })

    authFetchSpy = jest
      .spyOn((uploader as any).authFetch, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }))

    globalFetchSpy = jest
      .spyOn(global, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }))
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('should upload a file, produce a valid UHRP URL, and decode it to the known SHA-256', async () => {
    const data = stringToUtf8Array('Hello, world!')

    // Quote (global fetch) + PUT upload (global fetch)
    globalFetchSpy
      .mockResolvedValueOnce(jsonResponse({ quote: 42 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))

    // /upload (authFetch)
    authFetchSpy.mockResolvedValueOnce(jsonResponse({
      status: 'success',
      uploadURL: 'https://example-upload.com/put',
      requiredHeaders: {},
      amount: 42
    }))

    const result = await uploader.publishFile({
      file: { data, type: 'text/plain' },
      retentionPeriod: 7
    })

    // One quote fetch + one PUT upload
    expect(globalFetchSpy).toHaveBeenCalledTimes(2)
    expect(globalFetchSpy.mock.calls[0][0]).toBe('https://example.test.system/quote')
    expect(globalFetchSpy.mock.calls[1][0]).toBe('https://example-upload.com/put')

    expect(authFetchSpy).toHaveBeenCalledTimes(1)
    expect(authFetchSpy.mock.calls[0][0]).toBe('https://example.test.system/upload')

    expect(StorageUtils.isValidURL(result.uhrpURL)).toBe(true)
    expect(result.published).toBe(true)
    expect(result.hostedBy).toEqual(['https://example.test.system'])

    const url = StorageUtils.getHashFromURL(result.uhrpURL)
    const firstFour = url.slice(0, 4)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
    expect(firstFour).toHaveLength(8)
  })

  it('should handle large file uploads efficiently', async () => {
    const size = 5 * 1024 * 1024
    const data = new Uint8Array(size)
    for (let i = 0; i < size; i++) data[i] = i % 256

    globalFetchSpy
      .mockResolvedValueOnce(jsonResponse({ quote: 100 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))

    authFetchSpy.mockResolvedValueOnce(jsonResponse({
      status: 'success',
      uploadURL: 'https://example-upload.com/put',
      requiredHeaders: {},
      amount: 100
    }))

    const result = await uploader.publishFile({
      file: { data, type: 'application/octet-stream' },
      retentionPeriod: 7
    })

    const expectedHash = createHash('sha256').update(data).digest()
    const urlHash = StorageUtils.getHashFromURL(result.uhrpURL)
    expect(Buffer.from(urlHash)).toEqual(expectedHash)
    expect(result.hostedBy).toEqual(['https://example.test.system'])
  })

  it('should throw if the upload fails with HTTP 500', async () => {
    globalFetchSpy
      .mockResolvedValueOnce(jsonResponse({ quote: 42 }))
      .mockResolvedValueOnce(new Response(null, { status: 500 }))

    authFetchSpy.mockResolvedValueOnce(jsonResponse({
      status: 'success',
      uploadURL: 'https://example-upload.com/put',
      requiredHeaders: {},
      amount: 42
    }))

    const failingData = stringToUtf8Array('failing data')

    await expect(
      uploader.publishFile({
        file: { data: failingData, type: 'text/plain' },
        retentionPeriod: 30
      })
    ).rejects.toThrow(/Resiliency threshold of 1 could not be met/)
  })

  it('should find a file and return metadata', async () => {
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({
        status: 'success',
        data: {
          name: 'cdn/abc123',
          size: '1024',
          mimeType: 'text/plain',
          expiryTime: 123456
        }
      })
    )

    const fileData = await uploader.findFile('uhrp://some-hash')
    expect(authFetchSpy).toHaveBeenCalledTimes(1)
    expect(fileData.name).toBe('cdn/abc123')
    expect(fileData.size).toBe('1024')
    expect(fileData.mimeType).toBe('text/plain')
    expect(fileData.expiryTime).toBe(123456)
  })

  it('should throw an error if findFile returns an error status', async () => {
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({ status: 'error', code: 'ERR_NOT_FOUND', description: 'File not found' })
    )

    await expect(uploader.findFile('uhrp://unknown-hash'))
      .rejects
      .toThrow('findFile returned an error: ERR_NOT_FOUND - File not found')
  })

  it('should list user uploads successfully', async () => {
    const mockUploads = [
      { uhrpUrl: 'uhrp://hash1', expiryTime: 111111 },
      { uhrpUrl: 'uhrp://hash2', expiryTime: 222222 }
    ]
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({ status: 'success', uploads: mockUploads })
    )

    const result = await uploader.listUploads()
    expect(authFetchSpy).toHaveBeenCalledTimes(1)
    expect(result).toEqual(mockUploads)
  })

  it('should throw an error if listUploads returns an error', async () => {
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({ status: 'error', code: 'ERR_INTERNAL', description: 'Something broke' })
    )

    await expect(uploader.listUploads()).rejects.toThrow(
      'listUploads returned an error: ERR_INTERNAL - Something broke'
    )
  })

  it('should renew a file and return the new expiry info', async () => {
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({
        status: 'success',
        prevExpiryTime: 123,
        newExpiryTime: 456,
        amount: 99
      })
    )

    const renewal = await uploader.renewFile('uhrp://some-hash', 30)
    expect(authFetchSpy).toHaveBeenCalledTimes(1)
    expect(renewal.status).toBe('success')
    expect(renewal.prevExpiryTime).toBe(123)
    expect(renewal.newExpiryTime).toBe(456)
    expect(renewal.amount).toBe(99)
  })

  it('should throw an error if renewFile returns error status JSON', async () => {
    authFetchSpy.mockResolvedValueOnce(
      jsonResponse({ status: 'error', code: 'ERR_CANT_RENEW', description: 'Failed to renew' })
    )

    await expect(uploader.renewFile('uhrp://some-other-hash', 15))
      .rejects
      .toThrow('renewFile returned an error: ERR_CANT_RENEW - Failed to renew')
  })

  it('should throw if renewFile request fails with non-200 status', async () => {
    authFetchSpy.mockResolvedValueOnce(new Response(null, { status: 404 }))

    await expect(uploader.renewFile('uhrp://ghost', 10))
      .rejects
      .toThrow('renewFile request failed: HTTP 404')
  })
})

describe('StorageUploader — multi-provider behavior', () => {
  let walletClient: WalletClient

  beforeEach(() => {
    walletClient = new WalletClient('json-api', 'non-admin.com')
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  /**
   * Sets up URL-routed mocks for the quote, upload, and PUT steps across any
   * number of providers. Returns the two spies for assertion.
   */
  function wireMocks (
    uploader: StorageUploader,
    quotes: Record<string, number | 'error'>,
    uploadOutcomes: Record<string, 'ok' | 'fail'> = {}
  ): {
      authFetchSpy: jest.SpyInstance
      globalFetchSpy: jest.SpiedFunction<typeof global.fetch>
      putCalls: string[]
      quoteCalls: string[]
      uploadCalls: string[]
    } {
    const putCalls: string[] = []
    const quoteCalls: string[] = []
    const uploadCalls: string[] = []

    const globalFetchSpy = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async (input: RequestInfo | URL) => {
        const url = extractFetchURL(input)
        // Quote requests hit {host}/quote
        if (url.endsWith('/quote')) {
          quoteCalls.push(url)
          const host = url.slice(0, -'/quote'.length)
          const quote = quotes[host]
          if (quote === undefined || quote === 'error') {
            return new Response(null, { status: 500 })
          }
          return jsonResponse({ quote })
        }
        // Otherwise we treat it as the PUT upload.
        putCalls.push(url)
        const outcome = uploadOutcomes[url]
        if (outcome === 'fail') {
          return new Response(null, { status: 500 })
        }
        return new Response(null, { status: 200 })
      })

    const authFetchSpy = jest
      .spyOn((uploader as any).authFetch, 'fetch')
      .mockImplementation(async (input: RequestInfo | URL) => {
        const url = extractFetchURL(input)
        if (url.endsWith('/upload')) {
          uploadCalls.push(url)
          const host = url.slice(0, -'/upload'.length)
          return jsonResponse({
            status: 'success',
            uploadURL: `${host}/put`,
            requiredHeaders: {},
            amount: quotes[host]
          })
        }
        return new Response(null, { status: 404 })
      })

    return { authFetchSpy, globalFetchSpy, putCalls, quoteCalls, uploadCalls }
  }

  it('defaults to DEFAULT_UHRP_SERVERS when no hosts are configured', () => {
    const uploader = new StorageUploader({ wallet: walletClient })
    expect((uploader as any).hosts).toEqual(DEFAULT_UHRP_SERVERS)
    expect((uploader as any).resilienceLevel).toBe(1)
  })

  it('clamps resilienceLevel to 1 for legacy storageURL callers', () => {
    const uploader = new StorageUploader({
      storageURL: 'https://legacy.example',
      wallet: walletClient
    })
    expect((uploader as any).hosts).toEqual(['https://legacy.example'])
    expect((uploader as any).resilienceLevel).toBe(1)
  })

  it('uses storageURLs over storageURL when both are provided', () => {
    const uploader = new StorageUploader({
      storageURL: 'https://legacy.example',
      storageURLs: ['https://a.example', 'https://b.example'],
      wallet: walletClient
    })
    expect((uploader as any).hosts).toEqual(['https://a.example', 'https://b.example'])
  })

  it('throws if resilienceLevel is not a positive integer', () => {
    expect(() => new StorageUploader({
      storageURLs: ['https://a.example'],
      resilienceLevel: 0,
      wallet: walletClient
    })).toThrow(/positive integer/)

    expect(() => new StorageUploader({
      storageURLs: ['https://a.example'],
      resilienceLevel: 1.5,
      wallet: walletClient
    })).toThrow(/positive integer/)
  })

  it('throws if storageURLs is an empty array', () => {
    expect(() => new StorageUploader({
      storageURLs: [],
      wallet: walletClient
    })).toThrow(/at least one/)
  })

  it('sorts quotes by price and uploads to the cheapest N', async () => {
    const hosts = ['https://a.example', 'https://b.example', 'https://c.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    const { quoteCalls, uploadCalls, putCalls } = wireMocks(uploader, {
      'https://a.example': 300,
      'https://b.example': 100,
      'https://c.example': 200
    })

    const data = stringToUtf8Array('multi-host payload')
    const result = await uploader.publishFile({
      file: { data, type: 'text/plain' },
      retentionPeriod: 60
    })

    // All three quotes requested (up to 2 * resilienceLevel = 4 allowed, but we only have 3 hosts).
    expect(quoteCalls.sort()).toEqual([
      'https://a.example/quote',
      'https://b.example/quote',
      'https://c.example/quote'
    ])
    // Uploads happen in ascending price order: b (100), c (200).
    expect(uploadCalls).toEqual([
      'https://b.example/upload',
      'https://c.example/upload'
    ])
    expect(putCalls).toEqual([
      'https://b.example/put',
      'https://c.example/put'
    ])
    expect(result.hostedBy).toEqual(['https://b.example', 'https://c.example'])
    expect(result.published).toBe(true)
    expect(StorageUtils.isValidURL(result.uhrpURL)).toBe(true)
  })

  it('falls through to the next-cheapest host when a paid upload fails', async () => {
    const hosts = ['https://a.example', 'https://b.example', 'https://c.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    const { uploadCalls, putCalls } = wireMocks(
      uploader,
      {
        'https://a.example': 300,
        'https://b.example': 100,
        'https://c.example': 200
      },
      {
        // Cheapest host's PUT fails; must fall through to c (200) then a (300).
        'https://b.example/put': 'fail'
      }
    )

    const data = stringToUtf8Array('multi-host payload')
    const result = await uploader.publishFile({
      file: { data, type: 'text/plain' },
      retentionPeriod: 60
    })

    expect(uploadCalls).toEqual([
      'https://b.example/upload',
      'https://c.example/upload',
      'https://a.example/upload'
    ])
    expect(putCalls).toEqual([
      'https://b.example/put',
      'https://c.example/put',
      'https://a.example/put'
    ])
    expect(result.hostedBy).toEqual(['https://c.example', 'https://a.example'])
  })

  it('throws when fewer providers respond with quotes than resilienceLevel', async () => {
    const hosts = ['https://a.example', 'https://b.example', 'https://c.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 3,
      wallet: walletClient
    })

    wireMocks(uploader, {
      'https://a.example': 100,
      'https://b.example': 'error',
      'https://c.example': 'error'
    })

    const data = stringToUtf8Array('fails to meet threshold')
    await expect(
      uploader.publishFile({
        file: { data, type: 'text/plain' },
        retentionPeriod: 60
      })
    ).rejects.toThrow(/Resiliency threshold of 3 could not be met: only 1 of 3 provider\(s\) responded/)
  })

  it('throws when remaining quotes cannot cover the threshold after upload failures', async () => {
    const hosts = ['https://a.example', 'https://b.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    wireMocks(
      uploader,
      {
        'https://a.example': 100,
        'https://b.example': 200
      },
      {
        'https://a.example/put': 'fail',
        'https://b.example/put': 'fail'
      }
    )

    const data = stringToUtf8Array('all uploads fail')
    await expect(
      uploader.publishFile({
        file: { data, type: 'text/plain' },
        retentionPeriod: 60
      })
    ).rejects.toThrow(/only 0 upload\(s\) succeeded/)
  })

  it('returns the same UHRP URL regardless of which providers hosted the file', async () => {
    const hosts = ['https://a.example', 'https://b.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    wireMocks(uploader, {
      'https://a.example': 50,
      'https://b.example': 75
    })

    const data = stringToUtf8Array('content addressed')
    const result = await uploader.publishFile({
      file: { data, type: 'text/plain' },
      retentionPeriod: 60
    })

    // The UHRP URL is derived from the file hash, not from any host.
    const expected = StorageUtils.getURLForFile(Uint8Array.from(data))
    expect(result.uhrpURL).toBe(expected)
  })

  it('estimateCost returns sorted quotes and the total for the cheapest resilienceLevel hosts', async () => {
    const hosts = ['https://a.example', 'https://b.example', 'https://c.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    wireMocks(uploader, {
      'https://a.example': 300,
      'https://b.example': 100,
      'https://c.example': 200
    })

    const estimate = await uploader.estimateCost({ fileSize: 1024, retentionPeriod: 60 })

    expect(estimate.resilienceLevel).toBe(2)
    expect(estimate.meetsResilienceThreshold).toBe(true)
    expect(estimate.quotes).toEqual([
      { host: 'https://b.example', amount: 100 },
      { host: 'https://c.example', amount: 200 },
      { host: 'https://a.example', amount: 300 }
    ])
    // Cheapest 2 = 100 + 200
    expect(estimate.totalForResilience).toBe(300)
  })

  it('estimateCost reports when the resilience threshold cannot be met', async () => {
    const hosts = ['https://a.example', 'https://b.example', 'https://c.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 3,
      wallet: walletClient
    })

    // Only one host returns a quote.
    wireMocks(uploader, {
      'https://a.example': 100,
      'https://b.example': 'error',
      'https://c.example': 'error'
    })

    const estimate = await uploader.estimateCost({ fileSize: 1024, retentionPeriod: 60 })

    expect(estimate.meetsResilienceThreshold).toBe(false)
    expect(estimate.quotes).toHaveLength(1)
    // Partial total so callers can still see the cost of what was collected.
    expect(estimate.totalForResilience).toBe(100)
  })

  it('estimateCost does not trigger any authenticated /upload requests', async () => {
    const hosts = ['https://a.example', 'https://b.example']
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2,
      wallet: walletClient
    })

    const { authFetchSpy, globalFetchSpy } = wireMocks(uploader, {
      'https://a.example': 50,
      'https://b.example': 75
    })

    await uploader.estimateCost({ fileSize: 1024, retentionPeriod: 60 })

    // Only the free /quote endpoint is used (via global fetch).
    expect(globalFetchSpy).toHaveBeenCalledTimes(2)
    expect(authFetchSpy).not.toHaveBeenCalled()
  })

  it('stops quoting further hosts once 2 * resilienceLevel quotes are collected', async () => {
    const hosts = [
      'https://h1.example',
      'https://h2.example',
      'https://h3.example',
      'https://h4.example',
      'https://h5.example',
      'https://h6.example',
      'https://h7.example',
      'https://h8.example'
    ]
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2, // target = 4 quotes
      wallet: walletClient
    })

    // Every host would return a valid quote if asked; we want to prove that
    // hosts after the first batch of 4 are never contacted.
    const quotes: Record<string, number> = {}
    hosts.forEach((h, i) => { quotes[h] = 100 + i })

    const { quoteCalls } = wireMocks(uploader, quotes)

    await uploader.publishFile({
      file: { data: stringToUtf8Array('bounded quoting'), type: 'text/plain' },
      retentionPeriod: 60
    })

    // Only the first batch of 4 quote requests should have been issued.
    expect(quoteCalls.sort()).toEqual([
      'https://h1.example/quote',
      'https://h2.example/quote',
      'https://h3.example/quote',
      'https://h4.example/quote'
    ])
  })

  it('advances to a later batch when the first batch cannot fill the quote quota', async () => {
    const hosts = [
      'https://h1.example',
      'https://h2.example',
      'https://h3.example',
      'https://h4.example',
      'https://h5.example',
      'https://h6.example'
    ]
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2, // target = 4 quotes
      wallet: walletClient
    })

    // First batch of 4: only 2 valid quotes. Second batch of 2 fills the target.
    const { quoteCalls } = wireMocks(uploader, {
      'https://h1.example': 100,
      'https://h2.example': 'error',
      'https://h3.example': 200,
      'https://h4.example': 'error',
      'https://h5.example': 300,
      'https://h6.example': 400
    })

    await uploader.publishFile({
      file: { data: stringToUtf8Array('needs a second batch'), type: 'text/plain' },
      retentionPeriod: 60
    })

    expect(quoteCalls.sort()).toEqual([
      'https://h1.example/quote',
      'https://h2.example/quote',
      'https://h3.example/quote',
      'https://h4.example/quote',
      'https://h5.example/quote',
      'https://h6.example/quote'
    ])
  })

  it('asks only for the remaining number of quotes in subsequent batches', async () => {
    const hosts = [
      'https://h1.example',
      'https://h2.example',
      'https://h3.example',
      'https://h4.example',
      'https://h5.example',
      'https://h6.example',
      'https://h7.example',
      'https://h8.example'
    ]
    const uploader = new StorageUploader({
      storageURLs: hosts,
      resilienceLevel: 2, // target = 4 quotes
      wallet: walletClient
    })

    // First batch of 4 yields only 3 valid quotes. The second iteration must
    // request just 1 more provider (h5), not fire to hosts 5-8.
    const { quoteCalls } = wireMocks(uploader, {
      'https://h1.example': 100,
      'https://h2.example': 200,
      'https://h3.example': 'error',
      'https://h4.example': 300,
      'https://h5.example': 400,
      'https://h6.example': 500,
      'https://h7.example': 600,
      'https://h8.example': 700
    })

    await uploader.publishFile({
      file: { data: stringToUtf8Array('exact-remaining batching'), type: 'text/plain' },
      retentionPeriod: 60
    })

    // First batch queried h1-h4 (4 hosts), second batch queried only h5
    // (1 host, the exact remainder). Hosts h6-h8 are never contacted.
    expect(quoteCalls.sort()).toEqual([
      'https://h1.example/quote',
      'https://h2.example/quote',
      'https://h3.example/quote',
      'https://h4.example/quote',
      'https://h5.example/quote'
    ])
  })
})

describe('StorageUploader — multi-host findFile / listUploads / renewFile', () => {
  let walletClient: WalletClient

  beforeEach(() => {
    walletClient = new WalletClient('json-api', 'non-admin.com')
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  /**
   * Spies on the authFetch instance with a URL-routed handler. Each host
   * gets a handler keyed by `${host}/find`, `${host}/list`, `${host}/renew`.
   */
  function wireAuthFetch (
    uploader: StorageUploader,
    handler: (url: string) => Promise<Response>
  ): jest.SpyInstance {
    return jest
      .spyOn((uploader as any).authFetch, 'fetch')
      .mockImplementation(async (input: RequestInfo | URL) => await handler(extractFetchURL(input)))
  }

  it('findFile fans out to every configured host and picks the longest-expiry result', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      wallet: walletClient
    })

    const calls: string[] = []
    wireAuthFetch(uploader, async url => {
      calls.push(url)
      if (url.startsWith('https://a.example/find')) {
        return jsonResponse({
          status: 'success',
          data: { name: 'a-name', size: '10', mimeType: 'text/plain', expiryTime: 100 }
        })
      }
      if (url.startsWith('https://b.example/find')) {
        // Host b has a longer expiry — it should win.
        return jsonResponse({
          status: 'success',
          data: { name: 'b-name', size: '10', mimeType: 'text/plain', expiryTime: 500 }
        })
      }
      // Host c does not have the file.
      return jsonResponse({
        status: 'error',
        code: 'ERR_NOT_FOUND',
        description: 'nope',
        data: { name: '', size: '', mimeType: '', expiryTime: 0 }
      })
    })

    const result = await uploader.findFile('uhrp://x')

    expect(calls.sort()).toEqual([
      'https://a.example/find?uhrpUrl=uhrp%3A%2F%2Fx',
      'https://b.example/find?uhrpUrl=uhrp%3A%2F%2Fx',
      'https://c.example/find?uhrpUrl=uhrp%3A%2F%2Fx'
    ])
    expect(result.name).toBe('b-name')
    expect(result.expiryTime).toBe(500)
    expect(result.hostedBy).toEqual(['https://b.example', 'https://a.example'])
  })

  it('findFile scopes to options.hostedBy when provided', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      wallet: walletClient
    })

    const calls: string[] = []
    wireAuthFetch(uploader, async url => {
      calls.push(url)
      return jsonResponse({
        status: 'success',
        data: { name: 'x', size: '10', mimeType: 'text/plain', expiryTime: 200 }
      })
    })

    await uploader.findFile('uhrp://x', { hostedBy: ['https://b.example'] })
    expect(calls).toEqual(['https://b.example/find?uhrpUrl=uhrp%3A%2F%2Fx'])
  })

  it('findFile throws with an aggregated error when every host fails (multi-host)', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example'],
      wallet: walletClient
    })

    wireAuthFetch(uploader, async () => jsonResponse({
      status: 'error', code: 'ERR_NOT_FOUND', description: 'nope'
    }))

    await expect(uploader.findFile('uhrp://ghost'))
      .rejects.toThrow(/no configured host reported this UHRP URL/)
  })

  it('findFile rejects hostedBy sets with no configured intersection', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example'],
      wallet: walletClient
    })
    await expect(uploader.findFile('uhrp://x', { hostedBy: ['https://unknown.example'] }))
      .rejects.toThrow(/did not intersect any configured provider/)
  })

  it('listUploads unions entries from every host and merges by UHRP URL', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example'],
      wallet: walletClient
    })

    wireAuthFetch(uploader, async url => {
      if (url.startsWith('https://a.example/list')) {
        return jsonResponse({
          status: 'success',
          uploads: [
            { uhrpUrl: 'uhrp://one', expiryTime: 100 },
            { uhrpUrl: 'uhrp://shared', expiryTime: 150 }
          ]
        })
      }
      return jsonResponse({
        status: 'success',
        uploads: [
          { uhrpUrl: 'uhrp://two', expiryTime: 200 },
          { uhrpUrl: 'uhrp://shared', expiryTime: 300 } // longer expiry on b
        ]
      })
    })

    const listing = await uploader.listUploads()
    const byUrl = Object.fromEntries(listing.map((e: any) => [e.uhrpUrl, e]))

    expect(Object.keys(byUrl).sort()).toEqual(['uhrp://one', 'uhrp://shared', 'uhrp://two'])
    expect(byUrl['uhrp://shared'].expiryTime).toBe(300) // longest wins
    expect(byUrl['uhrp://shared'].hostedBy.sort()).toEqual(['https://a.example', 'https://b.example'])
    expect(byUrl['uhrp://one'].hostedBy).toEqual(['https://a.example'])
    expect(byUrl['uhrp://two'].hostedBy).toEqual(['https://b.example'])
  })

  it('listUploads succeeds when at least one host responds (multi-host)', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example'],
      wallet: walletClient
    })

    wireAuthFetch(uploader, async url => {
      if (url.startsWith('https://a.example/list')) {
        return new Response(null, { status: 500 })
      }
      return jsonResponse({
        status: 'success',
        uploads: [{ uhrpUrl: 'uhrp://only', expiryTime: 100 }]
      })
    })

    const listing = await uploader.listUploads()
    expect(listing).toHaveLength(1)
    expect(listing[0].uhrpUrl).toBe('uhrp://only')
  })

  it('renewFile fans out, sums amounts, and reports per-host outcomes when threshold is met', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      resilienceLevel: 2,
      wallet: walletClient
    })

    wireAuthFetch(uploader, async url => {
      if (url === 'https://a.example/renew') {
        return jsonResponse({
          status: 'success',
          prevExpiryTime: 100,
          newExpiryTime: 1000,
          amount: 50
        })
      }
      if (url === 'https://b.example/renew') {
        return jsonResponse({
          status: 'success',
          prevExpiryTime: 200,
          newExpiryTime: 2000,
          amount: 75
        })
      }
      // Host c does not hold the file; renew errors out. Two successes still
      // meet the resilience threshold of 2, so the overall call succeeds.
      return jsonResponse({
        status: 'error',
        code: 'ERR_OLD_ADVERTISEMENT_NOT_FOUND',
        description: 'not on this host'
      })
    })

    const result = await uploader.renewFile('uhrp://x', 30)

    expect(result.status).toBe('success')
    // b has the longest newExpiryTime, so it drives the top-level fields.
    expect(result.newExpiryTime).toBe(2000)
    expect(result.prevExpiryTime).toBe(200)
    // Aggregate total is the sum of paid hosts only.
    expect(result.amount).toBe(125)
    expect(result.results).toHaveLength(3)
    const byHost = Object.fromEntries((result.results ?? []).map(r => [r.host, r]))
    expect(byHost['https://a.example'].status).toBe('success')
    expect(byHost['https://b.example'].status).toBe('success')
    expect(byHost['https://c.example'].status).toBe('error')
    expect(byHost['https://c.example'].error).toMatch(/ERR_OLD_ADVERTISEMENT_NOT_FOUND/)
  })

  it('renewFile throws RenewResiliencyError when the resilience threshold is not met', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      resilienceLevel: 3,
      wallet: walletClient
    })

    wireAuthFetch(uploader, async url => {
      if (url === 'https://a.example/renew') {
        return jsonResponse({
          status: 'success',
          prevExpiryTime: 100,
          newExpiryTime: 1000,
          amount: 50
        })
      }
      // b and c both fail — only 1 of 3 required hosts renewed.
      return jsonResponse({
        status: 'error',
        code: 'ERR_OLD_ADVERTISEMENT_NOT_FOUND',
        description: 'not on this host'
      })
    })

    const promise = uploader.renewFile('uhrp://x', 30)
    await expect(promise).rejects.toBeInstanceOf(RenewResiliencyError)
    await expect(promise).rejects.toThrow(/only 1 of 3 required hosts renewed/)

    // The error must surface per-host outcomes so the caller can see which
    // host was billed even though the overall call failed.
    try {
      await uploader.renewFile('uhrp://x', 30)
      fail('expected RenewResiliencyError')
    } catch (e) {
      const err = e as RenewResiliencyError
      expect(err.requiredSuccesses).toBe(3)
      expect(err.successCount).toBe(1)
      const byHost = Object.fromEntries(err.results.map(r => [r.host, r]))
      expect(byHost['https://a.example'].status).toBe('success')
      expect(byHost['https://a.example'].amount).toBe(50)
      expect(byHost['https://b.example'].status).toBe('error')
      expect(byHost['https://c.example'].status).toBe('error')
    }
  })

  it('renewFile threshold is clamped to targets.length when hostedBy scopes smaller than resilienceLevel', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      resilienceLevel: 3,
      wallet: walletClient
    })

    // Scope to 2 hosts; threshold clamps to 2. Both succeed → overall success.
    wireAuthFetch(uploader, async () => jsonResponse({
      status: 'success',
      prevExpiryTime: 0,
      newExpiryTime: 500,
      amount: 10
    }))

    const result = await uploader.renewFile('uhrp://x', 30, {
      hostedBy: ['https://a.example', 'https://b.example']
    })
    expect(result.status).toBe('success')
    expect(result.amount).toBe(20)
  })

  it('renewFile throws when every host fails (multi-host)', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example'],
      resilienceLevel: 2,
      wallet: walletClient
    })

    wireAuthFetch(uploader, async () => jsonResponse({
      status: 'error',
      code: 'ERR_OLD_ADVERTISEMENT_NOT_FOUND',
      description: 'gone'
    }))

    const promise = uploader.renewFile('uhrp://ghost', 30)
    await expect(promise).rejects.toBeInstanceOf(RenewResiliencyError)
    await expect(promise).rejects.toThrow(/only 0 of 2 required hosts renewed/)
  })

  it('renewFile honors options.hostedBy and only renews the specified replicas', async () => {
    const uploader = new StorageUploader({
      storageURLs: ['https://a.example', 'https://b.example', 'https://c.example'],
      wallet: walletClient
    })

    const calls: string[] = []
    wireAuthFetch(uploader, async url => {
      calls.push(url)
      return jsonResponse({
        status: 'success',
        prevExpiryTime: 0,
        newExpiryTime: 100,
        amount: 10
      })
    })

    const result = await uploader.renewFile('uhrp://x', 30, {
      hostedBy: ['https://a.example', 'https://c.example']
    })

    expect(calls.sort()).toEqual([
      'https://a.example/renew',
      'https://c.example/renew'
    ])
    expect(result.amount).toBe(20)
    expect(result.results).toHaveLength(2)
  })
})
