import { StorageUploader } from '../StorageUploader.js'
import * as StorageUtils from '../StorageUtils.js'
import WalletClient from '../../wallet/WalletClient.js'
import { createHash } from 'crypto'

/**
 * A helper for converting a string to a number[] of UTF-8 bytes
 */
function stringToUtf8Array(str: string): number[] {
  return Array.from(new TextEncoder().encode(str))
}

describe('StorageUploader Tests', () => {
  let uploader: StorageUploader
  let walletClient: WalletClient

  // We'll have TWO spies:
  let authFetchSpy: jest.SpyInstance
  let globalFetchSpy: jest.SpiedFunction<typeof global.fetch>

  beforeEach(() => {
    walletClient = new WalletClient('json-api', 'non-admin.com')
    uploader = new StorageUploader({
      storageURL: 'https://example.test.system',
      wallet: walletClient
    })

    // 1) Spy on the "authFetch.fetch" calls for /find, /list, /renew
    authFetchSpy = jest
      .spyOn(uploader['authFetch'], 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }))

    // 2) Spy on the global "fetch" calls for file upload (uploadFile)
    globalFetchSpy = jest
      .spyOn(global, 'fetch')
      .mockResolvedValue(new Response(null, { status: 200 }))
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('should upload a file, produce a valid UHRP URL, and decode it to the known SHA-256', async () => {
    const data = stringToUtf8Array('Hello, world!')

    // Mock out getUploadInfo so we can control the returned upload/public URLs
    jest.spyOn(uploader as any, 'getUploadInfo').mockResolvedValue({
      uploadURL: 'https://example-upload.com/put'
    })

    const result = await uploader.publishFile({
      file: { data, type: 'text/plain' },
      retentionPeriod: 7
    })

    // This direct upload uses global.fetch, not authFetch
    expect(globalFetchSpy).toHaveBeenCalledTimes(1)

    // Check the result
    expect(StorageUtils.isValidURL(result.uhrpURL)).toBe(true)
    expect(result.published).toBe(true)

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

    jest.spyOn(uploader as any, 'getUploadInfo').mockResolvedValue({
      uploadURL: 'https://example-upload.com/put'
    })

    const result = await uploader.publishFile({
      file: { data, type: 'application/octet-stream' },
      retentionPeriod: 7
    })

    const expectedHash = createHash('sha256').update(data).digest()
    const urlHash = StorageUtils.getHashFromURL(result.uhrpURL)
    expect(Buffer.from(urlHash)).toEqual(expectedHash)
  })

  it('should throw if the upload fails with HTTP 500', async () => {
    // Force the direct upload (global fetch) to fail
    globalFetchSpy.mockResolvedValueOnce(new Response(null, { status: 500 }))

    // Also mock getUploadInfo
    jest.spyOn(uploader as any, 'getUploadInfo').mockResolvedValue({
      uploadURL: 'https://example-upload.com/put'
    })

    const failingData = stringToUtf8Array('failing data')

    await expect(
      uploader.publishFile({
        file: { data: failingData, type: 'text/plain' },
        retentionPeriod: 30
      })
    ).rejects.toThrow('File upload failed: HTTP 500')
  })

  it('should find a file and return metadata', async () => {
    // This route goes through authFetch, not global fetch
    authFetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          status: 'success',
          data: {
            name: 'cdn/abc123',
            size: '1024',
            mimeType: 'text/plain',
            expiryTime: 123456
          }
        }),
        { status: 200 }
      )
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
      new Response(
        JSON.stringify({ status: 'error', code: 'ERR_NOT_FOUND', description: 'File not found' }),
        { status: 200 }
      )
    )

    await expect(uploader.findFile('uhrp://unknown-hash'))
      .rejects
      .toThrow('findFile returned an error: ERR_NOT_FOUND - File not found')
  })

  it('should list user uploads successfully', async () => {
    // /list uses authFetch
    const mockUploads = [
      { uhrpUrl: 'uhrp://hash1', expiryTime: 111111 },
      { uhrpUrl: 'uhrp://hash2', expiryTime: 222222 }
    ]
    authFetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'success', uploads: mockUploads }),
        { status: 200 }
      )
    )

    const result = await uploader.listUploads()
    expect(authFetchSpy).toHaveBeenCalledTimes(1)
    expect(result).toEqual(mockUploads)
  })

  it('should throw an error if listUploads returns an error', async () => {
    authFetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'error', code: 'ERR_INTERNAL', description: 'Something broke' }),
        { status: 200 }
      )
    )

    await expect(uploader.listUploads()).rejects.toThrow(
      'listUploads returned an error: ERR_INTERNAL - Something broke'
    )
  })

  it('should renew a file and return the new expiry info', async () => {
    // /renew uses authFetch
    authFetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          status: 'success',
          prevExpiryTime: 123,
          newExpiryTime: 456,
          amount: 99
        }),
        { status: 200 }
      )
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
      new Response(
        JSON.stringify({ status: 'error', code: 'ERR_CANT_RENEW', description: 'Failed to renew' }),
        { status: 200 }
      )
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
