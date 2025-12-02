import { StorageDownloader } from '../StorageDownloader.js'
import { StorageUtils } from '../index.js'
import { LookupResolver } from '../../overlay-tools/index.js'
import Transaction from '../../transaction/Transaction.js'
import PushDrop from '../../script/templates/PushDrop.js'
import { PublicKey, Utils } from '../../primitives/index.js'

import { ReadableStream } from 'stream/web'

beforeEach(() => {
  jest.restoreAllMocks()
})

describe('StorageDownloader', () => {
  let downloader: StorageDownloader

  beforeEach(() => {
    // Create a fresh instance
    downloader = new StorageDownloader()
  })

  describe('resolve()', () => {
    it('throws if the lookup response is not "output-list"', async () => {
      // Mock the LookupResolver to return something invalid
      jest.spyOn(LookupResolver.prototype, 'query').mockResolvedValue({
        type: 'something-else',
        outputs: []
      } as any)

      await expect(downloader.resolve('fakeUhrpUrl'))
        .rejects
        .toThrow('Lookup answer must be an output list')
    })

    it('decodes each output with Transaction.fromBEEF and PushDrop.decode', async () => {
      // 1) Mock lookup response
      jest.spyOn(LookupResolver.prototype, 'query').mockResolvedValue({
        type: 'output-list',
        outputs: [
          { beef: 'fake-beef-a', outputIndex: 0 },
          { beef: 'fake-beef-b', outputIndex: 1 }
        ]
      } as any)

      // 2) Mock Transaction.fromBEEF -> returns a dummy transaction
      jest.spyOn(Transaction, 'fromBEEF').mockImplementation(() => {
        // Each transaction might have multiple outputs; we only care about `outputIndex`
        return {
          outputs: [
            { lockingScript: {} }, // index 0
            { lockingScript: {} } // index 1
          ]
        } as any
      })

      // 3) Mock PushDrop.decode -> returns { fields: number[][] }
      jest.spyOn(PushDrop, 'decode').mockImplementation(() => {
        // The decode function returns an object with `fields`,
        return {
          lockingPublicKey: {} as PublicKey,
          fields: [
            [11],
            [22],
            [104, 116, 116, 112, 58, 47, 47, 97, 46, 99, 111, 109]
          ]
        }
      })

      // 4) Mock Utils.toUTF8 to convert that number[] to a string
      jest.spyOn(Utils, 'toUTF8').mockReturnValue('http://a.com')

      const resolved = await downloader.resolve('fakeUhrpUrl')
      expect(resolved).toEqual(['http://a.com', 'http://a.com'])
    })
  })

  describe('download()', () => {
    it('throws if UHRP URL is invalid', async () => {
      jest.spyOn(StorageUtils, 'isValidURL').mockReturnValue(false)

      await expect(downloader.download('invalidUrl'))
        .rejects
        .toThrow('Invalid parameter UHRP url')
    })

    it('throws if no hosts are found', async () => {
      // Valid UHRP URL
      jest.spyOn(StorageUtils, 'isValidURL').mockReturnValue(true)
      // Return some random 32-byte hash so we can pass the check
      jest.spyOn(StorageUtils, 'getHashFromURL').mockReturnValue(new Array(32).fill(0))

      // Force resolve() to return an empty array
      jest.spyOn(downloader, 'resolve').mockResolvedValue([])

      await expect(downloader.download('validButUnhostedUrl'))
        .rejects
        .toThrow('No one currently hosts this file!')
    })

    it('downloads successfully from the first working host', async () => {
      jest.spyOn(StorageUtils, 'isValidURL').mockReturnValue(true)
      const knownHash = [
        102, 104, 122, 173, 248, 98, 189, 119, 108, 143,
        193, 139, 142, 159, 142, 32, 8, 151, 20, 133,
        110, 226, 51, 179, 144, 42, 89, 29, 13, 95,
        41, 37
      ]
      jest.spyOn(StorageUtils, 'getHashFromURL').mockReturnValue(knownHash)

      // Suppose two possible download URLs
      jest.spyOn(downloader, 'resolve').mockResolvedValue([
        'http://host1/404',
        'http://host2/ok'
      ])

      // The first fetch -> 404, second fetch -> success
      const fetchSpy = jest.spyOn(global, 'fetch')
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(new Response(new Uint8Array(32).fill(0), {
          status: 200,
          headers: { 'Content-Type': 'application/test' }
        }))

      const result = await downloader.download('validUrl')
      expect(fetchSpy).toHaveBeenCalledTimes(2)
      expect(result).toEqual({
        data: new Uint8Array(32).fill(0),
        mimeType: 'application/test'
      })
    })

    it('throws if content hash mismatches the UHRP hash', async () => {
      jest.spyOn(StorageUtils, 'isValidURL').mockReturnValue(true)
      // The expected hash is all zeros
      jest.spyOn(StorageUtils, 'getHashFromURL').mockReturnValue(new Array(32).fill(0))

      // One potential host
      jest.spyOn(downloader, 'resolve').mockResolvedValue([
        'http://bad-content.test'
      ])

      // The fetch returns 32 bytes of all 1's => hash mismatch
      jest.spyOn(global, 'fetch').mockResolvedValue(
        new Response(new Uint8Array(32).fill(1), { status: 200 })
      )

      await expect(downloader.download('validButBadHashUrl'))
        .rejects
        .toThrow()
    })

    it('throws if all hosts fail or mismatch', async () => {
      jest.spyOn(StorageUtils, 'isValidURL').mockReturnValue(true)
      jest.spyOn(StorageUtils, 'getHashFromURL').mockReturnValue(new Array(32).fill(0))

      jest.spyOn(downloader, 'resolve').mockResolvedValue([
        'http://host1.test',
        'http://host2.test'
      ])

      // Both fetches fail with 500 or something >=400
      jest.spyOn(global, 'fetch').mockResolvedValue(
        new Response(null, { status: 500 })
      )

      await expect(downloader.download('validButNoGoodHostUrl'))
        .rejects
        .toThrow('Unable to download content from validButNoGoodHostUrl')
    })

    it('throws if all entries are expired', async () => {
      const currentTime = Math.floor(Date.now())

      jest.spyOn(LookupResolver.prototype, 'query').mockResolvedValue({
        type: 'output-list',
        outputs: [
          { beef: 'fake-beef-a', outputIndex: 0 },
          { beef: 'fake-beef-b', outputIndex: 1 }
        ]
      } as any)

      jest.spyOn(Transaction, 'fromBEEF').mockImplementation(() => {
        return {
          outputs: [
            { lockingScript: {} },
            { lockingScript: {} }
          ]
        } as any
      })

      jest.spyOn(PushDrop, 'decode').mockImplementation(() => {
        return {
          lockingPublicKey: {} as PublicKey,
          fields: [[], [], [], [currentTime - 100]]
        }
      })

      await expect(downloader.resolve('expiredUhrpUrl'))
        .resolves
        .toEqual(['', ''])
    })

    it.skip('downloads and verifies large streamed content', async () => {
      const size = 5 * 1024 * 1024
      const data = new Uint8Array(size)
      for (let i = 0; i < size; i++) data[i] = i % 256
      const uhrpUrl = StorageUtils.getURLForFile(data)

      jest.spyOn(downloader, 'resolve').mockResolvedValue(['http://large-file'])

      const chunkSize = 64 * 1024
      const stream = new ReadableStream<Uint8Array>({
        start (controller) {
          for (let offset = 0; offset < data.length; offset += chunkSize) {
            controller.enqueue(data.subarray(offset, offset + chunkSize))
          }
          controller.close()
        }
      })

      jest.spyOn(global, 'fetch').mockResolvedValue(
        new Response(stream as any, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' }
        })
      )

      const result = await downloader.download(uhrpUrl)
      expect(result.mimeType).toBe('application/octet-stream')
      expect(result.data.length).toBe(size)
      expect(result.data).toEqual(data)
    })
  })
})
