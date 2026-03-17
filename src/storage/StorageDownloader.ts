import { LookupResolver } from '../overlay-tools/index.js'
import { StorageUtils } from './index.js'
import PushDrop from '../script/templates/PushDrop.js'
import Transaction from '../transaction/Transaction.js'
import { Hash, Utils } from '../primitives/index.js'

export interface DownloaderConfig {
  networkPreset: 'mainnet' | 'testnet' | 'local'
}

export interface DownloadResult {
  data: Uint8Array
  mimeType: string | null
}

export class StorageDownloader {
  private readonly networkPreset?: 'mainnet' | 'testnet' | 'local' = 'mainnet'
  private readonly lookupResolver: LookupResolver

  constructor (config?: DownloaderConfig) {
    this.networkPreset = config?.networkPreset ?? 'mainnet'
    this.lookupResolver = new LookupResolver({ networkPreset: this.networkPreset })
  }

  /**
   * Resolves the UHRP URL to a list of HTTP URLs where content can be downloaded.
   * @param uhrpUrl The UHRP URL to resolve.
   * @returns A promise that resolves to an array of HTTP URLs.
   */
  public async resolve (uhrpUrl: string): Promise<string[]> {
    // Use UHRP lookup service
    const response = await this.lookupResolver.query({ service: 'ls_uhrp', query: { uhrpUrl } })
    if (response.type !== 'output-list') {
      throw new Error('Lookup answer must be an output list')
    }
    const decodedResults: string[] = []
    const currentTime = Math.floor(Date.now() / 1000)
    for (const output of response.outputs) {
      const tx = Transaction.fromBEEF(output.beef)
      const { fields } = PushDrop.decode(tx.outputs[output.outputIndex].lockingScript)

      const expiryTime = new Utils.Reader(fields[3]).readVarIntNum()
      if (expiryTime < currentTime) {
        continue
      }

      decodedResults.push(Utils.toUTF8(fields[2]))
    }
    return decodedResults
  }

  /**
   * Downloads the content from the UHRP URL after validating the hash for integrity.
   * @param uhrpUrl The UHRP URL to download.
   * @returns A promise that resolves to the downloaded content.
   */
  public async download (uhrpUrl: string): Promise<DownloadResult> {
    if (!StorageUtils.isValidURL(uhrpUrl)) {
      throw new Error('Invalid parameter UHRP url')
    }
    const hash = StorageUtils.getHashFromURL(uhrpUrl)
    const expected = Utils.toHex(hash)
    const downloadURLs = await this.resolve(uhrpUrl)

    if (!Array.isArray(downloadURLs) || downloadURLs.length === 0) {
      throw new Error('No one currently hosts this file!')
    }

    for (const url of downloadURLs) {
      try {
        // The url is fetched
        const result = await fetch(url, { method: 'GET' })

        // If the request fails, continue to the next url
        if (!result.ok || result.status >= 400 || result.body == null) {
          continue
        }

        const reader = result.body.getReader()
        const hashStream = new Hash.SHA256()
        const chunks: Uint8Array[] = []
        let totalLength = 0

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          hashStream.update(Array.from(value))
          chunks.push(value)
          totalLength += value.length
        }

        const digest = Utils.toHex(hashStream.digest())
        if (digest !== expected) {
          throw new Error('Data integrity error: value of content does not match hash of the url given')
        }

        const data = new Uint8Array(totalLength)
        let offset = 0
        for (const chunk of chunks) {
          data.set(chunk, offset)
          offset += chunk.length
        }

        return {
          data,
          mimeType: result.headers.get('Content-Type')
        }
      } catch {
        continue
      }
    }
    throw new Error(`Unable to download content from ${uhrpUrl}`)
  }
}
