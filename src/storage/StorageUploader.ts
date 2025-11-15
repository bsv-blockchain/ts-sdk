import { AuthFetch } from '../auth/clients/AuthFetch.js'
import { WalletInterface } from '../wallet/Wallet.interfaces.js'
import * as StorageUtils from './StorageUtils.js'

export interface UploaderConfig {
  storageURL: string
  wallet: WalletInterface
}

export interface UploadableFile {
  data: Uint8Array | number[]
  type: string
}

export interface UploadFileResult {
  published: boolean
  uhrpURL: string
}

export interface FindFileData {
  name: string
  size: string
  mimeType: string
  expiryTime: number
}

export interface RenewFileResult {
  status: string
  prevExpiryTime?: number
  newExpiryTime?: number
  amount?: number
}

/**
 * The StorageUploader class provides client-side methods for:
 * - Uploading files with a specified retention period
 * - Finding file metadata by UHRP URL
 * - Listing all user uploads
 * - Renewing an existing advertisement's expiry time
 */
export class StorageUploader {
  private readonly authFetch: AuthFetch
  private readonly baseURL: string

  /**
   * Creates a new StorageUploader instance.
   * @param {UploaderConfig} config - An object containing the storage server's URL and a wallet interface
   */
  constructor (config: UploaderConfig) {
    this.baseURL = config.storageURL
    this.authFetch = new AuthFetch(config.wallet)
  }

  /**
   * Requests information from the server to upload a file (including presigned URL and headers).
   * @private
   * @param {number} fileSize - The size of the file, in bytes
   * @param {number} retentionPeriod - The desired hosting time, in minutes
   * @returns {Promise<{ uploadURL: string; requiredHeaders: Record<string, string>; amount?: number }>}
   * @throws {Error} If the server returns a non-OK response or an error status
   */
  private async getUploadInfo (
    fileSize: number,
    retentionPeriod: number
  ): Promise<{
      uploadURL: string
      requiredHeaders: Record<string, string>
      amount?: number
    }> {
    const url = `${this.baseURL}/upload`
    const body = { fileSize, retentionPeriod }

    const response = await this.authFetch.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    if (!response.ok) {
      throw new Error(`Upload info request failed: HTTP ${response.status}`)
    }
    const data = await response.json() as {
      status: string
      uploadURL: string
      amount?: number
      requiredHeaders: Record<string, string>
    }
    if (data.status === 'error') {
      throw new Error('Upload route returned an error.')
    }
    return {
      uploadURL: data.uploadURL,
      requiredHeaders: data.requiredHeaders,
      amount: data.amount
    }
  }

  /**
   * Performs the actual file upload (HTTP PUT) to the presigned URL returned by the server.
   * @private
   * @param {string} uploadURL - The presigned URL where the file is to be uploaded
   * @param {UploadableFile} file - The file to upload, including its raw data and MIME type
   * @param {Record<string, string>} requiredHeaders - Additional headers required by the server (e.g. content-length)
   * @returns {Promise<UploadFileResult>} An object indicating whether publishing was successful and the resulting UHRP URL
   * @throws {Error} If the server returns a non-OK response
   */
  private async uploadFile (
    uploadURL: string,
    file: UploadableFile,
    requiredHeaders: Record<string, string>
  ): Promise<UploadFileResult> {
    const body = file.data instanceof Uint8Array ? file.data : Uint8Array.from(file.data)

    const response = await fetch(uploadURL, {
      method: 'PUT',
      body: body as BodyInit,
      headers: {
        'Content-Type': file.type,
        ...requiredHeaders
      }
    })
    if (!response.ok) {
      throw new Error(`File upload failed: HTTP ${response.status}`)
    }

    const uhrpURL = StorageUtils.getURLForFile(body)
    return {
      published: true,
      uhrpURL
    }
  }

  /**
   * Publishes a file to the storage server with the specified retention period.
   *
   * This will:
   * 1. Request an upload URL from the server.
   * 2. Perform an HTTP PUT to upload the file’s raw bytes.
   * 3. Return a UHRP URL referencing the file once published.
   *
   * @param {Object} params
   * @param {UploadableFile} params.file - The file data + type
   * @param {number} params.retentionPeriod - Number of minutes to host the file
   * @returns {Promise<UploadFileResult>} An object with the file's UHRP URL
   * @throws {Error} If the server or upload step returns a non-OK response
   */
  public async publishFile (params: {
    file: UploadableFile
    retentionPeriod: number
  }): Promise<UploadFileResult> {
    const { file, retentionPeriod } = params
    const data = file.data instanceof Uint8Array ? file.data : Uint8Array.from(file.data)
    const fileSize = data.byteLength

    const { uploadURL, requiredHeaders } = await this.getUploadInfo(fileSize, retentionPeriod)
    return await this.uploadFile(uploadURL, { data, type: file.type }, requiredHeaders)
  }

  /**
   * Retrieves metadata for a file matching the given UHRP URL from the `/find` route.
   * @param {string} uhrpUrl - The UHRP URL, e.g. "uhrp://abcd..."
   * @returns {Promise<FindFileData>} An object with file name, size, MIME type, and expiry time
   * @throws {Error} If the server or the route returns an error
   */
  public async findFile (uhrpUrl: string): Promise<FindFileData> {
    const url = new URL(`${this.baseURL}/find`)
    url.searchParams.set('uhrpUrl', uhrpUrl)

    const response = await this.authFetch.fetch(url.toString(), {
      method: 'GET'
    })
    if (!response.ok) {
      throw new Error(`findFile request failed: HTTP ${response.status}`)
    }

    const data = await response.json() as {
      status: string
      data: { name: string, size: string, mimeType: string, expiryTime: number }
      code?: string
      description?: string
    }

    if (data.status === 'error') {
      const errCode = data.code ?? 'unknown-code'
      const errDesc = data.description ?? 'no-description'
      throw new Error(`findFile returned an error: ${errCode} - ${errDesc}`)
    }
    return data.data
  }

  /**
   * Lists all advertisements belonging to the user from the `/list` route.
   * @returns {Promise<any>} The array of uploads returned by the server
   * @throws {Error} If the server or the route returns an error
   */
  public async listUploads (): Promise<any> {
    const url = `${this.baseURL}/list`
    const response = await this.authFetch.fetch(url, {
      method: 'GET'
    })
    if (!response.ok) {
      throw new Error(`listUploads request failed: HTTP ${response.status}`)
    }

    const data = await response.json()
    if (data.status === 'error') {
      const errCode = data.code as string ?? 'unknown-code'
      const errDesc = data.description as string ?? 'no-description'
      throw new Error(`listUploads returned an error: ${errCode} - ${errDesc}`)
    }
    return data.uploads
  }

  /**
   * Renews the hosting time for an existing file advertisement identified by uhrpUrl.
   * Calls the `/renew` route to add `additionalMinutes` to the GCS customTime
   * and re-mint the advertisement token on-chain.
   *
   * @param {string} uhrpUrl - The UHRP URL of the file (e.g., "uhrp://abcd1234...")
   * @param {number} additionalMinutes - The number of minutes to extend
   * @returns {Promise<RenewFileResult>} An object with the new and previous expiry times, plus any cost
   * @throws {Error} If the request fails or the server returns an error
   */
  public async renewFile (uhrpUrl: string, additionalMinutes: number): Promise<RenewFileResult> {
    const url = `${this.baseURL}/renew`
    const body = { uhrpUrl, additionalMinutes }

    const response = await this.authFetch.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    if (!response.ok) {
      throw new Error(`renewFile request failed: HTTP ${response.status}`)
    }

    const data = await response.json() as {
      status: string
      prevExpiryTime?: number
      newExpiryTime?: number
      amount?: number
      code?: string
      description?: string
    }

    if (data.status === 'error') {
      const errCode = data.code ?? 'unknown-code'
      const errDesc = data.description ?? 'no-description'
      throw new Error(`renewFile returned an error: ${errCode} - ${errDesc}`)
    }

    return {
      status: data.status,
      prevExpiryTime: data.prevExpiryTime,
      newExpiryTime: data.newExpiryTime,
      amount: data.amount
    }
  }
}
