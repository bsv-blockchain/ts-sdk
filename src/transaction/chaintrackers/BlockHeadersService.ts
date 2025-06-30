import ChainTracker from '../ChainTracker.js'
import { HttpClient } from '../http/HttpClient.js'
import { defaultHttpClient } from '../http/DefaultHttpClient.js'

/** Configuration options for the BlockHeadersService ChainTracker. */
export interface BlockHeadersServiceConfig {
  /** The HTTP client used to make requests to the API. */
  httpClient?: HttpClient

  /** The API key used to authenticate requests to the BlockHeadersService API. */
  apiKey?: string
}

interface MerkleRootVerificationRequest {
  blockHeight: number
  merkleRoot: string
}

interface MerkleRootConfirmation {
  blockHash: string
  blockHeight: number
  merkleRoot: string
  confirmation: 'CONFIRMED' | 'UNCONFIRMED'
}

interface MerkleRootVerificationResponse {
  confirmationState: 'CONFIRMED' | 'UNCONFIRMED'
  confirmations: MerkleRootConfirmation[]
}

/**
 * Represents a chain tracker based on a BlockHeadersService API.
 * 
 * @example
 * ```typescript
 * const chainTracker = new BlockHeadersService('https://headers.spv.money', {
 *   apiKey: '17JxRHcJerGBEbusx56W8o1m8Js73TFGo'
 * })
 * ```
 */
export class BlockHeadersService implements ChainTracker {
  protected readonly baseUrl: string
  protected readonly httpClient: HttpClient
  protected readonly apiKey: string

  /**
   * Constructs an instance of the BlockHeadersService ChainTracker.
   * 
   * @param {string} baseUrl - The base URL for the BlockHeadersService API (e.g. https://headers.spv.money)
   * @param {BlockHeadersServiceConfig} config - Configuration options for the BlockHeadersService ChainTracker.
   */
  constructor(
    baseUrl: string,
    config: BlockHeadersServiceConfig = {}
  ) {
    const { httpClient, apiKey } = config
    this.baseUrl = baseUrl
    this.httpClient = httpClient ?? defaultHttpClient()
    this.apiKey = apiKey ?? ''
  }

  /**
   * Verifies if a given merkle root is valid for a specific block height.
   * 
   * @param {string} root - The merkle root to verify.
   * @param {number} height - The block height to check against.
   * @returns {Promise<boolean>} - A promise that resolves to true if the merkle root is valid for the specified block height, false otherwise.
   */
  async isValidRootForHeight(root: string, height: number): Promise<boolean> {
    const requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      data: [
        {
          blockHeight: height,
          merkleRoot: root
        }
      ] as MerkleRootVerificationRequest[]
    }

    try {
      const response = await this.httpClient.request<MerkleRootVerificationResponse>(
        `${this.baseUrl}/api/v1/chain/merkleroot/verify`,
        requestOptions
      )

      if (response.ok) {        
        return response.data.confirmationState === 'CONFIRMED'
      } else {
        throw new Error(
          `Failed to verify merkleroot for height ${height} because of an error: ${JSON.stringify(response.data)}`
        )
      }
    } catch (error) {
      throw new Error(
        `Failed to verify merkleroot for height ${height} because of an error: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Gets the current block height from the BlockHeadersService API.
   * 
   * @returns {Promise<number>} - A promise that resolves to the current block height.
   */
  async currentHeight(): Promise<number> {
    const requestOptions = {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      }
    }

    try {
      const response = await this.httpClient.request<{ height: number }>(
        `${this.baseUrl}/api/v1/chain/tip/longest`,
        requestOptions
      )
      
      if (response.ok && response.data && typeof response.data.height === 'number') {
        return response.data.height
      } else {
        throw new Error(
          `Failed to get current height because of an error: ${JSON.stringify(response.data)}`
        )
      }
    } catch (error) {
      throw new Error(
        `Failed to get current height because of an error: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
}
