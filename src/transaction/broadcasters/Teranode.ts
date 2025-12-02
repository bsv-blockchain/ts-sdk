import {
  BroadcastResponse,
  BroadcastFailure,
  Broadcaster
} from '../Broadcaster.js'
import Transaction from '../Transaction.js'
import { binaryHttpClient, HttpClient } from '../http/index.js'

/**
 * Represents an Teranode transaction broadcaster.
 */
export default class Teranode implements Broadcaster {
  readonly URL: string
  readonly httpClient: HttpClient

  /**
   * Constructs an instance of the Teranode broadcaster.
   *
   * @param {string} URL - The URL endpoint for the Teranode API.
   * @param {HttpClient} httpClient - The HTTP client used to make requests to the API, binaryHttpClient by default.
   */
  constructor (
    URL: string,
    httpClient: HttpClient = binaryHttpClient()
  ) {
    this.URL = URL
    this.httpClient = httpClient
  }

  /**
   * Broadcasts a transaction via Teranode.
   *
   * @param {Transaction} tx - The transaction to be broadcasted.
   * @returns {Promise<BroadcastResponse | BroadcastFailure>} A promise that resolves to either a success or failure response.
   */
  async broadcast (
    tx: Transaction
  ): Promise<BroadcastResponse | BroadcastFailure> {
    const rawTx = tx.toEF()
    const requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream'
      },
      data: new Blob([new Uint8Array(rawTx)])
    }
    try {
      const response = await this.httpClient.request<string>(
        this.URL,
        requestOptions
      )
      if (response.ok) {
        const txid = tx.id('hex')
        return {
          status: 'success',
          txid,
          message: 'broadcast successful'
        }
      } else {
        return {
          status: 'error',
          code: response.status.toString() ?? 'ERR_UNKNOWN',
          description: response.data ?? 'Unknown error'
        }
      }
    } catch (error) {
      return {
        status: 'error',
        code: '500',
        description:
          typeof error.message === 'string'
            ? error.message
            : 'Internal Server Error'
      }
    }
  }
}
