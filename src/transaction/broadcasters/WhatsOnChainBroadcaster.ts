import {
  BroadcastResponse,
  BroadcastFailure,
  Broadcaster
} from '../Broadcaster.js'
import Transaction from '../Transaction.js'
import { HttpClient } from '../http/HttpClient.js'
import { defaultHttpClient } from '../http/DefaultHttpClient.js'

/**
 * Represents an WhatsOnChain transaction broadcaster.
 */
export default class WhatsOnChainBroadcaster implements Broadcaster {
  readonly network: string
  private readonly URL: string
  private readonly httpClient: HttpClient

  /**
   * Constructs an instance of the WhatsOnChain broadcaster.
   *
   * @param {'main' | 'test' | 'stn'} network - The BSV network to use when calling the WhatsOnChain API.
   * @param {HttpClient} httpClient - The HTTP client used to make requests to the API.
   */
  constructor (
    network: 'main' | 'test' | 'stn' = 'main',
    httpClient: HttpClient = defaultHttpClient()
  ) {
    this.network = network
    this.URL = `https://api.whatsonchain.com/v1/bsv/${network}/tx/raw`
    this.httpClient = httpClient
  }

  /**
   * Broadcasts a transaction via WhatsOnChain.
   *
   * @param {Transaction} tx - The transaction to be broadcasted.
   * @returns {Promise<BroadcastResponse | BroadcastFailure>} A promise that resolves to either a success or failure response.
   */
  async broadcast (
    tx: Transaction
  ): Promise<BroadcastResponse | BroadcastFailure> {
    const rawTx = tx.toHex()

    const requestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/plain'
      },
      data: { txhex: rawTx }
    }

    try {
      const response = await this.httpClient.request<string>(
        this.URL,
        requestOptions
      )
      if (response.ok) {
        const txid = response.data
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
