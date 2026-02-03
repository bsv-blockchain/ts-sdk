import {
  BroadcastResponse,
  BroadcastFailure,
  Broadcaster
} from '../Broadcaster.js'
import Transaction from '../Transaction.js'
import { HttpClient, HttpClientRequestOptions } from '../http/HttpClient.js'
import { defaultHttpClient } from '../http/DefaultHttpClient.js'
import Random from '../../primitives/Random.js'
import { toHex } from '../../primitives/utils.js'

/** Configuration options for the ARC broadcaster. */
export interface ArcConfig {
  /** Authentication token for the ARC API */
  apiKey?: string
  /** The HTTP client used to make requests to the ARC API. */
  httpClient?: HttpClient
  /** Deployment id used annotating api calls in XDeployment-ID header - this value will be randomly generated if not set */
  deploymentId?: string
  /** notification callback endpoint for proofs and double spend notification */
  callbackUrl?: string
  /** default access token for notification callback endpoint. It will be used as a Authorization header for the http callback */
  callbackToken?: string
  /** additional headers to be attached to all tx submissions. */
  headers?: Record<string, string>
}

function defaultDeploymentId (): string {
  return `ts-sdk-${toHex(Random(16))}`
}

/**
 * Represents an ARC transaction broadcaster.
 */
export default class ARC implements Broadcaster {
  readonly URL: string
  readonly apiKey: string | undefined
  readonly deploymentId: string
  readonly callbackUrl: string | undefined
  readonly callbackToken: string | undefined
  readonly headers: Record<string, string> | undefined
  private readonly httpClient: HttpClient

  /**
   * Constructs an instance of the ARC broadcaster.
   *
   * @param {string} URL - The URL endpoint for the ARC API.
   * @param {ArcConfig} config - Configuration options for the ARC broadcaster.
   */
  constructor (URL: string, config?: ArcConfig)
  /**
   * Constructs an instance of the ARC broadcaster.
   *
   * @param {string} URL - The URL endpoint for the ARC API.
   * @param {string} apiKey - The API key used for authorization with the ARC API.
   */
  constructor (URL: string, apiKey?: string)

  constructor (URL: string, config?: string | ArcConfig) {
    this.URL = URL
    if (typeof config === 'string') {
      this.apiKey = config
      this.httpClient = defaultHttpClient()
      this.deploymentId = defaultDeploymentId()
      this.callbackToken = undefined
      this.callbackUrl = undefined
    } else {
      const configObj: ArcConfig = config ?? {}
      const {
        apiKey,
        deploymentId,
        httpClient,
        callbackToken,
        callbackUrl,
        headers
      } = configObj
      this.apiKey = apiKey
      this.httpClient = httpClient ?? defaultHttpClient()
      this.deploymentId = deploymentId ?? defaultDeploymentId()
      this.callbackToken = callbackToken
      this.callbackUrl = callbackUrl
      this.headers = headers
    }
  }

  /**
   * Constructs a dictionary of the default & supplied request headers.
   */
  private requestHeaders (): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'XDeployment-ID': this.deploymentId
    }

    if (this.apiKey != null && this.apiKey !== '') {
      headers.Authorization = `Bearer ${this.apiKey}`
    }

    if (this.callbackUrl != null && this.callbackUrl !== '') {
      headers['X-CallbackUrl'] = this.callbackUrl
    }

    if (this.callbackToken != null && this.callbackToken !== '') {
      headers['X-CallbackToken'] = this.callbackToken
    }

    if (this.headers != null) {
      for (const key in this.headers) {
        headers[key] = this.headers[key]
      }
    }

    return headers
  }

  /**
   * Broadcasts a transaction via ARC.
   *
   * @param {Transaction} tx - The transaction to be broadcasted.
   * @returns {Promise<BroadcastResponse | BroadcastFailure>} A promise that resolves to either a success or failure response.
   */
  async broadcast (
    tx: Transaction
  ): Promise<BroadcastResponse | BroadcastFailure> {
    let rawTx
    try {
      rawTx = tx.toHexEF()
    } catch (error) {
      if (
        error.message ===
        'All inputs must have source transactions when serializing to EF format'
      ) {
        rawTx = tx.toHex()
      } else {
        throw error
      }
    }

    const requestOptions: HttpClientRequestOptions = {
      method: 'POST',
      headers: this.requestHeaders(),
      data: { rawTx }
    }

    try {
      const response = await this.httpClient.request<ArcResponse>(
        `${this.URL}/v1/tx`,
        requestOptions
      )
      if (response.ok) {
        const { txid, extraInfo, txStatus, competingTxs } = response.data

        // Check for error txStatus values that ARC returns with HTTP 200
        // These should be treated as broadcast failures
        const errorStatuses = [
          'DOUBLE_SPEND_ATTEMPTED',
          'REJECTED',
          'INVALID',
          'MALFORMED',
          'MINED_IN_STALE_BLOCK'
        ]

        const isOrphan = extraInfo?.toUpperCase().includes('ORPHAN') ||
          txStatus?.toUpperCase().includes('ORPHAN')

        if (errorStatuses.includes(txStatus?.toUpperCase()) || isOrphan) {
          const failure: BroadcastFailure = {
            status: 'error',
            code: txStatus ?? 'UNKNOWN',
            txid,
            description: `${txStatus ?? ''} ${extraInfo ?? ''}`.trim()
          }
          if (competingTxs != null) {
            failure.more = { competingTxs }
          }
          return failure
        }

        const broadcastRes: BroadcastResponse = {
          status: 'success',
          txid,
          message: `${txStatus} ${extraInfo}`
        }
        if (competingTxs != null) {
          broadcastRes.competingTxs = competingTxs
        }
        return broadcastRes
      } else {
        const st = typeof response.status
        const r: BroadcastFailure = {
          status: 'error',
          code:
            st === 'number' || st === 'string'
              ? response.status.toString()
              : 'ERR_UNKNOWN',
          description: 'Unknown error'
        }
        let d = response.data
        if (typeof d === 'string') {
          try {
            d = JSON.parse(response.data as string)
          } catch {
            // Intentionally left empty
          }
        }
        if (typeof d === 'object') {
          if (d !== null) {
            r.more = d
          }
          if ((d != null) && typeof (d as { txid: string }).txid === 'string') {
            r.txid = (d as { txid: string }).txid
          }
          if ((d != null) && 'detail' in d && typeof (d as { detail: string }).detail === 'string') {
            r.description = (d as { detail: string }).detail
          }
        }
        return r
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

  /**
   * Broadcasts multiple transactions via ARC.
   * Handles mixed responses where some transactions succeed and others fail.
   *
   * @param {Transaction[]} txs - Array of transactions to be broadcasted.
   * @returns {Promise<Array<object>>} A promise that resolves to an array of objects.
   */
  async broadcastMany (txs: Transaction[]): Promise<object[]> {
    const rawTxs = txs.map((tx) => {
      try {
        return { rawTx: tx.toHexEF() }
      } catch (error) {
        if (
          error.message ===
          'All inputs must have source transactions when serializing to EF format'
        ) {
          return { rawTx: tx.toHex() }
        }
        throw error
      }
    })

    const requestOptions: HttpClientRequestOptions = {
      method: 'POST',
      headers: this.requestHeaders(),
      data: rawTxs
    }

    try {
      const response = await this.httpClient.request<object[]>(
        `${this.URL}/v1/txs`,
        requestOptions
      )

      return response.data as object[]
    } catch (error) {
      const errorResponse: BroadcastFailure = {
        status: 'error',
        code: '500',
        description: typeof error.message === 'string' ? error.message : 'Internal Server Error'
      }
      return txs.map(() => errorResponse)
    }
  }
}

interface ArcResponse {
  txid: string
  extraInfo: string
  txStatus: string
  competingTxs?: string[]
}
