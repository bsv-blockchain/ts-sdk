import {
  HttpClient,
  HttpClientRequestOptions,
  HttpClientResponse
} from './HttpClient.js'

/** Node Https module interface limited to options needed by ts-sdk */
export interface BinaryHttpsNodejs {
  request: (
    url: string,
    options: HttpClientRequestOptions,
    callback: (res: any) => void
  ) => BinaryNodejsHttpClientRequest
}

/** Nodejs result of the Node https.request call limited to options needed by ts-sdk */
export interface BinaryNodejsHttpClientRequest {
  write: (chunk: Buffer) => void

  on: (event: string, callback: (data: any) => void) => void

  end: (() => void) & (() => void)
}

/**
 * Adapter for Node Https module to be used as HttpClient
 */
export class BinaryNodejsHttpClient implements HttpClient {
  constructor (private readonly https: BinaryHttpsNodejs) { }

  async request (
    url: string,
    requestOptions: HttpClientRequestOptions
  ): Promise<HttpClientResponse> {
    return await new Promise((resolve, reject) => {
      const req = this.https.request(url, requestOptions, (res) => {
        let body = ''
        res.on('data', (chunk: string) => {
          body += chunk
        })
        res.on('end', () => {
          const ok = res.statusCode >= 200 && res.statusCode <= 299
          const mediaType = res.headers['content-type']
          const data =
            body !== '' && typeof mediaType === 'string' && mediaType.startsWith('application/json')
              ? JSON.parse(body)
              : body
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage,
            ok,
            data
          })
        })
      })

      req.on('error', (error: Error) => {
        reject(error)
      })

      if (requestOptions.data !== null && requestOptions.data !== undefined) {
        req.write(Buffer.from(requestOptions.data))
      }
      req.end()
    })
  }
}

/** fetch function interface limited to options needed by ts-sdk */
/**
 * Makes a request to the server.
 * @param url The URL to make the request to.
 * @param options The request configuration.
 */
export type Fetch = (url: string, options: FetchOptions) => Promise<Response>

/**
 * An interface for configuration of the request to be passed to the fetch method
 * limited to options needed by ts-sdk.
 */
export interface FetchOptions {
  /** A string to set request's method. */
  method?: string
  /** An object literal set request's headers. */
  headers?: Record<string, string>
  /** An object or null to set request's body. */
  body?: Buffer | Uint8Array | Blob | null
}

/**
 * Adapter for Node Https module to be used as HttpClient
 */
export class BinaryFetchClient implements HttpClient {
  constructor (private readonly fetch: Fetch) { }

  async request<D>(
    url: string,
    options: HttpClientRequestOptions
  ): Promise<HttpClientResponse<D>> {
    const fetchOptions: FetchOptions = {
      method: options.method,
      headers: options.headers,
      body: options.data
    }

    const res = await this.fetch(url, fetchOptions)
    const data = await res.text()

    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      data: data as D
    }
  }
}

export function binaryHttpClient (): HttpClient {
  const noHttpClient: HttpClient = {
    async request (..._): Promise<HttpClientResponse> {
      throw new Error('No method available to perform HTTP request')
    }
  }

  if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
    // Use fetch in a browser environment
    return new BinaryFetchClient(window.fetch.bind(window))
  } else if (typeof require !== 'undefined') {
    // Use Node https module
    // eslint-disable-next-line
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const https = require('https')
      return new BinaryNodejsHttpClient(https)
    } catch (e) {
      return noHttpClient
    }
  } else {
    return noHttpClient
  }
}
