import {
  HttpClient,
  HttpClientRequestOptions,
  HttpClientResponse
} from './HttpClient.js'

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
  body?: string | null
}

/**
 * Adapter for Node Https module to be used as HttpClient
 */
export class FetchHttpClient implements HttpClient {
  constructor (private readonly fetch: Fetch) { }

  async request<D>(
    url: string,
    options: HttpClientRequestOptions
  ): Promise<HttpClientResponse<D>> {
    const fetchOptions: FetchOptions = {
      method: options.method,
      headers: options.headers,
      body: JSON.stringify(options.data)
    }

    const res = await this.fetch(url, fetchOptions)
    const mediaType = res.headers.get('Content-Type')
    const data = mediaType?.startsWith('application/json') ?? false
      ? await res.json()
      : await res.text()

    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      data: data as D
    }
  }
}
