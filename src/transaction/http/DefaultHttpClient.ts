import { HttpClient, HttpClientResponse } from './HttpClient.js'
import { NodejsHttpClient } from './NodejsHttpClient.js'
import { FetchHttpClient } from './FetchHttpClient.js'

/**
 * Returns a default HttpClient implementation based on the environment that it is run on.
 * This method will attempt to use `window.fetch` if available (in browser environments),
 * then `globalThis.fetch` (service workers, Deno, Node 18+), then the Node `https` module.
 */
export function defaultHttpClient(): HttpClient {
  const noHttpClient: HttpClient = {
    async request(..._): Promise<HttpClientResponse> {
      throw new Error('No method available to perform HTTP request')
    }
  }

  if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
    // Browser tab/page context
    return new FetchHttpClient(window.fetch.bind(window))
  } else if (typeof globalThis.fetch === 'function') {
    // Service workers, Deno, Node 18+ (any environment with global fetch)
    return new FetchHttpClient(globalThis.fetch.bind(globalThis))
  } else if (typeof require !== 'undefined') {
    // Older Node.js — use https module
    // eslint-disable-next-line
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const https = require('https')
      return new NodejsHttpClient(https)
    } catch (e) {
      return noHttpClient
    }
  } else {
    return noHttpClient
  }
}
