import { HttpClient, HttpClientResponse } from './HttpClient.js'
import { NodejsHttpClient } from './NodejsHttpClient.js'
import { FetchHttpClient } from './FetchHttpClient.js'

/**
 * Returns a default HttpClient implementation based on the environment that it is run on.
 * This method will attempt to use `window.fetch` if available (in browser environments).
 * If running in a Node environment, it falls back to using the Node `https` module
 */
export function defaultHttpClient (): HttpClient {
  const noHttpClient: HttpClient = {
    async request (..._): Promise<HttpClientResponse> {
      throw new Error('No method available to perform HTTP request')
    }
  }

  if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
    // Use fetch in a browser environment
    return new FetchHttpClient(window.fetch.bind(window))
  } else if (typeof require !== 'undefined') {
    // Use Node https module
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
