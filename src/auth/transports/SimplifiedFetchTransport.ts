// @ts-nocheck
// @ts-expect-error
import { AuthMessage, RequestedCertificateSet, Transport } from '../types.js'
import * as Utils from '../../primitives/utils.js'

const defaultFetch: typeof fetch = 
  typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function'
    ? globalThis.fetch.bind(globalThis)
    : fetch

/**
 * Implements an HTTP-specific transport for handling Peer mutual authentication messages.
 * This class integrates with fetch to send and receive authenticated messages between peers.
 */
export class SimplifiedFetchTransport implements Transport {
  private onDataCallback?: (message: AuthMessage) => void
  fetchClient: typeof fetch
  baseUrl: string

  /**
   * Constructs a new instance of SimplifiedFetchTransport.
   * @param baseUrl - The base URL for all HTTP requests made by this transport.
   * @param fetchClient - A fetch implementation to use for HTTP requests (default: global fetch).
   */
  constructor (baseUrl: string, fetchClient = defaultFetch) {
    if (typeof fetchClient !== 'function') {
      throw new Error(
        'SimplifiedFetchTransport requires a fetch implementation. ' +
        'In environments without fetch, provide a polyfill or custom implementation.'
      )
    }
    this.fetchClient = fetchClient
    this.baseUrl = baseUrl
  }

  /**
   * Sends a message to an HTTP server using the transport mechanism.
   * Handles both general and authenticated message types. For general messages,
   * the payload is deserialized and sent as an HTTP request. For other message types,
   * the message is sent as a POST request to the `/auth` endpoint.
   *
   * @param message - The AuthMessage to send.
   * @returns A promise that resolves when the message is successfully sent.
   *
   * @throws Will throw an error if no listener has been registered via `onData`.
   */
  async send (message: AuthMessage): Promise<void> {
    if (this.onDataCallback == null) {
      throw new Error('Listen before you start speaking. God gave you two ears and one mouth for a reason.')
    }
    if (message.messageType !== 'general') {
      return await new Promise((resolve, reject) => {
        void (async () => {
          try {
            const authUrl = `${this.baseUrl}/.well-known/auth`
            const responsePromise = (async () => {
              try {
                return await this.fetchClient(authUrl, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify(message)
                })
              } catch (error) {
                throw this.createNetworkError(authUrl, error)
              }
            })()

            // For initialRequest message, mark connection as established and start pool.
            if (message.messageType !== 'initialRequest') {
              resolve()
            }

            const response = await responsePromise
            if (!response.ok) {
              const responseBodyArray = Array.from(new Uint8Array(await response.arrayBuffer()))
              throw this.createUnauthenticatedResponseError(authUrl, response, responseBodyArray)
            }

            if (this.onDataCallback != null) {
              const responseMessage = await response.json()
              this.onDataCallback(responseMessage as AuthMessage)
            }

            if (message.messageType === 'initialRequest') {
              resolve()
            }
          } catch (e) {
            reject(e)
          }
        })()
      })
    } else {
      // Parse message payload
      const httpRequest = this.deserializeRequestPayload(message.payload)

      // Send the byte array as the HTTP payload
      const url = `${this.baseUrl}${httpRequest.urlPostfix}`
      const httpRequestWithAuthHeaders: any = httpRequest
      if (typeof httpRequest.headers !== 'object') {
        httpRequestWithAuthHeaders.headers = {}
      }

      // Append auth headers in request to server
      httpRequestWithAuthHeaders.headers['x-bsv-auth-version'] = message.version
      httpRequestWithAuthHeaders.headers['x-bsv-auth-identity-key'] = message.identityKey
      httpRequestWithAuthHeaders.headers['x-bsv-auth-nonce'] = message.nonce
      httpRequestWithAuthHeaders.headers['x-bsv-auth-your-nonce'] = message.yourNonce
      httpRequestWithAuthHeaders.headers['x-bsv-auth-signature'] = Utils.toHex(message.signature)
      httpRequestWithAuthHeaders.headers['x-bsv-auth-request-id'] = httpRequest.requestId

      // Ensure Content-Type is set for requests with a body
      if (httpRequestWithAuthHeaders.body != null) {
        const headers = httpRequestWithAuthHeaders.headers
        if (headers['content-type'] == null) {
          throw new Error('Content-Type header is required for requests with a body.')
        }

        const contentType = String(headers['content-type'] ?? '')

        // Transform body based on Content-Type
        if (contentType.includes('application/json')) {
          // Convert byte array to JSON string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body)
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          // Convert byte array to URL-encoded string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body)
        } else if (contentType.includes('text/plain')) {
          // Convert byte array to plain UTF-8 string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body)
        } else {
          // For all other content types, treat as binary data
          httpRequestWithAuthHeaders.body = new Uint8Array(httpRequestWithAuthHeaders.body)
        }
      }

      // Send the actual fetch request to the server
      let response: Response
      try {
        response = await this.fetchClient(url, {
          method: httpRequestWithAuthHeaders.method,
          headers: httpRequestWithAuthHeaders.headers,
          body: httpRequestWithAuthHeaders.body
        })
      } catch (error) {
        throw this.createNetworkError(url, error)
      }

      const responseBodyBuffer = await response.arrayBuffer()
      const responseBodyArray = Array.from(new Uint8Array(responseBodyBuffer))

      const missingAuthHeaders = ['x-bsv-auth-version', 'x-bsv-auth-identity-key', 'x-bsv-auth-signature']
        .filter(headerName => {
          const headerValue = response.headers.get(headerName)
          return headerValue == null || headerValue.trim().length === 0
        })

      if (missingAuthHeaders.length > 0) {
        throw this.createUnauthenticatedResponseError(url, response, responseBodyArray, missingAuthHeaders)
      }

      const requestedCertificatesHeader = response.headers.get('x-bsv-auth-requested-certificates')
      let requestedCertificates: RequestedCertificateSet | undefined
      if (requestedCertificatesHeader != null) {
        try {
          requestedCertificates = JSON.parse(requestedCertificatesHeader) as RequestedCertificateSet
        } catch (error) {
          throw this.createMalformedHeaderError(url, 'x-bsv-auth-requested-certificates', requestedCertificatesHeader, error)
        }
      }
      const payloadWriter = new Utils.Writer()
      if (response.headers.get('x-bsv-auth-request-id') != null) {
        payloadWriter.write(Utils.toArray(response.headers.get('x-bsv-auth-request-id'), 'base64'))
      }
      payloadWriter.writeVarIntNum(response.status)

      // PARSE RESPONSE HEADERS FROM SERVER --------------------------------
      // Parse response headers from the server and include only the signed headers:
      // - Include custom headers prefixed with x-bsv (excluding those starting with x-bsv-auth)
      // - Include the authorization header
      const includedHeaders: Array<[string, string]> = []
      response.headers.forEach((value, key) => {
        const lowerKey = key.toLowerCase()
        if ((lowerKey.startsWith('x-bsv-') || lowerKey === 'authorization') && !lowerKey.startsWith('x-bsv-auth')) {
          includedHeaders.push([lowerKey, value])
        }
      })

      // Sort the headers by key to ensure a consistent order for signing and verification.
      includedHeaders.sort(([keyA], [keyB]) => keyA.localeCompare(keyB))

      // nHeaders
      payloadWriter.writeVarIntNum(includedHeaders.length)
      for (let i = 0; i < includedHeaders.length; i++) {
        // headerKeyLength
        const headerKeyAsArray = Utils.toArray(includedHeaders[i][0], 'utf8')
        payloadWriter.writeVarIntNum(headerKeyAsArray.length)
        // headerKey
        payloadWriter.write(headerKeyAsArray)
        // headerValueLength
        const headerValueAsArray = Utils.toArray(includedHeaders[i][1], 'utf8')
        payloadWriter.writeVarIntNum(headerValueAsArray.length)
        // headerValue
        payloadWriter.write(headerValueAsArray)
      }

      // Handle body
      payloadWriter.writeVarIntNum(responseBodyArray.length)
      if (responseBodyArray.length > 0) {
        payloadWriter.write(responseBodyArray)
      }

      // Build the correct AuthMessage for the response
      const responseMessage: AuthMessage = {
        version: response.headers.get('x-bsv-auth-version'),
        messageType: response.headers.get('x-bsv-auth-message-type') === 'certificateRequest' ? 'certificateRequest' : 'general',
        identityKey: response.headers.get('x-bsv-auth-identity-key'),
        nonce: response.headers.get('x-bsv-auth-nonce') ?? undefined,
        yourNonce: response.headers.get('x-bsv-auth-your-nonce') ?? undefined,
        requestedCertificates,
        payload: payloadWriter.toArray(),
        signature: Utils.toArray(response.headers.get('x-bsv-auth-signature'), 'hex')
      }

      // If the server didn't provide the correct authentication headers, throw an error
      if (responseMessage.version == null) {
        throw this.createUnauthenticatedResponseError(url, response, responseBodyArray)
      }

      // Handle the response if data is received and callback is set
      // Only process responses from auth endpoints as auth messages
      const responseUrl = new URL(url)
      const isAuthEndpoint = responseUrl.pathname === '/.well-known/auth' || responseUrl.pathname.endsWith('/.well-known/auth')

      if (isAuthEndpoint && this.onDataCallback != null) {
        this.onDataCallback(responseMessage)
      }
    }
  }

  /**
   * Registers a callback to handle incoming messages.
   * This must be called before sending any messages to ensure responses can be processed.
   *
   * @param callback - A function to invoke when an incoming AuthMessage is received.
   * @returns A promise that resolves once the callback is set.
   */
  async onData (callback: (message: AuthMessage) => Promise<void>): Promise<void> {
    this.onDataCallback = (m) => {
      void callback(m)
    }
  }

  private createNetworkError (url: string, originalError: unknown): Error {
    const baseMessage = `Network error while sending authenticated request to ${url}`
    if (originalError instanceof Error) {
      const error = new Error(`${baseMessage}: ${originalError.message}`)
      error.stack = originalError.stack
      ;(error as any).cause = originalError
      return error
    }
    return new Error(`${baseMessage}: ${String(originalError)}`)
  }

  private createUnauthenticatedResponseError (
    url: string,
    response: Response,
    bodyBytes: number[],
    missingHeaders: string[] = []
  ): Error {
    const statusText = (response.statusText ?? '').trim()
    const statusDescription = statusText.length > 0
      ? `${response.status} ${statusText}`
      : `${response.status}`
    const headerMessage = missingHeaders.length > 0
      ? `missing headers: ${missingHeaders.join(', ')}`
      : 'response lacked required BSV auth headers'
    const bodyPreview = this.getBodyPreview(bodyBytes, response.headers.get('content-type'))
    const parts = [`Received HTTP ${statusDescription} from ${url} without valid BSV authentication (${headerMessage})`]
    if (bodyPreview != null) {
      parts.push(`body preview: ${bodyPreview}`)
    }

    const error = new Error(parts.join(' - '))
    ;(error as any).details = {
      url,
      status: response.status,
      statusText: response.statusText,
      missingHeaders,
      bodyPreview
    }
    return error
  }

  private createMalformedHeaderError (
    url: string,
    headerName: string,
    headerValue: string,
    cause: unknown
  ): Error {
    const errorMessage = `Failed to parse ${headerName} returned by ${url}: ${headerValue}`
    if (cause instanceof Error) {
      const error = new Error(`${errorMessage}. ${cause.message}`)
      error.stack = cause.stack
      ;(error as any).cause = cause
      return error
    }
    return new Error(`${errorMessage}. ${String(cause)}`)
  }

  private getBodyPreview (bodyBytes: number[], contentType: string | null): string | undefined {
    if (bodyBytes.length === 0) {
      return undefined
    }

    const maxBytesForPreview = 1024
    const truncated = bodyBytes.length > maxBytesForPreview
    const slice = truncated ? bodyBytes.slice(0, maxBytesForPreview) : bodyBytes
    const isText = this.isTextualContent(contentType, slice)

    let preview: string
    if (isText) {
      try {
        preview = Utils.toUTF8(slice)
      } catch {
        preview = this.formatBinaryPreview(slice, truncated)
      }
    } else {
      preview = this.formatBinaryPreview(slice, truncated)
    }

    if (preview.length > 512) {
      preview = `${preview.slice(0, 512)}…`
    }
    if (truncated) {
      preview = `${preview} (truncated)`
    }
    return preview
  }

  private isTextualContent (contentType: string | null, sample: number[]): boolean {
    if (sample.length === 0) {
      return false
    }

    if (contentType != null) {
      const lowered = contentType.toLowerCase()
      const textualTokens = [
        'application/json',
        'application/problem+json',
        'application/xml',
        'application/xhtml+xml',
        'application/javascript',
        'application/ecmascript',
        'application/x-www-form-urlencoded',
        'text/'
      ]
      if (textualTokens.some(token => lowered.includes(token)) || lowered.includes('charset=')) {
        return true
      }
    }

    const printableCount = sample.reduce((count, byte) => {
      if (byte === 9 || byte === 10 || byte === 13) {
        return count + 1
      }
      if (byte >= 32 && byte <= 126) {
        return count + 1
      }
      return count
    }, 0)
    return (printableCount / sample.length) > 0.8
  }

  private formatBinaryPreview (bytes: number[], truncated: boolean): string {
    const hex = bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
    return `0x${hex}${truncated ? '…' : ''}`
  }

  /**
   * Deserializes a request payload from a byte array into an HTTP request-like structure.
   *
   * @param payload - The serialized payload to deserialize.
   * @returns An object representing the deserialized request, including the method,
   *          URL postfix (path and query string), headers, body, and request ID.
   */
  deserializeRequestPayload (payload: number[]): {
    method: string
    urlPostfix: string
    headers: Record<string, string>
    body: number[]
    requestId: string
  } {
    // Create a reader
    const requestReader = new Utils.Reader(payload)
    // The first 32 bytes is the requestId
    const requestId = Utils.toBase64(requestReader.read(32))

    // Method
    const methodLength = requestReader.readVarIntNum()
    let method = 'GET'
    if (methodLength > 0) {
      method = Utils.toUTF8(requestReader.read(methodLength))
    }

    // Path
    const pathLength = requestReader.readVarIntNum()
    let path = ''
    if (pathLength > 0) {
      path = Utils.toUTF8(requestReader.read(pathLength))
    }

    // Search
    const searchLength = requestReader.readVarIntNum()
    let search = ''
    if (searchLength > 0) {
      search = Utils.toUTF8(requestReader.read(searchLength))
    }

    // Read headers
    const requestHeaders = {}
    const nHeaders = requestReader.readVarIntNum()
    if (nHeaders > 0) {
      for (let i = 0; i < nHeaders; i++) {
        const nHeaderKeyBytes = requestReader.readVarIntNum()
        const headerKeyBytes = requestReader.read(nHeaderKeyBytes)
        const headerKey = Utils.toUTF8(headerKeyBytes)
        const nHeaderValueBytes = requestReader.readVarIntNum()
        const headerValueBytes = requestReader.read(nHeaderValueBytes)
        const headerValue = Utils.toUTF8(headerValueBytes)
        requestHeaders[headerKey] = headerValue
      }
    }

    // Read body
    let requestBody
    const requestBodyBytes = requestReader.readVarIntNum()
    if (requestBodyBytes > 0) {
      requestBody = requestReader.read(requestBodyBytes)
    }

    // Return the deserialized RequestInit
    return {
      urlPostfix: path + search,
      method,
      headers: requestHeaders,
      body: requestBody,
      requestId
    }
  }
}
