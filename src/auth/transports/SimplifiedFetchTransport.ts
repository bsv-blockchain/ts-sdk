// @ts-nocheck
// @ts-ignore
import { AuthMessage, RequestedCertificateSet, Transport } from "../types.js"
import * as Utils from '../../primitives/utils.js'

const SUCCESS_STATUS_CODES = [200, 402]

// Only bind window.fetch in the browser
const defaultFetch = typeof window !== 'undefined' ? fetch.bind(window) : fetch;

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
  constructor(baseUrl: string, fetchClient = defaultFetch) {
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
  async send(message: AuthMessage): Promise<void> {
    if (!this.onDataCallback) {
      throw new Error('Listen before you start speaking. God gave you two ears and one mouth for a reason.')
    }
    if (message.messageType !== 'general') {
      return new Promise(async (resolve, reject) => {
        try {
          const responsePromise = this.fetchClient(`${this.baseUrl}/.well-known/auth`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(message)
          })

          // For initialRequest message, mark connection as established and start pool.
          if (message.messageType !== "initialRequest") {
            resolve()
          }
          const response = await responsePromise
          // Handle the response if data is received and callback is set
          if (response.ok && this.onDataCallback) {
            const responseMessage = await response.json()
            this.onDataCallback(responseMessage as AuthMessage)
          } else {
            // Server may be a non authenticated server
            throw new Error('HTTP server failed to authenticate')
          }
          if (message.messageType === "initialRequest") {
            resolve()
          }
        } catch (e) {
          reject(e)
          return
        }
      })
    } else {
      // Parse message payload
      const httpRequest = this.deserializeRequestPayload(message.payload)

      // Send the byte array as the HTTP payload
      const url = `${this.baseUrl}${httpRequest.urlPostfix}`
      let httpRequestWithAuthHeaders: any = httpRequest
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
      if (httpRequestWithAuthHeaders.body) {
        const headers = httpRequestWithAuthHeaders.headers;
        if (!headers['content-type']) {
          throw new Error('Content-Type header is required for requests with a body.');
        }

        const contentType = headers['content-type'];

        // Transform body based on Content-Type
        if (contentType.includes('application/json')) {
          // Convert byte array to JSON string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body);
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          // Convert byte array to URL-encoded string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body);
        } else if (contentType.includes('text/plain')) {
          // Convert byte array to plain UTF-8 string
          httpRequestWithAuthHeaders.body = Utils.toUTF8(httpRequestWithAuthHeaders.body);
        } else {
          // For all other content types, treat as binary data
          httpRequestWithAuthHeaders.body = new Uint8Array(httpRequestWithAuthHeaders.body);
        }
      }

      // Send the actual fetch request to the server
      const response = await this.fetchClient(url, {
        method: httpRequestWithAuthHeaders.method,
        headers: httpRequestWithAuthHeaders.headers,
        body: httpRequestWithAuthHeaders.body
      })

      // Check for an acceptable status
      if (response.status === 500 && (response.headers.get('x-bsv-auth-request-id') == null &&
          response.headers.get('x-bsv-auth-requested-certificates') == null)) {
        // Try parsing JSON error
        const errorInfo = await response.json()
        // Otherwise just throw whatever we got
        throw new Error(`HTTP ${response.status} - ${JSON.stringify(errorInfo)}`);
      }

      const parsedBody = await response.arrayBuffer()
      const payloadWriter = new Utils.Writer()
      if(response.headers.get('x-bsv-auth-request-id') != null)
      {
          payloadWriter.write(Utils.toArray(response.headers.get('x-bsv-auth-request-id'), 'base64'));
      }
      payloadWriter.writeVarIntNum(response.status)

      // PARSE RESPONSE HEADERS FROM SERVER --------------------------------
      // Parse response headers from the server and include only the signed headers:
      // - Include custom headers prefixed with x-bsv (excluding those starting with x-bsv-auth)
      // - Include the authorization header
      const includedHeaders: [string, string][] = []
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
      if (parsedBody) {
        const bodyAsArray = Array.from(new Uint8Array(parsedBody))
        payloadWriter.writeVarIntNum(bodyAsArray.length)
        payloadWriter.write(bodyAsArray)
      } else {
        payloadWriter.writeVarIntNum(-1)
      }

      // Build the correct AuthMessage for the response
      const responseMessage: AuthMessage = {
        version: response.headers.get('x-bsv-auth-version'),
        messageType: response.headers.get('x-bsv-auth-message-type') === 'certificateRequest' ? 'certificateRequest' : 'general',
        identityKey: response.headers.get('x-bsv-auth-identity-key'),
        nonce: response.headers.get('x-bsv-auth-nonce'),
        yourNonce: response.headers.get('x-bsv-auth-your-nonce'),
        requestedCertificates: JSON.parse(response.headers.get('x-bsv-auth-requested-certificates')) as RequestedCertificateSet,
        payload: payloadWriter.toArray(),
        signature: Utils.toArray(response.headers.get('x-bsv-auth-signature'), 'hex'),
      }

      // If the server didn't provide the correct authentication headers, throw an error
      if (!responseMessage.version) {
        throw new Error('HTTP server failed to authenticate')
      }

      // Handle the response if data is received and callback is set
      this.onDataCallback(responseMessage)
    }
  }

  /**
   * Registers a callback to handle incoming messages. 
   * This must be called before sending any messages to ensure responses can be processed.
   * 
   * @param callback - A function to invoke when an incoming AuthMessage is received.
   * @returns A promise that resolves once the callback is set.
   */
  async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
    this.onDataCallback = (m) => {
      callback(m)
    }
  }

  /**
   * Deserializes a request payload from a byte array into an HTTP request-like structure.
   * 
   * @param payload - The serialized payload to deserialize.
   * @returns An object representing the deserialized request, including the method,
   *          URL postfix (path and query string), headers, body, and request ID.
   */
  deserializeRequestPayload(payload: number[]): {
    method: string,
    urlPostfix: string,
    headers: Record<string, string>,
    body: number[],
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