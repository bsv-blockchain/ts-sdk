import {
  HttpClientRequestOptions,
  HttpClientResponse
} from './HttpClient.js'

/** Common interface for Node.js https module request objects */
export interface NodejsRequestLike {
  write: (chunk: any) => void
  on: (event: string, callback: (data: any) => void) => void
  end: () => void
}

/** Common interface for Node.js https modules */
export interface HttpsModuleLike {
  request: (
    url: string,
    options: HttpClientRequestOptions,
    callback: (res: any) => void
  ) => NodejsRequestLike
}

/**
 * Shared implementation for handling Node.js HTTP requests.
 * Used by both NodejsHttpClient and BinaryNodejsHttpClient.
 *
 * @param https The Node.js https module (or compatible)
 * @param url The URL to make the request to
 * @param requestOptions The request configuration
 * @param serializeData Function to serialize the request data for writing
 */
export function executeNodejsRequest(
  https: HttpsModuleLike,
  url: string,
  requestOptions: HttpClientRequestOptions,
  serializeData: (data: any) => any
): Promise<HttpClientResponse> {
  return new Promise((resolve, reject) => {
    const req = https.request(url, requestOptions, (res) => {
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
      req.write(serializeData(requestOptions.data))
    }
    req.end()
  })
}
