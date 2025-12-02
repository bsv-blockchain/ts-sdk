import {
  HttpClient,
  HttpClientRequestOptions,
  HttpClientResponse
} from './HttpClient.js'

/** Node Https module interface limited to options needed by ts-sdk */
export interface HttpsNodejs {
  request: (
    url: string,
    options: HttpClientRequestOptions,
    callback: (res: any) => void
  ) => NodejsHttpClientRequest
}

/** Nodejs result of the Node https.request call limited to options needed by ts-sdk */
export interface NodejsHttpClientRequest {
  write: (chunk: string) => void

  on: (event: string, callback: (data: any) => void) => void

  end: (() => void) & (() => void)
}

/**
 * Adapter for Node Https module to be used as HttpClient
 */
export class NodejsHttpClient implements HttpClient {
  constructor (private readonly https: HttpsNodejs) { }

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
        req.write(JSON.stringify(requestOptions.data))
      }
      req.end()
    })
  }
}
