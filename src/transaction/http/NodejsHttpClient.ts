import {
  HttpClient,
  HttpClientRequestOptions,
  HttpClientResponse
} from './HttpClient.js'
import { HttpsModuleLike, executeNodejsRequest } from './NodejsHttpRequestUtils.js'

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

  end: () => void
}

/**
 * Adapter for Node Https module to be used as HttpClient
 */
export class NodejsHttpClient implements HttpClient {
  constructor(private readonly https: HttpsNodejs) { }

  async request(
    url: string,
    requestOptions: HttpClientRequestOptions
  ): Promise<HttpClientResponse> {
    return await executeNodejsRequest(
      this.https as unknown as HttpsModuleLike,
      url,
      requestOptions,
      (data) => JSON.stringify(data)
    )
  }
}
