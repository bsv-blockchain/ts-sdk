import WalletWire from './WalletWire.js'
import WalletWireCalls from './WalletWireCalls.js'
import * as Utils from '../../primitives/utils.js'

export default class HTTPWalletWire implements WalletWire {
  baseUrl: string
  httpClient: typeof fetch
  originator: string | undefined

  constructor (
    originator: string | undefined,
    baseUrl: string = 'http://localhost:3301',
    httpClient = fetch
  ) {
    this.baseUrl = baseUrl
    this.httpClient = httpClient
    this.originator = originator
  }

  async transmitToWallet (message: number[]): Promise<number[]> {
    const messageReader = new Utils.Reader(message)
    // Read call code
    const callCode = messageReader.readUInt8()

    // Map call code to call name
    const callName = WalletWireCalls[callCode] // calls is enum
    if (callName === undefined || callName === '') {
      // Invalid call code
      throw new Error(`Invalid call code: ${callCode}`)
    }

    // Read originator length
    const originatorLength = messageReader.readUInt8()
    let originator: string | undefined
    if (originatorLength > 0) {
      const originatorBytes = messageReader.read(originatorLength)
      originator = Utils.toUTF8(originatorBytes)
    }
    const payload = messageReader.read()
    const response = await fetch(`${this.baseUrl}/${callName}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        Origin: originator ?? '' // ✅ Explicitly handle null/undefined cases
      },
      body: new Uint8Array(payload)
    })
    const responseBuffer = await response.arrayBuffer()
    return Array.from(new Uint8Array(responseBuffer))
  }
}
