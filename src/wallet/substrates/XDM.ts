import Random from '../../primitives/Random.js'
import * as Utils from '../../primitives/utils.js'
import { WalletError } from '../WalletError.js'
import { CallType } from './WalletWireCalls.js'
import { InvokableWalletBase } from './InvokableWalletBase.js'

/**
 * Facilitates wallet operations over cross-document messaging.
 */
export default class XDMSubstrate extends InvokableWalletBase {
  private readonly domain: string

  constructor(domain: string = '*') {
    super()
    if (typeof window !== 'object') {
      throw new Error('The XDM substrate requires a global window object.')
    }
    if (typeof window.postMessage !== 'function') {
      throw new Error(
        'The window object does not seem to support postMessage calls.'
      )
    }
    this.domain = domain
  }

  async invoke(call: CallType, args: any): Promise<any> {
    return await new Promise((resolve, reject) => {
      const id = Utils.toBase64(Random(12))
      const listener = (e: MessageEvent): void => {
        if (
          e.data.type !== 'CWI' ||
          !e.isTrusted ||
          e.data.id !== id ||
          e.data.isInvocation === true
        ) { return }
        if (typeof window.removeEventListener === 'function') {
          window.removeEventListener('message', listener)
        }
        if (e.data.status === 'error') {
          const err = new WalletError(e.data.description, e.data.code)
          reject(err)
        } else {
          resolve(e.data.result)
        }
      }
      window.addEventListener('message', listener)
      window.parent.postMessage(
        {
          type: 'CWI',
          isInvocation: true,
          id,
          call,
          args
        },
        this.domain
      )
    })
  }
}
