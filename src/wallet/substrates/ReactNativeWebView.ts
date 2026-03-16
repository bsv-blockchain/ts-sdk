import Random from '../../primitives/Random.js'
import * as Utils from '../../primitives/utils.js'
import { WalletError } from '../WalletError.js'
import { CallType } from './WalletWireCalls.js'
import { InvokableWalletBase } from './InvokableWalletBase.js'

type ReactNativeWindow = Window & {
  ReactNativeWebView: {
    postMessage: (message: any) => void
  }
}

/**
 * Facilitates wallet operations over cross-document messaging.
 */
export default class ReactNativeWebView extends InvokableWalletBase {
  private readonly domain: string


  constructor(domain: string = '*') {
    super()
    if (typeof window !== 'object') {
      throw new Error('The XDM substrate requires a global window object.')
    }
    if (!(window as unknown as ReactNativeWindow).hasOwnProperty("ReactNativeWebView")) {
      throw new Error(
        'The window object does not have a ReactNativeWebView property.'
      )
    }
    if (typeof (window as unknown as ReactNativeWindow).ReactNativeWebView.postMessage !== 'function') {
      throw new Error(
        'The window.ReactNativeWebView property does not seem to support postMessage calls.'
      )
    }
    this.domain = domain
  }

  async invoke(call: CallType, args: any): Promise<any> {
    return await new Promise((resolve, reject) => {
      const id = Utils.toBase64(Random(12))
      const listener = (e: MessageEvent): void => {
        const data = JSON.parse(e.data)
        if (
          data.type !== 'CWI' ||
          data.id !== id ||
          data.isInvocation === true
        ) {
          return
        }
        if (typeof window.removeEventListener === 'function') {
          window.removeEventListener('message', listener)
        }
        if (data.status === 'error') {
          const err = new WalletError(data.description, data.code)
          reject(err)
        } else {
          resolve(data.result)
        }
      }
      window.addEventListener('message', listener)
      ;(window as unknown as ReactNativeWindow).ReactNativeWebView.postMessage(
        JSON.stringify({
          type: 'CWI',
          isInvocation: true,
          id,
          call,
          args
        })
      )
    })
  }
}
