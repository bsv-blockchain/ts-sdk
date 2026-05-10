import { AtomicBEEF, OutpointString, ReviewActionResult, SendWithResult, TXIDHexString } from './Wallet.interfaces.js'

/**
 * When a `createAction` or `signAction` is completed in undelayed mode (`acceptDelayedBroadcast`: false),
 * any unsuccessful result will return the results by way of this exception to ensure attention is
 * paid to processing errors.
 */
export class WERR_REVIEW_ACTIONS extends Error {
  code: number
  isError: boolean = true

  /**
   * All parameters correspond to their comparable `createAction` or `signAction` results
   * with the exception of `reviewActionResults`;
   * which contains more details, particularly for double spend results.
   */
  constructor (
    public reviewActionResults: ReviewActionResult[],
    public sendWithResults: SendWithResult[],
    public txid?: TXIDHexString,
    public tx?: AtomicBEEF,
    public noSendChange?: OutpointString[]
  ) {
    super('Undelayed createAction or signAction results require review.')
    this.code = 5
    this.name = this.constructor.name
  }
}

export default WERR_REVIEW_ACTIONS
