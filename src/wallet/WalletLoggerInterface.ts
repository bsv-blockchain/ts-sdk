/**
 * A console-like interface for logging within wallet operations.
 *
 * Intended to reflect a subset of standard `Console` interface methods used by `Wallet`
 */

export interface WalletLoggerInterface {
  /**
   * Increases indentation of subsequent lines.
   *
   * If one or more `label`s are provided, those are printed first without the
   * additional indentation.
   */
  group: (...label: any[]) => void
  /**
   * Decreases indentation of subsequent lines.
   */
  groupEnd: () => void
  /**
   * Log a message.
   */
  log: (message?: any, ...optionalParams: any[]) => void
  /**
   * Log an error message.
   */
  error: (message?: any, ...optionalParams: any[]) => void
  /**
   * Loggers may accumulate data instead of immediately handling it.
   *
   * Loggers that do not accumulate should not implement this method.
   *
   * @returns undefined if this was the origin and data has been logged, else a WalletLoggerJson object.
   */
  flush?: () => object | undefined

  /**
   * Merge log data from another logger.
   *
   * Typically used to merge log data from network request.
   *
   * @param log
   * @returns
   */
  merge?: (log: WalletLoggerInterface) => void

  /**
   * Optional. Logging levels that may influence what is logged.
   *
   * 'error' Only requests resulting in an exception should be logged.
   * 'warn' Also log requests that succeed but with an abnormal condition.
   * 'info' Also log normal successful requests.
   * 'debug' Add input parm and result details where possible.
   * 'trace' Instead of adding debug details, focus on execution path and timing.
   */
  level?: 'error' | 'warn' | 'info' | 'debug' | 'trace'

  /**
   * Valid if an accumulating logger. Count of `group` calls without matching `groupEnd`.
   */
  indent?: number
  /**
   * True if this is an accumulating logger and the logger belongs to the object servicing the initial request.
   */
  isOrigin?: boolean
  /**
   * True if this is an accumulating logger and an error was logged.
   */
  isError?: boolean

  /**
   * Optional array of accumulated logged data and errors.
   */
  logs?: WalletLoggerLog[]
}

export interface WalletLoggerLog {
  when: number
  indent: number
  log: string
  isError?: boolean
  isBegin?: boolean
  isEnd?: boolean
}

export type MakeWalletLogger = (log?: string | WalletLoggerInterface) => WalletLoggerInterface
