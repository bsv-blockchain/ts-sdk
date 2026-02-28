/**
 * @typedef {boolean} BooleanDefaultFalse
 * Represents an optional boolean parameter, which defaults to `false` if not provided.
 */
export type BooleanDefaultFalse = boolean

/**
 * @typedef {boolean} BooleanDefaultTrue
 * Represents an optional boolean parameter, which defaults to `true` if not provided.
 */
export type BooleanDefaultTrue = boolean

/**
 * @typedef {number} Byte
 * Represents an integer from 0 to 255 (inclusive).
 * @minimum 0
 * @maximum 255
 */
export type Byte = number

/**
 * @typedef {number} PositiveIntegerOrZero
 * A positive integer, includes zero and has an upper bound of `2^32 - 1`.
 * @minimum 0
 * @maximum 4294967295
 */
export type PositiveIntegerOrZero = number

/**
 * @typedef {number} PositiveInteger
 * A positive integer that excludes zero, and has an upper bound of `2^32 - 1`.
 * @minimum 1
 * @maximum 4294967295
 */
export type PositiveInteger = number

/**
 * @typedef {number} PositiveIntegerMax10
 * A positive integer that excludes zero, and has an upper bound of 10.
 * @minimum 1
 * @maximum 10
 */
export type PositiveIntegerMax10 = number

/**
 * @typedef {number} PositiveIntegerDefault10Max10000
 * A positive integer that defaults to 10, and has an upper bound of 10000.
 * @minimum 1
 * @default 10
 * @maximum 10000
 */
export type PositiveIntegerDefault10Max10000 = number

/**
 * @typedef {number} SatoshiValue
 * Represents a value in Satoshis, constrained by the max supply of Bitcoin (2.1 * 10^15 Satoshis).
 * @minimum 1
 * @maximum 2100000000000000
 */
export type SatoshiValue = number

/**
 * @typedef {string} ISOTimestampString
 * Represents an ISO timestamp string.
 */
export type ISOTimestampString = string

/**
 * @typedef {string} HexString
 * A string containing only hexadecimal characters (0-9, a-f).
 */
export type HexString = string

/**
 * @typedef {HexString} TXIDHexString
 * Represents a transaction ID, enforced to be exactly 64 characters in length and in hexadecimal format.
 * @length 64
 */
export type TXIDHexString = HexString

/**
 * @typedef {string} OutpointString
 * Represents a transaction ID and output index pair. The TXID is given as a hex string followed by a period "." and then the output index is given as a decimal integer.
 */
export type OutpointString = string

/**
 * @typedef {HexString} PubKeyHex
 * Represents a compressed DER secp256k1 public key, exactly 66 hex characters (33 bytes) in length.
 * @length 66
 */
export type PubKeyHex = HexString

/**
 * @typedef {string} Base64String
 * A standard base64 encoded string.
 */
export type Base64String = string

/**
 * @typedef {string} OriginatorDomainNameStringUnder250Bytes
 * Represents the fully qualified domain name (FQDN) of the application that originates the request.
 */
export type OriginatorDomainNameStringUnder250Bytes = string

/**
 * @typedef {string & { minLength: 5, maxLength: 50 }} DescriptionString5to50Bytes
 * A string used for descriptions, with a length between 5 and 50 characters.
 */
export type DescriptionString5to50Bytes = string

/**
 * @typedef {string & { maxLength: 300 }} BasketStringUnder300Bytes
 * A string for naming baskets, with a maximum length of 300 characters.
 */
export type BasketStringUnder300Bytes = string

/**
 * @typedef {string & { maxLength: 300 }} OutputTagStringUnder300Bytes
 * A string for tagging outputs, with a maximum length of 300 characters.
 */
export type OutputTagStringUnder300Bytes = string

/**
 * @typedef {string & { maxLength: 300 }} LabelStringUnder300Bytes
 * A string for labeling transactions, with a maximum length of 300 characters.
 */
export type LabelStringUnder300Bytes = string

/**
 * @typedef {Byte[] | Uint8Array} BEEF
 * An array of integers, each ranging from 0 to 255, indicating transaction data in BEEF (BRC-62) format.
 */
export type BEEF = Byte[] | Uint8Array

/**
 * @typedef {Byte[] | Uint8Array} AtomicBEEF
 * An array of integers, each ranging from 0 to 255, indicating transaction data in Atomic BEEF (BRC-95) format.
 */
export type AtomicBEEF = Byte[] | Uint8Array

/**
 * @typedef {string & { minLength: 5, maxLength: 400 }} ProtocolString5To400Bytes
 * A protocol identifier with a length between 5 and 400 characters.
 */
export type ProtocolString5To400Bytes = string

/**
 * @typedef {string & { maxLength: 800 }} KeyIDStringUnder800Bytes
 * Represents a key identifier string, with a maximum length of 800 characters.
 */
export type KeyIDStringUnder800Bytes = string

/**
 * @typedef {string & { maxLength: 50 }} CertificateFieldNameUnder50Bytes
 * Represents a certificate field name with a maximum length of 50 characters.
 */
export type CertificateFieldNameUnder50Bytes = string

/**
 * @typedef {string & { maxLength: 100 }} EntityNameStringMax100Bytes
 * Represents a trusted entity name with a maximum length of 100 characters.
 */
export type EntityNameStringMax100Bytes = string

/**
 * @typedef {string & { maxLength: 500 }} EntityIconURLStringMax500Bytes
 * Represents a trusted entity icon URL with a maximum length of 500 characters.
 */
export type EntityIconURLStringMax500Bytes = string

/**
 * @typedef {string & { minLength: 7, maxLength: 30 }} VersionString7To30Bytes
 * Represents a version string, with a length between 7 and 30 characters.
 *
 * The format is [vendor]-[major].[minor].[patch]
 */
export type VersionString7To30Bytes = string

/**
 * @typedef {string & { minLength: 10, maxLength: 40 }} ErrorCodeString10To40Bytes
 * Represents a machine-readable error code string, with a length between 10 and 40 characters.
 */
export type ErrorCodeString10To40Bytes = string

/**
 * @typedef {string & { minLength: 20, maxLength: 200 }} ErrorDescriptionString20To200Bytes
 * Represents a human-readable error description string, with a length between 20 and 200 characters.
 */
export type ErrorDescriptionString20To200Bytes = string

export type WalletNetwork = 'mainnet' | 'testnet'

/**
 * @enum {number} SecurityLevels
 *
 * Silent = 0 Silently grants the request with no user interation.
 * App = 1 Requires user approval for every application.
 * Counterparty = 2 Requires user approval per counterparty per application.
 */
export enum SecurityLevels {
  Silent = 0,
  App = 1,
  Counterparty = 2,
}

/**
 *
 * SecurityLevel for protocols.
 * 0 = Silently grants the request with no user interation.
 * 1 = Requires user approval for every application.
 * 2 = Requires user approval per counterparty per application.
 *
 */
export type SecurityLevel = 0 | 1 | 2

export type WalletProtocol = [SecurityLevel, ProtocolString5To400Bytes]

export type WalletCounterparty = PubKeyHex | 'self' | 'anyone'

export type AcquisitionProtocol = 'direct' | 'issuance'

export type KeyringRevealer = PubKeyHex | 'certifier'

export type ActionStatus =
  | 'completed'
  | 'unprocessed'
  | 'sending'
  | 'unproven'
  | 'unsigned'
  | 'nosend'
  | 'nonfinal'
  | 'failed'

/**
 * Controls behavior of input BEEF validation.
 *
 * If `known`, input transactions may omit supporting validity proof data for all TXIDs known to this wallet.
 *
 * If undefined, input BEEFs must be complete and valid.
 */
export type TrustSelf = 'known'

/**
 * @param {OutpointString} outpoint - The outpoint being consumed.
 * @param {DescriptionString5to50Bytes} inputDescription - A description of this input for contextual understanding of what it consumes.
 * @param {HexString} unlockingScript - Optional. The unlocking script needed to release the specified UTXO.
 * @param {PositiveInteger} unlockingScriptLength - Optional. Length of the unlocking script, in case it will be provided later using `signAction`.
 * @param {PositiveIntegerOrZero} sequenceNumber - Optional. The sequence number applied to the input.
 */
export interface CreateActionInput {
  outpoint: OutpointString
  inputDescription: DescriptionString5to50Bytes
  unlockingScript?: HexString
  unlockingScriptLength?: PositiveInteger
  sequenceNumber?: PositiveIntegerOrZero
}

/**
 * @param {HexString} lockingScript - The locking script that dictates how the output can later be spent.
 * @param {SatoshiValue} satoshis - Number of Satoshis that constitute this output.
 * @param {DescriptionString5to50Bytes} outputDescription - Description of what this output represents.
 * @param {BasketStringUnder300Bytes} [basket] - Name of the basket where this UTXO will be held, if tracking is desired.
 * @param {string} [customInstructions] - Custom instructions attached onto this UTXO, often utilized within application logic to provide necessary unlocking context or track token histories.
 * @param {OutputTagStringUnder300Bytes[]} [tags] - Tags assigned to the output for sorting or filtering.
 */
export interface CreateActionOutput {
  lockingScript: HexString
  satoshis: SatoshiValue
  outputDescription: DescriptionString5to50Bytes
  basket?: BasketStringUnder300Bytes
  customInstructions?: string
  tags?: OutputTagStringUnder300Bytes[]
}

/**
 * @param {BooleanDefaultTrue} [signAndProcess] - Optional. If true and all inputs have unlockingScripts, the new transaction will be signed and handed off for processing by the network; result `txid` and `tx` are valid and `signableTransaciton` is undefined. If false or an input has an unlockingScriptLength, result `txid` and `tx` are undefined and `signableTransaction` is valid.
 * @param {BooleanDefaultTrue} [acceptDelayedBroadcast] - Optional. If true, the transaction will be sent to the network by a background process; use `noSend` and `sendWith` options to batch chained transactions. If false, the transaction will be broadcast to the network and any errors returned in result; note that rapidly sent chained transactions may still fail due to network propagation delays.
 * @param {'known'} [trustSelf] - Optional. If `known`, input transactions may omit supporting validity proof data for TXIDs known to this wallet.
 * @param {TXIDHexString[]} [knownTxids] - Optional. When working with large chained transactions using `noSend` and `sendWith` options, include TXIDs of inputs that may be assumed to be valid even if not already known by this wallet.
 * @param {BooleanDefaultFalse} [returnTXIDOnly] - Optional. If true, only a TXID will be returned instead of a transaction.
 * @param {BooleanDefaultFalse} [noSend] - Optional. If true, the transaction will be constructed but not sent to the network. Supports the creation of chained batches of transactions using the `sendWith` option.
 * @param {OutPoint[]} [noSendChange] - Optional. Valid when `noSend` is true. May contain `noSendChange` outpoints previously returned by prior `noSend` actions in the same batch of chained actions.
 * @param {TXIDHexString[]} [sendWith] - Optional. Sends a batch of actions previously created as `noSend` actions to the network; either synchronously if `acceptDelayedBroadcast` is true or by a background process.
 * @param {BooleanDefaultTrue} [randomizeOutputs] — optional. When set to false, the wallet will avoid randomizing the order of outputs within the transaction.
 */
export interface CreateActionOptions {
  signAndProcess?: BooleanDefaultTrue
  acceptDelayedBroadcast?: BooleanDefaultTrue
  trustSelf?: TrustSelf
  knownTxids?: TXIDHexString[]
  returnTXIDOnly?: BooleanDefaultFalse
  noSend?: BooleanDefaultFalse
  noSendChange?: OutpointString[]
  sendWith?: TXIDHexString[]
  randomizeOutputs?: BooleanDefaultTrue
}

export type SendWithResultStatus = 'unproven' | 'sending' | 'failed'

export interface SendWithResult {
  txid: TXIDHexString
  status: SendWithResultStatus
}

/**
 * Indicates status of a new Action following a `createAction` or `signAction` in immediate mode:
 * When `acceptDelayedBroadcast` is falses.
 *
 * 'success': The action has been broadcast and accepted by the bitcoin processing network.
 * 'doulbeSpend': The action has been confirmed to double spend one or more inputs, and by the "first-seen-rule" is the loosing transaction.
 * 'invalidTx': The action was rejected by the processing network as an invalid bitcoin transaction.
 * 'serviceError': The broadcast services are currently unable to reach the bitcoin network. The action is now queued for delayed retries.
 */
export type ReviewActionResultStatus = 'success' | 'doubleSpend' | 'serviceError' | 'invalidTx'

export interface ReviewActionResult {
  txid: TXIDHexString
  status: ReviewActionResultStatus
  /**
   * Any competing txids reported for this txid, valid when status is 'doubleSpend'.
   */
  competingTxs?: string[]
  /**
   * Merged beef of competingTxs, valid when status is 'doubleSpend'.
   */
  competingBeef?: BEEF
}

export interface SignableTransaction {
  tx: AtomicBEEF
  reference: Base64String
}

export interface CreateActionResult {
  txid?: TXIDHexString
  tx?: AtomicBEEF
  noSendChange?: OutpointString[]
  sendWithResults?: SendWithResult[]
  signableTransaction?: SignableTransaction
}

/**
 * @param {DescriptionString5to50Bytes} description - A human-readable description of the action represented by this transaction.
 * @param {BEEF} [inputBEEF] - BEEF data associated with the set of input transactions from which UTXOs will be consumed.
 * @param {CreateActionInput[]} [inputs] - An optional array of input objects used in the transaction.
 * @param {CreateActionOutput[]} [outputs] - An optional array of output objects for the transaction.
 * @param {PositiveIntegerOrZero} [lockTime] - Optional lock time for the transaction.
 * @param {PositiveInteger} [version] - Optional transaction version specifier.
 * @param {LabelStringUnder300Bytes[]} [labels] - Optional labels providing additional categorization for the transaction.
 * @param {CreateActionOptions} [options] - Optional settings modifying transaction processing behavior.
 * @param {Base64String} [reference] - Optional reference for correlating related actions.
 */
export interface CreateActionArgs {
  description: DescriptionString5to50Bytes
  inputBEEF?: BEEF
  inputs?: CreateActionInput[]
  outputs?: CreateActionOutput[]
  lockTime?: PositiveIntegerOrZero
  version?: PositiveIntegerOrZero
  labels?: LabelStringUnder300Bytes[]
  options?: CreateActionOptions
  reference?: Base64String
}

/**
 * @param {HexString} unlockingScript - The unlocking script for the corresponding input.
 * @param {PositiveIntegerOrZero} [sequenceNumber] - The sequence number of the input.
 */
export interface SignActionSpend {
  unlockingScript: HexString
  sequenceNumber?: PositiveIntegerOrZero
}

/**
 * @param {BooleanDefaultTrue} [acceptDelayedBroadcast] - Optional. If true, transaction will be sent to the network by a background process; use `noSend` and `sendWith` options to batch chained transactions. If false, transaction will be broadcast to the network and any errors returned in result; note that rapidly sent chained transactions may still fail due to network propagation delays.
 * @param {'known'} [trustSelf] - Optional. If `known`, input transactions may omit supporting validity proof data for TXIDs known to this wallet or included in `knownTxids`.
 * @param {TXIDHexString[]} [knownTxids] - Optional. When working with large chained transactions using `noSend` and `sendWith` options, include TXIDs of inputs that may be assumed to be valid even if not already known by this wallet.
 * @param {BooleanDefaultFalse} [returnTXIDOnly] - Optional. If true, only a TXID will be returned instead of a transaction.
 * @param {BooleanDefaultFalse} [noSend] - Optional. If true, the transaction will be constructed but not sent to the network. Supports the creation of chained batches of transactions using the `sendWith` option.
 * @param {TXIDHexString[]} [sendWith] - Optional. Sends a batch of actions previously created as `noSend` actions to the network; either synchronously if `acceptDelayedBroadcast` is true or by a background process.
 */
export interface SignActionOptions {
  acceptDelayedBroadcast?: BooleanDefaultTrue
  returnTXIDOnly?: BooleanDefaultFalse
  noSend?: BooleanDefaultFalse
  sendWith?: TXIDHexString[]
}

/**
 * @param {Record<PositiveIntegerOrZero, SignActionSpend>} spends - Map of input indexes to the corresponding unlocking script and optional sequence number.
 * @param {Base64String} reference - Reference number returned from the call to `createAction`.
 * @param {SignActionOptions} [options] - Optional settings modifying transaction processing behavior.
 */
export interface SignActionArgs {
  spends: Record<PositiveIntegerOrZero, SignActionSpend>
  reference: Base64String
  options?: SignActionOptions
}

/**
 *
 */
export interface SignActionResult {
  txid?: TXIDHexString
  tx?: AtomicBEEF
  sendWithResults?: SendWithResult[]
}

/**
 * @param {Base64String} reference - Reference number for the transaction to abort.
 */
export interface AbortActionArgs {
  reference: Base64String
}

export interface AbortActionResult {
  aborted: true
}

export type AcquireCertificateResult = WalletCertificate

/**
 * @param {LabelStringUnder300Bytes[]} labels - An array of labels used to filter actions.
 * @param {'any' | 'all'} [labelQueryMode] - Specifies how to match labels (default is any which matches any of the labels).
 * @param {BooleanDefaultFalse} [includeLabels] - Whether to include transaction labels in the result set.
 * @param {BooleanDefaultFalse} [includeInputs] - Whether to include input details in the result set.
 * @param {BooleanDefaultFalse} [includeInputSourceLockingScripts] - Whether to include input source locking scripts in the result set.
 * @param {BooleanDefaultFalse} [includeInputUnlockingScripts] - Whether to include input unlocking scripts in the result set.
 * @param {BooleanDefaultFalse} [includeOutputs] - Whether to include output details in the result set.
 * @param {BooleanDefaultFalse} [includeOutputLockingScripts] - Whether to include output locking scripts in the result set.
 * @param {PositiveIntegerDefault10Max10000} [limit] - The maximum number of transactions to retrieve.
 * @param {PositiveIntegerOrZero} [offset] - Number of transactions to skip before starting to return the results.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 * @param {Base64String} [reference] - Optional reference for correlating related actions.
 */
export interface ListActionsArgs {
  labels: LabelStringUnder300Bytes[]
  labelQueryMode?: 'any' | 'all'
  includeLabels?: BooleanDefaultFalse
  includeInputs?: BooleanDefaultFalse
  includeInputSourceLockingScripts?: BooleanDefaultFalse
  includeInputUnlockingScripts?: BooleanDefaultFalse
  includeOutputs?: BooleanDefaultFalse
  includeOutputLockingScripts?: BooleanDefaultFalse
  limit?: PositiveIntegerDefault10Max10000
  offset?: PositiveIntegerOrZero
  seekPermission?: BooleanDefaultTrue
  reference?: Base64String
}

export interface WalletActionInput {
  sourceOutpoint: OutpointString
  sourceSatoshis: SatoshiValue
  sourceLockingScript?: HexString
  unlockingScript?: HexString
  inputDescription: DescriptionString5to50Bytes
  sequenceNumber: PositiveIntegerOrZero
}

export interface WalletActionOutput {
  satoshis: SatoshiValue
  lockingScript?: HexString
  spendable: boolean
  customInstructions?: string

  tags: OutputTagStringUnder300Bytes[]

  outputIndex: PositiveIntegerOrZero
  outputDescription: DescriptionString5to50Bytes

  basket: BasketStringUnder300Bytes
}

export interface WalletOutput {
  satoshis: SatoshiValue
  lockingScript?: HexString
  spendable: boolean
  customInstructions?: string

  tags?: OutputTagStringUnder300Bytes[]

  outpoint: OutpointString

  labels?: LabelStringUnder300Bytes[]
}

export interface WalletAction {
  txid: TXIDHexString
  satoshis: SatoshiValue
  status: ActionStatus
  isOutgoing: boolean
  description: DescriptionString5to50Bytes
  labels?: LabelStringUnder300Bytes[]
  version: PositiveIntegerOrZero
  lockTime: PositiveIntegerOrZero
  inputs?: WalletActionInput[]
  outputs?: WalletActionOutput[]
}

export interface ListActionsResult {
  totalActions: PositiveIntegerOrZero
  actions: WalletAction[]
}

/**
 * @param {Base64String} derivationPrefix - Payment-level derivation prefix used by the sender for key derivation (for payments).
 * @param {Base64String} derivationSuffix - Specific output-level derivation suffix used by the sender for key derivation (for payments).
 * @param {PubKeyHex} senderIdentityKey - Public identity key of the sender (for payments).
 */
export interface WalletPayment {
  derivationPrefix: Base64String
  derivationSuffix: Base64String
  senderIdentityKey: PubKeyHex
}

/**
 * @param {BasketStringUnder300Bytes} basket - Basket in which to place the output (for insertions).
 * @param {string} [customInstructions] - Optionally provided custom instructions attached to the output (for insertions).
 * @param {OutputTagStringUnder300Bytes[]} [tags] - Tags attached to the output (for insertions).
 */
export interface BasketInsertion {
  basket: BasketStringUnder300Bytes
  customInstructions?: string
  tags?: OutputTagStringUnder300Bytes[]
}

/**
 * @param {PositiveIntegerOrZero} outputIndex - Index of the output within the transaction.
 * @param {'payment' | 'insert'} protocol - Specifies whether the output is a payment (to be received into the wallet balance) or an insert operation (into a particular basket).
 * @param {WalletPayment} [paymentRemittance] - Optional. Remittance data, structured accordingly for the payment operation.
 * @param {BasketInsertion} [insertionRemittance] - Optional. Remittance data, structured accordingly for the insertion operation.
 */
export interface InternalizeOutput {
  outputIndex: PositiveIntegerOrZero
  protocol: 'wallet payment' | 'basket insertion'
  paymentRemittance?: WalletPayment
  insertionRemittance?: BasketInsertion
}

/**
 * @param {BEEF} tx - Atomic BEEF-formatted transaction to internalize.
 * @param {InternalizeOutput[]} outputs - Metadata about outputs, processed differently based on payment or insertion types.
 * @param {DescriptionString5to50Bytes} description - Human-readable description of the transaction being internalized.
 * @param {LabelStringUnder300Bytes[]} [labels] - Optional labels associated with this transaction.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 * @param {Base64String} [reference] - Optional reference for correlating related actions.
 */
export interface InternalizeActionArgs {
  tx: AtomicBEEF
  outputs: InternalizeOutput[]
  description: DescriptionString5to50Bytes
  labels?: LabelStringUnder300Bytes[]
  seekPermission?: BooleanDefaultTrue
  reference?: Base64String
}

export interface InternalizeActionResult {
  accepted: true
}

/**
 * @param {BasketStringUnder300Bytes} basket - The associated basket name whose outputs should be listed.
 * @param {OutputTagStringUnder300Bytes[]} [tags] - Filter outputs based on these tags.
 * @param {'all' | 'any'} [tagQueryMode] - Filter mode, defining whether all or any of the tags must match. By default, any tag can match.
 * @param {'locking scripts' | 'entire transactions'} [include] - Whether to include locking scripts (with each output) or entire transactions (as aggregated BEEF, at the top level) in the result. By default, unless specified, neither are returned.
 * @param {BooleanDefaultFalse} [includeEntireTransactions] - Whether to include the entire transaction(s) in the result.
 * @param {BooleanDefaultFalse} [includeCustomInstructions] - Whether custom instructions should be returned in the result.
 * @param {BooleanDefaultFalse} [includeTags] - Whether the tags associated with the output should be returned.
 * @param {BooleanDefaultFalse} [includeLabels] - Whether the labels associated with the transaction containing the output should be returned.
 * @param {PositiveIntegerDefault10Max10000} [limit] - Optional limit on the number of outputs to return.
 * @param {number} [offset] - If positive or zero: Number of outputs to skip before starting to return results, oldest first.
 * If negative: Outputs are returned newest first and offset of -1 is the newest output.
 * When using negative offsets, caution is required as new outputs may be added between calls,
 * potentially causing outputs to be duplicated across calls.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 */
export interface ListOutputsArgs {
  basket: BasketStringUnder300Bytes
  tags?: OutputTagStringUnder300Bytes[]
  tagQueryMode?: 'all' | 'any'
  include?: 'locking scripts' | 'entire transactions'
  includeCustomInstructions?: BooleanDefaultFalse
  includeTags?: BooleanDefaultFalse
  includeLabels?: BooleanDefaultFalse
  limit?: PositiveIntegerDefault10Max10000
  offset?: number
  seekPermission?: BooleanDefaultTrue
}

export interface ListOutputsResult {
  totalOutputs: PositiveIntegerOrZero
  BEEF?: BEEF
  outputs: WalletOutput[]
}

export interface RelinquishOutputArgs {
  basket: BasketStringUnder300Bytes
  output: OutpointString
}

export interface RelinquishOutputResult {
  relinquished: true
}

/**
 * @param {WalletProtocol} protocolID - The security level and protocol string under which the data should be encrypted.
 * @param {KeyIDStringUnder800Bytes} keyID - Key ID under which the encryption will be performed.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
 * @param {WalletCounterparty} [counterparty] - Public key of the counterparty (if two-party encryption is desired).
 * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 */
export interface WalletEncryptionArgs {
  protocolID: WalletProtocol
  keyID: KeyIDStringUnder800Bytes
  counterparty?: WalletCounterparty
  privileged?: BooleanDefaultFalse
  privilegedReason?: DescriptionString5to50Bytes
  seekPermission?: BooleanDefaultTrue
}

/**
 * When `identityKey` is true, `WalletEncryptionArgs` are not used.
 *
 * When `identityKey` is undefined, `WalletEncryptionArgs` are required.
 *
 * @param {BooleanDefaultFalse|true} [identityKey] - Use true to retrieve the current user's own identity key, overriding any protocol ID, key ID, or counterparty specified.
 * @param {BooleanDefaultFalse} [forSelf] - Whether to return the public key derived from the current user's own identity (as opposed to the counterparty's identity).
 */
export interface GetPublicKeyArgs extends Partial<WalletEncryptionArgs> {
  identityKey?: true
  forSelf?: BooleanDefaultFalse
}

/**
 * @param {PubKeyHex} counterparty - The public key of the counterparty involved in the linkage.
 * @param {PubKeyHex} verifier - The public key of the verifier requesting the linkage information.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
 * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
 */
export interface RevealCounterpartyKeyLinkageArgs {
  counterparty: PubKeyHex
  verifier: PubKeyHex
  privileged?: BooleanDefaultFalse
  privilegedReason?: DescriptionString5to50Bytes
}

/**
 * @param {PubKeyHex} counterparty - The public key of the counterparty involved in the linkage.
 * @param {PubKeyHex} verifier - The public key of the verifier requesting the linkage information.
 * @param {WalletProtocol} protocolID - The security level and protocol string associated with the linkage information to reveal.
 * @param {KeyIDStringUnder800Bytes} keyID - The key ID associated with the linkage information to reveal.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Optional. Reason provided for privileged access, required if this is a privileged operation.
 * @param {BooleanDefaultFalse} [privileged] - Optional. Whether this is a privileged request.
 */
export interface RevealSpecificKeyLinkageArgs {
  counterparty: WalletCounterparty
  verifier: PubKeyHex
  protocolID: WalletProtocol
  keyID: KeyIDStringUnder800Bytes
  privilegedReason?: DescriptionString5to50Bytes
  privileged?: BooleanDefaultFalse
}

/**
 */
export interface KeyLinkageResult {
  encryptedLinkage: Byte[]
  encryptedLinkageProof: Byte[]
  prover: PubKeyHex
  verifier: PubKeyHex
  counterparty: PubKeyHex
}

/**
 */
export interface RevealCounterpartyKeyLinkageResult extends KeyLinkageResult {
  revelationTime: ISOTimestampString
}

/**
 */
export interface RevealSpecificKeyLinkageResult extends KeyLinkageResult {
  protocolID: WalletProtocol
  keyID: KeyIDStringUnder800Bytes
  proofType: Byte
}

/**
 * @param {Byte[]} plaintext - Array of bytes constituting the plaintext data to be encrypted.
 */
export interface WalletEncryptArgs extends WalletEncryptionArgs {
  plaintext: Byte[]
}

export interface WalletEncryptResult {
  ciphertext: Byte[]
}

/**
 * @param {Byte[]} ciphertext - Encrypted bytes, including the initialization vector, for decryption.
 */
export interface WalletDecryptArgs extends WalletEncryptionArgs {
  ciphertext: Byte[]
}

export interface WalletDecryptResult {
  plaintext: Byte[]
}

/**
 * @param {Byte[]} data - Input data (in bytes) for which the HMAC needs to be created.
 */
export interface CreateHmacArgs extends WalletEncryptionArgs {
  data: Byte[]
}

export interface CreateHmacResult {
  hmac: Byte[]
}

/**
 * @param {Byte[]} data - The input data whose HMAC is to be verified.
 * @param {Byte[]} hmac - Byte array representing the HMAC value to be verified.
 */
export interface VerifyHmacArgs extends WalletEncryptionArgs {
  data: Byte[]
  hmac: Byte[]
}

export interface VerifyHmacResult {
  valid: true
}

/**
 * @param {Byte[]} [data] - Data to be signed using the derived private key with ECDSA. Required unless directly signing a hash.
 * @param {Byte[]} [hashToDirectlySign] - Sign a pre-hashed value in situations where data can't or shouldn't be revealed, whether due to its size or for privacy.
 */
export interface CreateSignatureArgs extends WalletEncryptionArgs {
  data?: Byte[]
  hashToDirectlySign?: Byte[]
}

export interface CreateSignatureResult {
  signature: Byte[]
}

/**
 * @param {Byte[]} [args.data] - The data originally signed, which is required for verification unless directly verifying a hash.
 * @param {Byte[]} [args.hashToDirectlyVerify] - Optional field to verify the signature against a precomputed hash instead of data.
 * @param {Byte[]} args.signature - The DER-encoded ECDSA signature to validate.
 * @param {BooleanDefaultFalse} [args.forSelf] - Whether the signature to be verified was created by this user rather than the counterparty.
 */
export interface VerifySignatureArgs extends WalletEncryptionArgs {
  data?: Byte[]
  hashToDirectlyVerify?: Byte[]
  signature: Byte[]
  forSelf?: BooleanDefaultFalse
}

export interface VerifySignatureResult {
  valid: true
}

/**
 * @param {Base64String} type - Type identifier for the certificate.
 * @param {PubKeyHex} certifier - The public identity key of the certifier.
 * @param {AcquisitionProtocol} acquisitionProtocol - Specifies the acquisition process, set to either 'issuance' or 'direct'.
 * @param {Record<CertificateFieldNameUnder50Bytes, string>} fields - The fields included within the certificate.
 * @param {Base64String} [serialNumber] - Serial number of the certificate to acquire (required when the acquisition protocol is direct).
 * @param {string} [revocationOutpoint] - Reference for an outpoint comprising a Bitcoin token that, if ever spent, marks the certificate as invalid (required when the acquisition protocol is direct).
 * @param {HexString} [signature] - Signature over the certificate (required when the acquisition protocol is direct).
 * @param {string} [certifierUrl] - URL of the certifier where certificate acquisition requests will be sent (required when the acquisition protocol is issuance).
 * @param {KeyringRevealer} [keyringRevealer] - The public identity key of the entity revealing the keyring to the user, if different from the certifier (required when the acquisition protocol is direct).
 * @param {Record<CertificateFieldNameUnder50Bytes, Base64String>} [keyringForSubject] - Keyring revealing all certificate fields to the subject (required when the acquisition protocol is direct).
 * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
 */
export interface AcquireCertificateArgs {
  type: Base64String
  certifier: PubKeyHex
  acquisitionProtocol: AcquisitionProtocol
  fields: Record<CertificateFieldNameUnder50Bytes, string>
  serialNumber?: Base64String
  revocationOutpoint?: OutpointString
  signature?: HexString
  certifierUrl?: string
  keyringRevealer?: KeyringRevealer
  keyringForSubject?: Record<CertificateFieldNameUnder50Bytes, Base64String>
  privileged?: BooleanDefaultFalse
  privilegedReason?: DescriptionString5to50Bytes
}

export interface WalletCertificate {
  type: Base64String
  subject: PubKeyHex
  serialNumber: Base64String
  certifier: PubKeyHex
  revocationOutpoint: OutpointString
  signature: HexString
  fields: Record<CertificateFieldNameUnder50Bytes, string>
}

export interface IdentityCertifier {
  name: EntityNameStringMax100Bytes
  iconUrl: EntityIconURLStringMax500Bytes
  description: DescriptionString5to50Bytes
  trust: PositiveIntegerMax10
}

export interface IdentityCertificate extends WalletCertificate {
  certifierInfo: IdentityCertifier
  publiclyRevealedKeyring: Record<
  CertificateFieldNameUnder50Bytes,
  Base64String
  >
  decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>
}

/**
 * @param {PubKeyHex[]} certifiers - An array of public keys for specific certifiers (filters by these certifiers).
 * @param {Base64String[]} types - An array of certificate types issued by any of the specified certifiers, which should be returned.
 * @param {PositiveIntegerDefault10Max10000} [limit] - Maximum number of certificates to return.
 * @param {PositiveIntegerOrZero} [offset] - Number of records to skip before starting to return results.
 * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
 */
export interface ListCertificatesArgs {
  certifiers: PubKeyHex[]
  types: Base64String[]
  limit?: PositiveIntegerDefault10Max10000
  offset?: PositiveIntegerOrZero
  privileged?: BooleanDefaultFalse
  privilegedReason?: DescriptionString5to50Bytes
}

export interface CertificateResult extends WalletCertificate {
  keyring?: Record<CertificateFieldNameUnder50Bytes, Base64String>
  verifier?: string
}

export interface ListCertificatesResult {
  totalCertificates: PositiveIntegerOrZero
  certificates: CertificateResult[]
}

/**
 * @param {WalletCertificate} certificate - The specific identity certificate being proven.
 * @param {CertificateFieldNameUnder50Bytes[]} fieldsToReveal - Array of field names that need to be revealed to the verifier.
 * @param {PubKeyHex} verifier - Public key of the verifier, to whom the key revelations will be made.
 * @param {BooleanDefaultFalse} [privileged] - Whether this is a privileged request.
 * @param {DescriptionString5to50Bytes} [privilegedReason] - Reason provided for privileged access, required if this is a privileged operation.
 */
export interface ProveCertificateArgs {
  certificate: Partial<WalletCertificate>
  fieldsToReveal: CertificateFieldNameUnder50Bytes[]
  verifier: PubKeyHex
  privileged?: BooleanDefaultFalse
  privilegedReason?: DescriptionString5to50Bytes
}

export interface ProveCertificateResult {
  keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>
  certificate?: WalletCertificate
  verifier?: PubKeyHex
}

/**
 * @param {Base64String} type - Type identifier for the certificate.
 * @param {PubKeyHex} certifier - The public identity key of the certifier.
 * @param {Base64String} serialNumber - Serial number of the certificate to relinquish.
 */
export interface RelinquishCertificateArgs {
  type: Base64String
  serialNumber: Base64String
  certifier: PubKeyHex
}

export interface RelinquishCertificateResult {
  relinquished: true
}

export interface AuthenticatedResult {
  authenticated: true
}

export interface GetHeightResult {
  height: PositiveInteger
}

/**
 * @param {PositiveInteger} height - Specifies the height at which the block header needs to be retrieved.
 */
export interface GetHeaderArgs {
  height: PositiveInteger
}

export interface GetHeaderResult {
  header: HexString
}

export interface GetNetworkResult {
  network: WalletNetwork
}

export interface GetVersionResult {
  version: VersionString7To30Bytes
}

/**
 * @param {PubKeyHex} identityKey - Identity key used to filter and discover certificates.
 * @param {PositiveIntegerDefault10Max10000} [limit] - Maximum number of certificates to return in the response.
 * @param {PositiveIntegerOrZero} [offset] - Skip this number of records before starting to provide results.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 */
export interface DiscoverByIdentityKeyArgs {
  identityKey: PubKeyHex
  limit?: PositiveIntegerDefault10Max10000
  offset?: PositiveIntegerOrZero
  seekPermission?: BooleanDefaultTrue
}

/**
 */
export interface DiscoverCertificatesResult {
  totalCertificates: PositiveIntegerOrZero
  certificates: IdentityCertificate[]
}

/**
 * @param {Record<CertificateFieldNameUnder50Bytes, string>} attributes - The attributes used to discover the certificates.
 * @param {PositiveIntegerDefault10Max10000} [limit] - Optional limit on the number of results returned.
 * @param {PositiveIntegerOrZero} [offset] - Starts retrieval of results after the specified number of records.
 * @param {BooleanDefaultTrue} [seekPermission] — Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.
 */
export interface DiscoverByAttributesArgs {
  attributes: Record<CertificateFieldNameUnder50Bytes, string>
  limit?: PositiveIntegerDefault10Max10000
  offset?: PositiveIntegerOrZero
  seekPermission?: BooleanDefaultTrue
}

// export interface AcquireCertificateResult extends WalletCertificate {}

/**
 * Every method of the `Wallet` interface has a return value of the form `Promise<object>`.
 * When errors occur, an exception object may be thrown which must conform to the `WalletErrorObject` interface.
 * Serialization layers can rely on the `isError` property being unique to error objects.
 * Deserialization should rethrow `WalletErrorObject` conforming objects.
 */
export interface WalletErrorObject extends Error {
  isError: true
}

/**
 *
 */
export interface GetPublicKeyResult {
  publicKey: PubKeyHex
}

/**
 * The Wallet interface defines a wallet capable of various tasks including transaction creation and signing,
 * encryption, decryption, identity certificate management, identity verification, and communication
 * with applications as per the BRC standards. This interface allows applications to interact with
 * the wallet for a range of functionalities aligned with the Babbage architectural principles.
 *
 * Error Handling
 *
 * Every method of the `Wallet` interface has a return value of the form `Promise<object>`.
 * When an error occurs, an exception object may be thrown which must conform to the `WalletErrorObject` interface.
 * Serialization layers can rely on the `isError` property being unique to error objects to
 * deserialize and rethrow `WalletErrorObject` conforming objects.
 */
export interface WalletInterface {
  /**
   * Retrieves a derived or identity public key based on the requested protocol, key ID, counterparty, and other factors.
   *
   * @param {GetPublicKeyArgs} args - Arguments to specify which public key to retrieve.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<GetPublicKeyResult>}} Resolves to an object containing the public key, or an error response.
   */
  getPublicKey: (
    args: GetPublicKeyArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<GetPublicKeyResult>

  /**
   * Reveals the key linkage between ourselves and a counterparty, to a particular verifier, across all interactions with the counterparty.
   *
   * @param {RevealCounterpartyKeyLinkageArgs} args - Contains information about counterparty, verifier, and whether the operation is privileged.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<RevealSpecificKeyLinkageResult>} Resolves to the key linkage, or an error response.
   */
  revealCounterpartyKeyLinkage: (
    args: RevealCounterpartyKeyLinkageArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<RevealCounterpartyKeyLinkageResult>

  /**
   * Reveals the key linkage between ourselves and a counterparty, to a particular verifier, with respect to a specific interaction.
   *
   * @param {RevealSpecificKeyLinkageArgs} args - The object defining the counterparty, verifier, protocol, and keyID for which linkage should be revealed.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<RevealSpecificKeyLinkageResult>} The promise returns the requested linkage information, or an error object.
   */
  revealSpecificKeyLinkage: (
    args: RevealSpecificKeyLinkageArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<RevealSpecificKeyLinkageResult>

  /**
   * Encrypts the provided plaintext data using derived keys, based on the protocol ID, key ID, counterparty, and other factors.
   *
   * @param {WalletEncryptArgs} args - Information needed for encryption, including the plaintext, protocol ID, and key ID.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<WalletEncryptResult>} Resolves to the encrypted ciphertext bytes or an error if encryption fails.
   */
  encrypt: (
    args: WalletEncryptArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<WalletEncryptResult>

  /**
   * Decrypts the provided ciphertext using derived keys, based on the protocol ID, key ID, counterparty, and other factors.
   *
   * @param {WalletDecryptArgs} args - Contains the ciphertext, protocol ID, and key ID required to decrypt the data.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<WalletDecryptResult>} Resolves to the decryption result, containing the plaintext data or an error.
   */
  decrypt: (
    args: WalletDecryptArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<WalletDecryptResult>

  /**
   * Creates an HMAC (Hash-based Message Authentication Code) based on the provided data, protocol, key ID, counterparty, and other factors.
   *
   * @param {CreateHmacArgs} args - Arguments containing the data, protocol ID, and key ID to generate the HMAC from.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<CreateHmacResult>} Resolves to an object containing the generated HMAC bytes, or an error if the creation fails.
   */
  createHmac: (
    args: CreateHmacArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<CreateHmacResult>

  /**
   * Verifies an HMAC (Hash-based Message Authentication Code) based on the provided data, protocol, key ID, counterparty, and other factors.
   *
   * @param {VerifyHmacArgs} args - Arguments containing the HMAC data, protocol ID, and key ID needed for verification.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<VerifyHmacResult>} Resolves to an object confirming whether the HMAC was valid or an error.
   */
  verifyHmac: (
    args: VerifyHmacArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<VerifyHmacResult>

  /**
   * Creates a digital signature for the provided data or hash using a specific protocol, key, and optionally considering privilege and counterparty.
   *
   * @param {CreateSignatureArgs} args - Arguments to specify data, protocol, key ID, and privilege for creating the signature.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<CreateSignatureResult>} The promise will resolve to an object containing the DER-encoded ECDSA signature, or an error on failure.
   */
  createSignature: (
    args: CreateSignatureArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<CreateSignatureResult>

  /**
   * Verifies a digital signature for the provided data or hash using a specific protocol, key, and optionally considering privilege and counterparty.
   *
   * @param {VerifySignatureArgs} args - Arguments specifying the data, signature, protocol, and key ID.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<VerifySignatureResult>} The promise resolves to a boolean object indicating whether the signature was valid or an error message.
   */
  verifySignature: (
    args: VerifySignatureArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<VerifySignatureResult>

  /**
   * Creates a new Bitcoin transaction based on the provided inputs, outputs, labels, locks, and other options.
   *
   * @param {CreateActionArgs} args - The arguments required to create the transaction.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<CreateActionResult>} The promise returns different structures based on the outcome: error response, response with TXID, response with transaction, or info about signable transaction (partial BEEF and reference number).
   */
  createAction: (
    args: CreateActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<CreateActionResult>

  /**
   * Signs a transaction previously created using `createAction`.
   *
   * @param {SignActionArgs} args - Arguments to sign the transaction.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<SignActionResult>} The promise returns an error response or a response with either the completed transaction or TXID.
   */
  signAction: (
    args: SignActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<SignActionResult>

  /**
   * Aborts a transaction that is in progress and has not yet been finalized or sent to the network.
   *
   * @param {AbortActionArgs} args - Arguments to identify the transaction that needs to be aborted.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<AbortActionResult>} The promise resolves to an object indicating the abortion result (either success or error).
   */
  abortAction: (
    args: AbortActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<AbortActionResult>

  /**
   * Lists all transactions matching the specified labels.
   *
   * @param {ListActionsArgs} args - Arguments to specify how to filter or retrieve transactions.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<ListActionsResult>} The promise resolves to an object containing actions, their metadata, inputs, and outputs if applicable, or an error object.
   */
  listActions: (
    args: ListActionsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<ListActionsResult>

  /**
   * Submits a transaction to be internalized and optionally labeled, outputs paid to the wallet balance, inserted into baskets, and/or tagged.
   *
   * @param {InternalizeActionArgs} args - Arguments required to internalize the transaction.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<InternalizeActionResult>} The promise resolves to an object indicating the success of the operation or an error object.
   */
  internalizeAction: (
    args: InternalizeActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<InternalizeActionResult>

  /**
   * Lists the spendable outputs kept within a specific basket, optionally tagged with specific labels.
   *
   * @param {ListOutputsArgs} args - Arguments detailing the query for listing spendable outputs.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<ListOutputsResult>} The promise returns an output listing or an error object.
   */
  listOutputs: (
    args: ListOutputsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<ListOutputsResult>

  /**
   * Relinquish an output out of a basket, removing it from tracking without spending it.
   *
   * @param {RelinquishOutputArgs} args - Arguments identifying the output in the basket.
   * @param {BasketStringUnder300Bytes} args.basket - The associated basket name where the output should be removed.
   * @param {OutpointString} args.outpoint - The output that should be removed from the basket.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<RelinquishOutputResult>} The promise returns an indication of successful removal or an error object.
   */
  relinquishOutput: (
    args: RelinquishOutputArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<RelinquishOutputResult>

  /**
   * Acquires an identity certificate, whether by acquiring one from the certifier or by directly receiving it.
   *
   * @param {AcquireCertificateArgs} args - Contains the type of certificate, certifier information, and fields of the certificate to be provided, among other details.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<AcquireCertificateResult>} The promise resolves to an object containing the acquired certificate, or an error object.
   */
  acquireCertificate: (
    args: AcquireCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<WalletCertificate>

  /**
   * Lists identity certificates belonging to the user, filtered by certifier(s) and type(s).
   *
   * @param {ListCertificatesArgs} args - Arguments used to filter or limit the list of certificates returned by the request.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<ListCertificatesResult>} The promise resolves to an object containing certificates or an error response.
   */
  listCertificates: (
    args: ListCertificatesArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<ListCertificatesResult>

  /**
   * Proves select fields of an identity certificate, as specified, when requested by a verifier.
   *
   * @param {ProveCertificateArgs} args - Arguments including the certificate, fields to reveal, and verifier's public key.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<ProveCertificateResult>} Resolves to a keyring for the verifier or an error object.
   */
  proveCertificate: (
    args: ProveCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<ProveCertificateResult>

  /**
   * Relinquishes an identity certificate, removing it from the wallet regardless of whether the revocation outpoint has become spent.
   *
   * @param {RelinquishCertificateArgs} args - Contains the type of certificate, certifier, and serial number for relinquishment.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<RelinquishCertificateResult>} The promise resolves to an indication of successful relinquishment or an error object.
   */
  relinquishCertificate: (
    args: RelinquishCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<RelinquishCertificateResult>

  /**
   * Discovers identity certificates, issued to a given identity key by a trusted entity.
   *
   * @param {DiscoverByIdentityKeyArgs} args - Arguments for requesting the discovery based on the identity key.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<DiscoverCertificatesResult>} The promise resolves to the list of certificates discovered or an error object.
   */
  discoverByIdentityKey: (
    args: DiscoverByIdentityKeyArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<DiscoverCertificatesResult>

  /**
   * Discovers identity certificates belonging to other users, where the documents contain specific attributes, issued by a trusted entity.
   *
   * @param {DiscoverByAttributesArgs} args - Attributes and optional parameters used to discover certificates.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<DiscoverByAttributesResult>} The promise resolves to a list of matching certificates or an error object.
   */
  discoverByAttributes: (
    args: DiscoverByAttributesArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<DiscoverCertificatesResult>

  /**
   * Checks the authentication status of the user.
   *
   * @param {{}} args - Empty object, as no parameters are needed.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<AuthenticatedResult>} The promise resolves to an object indicating whether the user is authenticated or an error response.
   */
  isAuthenticated: (
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<AuthenticatedResult>

  /**
   * Continuously waits until the user is authenticated, returning the result once confirmed.
   *
   * @param {{}} args - Not used, pass an empty object.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<AuthenticatedResult>} The final result indicating that the user is authenticated or an error object.
   */
  waitForAuthentication: (
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<AuthenticatedResult>

  /**
   * Retrieves the current height of the blockchain.
   *
   * @param {{}} args - Empty object as no other parameters are necessary.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<Object>} Resolves to an object indicating the current height or an error on failure.
   */
  getHeight: (
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<GetHeightResult>

  /**
   * Retrieves the block header of a block at a specified height.
   *
   * @param {GetHeaderArgs} args - Contains the height parameter needed to retrieve the block header.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<GetHeaderResult>} The promise resolves to an 80-byte block header or an error if it cannot be retrieved.
   */
  getHeaderForHeight: (
    args: GetHeaderArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<GetHeaderResult>

  /**
   * Retrieves the Bitcoin network the client is using (mainnet or testnet).
   *
   * @param {{}} args - No arguments required, pass an empty object.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<GetNetworkResult>} The promise resolves to an object indicating whether the client is using the mainnet or testnet.
   */
  getNetwork: (
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<GetNetworkResult>

  /**
   * Retrieves the current version string of the wallet.
   *
   * @param {{}} args - Empty argument object.
   * @param {OriginatorDomainNameStringUnder250Bytes} [originator] - Fully-qualified domain name (FQDN) of the application that originated the request.
   * @returns {Promise<GetVersionResult>} Resolves to an object containing the version string of the wallet, or an error.
   */
  getVersion: (
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) => Promise<GetVersionResult>
}
