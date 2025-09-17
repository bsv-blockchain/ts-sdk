
import {
  AcquireCertificateArgs,
  AcquireCertificateResult,
  SecurityLevel,
  SecurityLevels,
  Base64String,
  BasketStringUnder300Bytes,
  BEEF,
  BooleanDefaultFalse,
  BooleanDefaultTrue,
  Byte,
  CertificateFieldNameUnder50Bytes,
  CertificateResult,
  CreateActionArgs,
  CreateActionResult,
  DescriptionString5to50Bytes,
  DiscoverCertificatesResult,
  EntityIconURLStringMax500Bytes,
  EntityNameStringMax100Bytes,
  HexString,
  InternalizeActionArgs,
  ISOTimestampString,
  KeyIDStringUnder800Bytes,
  LabelStringUnder300Bytes,
  ListActionsArgs,
  ListActionsResult,
  ListCertificatesResult,
  ListOutputsArgs,
  ListOutputsResult,
  OriginatorDomainNameStringUnder250Bytes,
  OutpointString,
  OutputTagStringUnder300Bytes,
  PositiveInteger,
  PositiveIntegerDefault10Max10000,
  PositiveIntegerMax10,
  PositiveIntegerOrZero,
  ProtocolString5To400Bytes,
  ProveCertificateArgs,
  ProveCertificateResult,
  PubKeyHex,
  SatoshiValue,
  SignActionArgs,
  SignActionResult,
  TXIDHexString,
  VersionString7To30Bytes,
  WalletInterface,
  ActionStatus
} from '../Wallet.interfaces.js'
import WalletWire from './WalletWire.js'
import Certificate from '../../auth/certificates/Certificate.js'
import * as Utils from '../../primitives/utils.js'
import calls, { CallType } from './WalletWireCalls.js'
import { WalletError } from '../WalletError.js'

/**
 * A way to make remote calls to a wallet over a wallet wire.
 */
export default class WalletWireTransceiver implements WalletInterface {
  wire: WalletWire

  constructor(wire: WalletWire) {
    this.wire = wire
  }

  private async transmit(
    call: CallType,
    originator: OriginatorDomainNameStringUnder250Bytes = '',
    params: number[] = []
  ): Promise<number[]> {
    const frameWriter = new Utils.Writer()
    frameWriter.writeUInt8(calls[call])
    const originatorArray = Utils.toArray(originator, 'utf8')
    frameWriter.writeUInt8(originatorArray.length)
    frameWriter.write(originatorArray)
    if (params.length > 0) {
      frameWriter.write(params)
    }
    const frame = frameWriter.toArray()
    const result = await this.wire.transmitToWallet(frame)
    const resultReader = new Utils.Reader(result)
    const errorByte = resultReader.readUInt8()
    if (errorByte === 0) {
      const resultFrame = resultReader.read()
      return resultFrame
    } else {
      // Deserialize the error message length
      const errorMessageLength = resultReader.readVarIntNum()
      const errorMessageBytes = resultReader.read(errorMessageLength)
      const errorMessage = Utils.toUTF8(errorMessageBytes)

      // Deserialize the stack trace length
      const stackTraceLength = resultReader.readVarIntNum()
      const stackTraceBytes = resultReader.read(stackTraceLength)
      const stackTrace = Utils.toUTF8(stackTraceBytes)

      // Construct a custom wallet error
      const e = new WalletError(errorMessage, errorByte, stackTrace)
      throw e
    }
  }

  async createAction(
    args: CreateActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<CreateActionResult> {
    const paramWriter = new Utils.Writer()

    // Serialize description
    const descriptionBytes = Utils.toArray(args.description, 'utf8')
    paramWriter.writeVarIntNum(descriptionBytes.length)
    paramWriter.write(descriptionBytes)

    // input BEEF
    if (args.inputBEEF != null) {
      paramWriter.writeVarIntNum(args.inputBEEF.length)
      paramWriter.write(args.inputBEEF)
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize inputs
    if (args.inputs != null) {
      paramWriter.writeVarIntNum(args.inputs.length)
      for (const input of args.inputs) {
        // outpoint
        paramWriter.write(this.encodeOutpoint(input.outpoint))

        // unlockingScript / unlockingScriptLength
        if (input.unlockingScript != null && input.unlockingScript !== '') {
          const unlockingScriptBytes = Utils.toArray(
            input.unlockingScript,
            'hex'
          )
          paramWriter.writeVarIntNum(unlockingScriptBytes.length)
          paramWriter.write(unlockingScriptBytes)
        } else {
          paramWriter.writeVarIntNum(-1)
          paramWriter.writeVarIntNum(input.unlockingScriptLength ?? 0)
        }

        // inputDescription
        const inputDescriptionBytes = Utils.toArray(
          input.inputDescription,
          'utf8'
        )
        paramWriter.writeVarIntNum(inputDescriptionBytes.length)
        paramWriter.write(inputDescriptionBytes)

        // sequenceNumber
        if (typeof input.sequenceNumber === 'number') {
          paramWriter.writeVarIntNum(input.sequenceNumber)
        } else {
          paramWriter.writeVarIntNum(-1)
        }
      }
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize outputs
    if (args.outputs != null) {
      paramWriter.writeVarIntNum(args.outputs.length)
      for (const output of args.outputs) {
        // lockingScript
        const lockingScriptBytes = Utils.toArray(output.lockingScript, 'hex')
        paramWriter.writeVarIntNum(lockingScriptBytes.length)
        paramWriter.write(lockingScriptBytes)

        // satoshis
        paramWriter.writeVarIntNum(output.satoshis)

        // outputDescription
        const outputDescriptionBytes = Utils.toArray(
          output.outputDescription,
          'utf8'
        )
        paramWriter.writeVarIntNum(outputDescriptionBytes.length)
        paramWriter.write(outputDescriptionBytes)

        // basket
        if (output.basket != null && output.basket !== '') {
          const basketBytes = Utils.toArray(output.basket, 'utf8')
          paramWriter.writeVarIntNum(basketBytes.length)
          paramWriter.write(basketBytes)
        } else {
          paramWriter.writeVarIntNum(-1)
        }

        // customInstructions
        if (output.customInstructions != null && output.customInstructions !== '') {
          const customInstructionsBytes = Utils.toArray(
            output.customInstructions,
            'utf8'
          )
          paramWriter.writeVarIntNum(customInstructionsBytes.length)
          paramWriter.write(customInstructionsBytes)
        } else {
          paramWriter.writeVarIntNum(-1)
        }

        // tags
        if (output.tags != null) {
          paramWriter.writeVarIntNum(output.tags.length)
          for (const tag of output.tags) {
            const tagBytes = Utils.toArray(tag, 'utf8')
            paramWriter.writeVarIntNum(tagBytes.length)
            paramWriter.write(tagBytes)
          }
        } else {
          paramWriter.writeVarIntNum(-1)
        }
      }
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize lockTime
    if (typeof args.lockTime === 'number') {
      paramWriter.writeVarIntNum(args.lockTime)
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize version
    if (typeof args.version === 'number') {
      paramWriter.writeVarIntNum(args.version)
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize labels
    if (args.labels != null) {
      paramWriter.writeVarIntNum(args.labels.length)
      for (const label of args.labels) {
        const labelBytes = Utils.toArray(label, 'utf8')
        paramWriter.writeVarIntNum(labelBytes.length)
        paramWriter.write(labelBytes)
      }
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize options
    if (args.options != null) {
      paramWriter.writeInt8(1) // options present

      // signAndProcess
      if (typeof args.options.signAndProcess === 'boolean') {
        paramWriter.writeInt8(args.options.signAndProcess ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // acceptDelayedBroadcast
      if (typeof args.options.acceptDelayedBroadcast === 'boolean') {
        paramWriter.writeInt8(args.options.acceptDelayedBroadcast ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // trustSelf
      if (args.options.trustSelf === 'known') {
        paramWriter.writeInt8(1)
      } else {
        paramWriter.writeInt8(-1)
      }

      // knownTxids
      if (args.options.knownTxids != null) {
        paramWriter.writeVarIntNum(args.options.knownTxids.length)
        for (const txid of args.options.knownTxids) {
          const txidBytes = Utils.toArray(txid, 'hex')
          paramWriter.write(txidBytes)
        }
      } else {
        paramWriter.writeVarIntNum(-1)
      }

      // returnTXIDOnly
      if (typeof args.options.returnTXIDOnly === 'boolean') {
        paramWriter.writeInt8(args.options.returnTXIDOnly ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // noSend
      if (typeof args.options.noSend === 'boolean') {
        paramWriter.writeInt8(args.options.noSend ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // noSendChange
      if (args.options.noSendChange != null) {
        paramWriter.writeVarIntNum(args.options.noSendChange.length)
        for (const outpoint of args.options.noSendChange) {
          paramWriter.write(this.encodeOutpoint(outpoint))
        }
      } else {
        paramWriter.writeVarIntNum(-1)
      }

      // sendWith
      if (args.options.sendWith != null) {
        paramWriter.writeVarIntNum(args.options.sendWith.length)
        for (const txid of args.options.sendWith) {
          const txidBytes = Utils.toArray(txid, 'hex')
          paramWriter.write(txidBytes)
        }
      } else {
        paramWriter.writeVarIntNum(-1)
      }

      // randomizeOutputs
      if (typeof args.options.randomizeOutputs === 'boolean') {
        paramWriter.writeInt8(args.options.randomizeOutputs ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }
    } else {
      paramWriter.writeInt8(0) // options not present
    }

    // Transmit and parse response
    const result = await this.transmit(
      'createAction',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)

    const response: {
      txid?: TXIDHexString
      tx?: BEEF
      noSendChange?: OutpointString[]
      sendWithResults?: Array<{
        txid: TXIDHexString
        status: 'unproven' | 'sending' | 'failed'
      }>
      signableTransaction?: {
        tx: BEEF
        reference: Base64String
      }
    } = {}

    // Parse txid
    const txidFlag = resultReader.readInt8()
    if (txidFlag === 1) {
      const txidBytes = resultReader.read(32)
      response.txid = Utils.toHex(txidBytes)
    }

    // Parse tx
    const txFlag = resultReader.readInt8()
    if (txFlag === 1) {
      const txLength = resultReader.readVarIntNum()
      response.tx = resultReader.read(txLength)
    }

    // Parse noSendChange
    const noSendChangeLength = resultReader.readVarIntNum()
    if (noSendChangeLength >= 0) {
      response.noSendChange = []
      for (let i = 0; i < noSendChangeLength; i++) {
        const outpoint = this.readOutpoint(resultReader)
        response.noSendChange.push(outpoint)
      }
    }

    // Parse sendWithResults
    const sendWithResultsLength = resultReader.readVarIntNum()
    if (sendWithResultsLength >= 0) {
      response.sendWithResults = []
      for (let i = 0; i < sendWithResultsLength; i++) {
        const txidBytes = resultReader.read(32)
        const txid = Utils.toHex(txidBytes)
        const statusCode = resultReader.readInt8()
        let status: 'unproven' | 'sending' | 'failed' = 'unproven'
        if (statusCode === 1) status = 'unproven'
        else if (statusCode === 2) status = 'sending'
        else if (statusCode === 3) status = 'failed'
        response.sendWithResults.push({ txid, status })
      }
    }

    // Parse signableTransaction
    const signableTransactionFlag = resultReader.readInt8()
    if (signableTransactionFlag === 1) {
      const txLength = resultReader.readVarIntNum()
      const tx = resultReader.read(txLength)
      const referenceLength = resultReader.readVarIntNum()
      const referenceBytes = resultReader.read(referenceLength)
      response.signableTransaction = {
        tx,
        reference: Utils.toBase64(referenceBytes)
      }
    }

    return response
  }

  async signAction(
    args: SignActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<SignActionResult> {
    const paramWriter = new Utils.Writer()

    // Serialize spends
    const spendIndexes = Object.keys(args.spends)
    paramWriter.writeVarIntNum(spendIndexes.length)
    for (const index of spendIndexes) {
      paramWriter.writeVarIntNum(Number(index))
      const spend = args.spends[Number(index)]
      // unlockingScript
      const unlockingScriptBytes = Utils.toArray(spend.unlockingScript, 'hex')
      paramWriter.writeVarIntNum(unlockingScriptBytes.length)
      paramWriter.write(unlockingScriptBytes)
      // sequenceNumber
      if (typeof spend.sequenceNumber === 'number') {
        paramWriter.writeVarIntNum(spend.sequenceNumber)
      } else {
        paramWriter.writeVarIntNum(-1)
      }
    }

    // Serialize reference
    const referenceBytes = Utils.toArray(args.reference, 'base64')
    paramWriter.writeVarIntNum(referenceBytes.length)
    paramWriter.write(referenceBytes)

    // Serialize options
    if (args.options != null) {
      paramWriter.writeInt8(1) // options present

      // acceptDelayedBroadcast
      if (typeof args.options.acceptDelayedBroadcast === 'boolean') {
        paramWriter.writeInt8(args.options.acceptDelayedBroadcast ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // returnTXIDOnly
      if (typeof args.options.returnTXIDOnly === 'boolean') {
        paramWriter.writeInt8(args.options.returnTXIDOnly ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // noSend
      if (typeof args.options.noSend === 'boolean') {
        paramWriter.writeInt8(args.options.noSend ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }

      // sendWith
      if (args.options.sendWith != null) {
        paramWriter.writeVarIntNum(args.options.sendWith.length)
        for (const txid of args.options.sendWith) {
          const txidBytes = Utils.toArray(txid, 'hex')
          paramWriter.write(txidBytes)
        }
      } else {
        paramWriter.writeVarIntNum(-1)
      }
    } else {
      paramWriter.writeInt8(0) // options not present
    }

    // Transmit and parse response
    const result = await this.transmit(
      'signAction',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)

    const response: {
      txid?: TXIDHexString
      tx?: BEEF
      noSendChange?: OutpointString[]
      sendWithResults?: Array<{
        txid: TXIDHexString
        status: 'unproven' | 'sending' | 'failed'
      }>
    } = {}

    // Parse txid
    const txidFlag = resultReader.readInt8()
    if (txidFlag === 1) {
      const txidBytes = resultReader.read(32)
      response.txid = Utils.toHex(txidBytes)
    }

    // Parse tx
    const txFlag = resultReader.readInt8()
    if (txFlag === 1) {
      const txLength = resultReader.readVarIntNum()
      response.tx = resultReader.read(txLength)
    }

    // Parse sendWithResults
    const sendWithResultsLength = resultReader.readVarIntNum()
    if (sendWithResultsLength >= 0) {
      response.sendWithResults = []
      for (let i = 0; i < sendWithResultsLength; i++) {
        const txidBytes = resultReader.read(32)
        const txid = Utils.toHex(txidBytes)
        const statusCode = resultReader.readInt8()
        let status: 'unproven' | 'sending' | 'failed' = 'unproven'
        if (statusCode === 1) status = 'unproven'
        else if (statusCode === 2) status = 'sending'
        else if (statusCode === 3) status = 'failed'
        response.sendWithResults.push({ txid, status })
      }
    }

    return response
  }

  async abortAction(
    args: { reference: Base64String },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ aborted: true }> {
    await this.transmit(
      'abortAction',
      originator,
      Utils.toArray(args.reference, 'base64')
    )
    return { aborted: true }
  }

  async listActions(
    args: ListActionsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListActionsResult> {
    const paramWriter = new Utils.Writer()

    // Serialize labels
    paramWriter.writeVarIntNum(args.labels.length)
    for (const label of args.labels) {
      const labelBytes = Utils.toArray(label, 'utf8')
      paramWriter.writeVarIntNum(labelBytes.length)
      paramWriter.write(labelBytes)
    }

    // Serialize labelQueryMode
    if (args.labelQueryMode === 'any') {
      paramWriter.writeInt8(1)
    } else if (args.labelQueryMode === 'all') {
      paramWriter.writeInt8(2)
    } else {
      paramWriter.writeInt8(-1)
    }

    // Serialize include options
    const includeOptions = [
      args.includeLabels,
      args.includeInputs,
      args.includeInputSourceLockingScripts,
      args.includeInputUnlockingScripts,
      args.includeOutputs,
      args.includeOutputLockingScripts
    ]
    for (const option of includeOptions) {
      if (typeof option === 'boolean') {
        paramWriter.writeInt8(option ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }
    }

    // Serialize limit and offset
    if (typeof args.limit === 'number') {
      paramWriter.writeVarIntNum(args.limit)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    if (typeof args.offset === 'number') {
      paramWriter.writeVarIntNum(args.offset)
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )

    // Transmit and parse response
    const result = await this.transmit(
      'listActions',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)

    const totalActions = resultReader.readVarIntNum()
    const actions: Array<{
      txid: TXIDHexString
      satoshis: SatoshiValue
      status: ActionStatus
      isOutgoing: boolean
      description: DescriptionString5to50Bytes
      labels?: LabelStringUnder300Bytes[]
      version: PositiveIntegerOrZero
      lockTime: PositiveIntegerOrZero
      inputs?: Array<{
        sourceOutpoint: OutpointString
        sourceSatoshis: SatoshiValue
        sourceLockingScript?: HexString
        unlockingScript?: HexString
        inputDescription: DescriptionString5to50Bytes
        sequenceNumber: PositiveIntegerOrZero
      }>
      outputs?: Array<{
        outputIndex: PositiveIntegerOrZero
        satoshis: SatoshiValue
        lockingScript?: HexString
        spendable: boolean
        outputDescription: DescriptionString5to50Bytes
        basket: BasketStringUnder300Bytes
        tags: OutputTagStringUnder300Bytes[]
        customInstructions?: string
      }>
    }> = []

    for (let i = 0; i < totalActions; i++) {
      // Parse action fields
      const txidBytes = resultReader.read(32)
      const txid = Utils.toHex(txidBytes)

      const satoshis = resultReader.readVarIntNum()

      const statusCode = resultReader.readInt8()
      let status: ActionStatus
      switch (statusCode) {
        case 1:
          status = 'completed'
          break
        case 2:
          status = 'unprocessed'
          break
        case 3:
          status = 'sending'
          break
        case 4:
          status = 'unproven'
          break
        case 5:
          status = 'unsigned'
          break
        case 6:
          status = 'nosend'
          break
        case 7:
          status = 'nonfinal'
          break
        case 8:
          status = 'failed'
          break
        default:
          throw new Error(`Unknown status code: ${statusCode}`)
      }

      const isOutgoing = resultReader.readInt8() === 1

      const descriptionLength = resultReader.readVarIntNum()
      const descriptionBytes = resultReader.read(descriptionLength)
      const description = Utils.toUTF8(descriptionBytes)

      const action: any = {
        txid,
        satoshis,
        status,
        isOutgoing,
        description,
        version: 0,
        lockTime: 0
      }

      // Parse labels
      const labelsLength = resultReader.readVarIntNum()
      if (labelsLength >= 0) {
        action.labels = []
        for (let j = 0; j < labelsLength; j++) {
          const labelLength = resultReader.readVarIntNum()
          const labelBytes = resultReader.read(labelLength)
          action.labels.push(Utils.toUTF8(labelBytes))
        }
      }

      // Parse version and lockTime
      action.version = resultReader.readVarIntNum()
      action.lockTime = resultReader.readVarIntNum()

      // Parse inputs
      const inputsLength = resultReader.readVarIntNum()
      if (inputsLength >= 0) {
        action.inputs = []
        for (let k = 0; k < inputsLength; k++) {
          const sourceOutpoint = this.readOutpoint(resultReader)
          const sourceSatoshis = resultReader.readVarIntNum()

          // sourceLockingScript
          const sourceLockingScriptLength = resultReader.readVarIntNum()
          let sourceLockingScript: string | undefined
          if (sourceLockingScriptLength >= 0) {
            const sourceLockingScriptBytes = resultReader.read(
              sourceLockingScriptLength
            )
            sourceLockingScript = Utils.toHex(sourceLockingScriptBytes)
          }

          // unlockingScript
          const unlockingScriptLength = resultReader.readVarIntNum()
          let unlockingScript: string | undefined
          if (unlockingScriptLength >= 0) {
            const unlockingScriptBytes = resultReader.read(
              unlockingScriptLength
            )
            unlockingScript = Utils.toHex(unlockingScriptBytes)
          }

          // inputDescription
          const inputDescriptionLength = resultReader.readVarIntNum()
          const inputDescriptionBytes = resultReader.read(
            inputDescriptionLength
          )
          const inputDescription = Utils.toUTF8(inputDescriptionBytes)

          // sequenceNumber
          const sequenceNumber = resultReader.readVarIntNum()

          action.inputs.push({
            sourceOutpoint,
            sourceSatoshis,
            sourceLockingScript,
            unlockingScript,
            inputDescription,
            sequenceNumber
          })
        }
      }

      // Parse outputs
      const outputsLength = resultReader.readVarIntNum()
      if (outputsLength >= 0) {
        action.outputs = []
        for (let l = 0; l < outputsLength; l++) {
          const outputIndex = resultReader.readVarIntNum()
          const satoshis = resultReader.readVarIntNum()

          // lockingScript
          const lockingScriptLength = resultReader.readVarIntNum()
          let lockingScript: string | undefined
          if (lockingScriptLength >= 0) {
            const lockingScriptBytes = resultReader.read(lockingScriptLength)
            lockingScript = Utils.toHex(lockingScriptBytes)
          }

          const spendable = resultReader.readInt8() === 1

          // outputDescription
          const outputDescriptionLength = resultReader.readVarIntNum()
          const outputDescriptionBytes = resultReader.read(
            outputDescriptionLength
          )
          const outputDescription = Utils.toUTF8(outputDescriptionBytes)

          // basket
          const basketLength = resultReader.readVarIntNum()
          let basket: string | undefined
          if (basketLength >= 0) {
            const basketBytes = resultReader.read(basketLength)
            basket = Utils.toUTF8(basketBytes)
          }

          // tags
          const tagsLength = resultReader.readVarIntNum()
          const tags: string[] = []
          if (tagsLength >= 0) {
            for (let m = 0; m < tagsLength; m++) {
              const tagLength = resultReader.readVarIntNum()
              const tagBytes = resultReader.read(tagLength)
              tags.push(Utils.toUTF8(tagBytes))
            }
          }

          // customInstructions
          const customInstructionsLength = resultReader.readVarIntNum()
          let customInstructions: string | undefined
          if (customInstructionsLength >= 0) {
            const customInstructionsBytes = resultReader.read(
              customInstructionsLength
            )
            customInstructions = Utils.toUTF8(customInstructionsBytes)
          }

          action.outputs.push({
            outputIndex,
            satoshis,
            lockingScript,
            spendable,
            outputDescription,
            basket,
            tags,
            customInstructions
          })
        }
      }

      actions.push(action)
    }

    return {
      totalActions,
      actions
    }
  }

  async internalizeAction(
    args: InternalizeActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ accepted: true }> {
    const paramWriter = new Utils.Writer()
    paramWriter.writeVarIntNum(args.tx.length)
    paramWriter.write(args.tx)
    paramWriter.writeVarIntNum(args.outputs.length)
    for (const out of args.outputs) {
      paramWriter.writeVarIntNum(out.outputIndex)
      if (out.protocol === 'wallet payment') {
        if (out.paymentRemittance == null) {
          throw new Error('Payment remittance is required for wallet payment')
        }
        paramWriter.writeUInt8(1)
        paramWriter.write(
          Utils.toArray(out.paymentRemittance.senderIdentityKey, 'hex')
        )
        const derivationPrefixAsArray = Utils.toArray(
          out.paymentRemittance.derivationPrefix,
          'base64'
        )
        paramWriter.writeVarIntNum(derivationPrefixAsArray.length)
        paramWriter.write(derivationPrefixAsArray)
        const derivationSuffixAsArray = Utils.toArray(
          out.paymentRemittance.derivationSuffix,
          'base64'
        )
        paramWriter.writeVarIntNum(derivationSuffixAsArray.length)
        paramWriter.write(derivationSuffixAsArray)
      } else {
        paramWriter.writeUInt8(2)
        const basketAsArray = Utils.toArray(
          out.insertionRemittance?.basket,
          'utf8'
        )
        paramWriter.writeVarIntNum(basketAsArray.length)
        paramWriter.write(basketAsArray)
        if (typeof out.insertionRemittance?.customInstructions === 'string' && out.insertionRemittance.customInstructions !== '') {
          const customInstructionsAsArray = Utils.toArray(
            out.insertionRemittance.customInstructions,
            'utf8'
          )
          paramWriter.writeVarIntNum(customInstructionsAsArray.length)
          paramWriter.write(customInstructionsAsArray)
        } else {
          paramWriter.writeVarIntNum(-1)
        }
        if (typeof out.insertionRemittance?.tags === 'object') {
          paramWriter.writeVarIntNum(out.insertionRemittance.tags.length)
          for (const tag of out.insertionRemittance.tags) {
            const tagAsArray = Utils.toArray(tag, 'utf8')
            paramWriter.writeVarIntNum(tagAsArray.length)
            paramWriter.write(tagAsArray)
          }
        } else {
          paramWriter.writeVarIntNum(0)
        }
      }
    }
    if (typeof args.labels === 'object') {
      paramWriter.writeVarIntNum(args.labels.length)
      for (const l of args.labels) {
        const labelAsArray = Utils.toArray(l, 'utf8')
        paramWriter.writeVarIntNum(labelAsArray.length)
        paramWriter.write(labelAsArray)
      }
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    const descriptionAsArray = Utils.toArray(args.description)
    paramWriter.writeVarIntNum(descriptionAsArray.length)
    paramWriter.write(descriptionAsArray)

    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )

    await this.transmit('internalizeAction', originator, paramWriter.toArray())
    return { accepted: true }
  }

  async listOutputs(
    args: ListOutputsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListOutputsResult> {
    const paramWriter = new Utils.Writer()
    const basketAsArray = Utils.toArray(args.basket, 'utf8')
    paramWriter.writeVarIntNum(basketAsArray.length)
    paramWriter.write(basketAsArray)
    if (typeof args.tags === 'object') {
      paramWriter.writeVarIntNum(args.tags.length)
      for (const tag of args.tags) {
        const tagAsArray = Utils.toArray(tag, 'utf8')
        paramWriter.writeVarIntNum(tagAsArray.length)
        paramWriter.write(tagAsArray)
      }
    } else {
      paramWriter.writeVarIntNum(0)
    }
    if (args.tagQueryMode === 'all') {
      paramWriter.writeInt8(1)
    } else if (args.tagQueryMode === 'any') {
      paramWriter.writeInt8(2)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (args.include === 'locking scripts') {
      paramWriter.writeInt8(1)
    } else if (args.include === 'entire transactions') {
      paramWriter.writeInt8(2)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (typeof args.includeCustomInstructions === 'boolean') {
      paramWriter.writeInt8(args.includeCustomInstructions ? 1 : 0)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (typeof args.includeTags === 'boolean') {
      paramWriter.writeInt8(args.includeTags ? 1 : 0)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (typeof args.includeLabels === 'boolean') {
      paramWriter.writeInt8(args.includeLabels ? 1 : 0)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (typeof args.limit === 'number') {
      paramWriter.writeVarIntNum(args.limit)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    if (typeof args.offset === 'number') {
      paramWriter.writeVarIntNum(args.offset)
    } else {
      paramWriter.writeVarIntNum(-1)
    }

    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )

    const result = await this.transmit(
      'listOutputs',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)
    const totalOutputs = resultReader.readVarIntNum()
    const beefLength = resultReader.readVarIntNum()
    let BEEF
    if (beefLength >= 0) {
      BEEF = resultReader.read(beefLength)
    }
    const outputs: Array<{
      outpoint: OutpointString
      satoshis: SatoshiValue
      lockingScript?: HexString
      tx?: BEEF
      spendable: true
      customInstructions?: string
      tags?: OutputTagStringUnder300Bytes[]
      labels?: LabelStringUnder300Bytes[]
    }> = []
    for (let i = 0; i < totalOutputs; i++) {
      const outpoint = this.readOutpoint(resultReader)
      const satoshis = resultReader.readVarIntNum()
      const output: {
        outpoint: OutpointString
        satoshis: SatoshiValue
        lockingScript?: HexString
        tx?: BEEF
        spendable: true
        customInstructions?: string
        tags?: OutputTagStringUnder300Bytes[]
        labels?: LabelStringUnder300Bytes[]
      } = {
        spendable: true,
        outpoint,
        satoshis
      }
      const scriptLength = resultReader.readVarIntNum()
      if (scriptLength >= 0) {
        output.lockingScript = Utils.toHex(resultReader.read(scriptLength))
      }
      const customInstructionsLength = resultReader.readVarIntNum()
      if (customInstructionsLength >= 0) {
        output.customInstructions = Utils.toUTF8(
          resultReader.read(customInstructionsLength)
        )
      }
      const tagsLength = resultReader.readVarIntNum()
      if (tagsLength !== -1) {
        const tags: OutputTagStringUnder300Bytes[] = []
        for (let i = 0; i < tagsLength; i++) {
          const tagLength = resultReader.readVarIntNum()
          tags.push(Utils.toUTF8(resultReader.read(tagLength)))
        }
        output.tags = tags
      }
      const labelsLength = resultReader.readVarIntNum()
      if (labelsLength !== -1) {
        const labels: LabelStringUnder300Bytes[] = []
        for (let i = 0; i < labelsLength; i++) {
          const labelLength = resultReader.readVarIntNum()
          labels.push(Utils.toUTF8(resultReader.read(labelLength)))
        }
        output.labels = labels
      }
      outputs.push(output)
    }
    return {
      totalOutputs,
      BEEF,
      outputs
    }
  }

  async relinquishOutput(
    args: { basket: BasketStringUnder300Bytes, output: OutpointString },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ relinquished: true }> {
    const paramWriter = new Utils.Writer()
    const basketAsArray = Utils.toArray(args.basket, 'utf8')
    paramWriter.writeVarIntNum(basketAsArray.length)
    paramWriter.write(basketAsArray)
    paramWriter.write(this.encodeOutpoint(args.output))
    await this.transmit('relinquishOutput', originator, paramWriter.toArray())
    return { relinquished: true }
  }

  private encodeOutpoint(outpoint: OutpointString): number[] {
    const writer = new Utils.Writer()
    const [txid, index] = outpoint.split('.')
    writer.write(Utils.toArray(txid, 'hex'))
    writer.writeVarIntNum(Number(index))
    return writer.toArray()
  }

  private readOutpoint(reader: Utils.Reader): OutpointString {
    const txid = Utils.toHex(reader.read(32))
    const index = reader.readVarIntNum()
    return `${txid}.${index}`
  }

  async getPublicKey(
    args: {
      seekPermission?: BooleanDefaultTrue
      identityKey?: true
      protocolID?: [SecurityLevel, ProtocolString5To400Bytes]
      keyID?: KeyIDStringUnder800Bytes
      privileged?: BooleanDefaultFalse
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      forSelf?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ publicKey: PubKeyHex }> {
    const paramWriter = new Utils.Writer()
    paramWriter.writeUInt8(args.identityKey ? 1 : 0)
    if (!args.identityKey) {
      paramWriter.write(
        this.encodeKeyRelatedParams(
          args.protocolID ??= [SecurityLevels.Silent, 'default'],
          args.keyID ??= '',
          args.counterparty,
          args.privileged,
          args.privilegedReason
        )
      )
      if (typeof args.forSelf === 'boolean') {
        paramWriter.writeInt8(args.forSelf ? 1 : 0)
      } else {
        paramWriter.writeInt8(-1)
      }
    } else {
      paramWriter.write(
        this.encodePrivilegedParams(args.privileged, args.privilegedReason)
      )
    }

    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )

    const result = await this.transmit(
      'getPublicKey',
      originator,
      paramWriter.toArray()
    )
    return {
      publicKey: Utils.toHex(result)
    }
  }

  async revealCounterpartyKeyLinkage(
    args: {
      counterparty: PubKeyHex
      verifier: PubKeyHex
      privilegedReason?: DescriptionString5to50Bytes
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{
    prover: PubKeyHex
    verifier: PubKeyHex
    counterparty: PubKeyHex
    revelationTime: ISOTimestampString
    encryptedLinkage: Byte[]
    encryptedLinkageProof: number[]
  }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodePrivilegedParams(args.privileged, args.privilegedReason)
    )
    paramWriter.write(Utils.toArray(args.counterparty, 'hex'))
    paramWriter.write(Utils.toArray(args.verifier, 'hex'))
    const result = await this.transmit(
      'revealCounterpartyKeyLinkage',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)
    const prover = Utils.toHex(resultReader.read(33))
    const verifier = Utils.toHex(resultReader.read(33))
    const counterparty = Utils.toHex(resultReader.read(33))
    const revelationTimeLength = resultReader.readVarIntNum()
    const revelationTime = Utils.toUTF8(
      resultReader.read(revelationTimeLength)
    )
    const encryptedLinkageLength = resultReader.readVarIntNum()
    const encryptedLinkage = resultReader.read(encryptedLinkageLength)
    const encryptedLinkageProofLength = resultReader.readVarIntNum()
    const encryptedLinkageProof = resultReader.read(
      encryptedLinkageProofLength
    )
    return {
      prover,
      verifier,
      counterparty,
      revelationTime,
      encryptedLinkage,
      encryptedLinkageProof
    }
  }

  async revealSpecificKeyLinkage(
    args: {
      counterparty: PubKeyHex
      verifier: PubKeyHex
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{
    prover: PubKeyHex
    verifier: PubKeyHex
    counterparty: PubKeyHex
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    encryptedLinkage: Byte[]
    encryptedLinkageProof: Byte[]
    proofType: Byte
  }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    paramWriter.write(Utils.toArray(args.verifier, 'hex'))
    const result = await this.transmit(
      'revealSpecificKeyLinkage',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)
    const prover = Utils.toHex(resultReader.read(33))
    const verifier = Utils.toHex(resultReader.read(33))
    const counterparty = Utils.toHex(resultReader.read(33))
    const securityLevel = resultReader.readUInt8()
    const protocolLength = resultReader.readVarIntNum()
    const protocol = Utils.toUTF8(resultReader.read(protocolLength))
    const keyIDLength = resultReader.readVarIntNum()
    const keyID = Utils.toUTF8(resultReader.read(keyIDLength))
    const encryptedLinkageLength = resultReader.readVarIntNum()
    const encryptedLinkage = resultReader.read(encryptedLinkageLength)
    const encryptedLinkageProofLength = resultReader.readVarIntNum()
    const encryptedLinkageProof = resultReader.read(
      encryptedLinkageProofLength
    )
    const proofType = resultReader.readUInt8()
    return {
      prover,
      verifier,
      counterparty,
      protocolID: [securityLevel as SecurityLevel, protocol],
      keyID,
      encryptedLinkage,
      encryptedLinkageProof,
      proofType
    }
  }

  async encrypt(
    args: {
      seekPermission?: BooleanDefaultTrue
      plaintext: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ ciphertext: Byte[] }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    paramWriter.writeVarIntNum(args.plaintext.length)
    paramWriter.write(args.plaintext)
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    return {
      ciphertext: await this.transmit(
        'encrypt',
        originator,
        paramWriter.toArray()
      )
    }
  }

  async decrypt(
    args: {
      seekPermission?: BooleanDefaultTrue
      ciphertext: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ plaintext: Byte[] }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    paramWriter.writeVarIntNum(args.ciphertext.length)
    paramWriter.write(args.ciphertext)
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    return {
      plaintext: await this.transmit(
        'decrypt',
        originator,
        paramWriter.toArray()
      )
    }
  }

  async createHmac(
    args: {
      seekPermission?: BooleanDefaultTrue
      data: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ hmac: Byte[] }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    paramWriter.writeVarIntNum(args.data.length)
    paramWriter.write(args.data)
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    return {
      hmac: await this.transmit(
        'createHmac',
        originator,
        paramWriter.toArray()
      )
    }
  }

  async verifyHmac(
    args: {
      seekPermission?: BooleanDefaultTrue
      data: Byte[]
      hmac: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ valid: true }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    paramWriter.write(args.hmac)
    paramWriter.writeVarIntNum(args.data.length)
    paramWriter.write(args.data)
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    await this.transmit('verifyHmac', originator, paramWriter.toArray())
    return { valid: true }
  }

  async createSignature(
    args: {
      seekPermission?: BooleanDefaultTrue
      data?: Byte[]
      hashToDirectlySign?: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ signature: Byte[] }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    if (typeof args.data === 'object') {
      paramWriter.writeUInt8(1)
      paramWriter.writeVarIntNum(args.data.length)
      paramWriter.write(args.data)
    } else {
      paramWriter.writeUInt8(2)
      paramWriter.write(args.hashToDirectlySign ??= [])
    }
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    return {
      signature: await this.transmit(
        'createSignature',
        originator,
        paramWriter.toArray()
      )
    }
  }

  async verifySignature(
    args: {
      seekPermission?: BooleanDefaultTrue
      data?: Byte[]
      hashToDirectlyVerify?: Byte[]
      signature: Byte[]
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      privilegedReason?: DescriptionString5to50Bytes
      counterparty?: PubKeyHex | 'self' | 'anyone'
      forSelf?: BooleanDefaultFalse
      privileged?: BooleanDefaultFalse
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ valid: true }> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(
      this.encodeKeyRelatedParams(
        args.protocolID,
        args.keyID,
        args.counterparty,
        args.privileged,
        args.privilegedReason
      )
    )
    if (typeof args.forSelf === 'boolean') {
      paramWriter.writeInt8(args.forSelf ? 1 : 0)
    } else {
      paramWriter.writeInt8(-1)
    }
    paramWriter.writeVarIntNum(args.signature.length)
    paramWriter.write(args.signature)
    if (typeof args.data === 'object') {
      paramWriter.writeUInt8(1)
      paramWriter.writeVarIntNum(args.data.length)
      paramWriter.write(args.data)
    } else {
      paramWriter.writeUInt8(2)
      paramWriter.write(args.hashToDirectlyVerify ?? [])
    }
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    await this.transmit('verifySignature', originator, paramWriter.toArray())
    return { valid: true }
  }

  private encodeKeyRelatedParams(
    protocolID: [SecurityLevel, ProtocolString5To400Bytes],
    keyID: KeyIDStringUnder800Bytes,
    counterparty?: PubKeyHex | 'self' | 'anyone',
    privileged?: boolean,
    privilegedReason?: string
  ): number[] {
    const paramWriter = new Utils.Writer()
    paramWriter.writeUInt8(protocolID[0])
    const protocolAsArray = Utils.toArray(protocolID[1], 'utf8')
    paramWriter.writeVarIntNum(protocolAsArray.length)
    paramWriter.write(protocolAsArray)
    const keyIDAsArray = Utils.toArray(keyID, 'utf8')
    paramWriter.writeVarIntNum(keyIDAsArray.length)
    paramWriter.write(keyIDAsArray)
    if (typeof counterparty !== 'string') {
      paramWriter.writeUInt8(0)
    } else if (counterparty === 'self') {
      paramWriter.writeUInt8(11)
    } else if (counterparty === 'anyone') {
      paramWriter.writeUInt8(12)
    } else {
      paramWriter.write(Utils.toArray(counterparty, 'hex'))
    }
    paramWriter.write(
      this.encodePrivilegedParams(privileged, privilegedReason)
    )
    return paramWriter.toArray()
  }

  async acquireCertificate(
    args: AcquireCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<AcquireCertificateResult> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(Utils.toArray(args.type, 'base64'))
    paramWriter.write(Utils.toArray(args.certifier, 'hex'))

    const fieldEntries = Object.entries(args.fields)
    paramWriter.writeVarIntNum(fieldEntries.length)
    for (const [key, value] of fieldEntries) {
      const keyAsArray = Utils.toArray(key, 'utf8')
      const valueAsArray = Utils.toArray(value, 'utf8')

      paramWriter.writeVarIntNum(keyAsArray.length)
      paramWriter.write(keyAsArray)

      paramWriter.writeVarIntNum(valueAsArray.length)
      paramWriter.write(valueAsArray)
    }

    paramWriter.write(
      this.encodePrivilegedParams(args.privileged, args.privilegedReason)
    )
    paramWriter.writeUInt8(args.acquisitionProtocol === 'direct' ? 1 : 2)

    if (args.acquisitionProtocol === 'direct') {
      paramWriter.write(Utils.toArray(args.serialNumber, 'base64'))
      paramWriter.write(this.encodeOutpoint(args.revocationOutpoint ?? ''))
      const signatureAsArray = Utils.toArray(args.signature, 'hex')
      paramWriter.writeVarIntNum(signatureAsArray.length)
      paramWriter.write(signatureAsArray)

      const keyringRevealerAsArray =
        args.keyringRevealer !== 'certifier'
          ? Utils.toArray(args.keyringRevealer, 'hex')
          : [11]
      paramWriter.write(keyringRevealerAsArray)

      const keyringKeys = Object.keys(args.keyringForSubject ?? {})
      paramWriter.writeVarIntNum(keyringKeys.length)
      for (let i = 0; i < keyringKeys.length; i++) {
        const keyringKeysAsArray = Utils.toArray(keyringKeys[i], 'utf8')
        paramWriter.writeVarIntNum(keyringKeysAsArray.length)
        paramWriter.write(keyringKeysAsArray)
        const keyringForSubjectAsArray = Utils.toArray(
          args.keyringForSubject?.[keyringKeys[i]],
          'base64'
        )
        paramWriter.writeVarIntNum(keyringForSubjectAsArray.length)
        paramWriter.write(keyringForSubjectAsArray)
      }
    } else {
      const certifierUrlAsArray = Utils.toArray(args.certifierUrl, 'utf8')
      paramWriter.writeVarIntNum(certifierUrlAsArray.length)
      paramWriter.write(certifierUrlAsArray)
    }

    const result = await this.transmit(
      'acquireCertificate',
      originator,
      paramWriter.toArray()
    )
    const cert = Certificate.fromBinary(result)
    return {
      ...cert,
      signature: cert.signature as string
    }
  }

  private encodePrivilegedParams(
    privileged?: boolean,
    privilegedReason?: string
  ): number[] {
    const paramWriter = new Utils.Writer()
    if (typeof privileged === 'boolean') {
      paramWriter.writeInt8(privileged ? 1 : 0)
    } else {
      paramWriter.writeInt8(-1)
    }
    if (typeof privilegedReason === 'string') {
      const privilegedReasonAsArray = Utils.toArray(privilegedReason, 'utf8')
      paramWriter.writeInt8(privilegedReasonAsArray.length)
      paramWriter.write(privilegedReasonAsArray)
    } else {
      paramWriter.writeInt8(-1)
    }
    return paramWriter.toArray()
  }

  async listCertificates(
    args: {
      certifiers: PubKeyHex[]
      types: Base64String[]
      limit?: PositiveIntegerDefault10Max10000
      offset?: PositiveIntegerOrZero
      privileged?: BooleanDefaultFalse
      privilegedReason?: DescriptionString5to50Bytes
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListCertificatesResult> {
    const paramWriter = new Utils.Writer()
    paramWriter.writeVarIntNum(args.certifiers.length)
    for (let i = 0; i < args.certifiers.length; i++) {
      paramWriter.write(Utils.toArray(args.certifiers[i], 'hex'))
    }

    paramWriter.writeVarIntNum(args.types.length)
    for (let i = 0; i < args.types.length; i++) {
      paramWriter.write(Utils.toArray(args.types[i], 'base64'))
    }
    if (typeof args.limit === 'number') {
      paramWriter.writeVarIntNum(args.limit)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    if (typeof args.offset === 'number') {
      paramWriter.writeVarIntNum(args.offset)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    paramWriter.write(
      this.encodePrivilegedParams(args.privileged, args.privilegedReason)
    )
    const result = await this.transmit(
      'listCertificates',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)
    const totalCertificates = resultReader.readVarIntNum()
    const certificates: Array<CertificateResult> = []
    for (let i = 0; i < totalCertificates; i++) {
      const certificateLength = resultReader.readVarIntNum()
      const certificateBin = resultReader.read(certificateLength)
      const cert = Certificate.fromBinary(certificateBin)
      const keyringForVerifier: Record<string, string> = {}
      if (resultReader.readInt8() === 1) {
        const numFields = resultReader.readVarIntNum()
        for (let i = 0; i < numFields; i++) {
          const fieldKeyLength = resultReader.readVarIntNum()
          const fieldKey = Utils.toUTF8(resultReader.read(fieldKeyLength))
          const fieldValueLength = resultReader.readVarIntNum()
          keyringForVerifier[fieldKey] = Utils.toBase64(
              resultReader.read(fieldValueLength)
          )
        }
      }
      const verifierLength = resultReader.readVarIntNum()
      let verifier: string | undefined = undefined
      if (verifierLength > 0) {
        verifier = Utils.toUTF8(resultReader.read(verifierLength))
      }
      certificates.push({
        ...cert,
        signature: cert.signature as string,
        keyring: keyringForVerifier,
        verifier,
      })
    }
    return {
      totalCertificates,
      certificates
    }
  }

  async proveCertificate(
    args: ProveCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ProveCertificateResult> {
    const paramWriter = new Utils.Writer()
    const typeAsArray = Utils.toArray(args.certificate.type, 'base64')
    paramWriter.write(typeAsArray)
    const subjectAsArray = Utils.toArray(args.certificate.subject, 'hex')
    paramWriter.write(subjectAsArray)
    const serialNumberAsArray = Utils.toArray(
      args.certificate.serialNumber,
      'base64'
    )
    paramWriter.write(serialNumberAsArray)
    const certifierAsArray = Utils.toArray(args.certificate.certifier, 'hex')
    paramWriter.write(certifierAsArray)
    const revocationOutpointAsArray = this.encodeOutpoint(
      args.certificate.revocationOutpoint ?? ''
    )
    paramWriter.write(revocationOutpointAsArray)
    const signatureAsArray = Utils.toArray(args.certificate.signature, 'hex')
    paramWriter.writeVarIntNum(signatureAsArray.length)
    paramWriter.write(signatureAsArray)
    const fieldEntries = Object.entries(args.certificate.fields ?? {})
    paramWriter.writeVarIntNum(fieldEntries.length)
    for (const [key, value] of fieldEntries) {
      const keyAsArray = Utils.toArray(key, 'utf8')
      const valueAsArray = Utils.toArray(value, 'utf8')
      paramWriter.writeVarIntNum(keyAsArray.length)
      paramWriter.write(keyAsArray)
      paramWriter.writeVarIntNum(valueAsArray.length)
      paramWriter.write(valueAsArray)
    }
    paramWriter.writeVarIntNum(args.fieldsToReveal.length)
    for (const field of args.fieldsToReveal) {
      const fieldAsArray = Utils.toArray(field, 'utf8')
      paramWriter.writeVarIntNum(fieldAsArray.length)
      paramWriter.write(fieldAsArray)
    }
    paramWriter.write(Utils.toArray(args.verifier, 'hex'))
    paramWriter.write(
      this.encodePrivilegedParams(args.privileged, args.privilegedReason)
    )
    const result = await this.transmit(
      'proveCertificate',
      originator,
      paramWriter.toArray()
    )
    const resultReader = new Utils.Reader(result)
    const numFields = resultReader.readVarIntNum()
    const keyringForVerifier: Record<string, string> = {}
    for (let i = 0; i < numFields; i++) {
      const fieldKeyLength = resultReader.readVarIntNum()
      const fieldKey = Utils.toUTF8(resultReader.read(fieldKeyLength))
      const fieldValueLength = resultReader.readVarIntNum()
      keyringForVerifier[fieldKey] = Utils.toBase64(
        resultReader.read(fieldValueLength)
      )
    }
    return {
      keyringForVerifier
    }
  }

  async relinquishCertificate(
    args: {
      type: Base64String
      serialNumber: Base64String
      certifier: PubKeyHex
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ relinquished: true }> {
    const paramWriter = new Utils.Writer()
    const typeAsArray = Utils.toArray(args.type, 'base64')
    paramWriter.write(typeAsArray)
    const serialNumberAsArray = Utils.toArray(args.serialNumber, 'base64')
    paramWriter.write(serialNumberAsArray)
    const certifierAsArray = Utils.toArray(args.certifier, 'hex')
    paramWriter.write(certifierAsArray)
    await this.transmit(
      'relinquishCertificate',
      originator,
      paramWriter.toArray()
    )
    return { relinquished: true }
  }

  private parseDiscoveryResult(result: number[]): {
    totalCertificates: number
    certificates: Array<{
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
      certifierInfo: {
        name: EntityNameStringMax100Bytes
        iconUrl: EntityIconURLStringMax500Bytes
        description: DescriptionString5to50Bytes
        trust: PositiveIntegerMax10
      }
      publiclyRevealedKeyring: Record<
        CertificateFieldNameUnder50Bytes,
        Base64String
      >
      decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>
    }>
  } {
    const resultReader = new Utils.Reader(result)
    const totalCertificates = resultReader.readVarIntNum()
    const certificates: Array<{
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
      certifierInfo: {
        name: EntityNameStringMax100Bytes
        iconUrl: EntityIconURLStringMax500Bytes
        description: DescriptionString5to50Bytes
        trust: PositiveIntegerMax10
      }
      publiclyRevealedKeyring: Record<
        CertificateFieldNameUnder50Bytes,
        Base64String
      >
      decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>
    }> = []
    for (let i = 0; i < totalCertificates; i++) {
      const certBinLen = resultReader.readVarIntNum()
      const certBin = resultReader.read(certBinLen)
      const cert = Certificate.fromBinary(certBin)
      const nameLength = resultReader.readVarIntNum()
      const name = Utils.toUTF8(resultReader.read(nameLength))
      const iconUrlLength = resultReader.readVarIntNum()
      const iconUrl = Utils.toUTF8(resultReader.read(iconUrlLength))
      const descriptionLength = resultReader.readVarIntNum()
      const description = Utils.toUTF8(resultReader.read(descriptionLength))
      const trust = resultReader.readUInt8()
      const publiclyRevealedKeyring = {}
      const numPublicKeyringEntries = resultReader.readVarIntNum()
      for (let j = 0; j < numPublicKeyringEntries; j++) {
        const fieldKeyLen = resultReader.readVarIntNum()
        const fieldKey = Utils.toUTF8(resultReader.read(fieldKeyLen))
        const fieldValueLen = resultReader.readVarIntNum()
        publiclyRevealedKeyring[fieldKey] = resultReader.read(fieldValueLen)
      }
      const decryptedFields = {}
      const numDecryptedFields = resultReader.readVarIntNum()
      for (let k = 0; k < numDecryptedFields; k++) {
        const fieldKeyLen = resultReader.readVarIntNum()
        const fieldKey = Utils.toUTF8(resultReader.read(fieldKeyLen))
        const fieldValueLen = resultReader.readVarIntNum()
        decryptedFields[fieldKey] = Utils.toUTF8(
          resultReader.read(fieldValueLen)
        )
      }
      certificates.push({
        ...cert,
        signature: cert.signature as string,
        certifierInfo: { iconUrl, name, description, trust },
        publiclyRevealedKeyring,
        decryptedFields
      })
    }
    return {
      totalCertificates,
      certificates
    }
  }

  async discoverByIdentityKey(
    args: {
      seekPermission?: BooleanDefaultTrue
      identityKey: PubKeyHex
      limit?: PositiveIntegerDefault10Max10000
      offset?: PositiveIntegerOrZero
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<DiscoverCertificatesResult> {
    const paramWriter = new Utils.Writer()
    paramWriter.write(Utils.toArray(args.identityKey, 'hex'))
    if (typeof args.limit === 'number') {
      paramWriter.writeVarIntNum(args.limit)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    if (typeof args.offset === 'number') {
      paramWriter.writeVarIntNum(args.offset)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    const result = await this.transmit(
      'discoverByIdentityKey',
      originator,
      paramWriter.toArray()
    )
    return this.parseDiscoveryResult(result)
  }

  async discoverByAttributes(
    args: {
      seekPermission?: BooleanDefaultTrue
      attributes: Record<CertificateFieldNameUnder50Bytes, string>
      limit?: PositiveIntegerDefault10Max10000
      offset?: PositiveIntegerOrZero
    },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<DiscoverCertificatesResult> {
    const paramWriter = new Utils.Writer()
    const attributeKeys = Object.keys(args.attributes)
    paramWriter.writeVarIntNum(attributeKeys.length)
    for (let i = 0; i < attributeKeys.length; i++) {
      paramWriter.writeVarIntNum(attributeKeys[i].length)
      paramWriter.write(Utils.toArray(attributeKeys[i], 'utf8'))
      paramWriter.writeVarIntNum(args.attributes[attributeKeys[i]].length)
      paramWriter.write(
        Utils.toArray(args.attributes[attributeKeys[i]], 'utf8')
      )
    }
    if (typeof args.limit === 'number') {
      paramWriter.writeVarIntNum(args.limit)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    if (typeof args.offset === 'number') {
      paramWriter.writeVarIntNum(args.offset)
    } else {
      paramWriter.writeVarIntNum(-1)
    }
    // Serialize seekPermission
    paramWriter.writeInt8(
      typeof args.seekPermission === 'boolean'
        ? args.seekPermission
          ? 1
          : 0
        : -1
    )
    const result = await this.transmit(
      'discoverByAttributes',
      originator,
      paramWriter.toArray()
    )
    return this.parseDiscoveryResult(result)
  }

  async isAuthenticated(
    args: {},
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ authenticated: true }> {
    const result = await this.transmit('isAuthenticated', originator)
    // @ts-expect-error
    return { authenticated: result[0] === 1 }
  }

  async waitForAuthentication(
    args: {},
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ authenticated: true }> {
    await this.transmit('waitForAuthentication', originator)
    return { authenticated: true }
  }

  async getHeight(
    args: {},
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ height: PositiveInteger }> {
    const result = await this.transmit('getHeight', originator)
    const resultReader = new Utils.Reader(result)
    return {
      height: resultReader.readVarIntNum()
    }
  }

  async getHeaderForHeight(
    args: { height: PositiveInteger },
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ header: HexString }> {
    const paramWriter = new Utils.Writer()
    paramWriter.writeVarIntNum(args.height)
    const header = await this.transmit(
      'getHeaderForHeight',
      originator,
      paramWriter.toArray()
    )
    return {
      header: Utils.toHex(header)
    }
  }

  async getNetwork(
    args: {},
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ network: 'mainnet' | 'testnet' }> {
    const net = await this.transmit('getNetwork', originator)
    return {
      network: net[0] === 0 ? 'mainnet' : 'testnet'
    }
  }

  async getVersion(
    args: {},
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<{ version: VersionString7To30Bytes }> {
    const version = await this.transmit('getVersion', originator)
    return {
      version: Utils.toUTF8(version)
    }
  }
}
