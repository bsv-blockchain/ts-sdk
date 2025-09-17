import { WalletInterface, SecurityLevel } from '../Wallet.interfaces.js'
import WalletWire from './WalletWire.js'
import * as Utils from '../../primitives/utils.js'
import calls from './WalletWireCalls.js'
import Certificate from '../../auth/certificates/Certificate.js'

/**
 * Processes incoming wallet calls received over a wallet wire, with a given wallet.
 */
export default class WalletWireProcessor implements WalletWire {
  wallet: WalletInterface

  constructor(wallet: WalletInterface) {
    this.wallet = wallet
  }

  private decodeOutpoint(reader: Utils.Reader): string {
    const txidBytes = reader.read(32)
    const txid = Utils.toHex(txidBytes)
    const index = reader.readVarIntNum()
    return `${txid}.${index}`
  }

  private encodeOutpoint(outpoint: string): number[] {
    const writer = new Utils.Writer()
    const [txid, index] = outpoint.split('.')
    writer.write(Utils.toArray(txid, 'hex'))
    writer.writeVarIntNum(Number(index))
    return writer.toArray()
  }

  async transmitToWallet(message: number[]): Promise<number[]> {
    const messageReader = new Utils.Reader(message)
    try {
      // Read call code
      const callCode = messageReader.readUInt8()

      // Map call code to call name
      const callName = calls[callCode] // calls is enum
      if (callName === undefined || callName === '') {
        // Invalid call code
        throw new Error(`Invalid call code: ${callCode}`)
      }

      // Read originator length
      const originatorLength = messageReader.readUInt8()
      const originatorBytes = messageReader.read(originatorLength)
      const originator = Utils.toUTF8(originatorBytes)

      // Read parameters
      const paramsReader = messageReader // Remaining bytes

      switch (callName) {
        case 'createAction': {
          // Deserialize parameters from paramsReader
          const args: any = {}

          // Read description
          const descriptionLength = paramsReader.readVarIntNum()
          const descriptionBytes = paramsReader.read(descriptionLength)
          args.description = Utils.toUTF8(descriptionBytes)

          // tx
          const inputBeefLength = paramsReader.readVarIntNum()
          if (inputBeefLength >= 0) {
            args.inputBEEF = paramsReader.read(inputBeefLength) // BEEF (Byte[])
          } else {
            args.inputBEEF = undefined
          }

          // Read inputs
          const inputsLength = paramsReader.readVarIntNum()
          if (inputsLength >= 0) {
            args.inputs = []
            for (let i = 0; i < inputsLength; i++) {
              const input: any = {}

              // outpoint
              input.outpoint = this.decodeOutpoint(paramsReader)

              // unlockingScript / unlockingScriptLength
              const unlockingScriptLength = paramsReader.readVarIntNum()
              if (unlockingScriptLength >= 0) {
                const unlockingScriptBytes = paramsReader.read(
                  unlockingScriptLength
                )
                input.unlockingScript = Utils.toHex(unlockingScriptBytes)
              } else {
                input.unlockingScript = undefined
                const unlockingScriptLengthValue = paramsReader.readVarIntNum()
                input.unlockingScriptLength = unlockingScriptLengthValue
              }

              // inputDescription
              const inputDescriptionLength = paramsReader.readVarIntNum()
              const inputDescriptionBytes = paramsReader.read(
                inputDescriptionLength
              )
              input.inputDescription = Utils.toUTF8(inputDescriptionBytes)

              // sequenceNumber
              const sequenceNumber = paramsReader.readVarIntNum()
              if (sequenceNumber >= 0) {
                input.sequenceNumber = sequenceNumber
              } else {
                input.sequenceNumber = undefined
              }

              args.inputs.push(input)
            }
          } else {
            args.inputs = undefined
          }

          // Read outputs
          const outputsLength = paramsReader.readVarIntNum()
          if (outputsLength >= 0) {
            args.outputs = []
            for (let i = 0; i < outputsLength; i++) {
              const output: any = {}

              // lockingScript
              const lockingScriptLength = paramsReader.readVarIntNum()
              const lockingScriptBytes = paramsReader.read(lockingScriptLength)
              output.lockingScript = Utils.toHex(lockingScriptBytes)

              // satoshis
              output.satoshis = paramsReader.readVarIntNum()

              // outputDescription
              const outputDescriptionLength = paramsReader.readVarIntNum()
              const outputDescriptionBytes = paramsReader.read(
                outputDescriptionLength
              )
              output.outputDescription = Utils.toUTF8(outputDescriptionBytes)

              // basket
              const basketLength = paramsReader.readVarIntNum()
              if (basketLength >= 0) {
                const basketBytes = paramsReader.read(basketLength)
                output.basket = Utils.toUTF8(basketBytes)
              } else {
                output.basket = undefined
              }

              // customInstructions
              const customInstructionsLength = paramsReader.readVarIntNum()
              if (customInstructionsLength >= 0) {
                const customInstructionsBytes = paramsReader.read(
                  customInstructionsLength
                )
                output.customInstructions = Utils.toUTF8(
                  customInstructionsBytes
                )
              } else {
                output.customInstructions = undefined
              }

              // tags
              const tagsLength = paramsReader.readVarIntNum()
              if (tagsLength >= 0) {
                output.tags = []
                for (let j = 0; j < tagsLength; j++) {
                  const tagLength = paramsReader.readVarIntNum()
                  const tagBytes = paramsReader.read(tagLength)
                  const tag = Utils.toUTF8(tagBytes)
                  output.tags.push(tag)
                }
              } else {
                output.tags = undefined
              }

              args.outputs.push(output)
            }
          } else {
            args.outputs = undefined
          }

          // lockTime
          const lockTime = paramsReader.readVarIntNum()
          if (lockTime >= 0) {
            args.lockTime = lockTime
          } else {
            args.lockTime = undefined
          }

          // version
          const version = paramsReader.readVarIntNum()
          if (version >= 0) {
            args.version = version
          } else {
            args.version = undefined
          }

          // labels
          const labelsLength = paramsReader.readVarIntNum()
          if (labelsLength >= 0) {
            args.labels = []
            for (let i = 0; i < labelsLength; i++) {
              const labelLength = paramsReader.readVarIntNum()
              const labelBytes = paramsReader.read(labelLength)
              const label = Utils.toUTF8(labelBytes)
              args.labels.push(label)
            }
          } else {
            args.labels = undefined
          }

          // options
          const optionsPresent = paramsReader.readInt8()
          if (optionsPresent === 1) {
            args.options = {}

            // signAndProcess
            const signAndProcessFlag = paramsReader.readInt8()
            if (signAndProcessFlag === -1) {
              args.options.signAndProcess = undefined
            } else {
              args.options.signAndProcess = signAndProcessFlag === 1
            }

            // acceptDelayedBroadcast
            const acceptDelayedBroadcastFlag = paramsReader.readInt8()
            if (acceptDelayedBroadcastFlag === -1) {
              args.options.acceptDelayedBroadcast = undefined
            } else {
              args.options.acceptDelayedBroadcast =
                acceptDelayedBroadcastFlag === 1
            }

            // trustSelf
            const trustSelfFlag = paramsReader.readInt8()
            if (trustSelfFlag === -1) {
              args.options.trustSelf = undefined
            } else if (trustSelfFlag === 1) {
              args.options.trustSelf = 'known'
            }

            // knownTxids
            const knownTxidsLength = paramsReader.readVarIntNum()
            if (knownTxidsLength >= 0) {
              args.options.knownTxids = []
              for (let i = 0; i < knownTxidsLength; i++) {
                const txidBytes = paramsReader.read(32)
                const txid = Utils.toHex(txidBytes)
                args.options.knownTxids.push(txid)
              }
            } else {
              args.options.knownTxids = undefined
            }

            // returnTXIDOnly
            const returnTXIDOnlyFlag = paramsReader.readInt8()
            if (returnTXIDOnlyFlag === -1) {
              args.options.returnTXIDOnly = undefined
            } else {
              args.options.returnTXIDOnly = returnTXIDOnlyFlag === 1
            }

            // noSend
            const noSendFlag = paramsReader.readInt8()
            if (noSendFlag === -1) {
              args.options.noSend = undefined
            } else {
              args.options.noSend = noSendFlag === 1
            }

            // noSendChange
            const noSendChangeLength = paramsReader.readVarIntNum()
            if (noSendChangeLength >= 0) {
              args.options.noSendChange = []
              for (let i = 0; i < noSendChangeLength; i++) {
                const outpoint = this.decodeOutpoint(paramsReader)
                args.options.noSendChange.push(outpoint)
              }
            } else {
              args.options.noSendChange = undefined
            }

            // sendWith
            const sendWithLength = paramsReader.readVarIntNum()
            if (sendWithLength >= 0) {
              args.options.sendWith = []
              for (let i = 0; i < sendWithLength; i++) {
                const txidBytes = paramsReader.read(32)
                const txid = Utils.toHex(txidBytes)
                args.options.sendWith.push(txid)
              }
            } else {
              args.options.sendWith = undefined
            }

            // randomizeOutputs
            const randomizeOutputsFlag = paramsReader.readInt8()
            if (randomizeOutputsFlag === -1) {
              args.options.randomizeOutputs = undefined
            } else {
              args.options.randomizeOutputs = randomizeOutputsFlag === 1
            }
          } else {
            args.options = undefined
          }

          // Call the method
          const createActionResult = await this.wallet.createAction(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // txid
          if (createActionResult.txid != null && createActionResult.txid !== '') {
            resultWriter.writeInt8(1)
            resultWriter.write(Utils.toArray(createActionResult.txid, 'hex'))
          } else {
            resultWriter.writeInt8(0)
          }

          // tx
          if (createActionResult.tx != null) {
            resultWriter.writeInt8(1)
            resultWriter.writeVarIntNum(createActionResult.tx.length)
            resultWriter.write(createActionResult.tx)
          } else {
            resultWriter.writeInt8(0)
          }

          // noSendChange
          if (createActionResult.noSendChange != null) {
            resultWriter.writeVarIntNum(createActionResult.noSendChange.length)
            for (const outpoint of createActionResult.noSendChange) {
              resultWriter.write(this.encodeOutpoint(outpoint))
            }
          } else {
            resultWriter.writeVarIntNum(-1)
          }

          // sendWithResults
          if (createActionResult.sendWithResults != null) {
            resultWriter.writeVarIntNum(
              createActionResult.sendWithResults.length
            )
            for (const result of createActionResult.sendWithResults) {
              resultWriter.write(Utils.toArray(result.txid, 'hex'))
              let statusCode
              if (result.status === 'unproven') statusCode = 1
              else if (result.status === 'sending') statusCode = 2
              else if (result.status === 'failed') statusCode = 3
              resultWriter.writeInt8(statusCode)
            }
          } else {
            resultWriter.writeVarIntNum(-1)
          }

          // signableTransaction
          if (createActionResult.signableTransaction != null) {
            resultWriter.writeInt8(1)
            resultWriter.writeVarIntNum(
              createActionResult.signableTransaction.tx.length
            )
            resultWriter.write(createActionResult.signableTransaction.tx)
            const referenceBytes = Utils.toArray(
              createActionResult.signableTransaction.reference,
              'base64'
            )
            resultWriter.writeVarIntNum(referenceBytes.length)
            resultWriter.write(referenceBytes)
          } else {
            resultWriter.writeInt8(0)
          }

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }
        case 'signAction': {
          const args: any = {}

          // Deserialize spends
          const spendCount = paramsReader.readVarIntNum()
          args.spends = {}
          for (let i = 0; i < spendCount; i++) {
            const inputIndex = paramsReader.readVarIntNum()
            const spend: any = {}

            // unlockingScript
            const unlockingScriptLength = paramsReader.readVarIntNum()
            const unlockingScriptBytes = paramsReader.read(
              unlockingScriptLength
            )
            spend.unlockingScript = Utils.toHex(unlockingScriptBytes)

            // sequenceNumber
            const sequenceNumber = paramsReader.readVarIntNum()
            if (sequenceNumber >= 0) {
              spend.sequenceNumber = sequenceNumber
            } else {
              spend.sequenceNumber = undefined
            }

            args.spends[inputIndex] = spend
          }

          // Deserialize reference
          const referenceLength = paramsReader.readVarIntNum()
          const referenceBytes = paramsReader.read(referenceLength)
          args.reference = Utils.toBase64(referenceBytes)

          // Deserialize options
          const optionsPresent = paramsReader.readInt8()
          if (optionsPresent === 1) {
            args.options = {}

            // acceptDelayedBroadcast
            const acceptDelayedBroadcastFlag = paramsReader.readInt8()
            if (acceptDelayedBroadcastFlag === -1) {
              args.options.acceptDelayedBroadcast = undefined
            } else {
              args.options.acceptDelayedBroadcast =
                acceptDelayedBroadcastFlag === 1
            }

            // returnTXIDOnly
            const returnTXIDOnlyFlag = paramsReader.readInt8()
            if (returnTXIDOnlyFlag === -1) {
              args.options.returnTXIDOnly = undefined
            } else {
              args.options.returnTXIDOnly = returnTXIDOnlyFlag === 1
            }

            // noSend
            const noSendFlag = paramsReader.readInt8()
            if (noSendFlag === -1) {
              args.options.noSend = undefined
            } else {
              args.options.noSend = noSendFlag === 1
            }

            // sendWith
            const sendWithLength = paramsReader.readVarIntNum()
            if (sendWithLength >= 0) {
              args.options.sendWith = []
              for (let i = 0; i < sendWithLength; i++) {
                const txidBytes = paramsReader.read(32)
                const txid = Utils.toHex(txidBytes)
                args.options.sendWith.push(txid)
              }
            } else {
              args.options.sendWith = undefined
            }
          } else {
            args.options = undefined
          }

          // Call the method
          const signActionResult = await this.wallet.signAction(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // txid
          if (signActionResult.txid != null && signActionResult.txid !== '') {
            resultWriter.writeInt8(1)
            resultWriter.write(Utils.toArray(signActionResult.txid, 'hex'))
          } else {
            resultWriter.writeInt8(0)
          }

          // tx
          if (signActionResult.tx != null) {
            resultWriter.writeInt8(1)
            resultWriter.writeVarIntNum(signActionResult.tx.length)
            resultWriter.write(signActionResult.tx)
          } else {
            resultWriter.writeInt8(0)
          }

          // sendWithResults
          if (signActionResult.sendWithResults != null) {
            resultWriter.writeVarIntNum(
              signActionResult.sendWithResults.length
            )
            for (const result of signActionResult.sendWithResults) {
              resultWriter.write(Utils.toArray(result.txid, 'hex'))
              let statusCode
              if (result.status === 'unproven') statusCode = 1
              else if (result.status === 'sending') statusCode = 2
              else if (result.status === 'failed') statusCode = 3
              resultWriter.writeInt8(statusCode)
            }
          } else {
            resultWriter.writeVarIntNum(-1)
          }

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }
        case 'abortAction': {
          // Deserialize reference
          const referenceBytes = paramsReader.read()
          const reference = Utils.toBase64(referenceBytes)

          // Call the method
          await this.wallet.abortAction({ reference }, originator)

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }
        case 'listActions': {
          const args: any = {}

          // Deserialize labels
          const labelsLength = paramsReader.readVarIntNum()
          args.labels = []
          for (let i = 0; i < labelsLength; i++) {
            const labelLength = paramsReader.readVarIntNum()
            const labelBytes = paramsReader.read(labelLength)
            args.labels.push(Utils.toUTF8(labelBytes))
          }

          // Deserialize labelQueryMode
          const labelQueryModeFlag = paramsReader.readInt8()
          if (labelQueryModeFlag === -1) {
            args.labelQueryMode = undefined
          } else if (labelQueryModeFlag === 1) {
            args.labelQueryMode = 'any'
          } else if (labelQueryModeFlag === 2) {
            args.labelQueryMode = 'all'
          }

          // Deserialize include options
          const includeOptionsNames = [
            'includeLabels',
            'includeInputs',
            'includeInputSourceLockingScripts',
            'includeInputUnlockingScripts',
            'includeOutputs',
            'includeOutputLockingScripts'
          ]
          for (const optionName of includeOptionsNames) {
            const optionFlag = paramsReader.readInt8()
            if (optionFlag === -1) {
              args[optionName] = undefined
            } else {
              args[optionName] = optionFlag === 1
            }
          }

          // Deserialize limit
          const limit = paramsReader.readVarIntNum()
          if (limit >= 0) {
            args.limit = limit
          } else {
            args.limit = undefined
          }

          // Deserialize offset
          const offset = paramsReader.readVarIntNum()
          if (offset >= 0) {
            args.offset = offset
          } else {
            args.offset = undefined
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const listActionsResult = await this.wallet.listActions(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // totalActions
          resultWriter.writeVarIntNum(listActionsResult.totalActions)

          // actions
          for (const action of listActionsResult.actions) {
            // txid
            resultWriter.write(Utils.toArray(action.txid, 'hex'))

            // satoshis
            resultWriter.writeVarIntNum(action.satoshis)

            // status
            let statusCode
            switch (action.status) {
              case 'completed':
                statusCode = 1
                break
              case 'unprocessed':
                statusCode = 2
                break
              case 'sending':
                statusCode = 3
                break
              case 'unproven':
                statusCode = 4
                break
              case 'unsigned':
                statusCode = 5
                break
              case 'nosend':
                statusCode = 6
                break
              case 'nonfinal':
                statusCode = 7
                break
              case 'failed':
                statusCode = 8
                break
              default:
                statusCode = -1
                break
            }
            resultWriter.writeInt8(statusCode)

            // isOutgoing
            resultWriter.writeInt8(action.isOutgoing ? 1 : 0)

            // description
            const descriptionBytes = Utils.toArray(action.description, 'utf8')
            resultWriter.writeVarIntNum(descriptionBytes.length)
            resultWriter.write(descriptionBytes)

            // labels
            if (action.labels !== undefined) {
              resultWriter.writeVarIntNum(action.labels.length)
              for (const label of action.labels) {
                const labelBytes = Utils.toArray(label, 'utf8')
                resultWriter.writeVarIntNum(labelBytes.length)
                resultWriter.write(labelBytes)
              }
            } else {
              resultWriter.writeVarIntNum(-1)
            }

            // version
            resultWriter.writeVarIntNum(action.version)

            // lockTime
            resultWriter.writeVarIntNum(action.lockTime)

            // inputs
            if (action.inputs !== undefined) {
              resultWriter.writeVarIntNum(action.inputs.length)
              for (const input of action.inputs) {
                // sourceOutpoint
                resultWriter.write(this.encodeOutpoint(input.sourceOutpoint))

                // sourceSatoshis
                resultWriter.writeVarIntNum(input.sourceSatoshis)

                // sourceLockingScript
                if (input.sourceLockingScript !== undefined) {
                  const sourceLockingScriptBytes = Utils.toArray(
                    input.sourceLockingScript,
                    'hex'
                  )
                  resultWriter.writeVarIntNum(sourceLockingScriptBytes.length)
                  resultWriter.write(sourceLockingScriptBytes)
                } else {
                  resultWriter.writeVarIntNum(-1)
                }

                // unlockingScript
                if (input.unlockingScript !== undefined) {
                  const unlockingScriptBytes = Utils.toArray(
                    input.unlockingScript,
                    'hex'
                  )
                  resultWriter.writeVarIntNum(unlockingScriptBytes.length)
                  resultWriter.write(unlockingScriptBytes)
                } else {
                  resultWriter.writeVarIntNum(-1)
                }

                // inputDescription
                const inputDescriptionBytes = Utils.toArray(
                  input.inputDescription,
                  'utf8'
                )
                resultWriter.writeVarIntNum(inputDescriptionBytes.length)
                resultWriter.write(inputDescriptionBytes)

                // sequenceNumber
                resultWriter.writeVarIntNum(input.sequenceNumber)
              }
            } else {
              resultWriter.writeVarIntNum(-1)
            }

            // outputs
            if (action.outputs !== undefined) {
              resultWriter.writeVarIntNum(action.outputs.length)
              for (const output of action.outputs) {
                // outputIndex
                resultWriter.writeVarIntNum(output.outputIndex)

                // satoshis
                resultWriter.writeVarIntNum(output.satoshis)

                // lockingScript
                if (output.lockingScript !== undefined) {
                  const lockingScriptBytes = Utils.toArray(
                    output.lockingScript,
                    'hex'
                  )
                  resultWriter.writeVarIntNum(lockingScriptBytes.length)
                  resultWriter.write(lockingScriptBytes)
                } else {
                  resultWriter.writeVarIntNum(-1)
                }

                // spendable
                resultWriter.writeInt8(output.spendable ? 1 : 0)

                // outputDescription
                const outputDescriptionBytes = Utils.toArray(
                  output.outputDescription,
                  'utf8'
                )
                resultWriter.writeVarIntNum(outputDescriptionBytes.length)
                resultWriter.write(outputDescriptionBytes)

                // basket
                if (output.basket !== undefined) {
                  const basketBytes = Utils.toArray(output.basket, 'utf8')
                  resultWriter.writeVarIntNum(basketBytes.length)
                  resultWriter.write(basketBytes)
                } else {
                  resultWriter.writeVarIntNum(-1)
                }

                // tags
                if (output.tags !== undefined) {
                  resultWriter.writeVarIntNum(output.tags.length)
                  for (const tag of output.tags) {
                    const tagBytes = Utils.toArray(tag, 'utf8')
                    resultWriter.writeVarIntNum(tagBytes.length)
                    resultWriter.write(tagBytes)
                  }
                } else {
                  resultWriter.writeVarIntNum(-1)
                }

                // customInstructions
                if (output.customInstructions !== undefined) {
                  const customInstructionsBytes = Utils.toArray(
                    output.customInstructions,
                    'utf8'
                  )
                  resultWriter.writeVarIntNum(customInstructionsBytes.length)
                  resultWriter.write(customInstructionsBytes)
                } else {
                  resultWriter.writeVarIntNum(-1)
                }
              }
            } else {
              resultWriter.writeVarIntNum(-1)
            }
          }

          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }
        case 'internalizeAction': {
          const args: any = {}

          // Read tx
          const txLength = paramsReader.readVarIntNum()
          args.tx = paramsReader.read(txLength)

          // Read outputs
          const outputsLength = paramsReader.readVarIntNum()
          args.outputs = []
          for (let i = 0; i < outputsLength; i++) {
            const output: any = {}

            // outputIndex
            output.outputIndex = paramsReader.readVarIntNum()

            // protocol
            const protocolFlag = paramsReader.readUInt8()
            if (protocolFlag === 1) {
              output.protocol = 'wallet payment'
              output.paymentRemittance = {}

              // senderIdentityKey
              const senderIdentityKeyBytes = paramsReader.read(33)
              output.paymentRemittance.senderIdentityKey = Utils.toHex(
                senderIdentityKeyBytes
              )

              // derivationPrefix
              const derivationPrefixLength = paramsReader.readVarIntNum()
              const derivationPrefixBytes = paramsReader.read(
                derivationPrefixLength
              )
              output.paymentRemittance.derivationPrefix = Utils.toBase64(
                derivationPrefixBytes
              )

              // derivationSuffix
              const derivationSuffixLength = paramsReader.readVarIntNum()
              const derivationSuffixBytes = paramsReader.read(
                derivationSuffixLength
              )
              output.paymentRemittance.derivationSuffix = Utils.toBase64(
                derivationSuffixBytes
              )
            } else if (protocolFlag === 2) {
              output.protocol = 'basket insertion'
              output.insertionRemittance = {}

              // basket
              const basketLength = paramsReader.readVarIntNum()
              const basketBytes = paramsReader.read(basketLength)
              output.insertionRemittance.basket = Utils.toUTF8(basketBytes)

              // customInstructions
              const customInstructionsLength = paramsReader.readVarIntNum()
              if (customInstructionsLength >= 0) {
                const customInstructionsBytes = paramsReader.read(
                  customInstructionsLength
                )
                output.insertionRemittance.customInstructions = Utils.toUTF8(
                  customInstructionsBytes
                )
              }

              // tags
              const tagsLength = paramsReader.readVarIntNum()
              if (tagsLength > 0) {
                output.insertionRemittance.tags = []
                for (let j = 0; j < tagsLength; j++) {
                  const tagLength = paramsReader.readVarIntNum()
                  const tagBytes = paramsReader.read(tagLength)
                  output.insertionRemittance.tags.push(Utils.toUTF8(tagBytes))
                }
              } else {
                output.insertionRemittance.tags = []
              }
            }

            args.outputs.push(output)
          }

          const numberOfLabels = paramsReader.readVarIntNum()
          if (numberOfLabels >= 0) {
            args.labels = []
            for (let i = 0; i < numberOfLabels; i++) {
              const labelLength = paramsReader.readVarIntNum()
              args.labels.push(Utils.toUTF8(paramsReader.read(labelLength)))
            }
          }

          const descriptionLength = paramsReader.readVarIntNum()
          args.description = Utils.toUTF8(paramsReader.read(descriptionLength))

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          await this.wallet.internalizeAction(args, originator)

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'listOutputs': {
          const args: any = {}

          // Deserialize basket
          const basketLength = paramsReader.readVarIntNum()
          const basketBytes = paramsReader.read(basketLength)
          args.basket = Utils.toUTF8(basketBytes)

          // Deserialize tags
          const tagsLength = paramsReader.readVarIntNum()
          if (tagsLength > 0) {
            args.tags = []
            for (let i = 0; i < tagsLength; i++) {
              const tagLength = paramsReader.readVarIntNum()
              const tagBytes = paramsReader.read(tagLength)
              args.tags.push(Utils.toUTF8(tagBytes))
            }
          } else {
            args.tags = undefined
          }

          // Deserialize tagQueryMode
          const tagQueryModeFlag = paramsReader.readInt8()
          if (tagQueryModeFlag === 1) {
            args.tagQueryMode = 'all'
          } else if (tagQueryModeFlag === 2) {
            args.tagQueryMode = 'any'
          } else {
            args.tagQueryMode = undefined
          }

          // Deserialize include
          const includeFlag = paramsReader.readInt8()
          if (includeFlag === 1) {
            args.include = 'locking scripts'
          } else if (includeFlag === 2) {
            args.include = 'entire transactions'
          } else {
            args.include = undefined
          }

          // Deserialize includeCustomInstructions
          const includeCustomInstructionsFlag = paramsReader.readInt8()
          if (includeCustomInstructionsFlag === -1) {
            args.includeCustomInstructions = undefined
          } else {
            args.includeCustomInstructions =
              includeCustomInstructionsFlag === 1
          }

          // Deserialize includeTags
          const includeTagsFlag = paramsReader.readInt8()
          if (includeTagsFlag === -1) {
            args.includeTags = undefined
          } else {
            args.includeTags = includeTagsFlag === 1
          }

          // Deserialize includeLabels
          const includeLabelsFlag = paramsReader.readInt8()
          if (includeLabelsFlag === -1) {
            args.includeLabels = undefined
          } else {
            args.includeLabels = includeLabelsFlag === 1
          }

          // Deserialize limit
          const limit = paramsReader.readVarIntNum()
          if (limit >= 0) {
            args.limit = limit
          } else {
            args.limit = undefined
          }

          // Deserialize offset
          const offset = paramsReader.readVarIntNum()
          if (offset >= 0) {
            args.offset = offset
          } else {
            args.offset = undefined
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const listOutputsResult = await this.wallet.listOutputs(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // totalOutputs
          resultWriter.writeVarIntNum(listOutputsResult.totalOutputs)

          // BEEF length and BEEF or -1
          if (listOutputsResult.BEEF != null) {
            resultWriter.writeVarIntNum(listOutputsResult.BEEF.length)
            resultWriter.write(listOutputsResult.BEEF)
          } else {
            resultWriter.writeVarIntNum(-1)
          }

          // outputs
          for (const output of listOutputsResult.outputs) {
            // outpoint
            resultWriter.write(this.encodeOutpoint(output.outpoint))

            // satoshis
            resultWriter.writeVarIntNum(output.satoshis)

            // lockingScript
            if (output.lockingScript !== undefined) {
              const lockingScriptBytes = Utils.toArray(
                output.lockingScript,
                'hex'
              )
              resultWriter.writeVarIntNum(lockingScriptBytes.length)
              resultWriter.write(lockingScriptBytes)
            } else {
              resultWriter.writeVarIntNum(-1)
            }

            // customInstructions
            if (output.customInstructions !== undefined) {
              const customInstructionsBytes = Utils.toArray(
                output.customInstructions,
                'utf8'
              )
              resultWriter.writeVarIntNum(customInstructionsBytes.length)
              resultWriter.write(customInstructionsBytes)
            } else {
              resultWriter.writeVarIntNum(-1)
            }

            // tags
            if (output.tags !== undefined) {
              resultWriter.writeVarIntNum(output.tags.length)
              for (const tag of output.tags) {
                const tagBytes = Utils.toArray(tag, 'utf8')
                resultWriter.writeVarIntNum(tagBytes.length)
                resultWriter.write(tagBytes)
              }
            } else {
              resultWriter.writeVarIntNum(-1)
            }

            // labels
            if (output.labels !== undefined) {
              resultWriter.writeVarIntNum(output.labels.length)
              for (const label of output.labels) {
                const labelBytes = Utils.toArray(label, 'utf8')
                resultWriter.writeVarIntNum(labelBytes.length)
                resultWriter.write(labelBytes)
              }
            } else {
              resultWriter.writeVarIntNum(-1)
            }
          }

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }

        case 'relinquishOutput': {
          const args: any = {}

          // Deserialize basket
          const basketLength = paramsReader.readVarIntNum()
          const basketBytes = paramsReader.read(basketLength)
          args.basket = Utils.toUTF8(basketBytes)

          // Deserialize outpoint
          args.output = this.decodeOutpoint(paramsReader)

          // Call the method
          await this.wallet.relinquishOutput(args, originator)

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'getPublicKey': {
          const args: any = {}

          // Deserialize identityKey flag
          const identityKeyFlag = paramsReader.readUInt8()
          args.identityKey = identityKeyFlag === 1

          if (args.identityKey !== true) {
            // Deserialize protocolID
            args.protocolID = this.decodeProtocolID(paramsReader)

            // Deserialize keyID
            args.keyID = this.decodeString(paramsReader)

            // Deserialize counterparty
            args.counterparty = this.decodeCounterparty(paramsReader)

            // Deserialize privilege parameters
            const privilegedFlag = paramsReader.readInt8()
            if (privilegedFlag === -1) {
              args.privileged = undefined
            } else {
              args.privileged = privilegedFlag === 1
            }

            const privilegedReasonLength = paramsReader.readInt8()
            if (privilegedReasonLength !== -1) {
              const privilegedReasonBytes = paramsReader.read(
                privilegedReasonLength
              )
              args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
            } else {
              args.privilegedReason = undefined
            }

            // Deserialize forSelf
            const forSelfFlag = paramsReader.readInt8()
            if (forSelfFlag === -1) {
              args.forSelf = undefined
            } else {
              args.forSelf = forSelfFlag === 1
            }
          } else {
            // Deserialize privilege parameters
            const privilegedFlag = paramsReader.readInt8()
            if (privilegedFlag === -1) {
              args.privileged = undefined
            } else {
              args.privileged = privilegedFlag === 1
            }

            const privilegedReasonLength = paramsReader.readInt8()
            if (privilegedReasonLength !== -1) {
              const privilegedReasonBytes = paramsReader.read(
                privilegedReasonLength
              )
              args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
            } else {
              args.privilegedReason = undefined
            }
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const getPublicKeyResult = await this.wallet.getPublicKey(
            args,
            originator
          )

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          const publicKeyBytes = Utils.toArray(
            getPublicKeyResult.publicKey,
            'hex'
          )
          responseWriter.write(publicKeyBytes)
          return responseWriter.toArray()
        }

        case 'encrypt': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize plaintext
          const plaintextLength = paramsReader.readVarIntNum()
          args.plaintext = paramsReader.read(plaintextLength)

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const encryptResult = await this.wallet.encrypt(args, originator)

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(encryptResult.ciphertext)
          return responseWriter.toArray()
        }

        case 'decrypt': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize ciphertext
          const ciphertextLength = paramsReader.readVarIntNum()
          args.ciphertext = paramsReader.read(ciphertextLength)

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const decryptResult = await this.wallet.decrypt(args, originator)

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(decryptResult.plaintext)
          return responseWriter.toArray()
        }

        case 'createHmac': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize data
          const dataLength = paramsReader.readVarIntNum()
          args.data = paramsReader.read(dataLength)

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const createHmacResult = await this.wallet.createHmac(
            args,
            originator
          )

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(createHmacResult.hmac)
          return responseWriter.toArray()
        }

        case 'verifyHmac': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize hmac
          args.hmac = paramsReader.read(32)

          // Deserialize data
          const dataLength = paramsReader.readVarIntNum()
          args.data = paramsReader.read(dataLength)

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          await this.wallet.verifyHmac(args, originator)

          // Serialize the result (no data to return)
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'createSignature': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize data or hashToDirectlySign
          const dataTypeFlag = paramsReader.readUInt8()
          if (dataTypeFlag === 1) {
            const dataLength = paramsReader.readVarIntNum()
            args.data = paramsReader.read(dataLength)
          } else if (dataTypeFlag === 2) {
            args.hashToDirectlySign = paramsReader.read(32)
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const createSignatureResult = await this.wallet.createSignature(
            args,
            originator
          )

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(createSignatureResult.signature)
          return responseWriter.toArray()
        }

        case 'verifySignature': {
          const args: any = this.decodeKeyRelatedParams(paramsReader)

          // Deserialize forSelf
          const forSelfFlag = paramsReader.readInt8()
          if (forSelfFlag === -1) {
            args.forSelf = undefined
          } else {
            args.forSelf = forSelfFlag === 1
          }

          // Deserialize signature
          const signatureLength = paramsReader.readVarIntNum()
          args.signature = paramsReader.read(signatureLength)

          // Deserialize data or hashToDirectlyVerify
          const dataTypeFlag = paramsReader.readUInt8()
          if (dataTypeFlag === 1) {
            const dataLength = paramsReader.readVarIntNum()
            args.data = paramsReader.read(dataLength)
          } else if (dataTypeFlag === 2) {
            args.hashToDirectlyVerify = paramsReader.read(32)
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          await this.wallet.verifySignature(args, originator)

          // Serialize the result (no data to return)
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'isAuthenticated': {
          // No parameters to deserialize

          // Call the method
          const isAuthenticatedResult = await this.wallet.isAuthenticated(
            {},
            originator
          )

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.writeUInt8(
            isAuthenticatedResult.authenticated ? 1 : 0
          )
          return responseWriter.toArray()
        }

        case 'waitForAuthentication': {
          // No parameters to deserialize

          // Call the method
          await this.wallet.waitForAuthentication({}, originator)

          // Serialize the result (authenticated is always true)
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'getHeight': {
          // No parameters to deserialize

          // Call the method
          const getHeightResult = await this.wallet.getHeight({}, originator)

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.writeVarIntNum(getHeightResult.height)
          return responseWriter.toArray()
        }

        case 'getHeaderForHeight': {
          const args: any = {}

          // Deserialize height
          args.height = paramsReader.readVarIntNum()

          // Call the method
          const getHeaderResult = await this.wallet.getHeaderForHeight(
            args,
            originator
          )

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          const headerBytes = Utils.toArray(getHeaderResult.header, 'hex')
          responseWriter.write(headerBytes)
          return responseWriter.toArray()
        }

        case 'getNetwork': {
          // No parameters to deserialize

          // Call the method
          const getNetworkResult = await this.wallet.getNetwork({}, originator)

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.writeUInt8(
            getNetworkResult.network === 'mainnet' ? 0 : 1
          )
          return responseWriter.toArray()
        }

        case 'getVersion': {
          // No parameters to deserialize

          // Call the method
          const getVersionResult = await this.wallet.getVersion({}, originator)

          // Serialize the result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          const versionBytes = Utils.toArray(getVersionResult.version, 'utf8')
          responseWriter.write(versionBytes)
          return responseWriter.toArray()
        }

        case 'revealCounterpartyKeyLinkage': {
          const args: any = {}

          // Read privileged parameters
          const privilegedFlag = paramsReader.readInt8()
          if (privilegedFlag === -1) {
            args.privileged = undefined
          } else {
            args.privileged = privilegedFlag === 1
          }

          const privilegedReasonLength = paramsReader.readInt8()
          if (privilegedReasonLength === -1) {
            args.privilegedReason = undefined
          } else {
            const privilegedReasonBytes = paramsReader.read(
              privilegedReasonLength
            )
            args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
          }

          // Read counterparty public key
          const counterpartyBytes = paramsReader.read(33)
          args.counterparty = Utils.toHex(counterpartyBytes)

          // Read verifier public key
          const verifierBytes = paramsReader.read(33)
          args.verifier = Utils.toHex(verifierBytes)

          // Call the method
          const revealResult = await this.wallet.revealCounterpartyKeyLinkage(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // Write prover
          resultWriter.write(Utils.toArray(revealResult.prover, 'hex'))

          // Write verifier
          resultWriter.write(Utils.toArray(revealResult.verifier, 'hex'))

          // Write counterparty
          resultWriter.write(Utils.toArray(revealResult.counterparty, 'hex'))

          // Write revelationTime
          const revelationTimeBytes = Utils.toArray(
            revealResult.revelationTime,
            'utf8'
          )
          resultWriter.writeVarIntNum(revelationTimeBytes.length)
          resultWriter.write(revelationTimeBytes)

          // Write encryptedLinkage
          resultWriter.writeVarIntNum(revealResult.encryptedLinkage.length)
          resultWriter.write(revealResult.encryptedLinkage)

          // Write encryptedLinkageProof
          resultWriter.writeVarIntNum(
            revealResult.encryptedLinkageProof.length
          )
          resultWriter.write(revealResult.encryptedLinkageProof)

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }

        case 'revealSpecificKeyLinkage': {
          // Deserialize key-related parameters and privileged parameters
          const args = this.decodeKeyRelatedParams(paramsReader)

          // Read verifier public key
          const verifierBytes = paramsReader.read(33)
          args.verifier = Utils.toHex(verifierBytes)

          // Call the method
          const revealResult = await this.wallet.revealSpecificKeyLinkage(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // Write prover
          resultWriter.write(Utils.toArray(revealResult.prover, 'hex'))

          // Write verifier
          resultWriter.write(Utils.toArray(revealResult.verifier, 'hex'))

          // Write counterparty
          resultWriter.write(Utils.toArray(revealResult.counterparty, 'hex'))

          // Write securityLevel
          resultWriter.writeUInt8(revealResult.protocolID[0])

          // Write protocol string
          const protocolBytesOut = Utils.toArray(
            revealResult.protocolID[1],
            'utf8'
          )
          resultWriter.writeVarIntNum(protocolBytesOut.length)
          resultWriter.write(protocolBytesOut)

          // Write keyID
          const keyIDBytesOut = Utils.toArray(revealResult.keyID, 'utf8')
          resultWriter.writeVarIntNum(keyIDBytesOut.length)
          resultWriter.write(keyIDBytesOut)

          // Write encryptedLinkage
          resultWriter.writeVarIntNum(revealResult.encryptedLinkage.length)
          resultWriter.write(revealResult.encryptedLinkage)

          // Write encryptedLinkageProof
          resultWriter.writeVarIntNum(
            revealResult.encryptedLinkageProof.length
          )
          resultWriter.write(revealResult.encryptedLinkageProof)

          // Write proofType
          resultWriter.writeUInt8(revealResult.proofType)

          // Return success code and result
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }

        case 'acquireCertificate': {
          const args: any = {}

          // Read args.type
          const typeBytes = paramsReader.read(32)
          args.type = Utils.toBase64(typeBytes)

          // args.certifier
          const certifierBytes = paramsReader.read(33)
          args.certifier = Utils.toHex(certifierBytes)

          // Read fields
          const fieldsLength = paramsReader.readVarIntNum()
          args.fields = {}
          for (let i = 0; i < fieldsLength; i++) {
            const fieldNameLength = paramsReader.readVarIntNum()
            const fieldNameBytes = paramsReader.read(fieldNameLength)
            const fieldName = Utils.toUTF8(fieldNameBytes)

            const fieldValueLength = paramsReader.readVarIntNum()
            const fieldValueBytes = paramsReader.read(fieldValueLength)
            const fieldValue = Utils.toUTF8(fieldValueBytes)

            args.fields[fieldName] = fieldValue
          }

          // Read privileged parameters
          const privilegedFlag = paramsReader.readInt8()
          if (privilegedFlag === -1) {
            args.privileged = undefined
          } else {
            args.privileged = privilegedFlag === 1
          }

          const privilegedReasonLength = paramsReader.readInt8()
          if (privilegedReasonLength === -1) {
            args.privilegedReason = undefined
          } else {
            const privilegedReasonBytes = paramsReader.read(
              privilegedReasonLength
            )
            args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
          }

          // Read acquisitionProtocol
          const acquisitionProtocolFlag = paramsReader.readUInt8()
          args.acquisitionProtocol =
            acquisitionProtocolFlag === 1 ? 'direct' : 'issuance'

          if (args.acquisitionProtocol === 'direct') {
            // args.serialNumber
            const serialNumberBytes = paramsReader.read(32)
            args.serialNumber = Utils.toBase64(serialNumberBytes)

            // args.revocationOutpoint
            args.revocationOutpoint = this.decodeOutpoint(paramsReader)

            // args.signature
            const signatureLength = paramsReader.readVarIntNum()
            const signatureBytes = paramsReader.read(signatureLength)
            args.signature = Utils.toHex(signatureBytes)

            // args.keyringRevealer
            const keyringRevealerIdentifier = paramsReader.readUInt8()
            if (keyringRevealerIdentifier === 11) {
              args.keyringRevealer = 'certifier'
            } else {
              const keyringRevealerBytes = [keyringRevealerIdentifier].concat(
                paramsReader.read(32)
              )
              args.keyringRevealer = Utils.toHex(keyringRevealerBytes)
            }

            // args.keyringForSubject
            const keyringEntriesLength = paramsReader.readVarIntNum()
            args.keyringForSubject = {}
            for (let i = 0; i < keyringEntriesLength; i++) {
              const fieldKeyLength = paramsReader.readVarIntNum()
              const fieldKeyBytes = paramsReader.read(fieldKeyLength)
              const fieldKey = Utils.toUTF8(fieldKeyBytes)

              const fieldValueLength = paramsReader.readVarIntNum()
              const fieldValueBytes = paramsReader.read(fieldValueLength)
              const fieldValue = Utils.toBase64(fieldValueBytes)

              args.keyringForSubject[fieldKey] = fieldValue
            }
          } else {
            // args.certifierUrl
            const certifierUrlLength = paramsReader.readVarIntNum()
            const certifierUrlBytes = paramsReader.read(certifierUrlLength)
            args.certifierUrl = Utils.toUTF8(certifierUrlBytes)
          }

          // Call the method
          const acquireResult = await this.wallet.acquireCertificate(
            args,
            originator
          )

          // Serialize the certificate (assuming Certificate class is available)
          const cert = new Certificate(
            acquireResult.type,
            acquireResult.serialNumber,
            acquireResult.subject,
            acquireResult.certifier,
            acquireResult.revocationOutpoint,
            acquireResult.fields,
            acquireResult.signature
          )
          const certBin = cert.toBinary()

          // Return success code and certificate binary
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(certBin)
          return responseWriter.toArray()
        }

        case 'listCertificates': {
          const args: any = {}

          // Read certifiers
          const certifiersLength = paramsReader.readVarIntNum()
          args.certifiers = []
          for (let i = 0; i < certifiersLength; i++) {
            const certifierBytes = paramsReader.read(33)
            args.certifiers.push(Utils.toHex(certifierBytes))
          }

          // Read types
          const typesLength = paramsReader.readVarIntNum()
          args.types = []
          for (let i = 0; i < typesLength; i++) {
            const typeBytes = paramsReader.read(32)
            args.types.push(Utils.toBase64(typeBytes))
          }

          // Read limit and offset
          const limit = paramsReader.readVarIntNum()
          if (limit >= 0) {
            args.limit = limit
          } else {
            args.limit = undefined
          }

          const offset = paramsReader.readVarIntNum()
          if (offset >= 0) {
            args.offset = offset
          } else {
            args.offset = undefined
          }

          // Read privileged parameters
          const privilegedFlag = paramsReader.readInt8()
          if (privilegedFlag === -1) {
            args.privileged = undefined
          } else {
            args.privileged = privilegedFlag === 1
          }

          const privilegedReasonLength = paramsReader.readInt8()
          if (privilegedReasonLength === -1) {
            args.privilegedReason = undefined
          } else {
            const privilegedReasonBytes = paramsReader.read(
              privilegedReasonLength
            )
            args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
          }

          // Call the method
          const listResult = await this.wallet.listCertificates(
            args,
            originator
          )

          // Serialize the result
          const resultWriter = new Utils.Writer()

          // totalCertificates
          resultWriter.writeVarIntNum(listResult.totalCertificates)

          // certificates
          for (const cert of listResult.certificates) {
            const certificate = new Certificate(
              cert.type,
              cert.serialNumber,
              cert.subject,
              cert.certifier,
              cert.revocationOutpoint,
              cert.fields,
              cert.signature
            )
            const certBin = certificate.toBinary()

            // Write certificate binary length and data
            resultWriter.writeVarIntNum(certBin.length)
            resultWriter.write(certBin)

            if (cert.keyring && Object.keys(cert.keyring).length > 0) {
              resultWriter.writeInt8(1) // Flag indicating keyring is present
              const keyringEntries = Object.entries(cert.keyring)
              resultWriter.writeVarIntNum(keyringEntries.length)
              for (const [fieldName, fieldValue] of keyringEntries) {
                const fieldNameBytes = Utils.toArray(fieldName, 'utf8')
                resultWriter.writeVarIntNum(fieldNameBytes.length)
                resultWriter.write(fieldNameBytes)

                const fieldValueBytes = Utils.toArray(fieldValue, 'base64')
                resultWriter.writeVarIntNum(fieldValueBytes.length)
                resultWriter.write(fieldValueBytes)
              }
            } else {
              resultWriter.writeInt8(0) // Flag indicating no keyring
            }

            const verifierBytes = Utils.toArray(cert.verifier, 'hex')
            resultWriter.writeVarIntNum(verifierBytes.length)
            resultWriter.write(verifierBytes)
          }

          // Return the response
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }

        case 'proveCertificate': {
          const args: any = {}

          // Read certificate
          const cert: any = {}

          // Read type
          const typeBytes = paramsReader.read(32)
          cert.type = Utils.toBase64(typeBytes)

          // Read subject
          const subjectBytes = paramsReader.read(33)
          cert.subject = Utils.toHex(subjectBytes)

          // Read serialNumber
          const serialNumberBytes = paramsReader.read(32)
          cert.serialNumber = Utils.toBase64(serialNumberBytes)

          // Read certifier
          const certifierBytes = paramsReader.read(33)
          cert.certifier = Utils.toHex(certifierBytes)

          // Read revocationOutpoint
          cert.revocationOutpoint = this.decodeOutpoint(paramsReader)

          // Read signature
          const signatureLength = paramsReader.readVarIntNum()
          const signatureBytes = paramsReader.read(signatureLength)
          cert.signature = Utils.toHex(signatureBytes)

          // Read fields
          const fieldsLength = paramsReader.readVarIntNum()
          cert.fields = {}
          for (let i = 0; i < fieldsLength; i++) {
            const fieldNameLength = paramsReader.readVarIntNum()
            const fieldNameBytes = paramsReader.read(fieldNameLength)
            const fieldName = Utils.toUTF8(fieldNameBytes)

            const fieldValueLength = paramsReader.readVarIntNum()
            const fieldValueBytes = paramsReader.read(fieldValueLength)
            const fieldValue = Utils.toUTF8(fieldValueBytes)

            cert.fields[fieldName] = fieldValue
          }

          args.certificate = cert

          // Read fields to reveal
          const fieldsToRevealLength = paramsReader.readVarIntNum()
          args.fieldsToReveal = []
          for (let i = 0; i < fieldsToRevealLength; i++) {
            const fieldNameLength = paramsReader.readVarIntNum()
            const fieldNameBytes = paramsReader.read(fieldNameLength)
            const fieldName = Utils.toUTF8(fieldNameBytes)
            args.fieldsToReveal.push(fieldName)
          }

          // Read verifier
          const verifierBytes = paramsReader.read(33)
          args.verifier = Utils.toHex(verifierBytes)

          // Read privileged parameters
          const privilegedFlag = paramsReader.readInt8()
          if (privilegedFlag === -1) {
            args.privileged = undefined
          } else {
            args.privileged = privilegedFlag === 1
          }

          const privilegedReasonLength = paramsReader.readInt8()
          if (privilegedReasonLength === -1) {
            args.privilegedReason = undefined
          } else {
            const privilegedReasonBytes = paramsReader.read(
              privilegedReasonLength
            )
            args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
          }

          // Call the method
          const proveResult = await this.wallet.proveCertificate(
            args,
            originator
          )

          // Serialize keyringForVerifier
          const resultWriter = new Utils.Writer()

          const keyringEntries = Object.entries(proveResult.keyringForVerifier)
          resultWriter.writeVarIntNum(keyringEntries.length)
          for (const [fieldName, fieldValue] of keyringEntries) {
            const fieldNameBytes = Utils.toArray(fieldName, 'utf8')
            resultWriter.writeVarIntNum(fieldNameBytes.length)
            resultWriter.write(fieldNameBytes)

            const fieldValueBytes = Utils.toArray(fieldValue, 'base64')
            resultWriter.writeVarIntNum(fieldValueBytes.length)
            resultWriter.write(fieldValueBytes)
          }

          // Return the response
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(resultWriter.toArray())
          return responseWriter.toArray()
        }

        case 'relinquishCertificate': {
          const args: any = {}

          // Read type
          const typeBytes = paramsReader.read(32)
          args.type = Utils.toBase64(typeBytes)

          // Read serialNumber
          const serialNumberBytes = paramsReader.read(32)
          args.serialNumber = Utils.toBase64(serialNumberBytes)

          // Read certifier
          const certifierBytes = paramsReader.read(33)
          args.certifier = Utils.toHex(certifierBytes)

          // Call the method
          await this.wallet.relinquishCertificate(args, originator)

          // Return success code
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          return responseWriter.toArray()
        }

        case 'discoverByIdentityKey': {
          const args: any = {}

          // Read identityKey
          const identityKeyBytes = paramsReader.read(33)
          args.identityKey = Utils.toHex(identityKeyBytes)

          // Read limit and offset
          const limit = paramsReader.readVarIntNum()
          if (limit >= 0) {
            args.limit = limit
          } else {
            args.limit = undefined
          }

          const offset = paramsReader.readVarIntNum()
          if (offset >= 0) {
            args.offset = offset
          } else {
            args.offset = undefined
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const discoverResult = await this.wallet.discoverByIdentityKey(
            args,
            originator
          )

          // Serialize the result
          const result = this.serializeDiscoveryResult(discoverResult)

          // Return the response
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(result)
          return responseWriter.toArray()
        }

        case 'discoverByAttributes': {
          const args: any = {}

          // Read attributes
          const attributesLength = paramsReader.readVarIntNum()
          args.attributes = {}
          for (let i = 0; i < attributesLength; i++) {
            const fieldKeyLength = paramsReader.readVarIntNum()
            const fieldKeyBytes = paramsReader.read(fieldKeyLength)
            const fieldKey = Utils.toUTF8(fieldKeyBytes)

            const fieldValueLength = paramsReader.readVarIntNum()
            const fieldValueBytes = paramsReader.read(fieldValueLength)
            const fieldValue = Utils.toUTF8(fieldValueBytes)

            args.attributes[fieldKey] = fieldValue
          }

          // Read limit and offset
          const limit = paramsReader.readVarIntNum()
          if (limit >= 0) {
            args.limit = limit
          } else {
            args.limit = undefined
          }

          const offset = paramsReader.readVarIntNum()
          if (offset >= 0) {
            args.offset = offset
          } else {
            args.offset = undefined
          }

          // Deserialize seekPermission
          const seekPermission = paramsReader.readInt8()
          if (seekPermission >= 0) {
            args.seekPermission = seekPermission === 1
          } else {
            args.seekPermission = undefined
          }

          // Call the method
          const discoverResult = await this.wallet.discoverByAttributes(
            args,
            originator
          )

          // Serialize the result
          const result = this.serializeDiscoveryResult(discoverResult)

          // Return the response
          const responseWriter = new Utils.Writer()
          responseWriter.writeUInt8(0) // errorByte = 0
          responseWriter.write(result)
          return responseWriter.toArray()
        }

        default:
          throw new Error(`Method ${callName} not implemented`)
      }
    } catch (err) {
      const responseWriter = new Utils.Writer()
      responseWriter.writeUInt8(typeof err.code === 'number' ? err.code : 1) // errorCode = 1 (generic error)

      // Serialize the error message
      const errorMessage = typeof err.message === 'string' ? err.message : 'Unknown error'
      const errorMessageBytes = Utils.toArray(errorMessage, 'utf8')
      responseWriter.writeVarIntNum(errorMessageBytes.length)
      responseWriter.write(errorMessageBytes)

      // Serialize the stack trace
      const stackTrace = typeof err.stack === 'string' ? err.stack : ''
      const stackTraceBytes = Utils.toArray(stackTrace, 'utf8')
      responseWriter.writeVarIntNum(stackTraceBytes.length)
      responseWriter.write(stackTraceBytes)

      return responseWriter.toArray()
    }
  }

  private decodeProtocolID(reader: Utils.Reader): [SecurityLevel, string] {
    const securityLevel = reader.readUInt8() as SecurityLevel
    const protocolLength = reader.readVarIntNum()
    const protocolBytes = reader.read(protocolLength)
    const protocolString = Utils.toUTF8(protocolBytes)
    return [securityLevel, protocolString]
  }

  private decodeString(reader: Utils.Reader): string {
    const length = reader.readVarIntNum()
    const bytes = reader.read(length)
    return Utils.toUTF8(bytes)
  }

  private decodeCounterparty(
    reader: Utils.Reader
  ): string | 'self' | 'anyone' | undefined {
    const counterpartyFlag = reader.readUInt8()
    if (counterpartyFlag === 11) {
      return 'self'
    } else if (counterpartyFlag === 12) {
      return 'anyone'
    } else if (counterpartyFlag === 0) {
      return undefined
    } else {
      const counterpartyRemainingBytes = reader.read(32)
      return Utils.toHex([counterpartyFlag, ...counterpartyRemainingBytes])
    }
  }

  private serializeDiscoveryResult(discoverResult: any): number[] {
    const resultWriter = new Utils.Writer()

    // totalCertificates
    resultWriter.writeVarIntNum(discoverResult.totalCertificates)

    // certificates
    for (const cert of discoverResult.certificates) {
      // Serialize certificate binary
      const certificate = new Certificate(
        cert.type,
        cert.serialNumber,
        cert.subject,
        cert.certifier,
        cert.revocationOutpoint,
        cert.fields,
        cert.signature
      )
      const certBin = certificate.toBinary()

      // Write certificate binary length and data
      resultWriter.writeVarIntNum(certBin.length)
      resultWriter.write(certBin)

      // Serialize certifierInfo
      const nameBytes = Utils.toArray(cert.certifierInfo.name, 'utf8')
      resultWriter.writeVarIntNum(nameBytes.length)
      resultWriter.write(nameBytes)

      const iconUrlBytes = Utils.toArray(cert.certifierInfo.iconUrl, 'utf8')
      resultWriter.writeVarIntNum(iconUrlBytes.length)
      resultWriter.write(iconUrlBytes)

      const descriptionBytes = Utils.toArray(
        cert.certifierInfo.description,
        'utf8'
      )
      resultWriter.writeVarIntNum(descriptionBytes.length)
      resultWriter.write(descriptionBytes)

      resultWriter.writeUInt8(cert.certifierInfo.trust)

      // Serialize publiclyRevealedKeyring
      const publicKeyringEntries = Object.entries(cert.publiclyRevealedKeyring)
      resultWriter.writeVarIntNum(publicKeyringEntries.length)
      for (const [fieldName, fieldValue] of publicKeyringEntries) {
        const fieldNameBytes = Utils.toArray(fieldName, 'utf8')
        resultWriter.writeVarIntNum(fieldNameBytes.length)
        resultWriter.write(fieldNameBytes)

        const fieldValueBytes = Utils.toArray(fieldValue, 'base64')
        resultWriter.writeVarIntNum(fieldValueBytes.length)
        resultWriter.write(fieldValueBytes)
      }

      // Serialize decryptedFields
      const decryptedFieldEntries = Object.entries(cert.decryptedFields)
      resultWriter.writeVarIntNum(decryptedFieldEntries.length)
      for (const [fieldName, fieldValue] of decryptedFieldEntries) {
        const fieldNameBytes = Utils.toArray(fieldName, 'utf8')
        resultWriter.writeVarIntNum(fieldNameBytes.length)
        resultWriter.write(fieldNameBytes)

        const fieldValueBytes = Utils.toArray(fieldValue, 'utf8')
        resultWriter.writeVarIntNum(fieldValueBytes.length)
        resultWriter.write(fieldValueBytes)
      }
    }

    return resultWriter.toArray()
  }

  private decodeKeyRelatedParams(paramsReader: Utils.Reader): any {
    const args: any = {}

    // Read protocolID
    args.protocolID = this.decodeProtocolID(paramsReader)

    // Read keyID
    const keyIDLength = paramsReader.readVarIntNum()
    const keyIDBytes = paramsReader.read(keyIDLength)
    args.keyID = Utils.toUTF8(keyIDBytes)

    // Read counterparty
    args.counterparty = this.decodeCounterparty(paramsReader)

    // Read privileged parameters
    const privilegedFlag = paramsReader.readInt8()
    if (privilegedFlag === -1) {
      args.privileged = undefined
    } else {
      args.privileged = privilegedFlag === 1
    }

    const privilegedReasonLength = paramsReader.readInt8()
    if (privilegedReasonLength === -1) {
      args.privilegedReason = undefined
    } else {
      const privilegedReasonBytes = paramsReader.read(privilegedReasonLength)
      args.privilegedReason = Utils.toUTF8(privilegedReasonBytes)
    }

    return args
  }
}
