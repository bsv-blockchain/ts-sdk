import { WalletProtocol } from './Wallet.interfaces.js'

export function computeInvoiceNumber (
  protocolID: WalletProtocol,
  keyID: string
): string {
  const securityLevel = protocolID[0]
  if (
    !Number.isInteger(securityLevel) ||
    securityLevel < 0 ||
    securityLevel > 2
  ) {
    throw new Error('Protocol security level must be 0, 1, or 2')
  }
  const protocolName = protocolID[1].toLowerCase().trim()
  if (keyID.length > 800) {
    throw new Error('Key IDs must be 800 characters or less')
  }
  if (keyID.length < 1) {
    throw new Error('Key IDs must be 1 character or more')
  }
  if (protocolName.length > 400) {
    if (protocolName.startsWith('specific linkage revelation ')) {
      if (protocolName.length > 430) {
        throw new Error(
          'Specific linkage revelation protocol names must be 430 characters or less'
        )
      }
    } else {
      throw new Error('Protocol names must be 400 characters or less')
    }
  }
  if (protocolName.length < 5) {
    throw new Error('Protocol names must be 5 characters or more')
  }
  if (protocolName.includes('  ')) {
    throw new Error(
      'Protocol names cannot contain multiple consecutive spaces ("  ")'
    )
  }
  if (!/^[a-z0-9 ]+$/g.test(protocolName)) {
    throw new Error(
      'Protocol names can only contain letters, numbers and spaces'
    )
  }
  if (protocolName.endsWith(' protocol')) {
    throw new Error('No need to end your protocol name with " protocol"')
  }
  return `${securityLevel}-${protocolName}-${keyID}`
}
