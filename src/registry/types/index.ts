import { BEEF, PubKeyHex, WalletProtocol } from '../../wallet/index.js'

/**
 * We unify the registry “type” to these three strings everywhere:
 *   'basket' | 'protocol' | 'certificate'
 */
export type DefinitionType = 'basket' | 'protocol' | 'certificate'

/**
 * Describes a re-usable structure for certificate fields (used by CertMap).
 */
export interface CertificateFieldDescriptor {
  friendlyName: string
  description: string
  type: 'text' | 'imageURL' | 'other'
  fieldIcon: string
}

/**
 * Registry data for a Basket-style record.
 */
export interface BasketDefinitionData {
  definitionType: 'basket'
  basketID: string
  name: string
  iconURL: string
  description: string
  documentationURL: string
  registryOperator?: PubKeyHex
}

/**
 * Registry data for a Protocol-style record.
 */
export interface ProtocolDefinitionData {
  definitionType: 'protocol'
  protocolID: WalletProtocol
  name: string
  iconURL: string
  description: string
  documentationURL: string
  registryOperator?: PubKeyHex
}

/**
 * Registry data for a Certificate-style record.
 */
export interface CertificateDefinitionData {
  definitionType: 'certificate'
  type: string
  name: string
  iconURL: string
  description: string
  documentationURL: string
  fields: Record<string, CertificateFieldDescriptor>
  registryOperator?: PubKeyHex
}

/**
 * Union of all possible definition data objects.
 */
export type DefinitionData =
  | BasketDefinitionData
  | ProtocolDefinitionData
  | CertificateDefinitionData

/**
 * Common info for the on-chain token/UTXO that points to a registry entry.
 */
export interface TokenData {
  txid: string
  outputIndex: number
  satoshis: number
  lockingScript: string
  beef: BEEF
}

/**
 * A registry record is a combination of the typed definition data
 * plus the on-chain token data for the UTXO holding it.
 */
export type RegistryRecord = DefinitionData & TokenData

// -------------------------------------------------------------------------
// Query type definitions
// -------------------------------------------------------------------------

/**
 * When searching for basket definitions, we can filter by:
 *  - basketID
 *  - registryOperators
 *  - name
 */
export interface BasketQuery {
  basketID?: string
  registryOperators?: string[]
  name?: string
}

/**
 * When searching for protocol definitions, we can filter by:
 *  - name
 *  - registryOperators
 *  - protocolID
 */
export interface ProtocolQuery {
  name?: string
  registryOperators?: string[]
  protocolID?: WalletProtocol
}

/**
 * When searching for certificate definitions, we can filter by:
 *  - type
 *  - name
 *  - registryOperators
 */
export interface CertificateQuery {
  type?: string
  name?: string
  registryOperators?: string[]
}

/**
 * A lookup-service mapping of queries by each definition type.
 */
export interface RegistryQueryMapping {
  basket: BasketQuery
  protocol: ProtocolQuery
  certificate: CertificateQuery
}
