# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| |
| --- |
| [BasketDefinitionData](#interface-basketdefinitiondata) |
| [BasketQuery](#interface-basketquery) |
| [CertificateDefinitionData](#interface-certificatedefinitiondata) |
| [CertificateFieldDescriptor](#interface-certificatefielddescriptor) |
| [CertificateQuery](#interface-certificatequery) |
| [ProtocolDefinitionData](#interface-protocoldefinitiondata) |
| [ProtocolQuery](#interface-protocolquery) |
| [RegistryQueryMapping](#interface-registryquerymapping) |
| [TokenData](#interface-tokendata) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: BasketDefinitionData

Registry data for a Basket-style record.

```ts
export interface BasketDefinitionData {
    definitionType: "basket";
    basketID: string;
    name: string;
    iconURL: string;
    description: string;
    documentationURL: string;
    registryOperator?: PubKeyHex;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: BasketQuery

When searching for basket definitions, we can filter by:
 - basketID
 - registryOperators
 - name

```ts
export interface BasketQuery {
    basketID?: string;
    registryOperators?: string[];
    name?: string;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CertificateDefinitionData

Registry data for a Certificate-style record.

```ts
export interface CertificateDefinitionData {
    definitionType: "certificate";
    type: string;
    name: string;
    iconURL: string;
    description: string;
    documentationURL: string;
    fields: Record<string, CertificateFieldDescriptor>;
    registryOperator?: PubKeyHex;
}
```

See also: [CertificateFieldDescriptor](./registry.md#interface-certificatefielddescriptor), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CertificateFieldDescriptor

Describes a re-usable structure for certificate fields (used by CertMap).

```ts
export interface CertificateFieldDescriptor {
    friendlyName: string;
    description: string;
    type: "text" | "imageURL" | "other";
    fieldIcon: string;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CertificateQuery

When searching for certificate definitions, we can filter by:
 - type
 - name
 - registryOperators

```ts
export interface CertificateQuery {
    type?: string;
    name?: string;
    registryOperators?: string[];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ProtocolDefinitionData

Registry data for a Protocol-style record.

```ts
export interface ProtocolDefinitionData {
    definitionType: "protocol";
    protocolID: WalletProtocol;
    name: string;
    iconURL: string;
    description: string;
    documentationURL: string;
    registryOperator?: PubKeyHex;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ProtocolQuery

When searching for protocol definitions, we can filter by:
 - name
 - registryOperators
 - protocolID

```ts
export interface ProtocolQuery {
    name?: string;
    registryOperators?: string[];
    protocolID?: WalletProtocol;
}
```

See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RegistryQueryMapping

A lookup-service mapping of queries by each definition type.

```ts
export interface RegistryQueryMapping {
    basket: BasketQuery;
    protocol: ProtocolQuery;
    certificate: CertificateQuery;
}
```

See also: [BasketQuery](./registry.md#interface-basketquery), [CertificateQuery](./registry.md#interface-certificatequery), [ProtocolQuery](./registry.md#interface-protocolquery)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: TokenData

Common info for the on-chain token/UTXO that points to a registry entry.

```ts
export interface TokenData {
    txid: string;
    outputIndex: number;
    satoshis: number;
    lockingScript: string;
    beef: BEEF;
}
```

See also: [BEEF](./wallet.md#type-beef)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

### Class: RegistryClient

RegistryClient manages on-chain registry definitions for three types:
- basket (basket-based items)
- protocol (protocol-based items)
- certificate (certificate-based items)

It provides methods to:
- Register new definitions using pushdrop-based UTXOs.
- Resolve existing definitions using a lookup service.
- List registry entries associated with the operator's wallet.
- Remove existing registry entries by spending their UTXOs.
- Update existing registry entries.

Registry operators use this client to establish and manage
canonical references for baskets, protocols, and certificate types.

```ts
export class RegistryClient {
    constructor(private readonly wallet: WalletInterface = new WalletClient(), options: {
        acceptDelayedBroadcast?: boolean;
        resolver?: LookupResolver;
    } = {}, private readonly originator?: OriginatorDomainNameStringUnder250Bytes) 
    async registerDefinition(data: DefinitionData): Promise<BroadcastResponse | BroadcastFailure> 
    async resolve<T extends DefinitionType>(definitionType: T, query: RegistryQueryMapping[T]): Promise<DefinitionData[]> 
    async listOwnRegistryEntries(definitionType: DefinitionType): Promise<RegistryRecord[]> 
    async removeDefinition(registryRecord: RegistryRecord): Promise<BroadcastResponse | BroadcastFailure> 
    async updateDefinition(registryRecord: RegistryRecord, updatedData: DefinitionData): Promise<BroadcastResponse | BroadcastFailure> 
}
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [DefinitionData](./registry.md#type-definitiondata), [DefinitionType](./registry.md#type-definitiontype), [LookupResolver](./overlay-tools.md#class-lookupresolver), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RegistryQueryMapping](./registry.md#interface-registryquerymapping), [RegistryRecord](./registry.md#type-registryrecord), [WalletClient](./wallet.md#class-walletclient), [WalletInterface](./wallet.md#interface-walletinterface)

#### Method listOwnRegistryEntries

Lists the registry operator's published definitions for the given type.

Returns parsed registry records including transaction details such as txid, outputIndex, satoshis, and the locking script.

```ts
async listOwnRegistryEntries(definitionType: DefinitionType): Promise<RegistryRecord[]> 
```
See also: [DefinitionType](./registry.md#type-definitiontype), [RegistryRecord](./registry.md#type-registryrecord)

Returns

A promise that resolves to an array of RegistryRecord objects.

Argument Details

+ **definitionType**
  + The type of registry definition to list ('basket', 'protocol', or 'certificate').

#### Method registerDefinition

Publishes a new on-chain definition for baskets, protocols, or certificates.
The definition data is encoded in a pushdrop-based UTXO.

Registry operators (i.e., identity key owners) can create these definitions
to establish canonical references for basket IDs, protocol specs, or certificate schemas.

```ts
async registerDefinition(data: DefinitionData): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [DefinitionData](./registry.md#type-definitiondata)

Returns

A promise with the broadcast result or failure.

Argument Details

+ **data**
  + Structured information about a 'basket', 'protocol', or 'certificate'.

#### Method removeDefinition

Removes a registry definition by spending its associated UTXO.

```ts
async removeDefinition(registryRecord: RegistryRecord): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [RegistryRecord](./registry.md#type-registryrecord)

Returns

Broadcast success/failure.

Argument Details

+ **registryRecord**
  + The registry record to remove (must have valid txid, outputIndex, and lockingScript).

#### Method resolve

Resolves registrant tokens of a particular type using a lookup service.

The query object shape depends on the registry type:
- For "basket", the query is of type BasketMapQuery:
  { basketID?: string; name?: string; registryOperators?: string[]; }
- For "protocol", the query is of type ProtoMapQuery:
  { name?: string; registryOperators?: string[]; protocolID?: WalletProtocol; }
- For "certificate", the query is of type CertMapQuery:
  { type?: string; name?: string; registryOperators?: string[]; }

```ts
async resolve<T extends DefinitionType>(definitionType: T, query: RegistryQueryMapping[T]): Promise<DefinitionData[]> 
```
See also: [DefinitionData](./registry.md#type-definitiondata), [DefinitionType](./registry.md#type-definitiontype), [RegistryQueryMapping](./registry.md#interface-registryquerymapping)

Returns

A promise that resolves to an array of matching registry records.

Argument Details

+ **definitionType**
  + The registry type, which can be 'basket', 'protocol', or 'certificate'.
+ **query**
  + The query object used to filter registry records, whose shape is determined by the registry type.

#### Method updateDefinition

Updates an existing registry record by spending its UTXO and creating a new one with updated data.

```ts
async updateDefinition(registryRecord: RegistryRecord, updatedData: DefinitionData): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [DefinitionData](./registry.md#type-definitiondata), [RegistryRecord](./registry.md#type-registryrecord)

Returns

Broadcast success/failure.

Argument Details

+ **registryRecord**
  + The existing registry record to update (must have valid txid, outputIndex, and lockingScript).
+ **updatedData**
  + The new definition data to replace the old record.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

### Function: deserializeWalletProtocol

```ts
export function deserializeWalletProtocol(str: string): WalletProtocol 
```

See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Types

| |
| --- |
| [DefinitionData](#type-definitiondata) |
| [DefinitionType](#type-definitiontype) |
| [RegistryRecord](#type-registryrecord) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Type: DefinitionData

Union of all possible definition data objects.

```ts
export type DefinitionData = BasketDefinitionData | ProtocolDefinitionData | CertificateDefinitionData
```

See also: [BasketDefinitionData](./registry.md#interface-basketdefinitiondata), [CertificateDefinitionData](./registry.md#interface-certificatedefinitiondata), [ProtocolDefinitionData](./registry.md#interface-protocoldefinitiondata)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: DefinitionType

We unify the registry “type” to these three strings everywhere:
  'basket' | 'protocol' | 'certificate'

```ts
export type DefinitionType = "basket" | "protocol" | "certificate"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: RegistryRecord

A registry record is a combination of the typed definition data
plus the on-chain token data for the UTXO holding it.

```ts
export type RegistryRecord = DefinitionData & TokenData
```

See also: [DefinitionData](./registry.md#type-definitiondata), [TokenData](./registry.md#interface-tokendata)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Enums

## Variables

