# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| | | |
| --- | --- | --- |
| [AbortActionArgs](#interface-abortactionargs) | [ListCertificatesArgs](#interface-listcertificatesargs) | [ValidInternalizeOutput](#interface-validinternalizeoutput) |
| [AbortActionResult](#interface-abortactionresult) | [ListCertificatesResult](#interface-listcertificatesresult) | [ValidListActionsArgs](#interface-validlistactionsargs) |
| [AcquireCertificateArgs](#interface-acquirecertificateargs) | [ListOutputsArgs](#interface-listoutputsargs) | [ValidListCertificatesArgs](#interface-validlistcertificatesargs) |
| [AuthenticatedResult](#interface-authenticatedresult) | [ListOutputsResult](#interface-listoutputsresult) | [ValidListOutputsArgs](#interface-validlistoutputsargs) |
| [BasketInsertion](#interface-basketinsertion) | [OutPoint](#interface-outpoint) | [ValidProcessActionArgs](#interface-validprocessactionargs) |
| [CertificateResult](#interface-certificateresult) | [ProveCertificateArgs](#interface-provecertificateargs) | [ValidProcessActionOptions](#interface-validprocessactionoptions) |
| [CreateActionArgs](#interface-createactionargs) | [ProveCertificateResult](#interface-provecertificateresult) | [ValidProveCertificateArgs](#interface-validprovecertificateargs) |
| [CreateActionInput](#interface-createactioninput) | [RelinquishCertificateArgs](#interface-relinquishcertificateargs) | [ValidRelinquishCertificateArgs](#interface-validrelinquishcertificateargs) |
| [CreateActionOptions](#interface-createactionoptions) | [RelinquishCertificateResult](#interface-relinquishcertificateresult) | [ValidRelinquishOutputArgs](#interface-validrelinquishoutputargs) |
| [CreateActionOutput](#interface-createactionoutput) | [RelinquishOutputArgs](#interface-relinquishoutputargs) | [ValidSignActionArgs](#interface-validsignactionargs) |
| [CreateActionResult](#interface-createactionresult) | [RelinquishOutputResult](#interface-relinquishoutputresult) | [ValidSignActionOptions](#interface-validsignactionoptions) |
| [CreateHmacArgs](#interface-createhmacargs) | [RevealCounterpartyKeyLinkageArgs](#interface-revealcounterpartykeylinkageargs) | [ValidWalletPayment](#interface-validwalletpayment) |
| [CreateHmacResult](#interface-createhmacresult) | [RevealCounterpartyKeyLinkageResult](#interface-revealcounterpartykeylinkageresult) | [ValidWalletSignerArgs](#interface-validwalletsignerargs) |
| [CreateSignatureArgs](#interface-createsignatureargs) | [RevealSpecificKeyLinkageArgs](#interface-revealspecifickeylinkageargs) | [VerifyHmacArgs](#interface-verifyhmacargs) |
| [CreateSignatureResult](#interface-createsignatureresult) | [RevealSpecificKeyLinkageResult](#interface-revealspecifickeylinkageresult) | [VerifyHmacResult](#interface-verifyhmacresult) |
| [DiscoverByAttributesArgs](#interface-discoverbyattributesargs) | [ReviewActionResult](#interface-reviewactionresult) | [VerifySignatureArgs](#interface-verifysignatureargs) |
| [DiscoverByIdentityKeyArgs](#interface-discoverbyidentitykeyargs) | [SendWithResult](#interface-sendwithresult) | [VerifySignatureResult](#interface-verifysignatureresult) |
| [DiscoverCertificatesResult](#interface-discovercertificatesresult) | [SignActionArgs](#interface-signactionargs) | [WalletAction](#interface-walletaction) |
| [GetHeaderArgs](#interface-getheaderargs) | [SignActionOptions](#interface-signactionoptions) | [WalletActionInput](#interface-walletactioninput) |
| [GetHeaderResult](#interface-getheaderresult) | [SignActionResult](#interface-signactionresult) | [WalletActionOutput](#interface-walletactionoutput) |
| [GetHeightResult](#interface-getheightresult) | [SignActionSpend](#interface-signactionspend) | [WalletCertificate](#interface-walletcertificate) |
| [GetNetworkResult](#interface-getnetworkresult) | [SignableTransaction](#interface-signabletransaction) | [WalletDecryptArgs](#interface-walletdecryptargs) |
| [GetPublicKeyArgs](#interface-getpublickeyargs) | [ValidAbortActionArgs](#interface-validabortactionargs) | [WalletDecryptResult](#interface-walletdecryptresult) |
| [GetPublicKeyResult](#interface-getpublickeyresult) | [ValidAcquireCertificateArgs](#interface-validacquirecertificateargs) | [WalletEncryptArgs](#interface-walletencryptargs) |
| [GetVersionResult](#interface-getversionresult) | [ValidAcquireDirectCertificateArgs](#interface-validacquiredirectcertificateargs) | [WalletEncryptResult](#interface-walletencryptresult) |
| [IdentityCertificate](#interface-identitycertificate) | [ValidAcquireIssuanceCertificateArgs](#interface-validacquireissuancecertificateargs) | [WalletEncryptionArgs](#interface-walletencryptionargs) |
| [IdentityCertifier](#interface-identitycertifier) | [ValidBasketInsertion](#interface-validbasketinsertion) | [WalletErrorObject](#interface-walleterrorobject) |
| [InternalizeActionArgs](#interface-internalizeactionargs) | [ValidCreateActionArgs](#interface-validcreateactionargs) | [WalletInterface](#interface-walletinterface) |
| [InternalizeActionResult](#interface-internalizeactionresult) | [ValidCreateActionInput](#interface-validcreateactioninput) | [WalletLoggerInterface](#interface-walletloggerinterface) |
| [InternalizeOutput](#interface-internalizeoutput) | [ValidCreateActionOptions](#interface-validcreateactionoptions) | [WalletLoggerLog](#interface-walletloggerlog) |
| [KeyDeriverApi](#interface-keyderiverapi) | [ValidCreateActionOutput](#interface-validcreateactionoutput) | [WalletOutput](#interface-walletoutput) |
| [KeyLinkageResult](#interface-keylinkageresult) | [ValidDiscoverByAttributesArgs](#interface-validdiscoverbyattributesargs) | [WalletPayment](#interface-walletpayment) |
| [ListActionsArgs](#interface-listactionsargs) | [ValidDiscoverByIdentityKeyArgs](#interface-validdiscoverbyidentitykeyargs) | [WalletWire](#interface-walletwire) |
| [ListActionsResult](#interface-listactionsresult) | [ValidInternalizeActionArgs](#interface-validinternalizeactionargs) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: AbortActionArgs

```ts
export interface AbortActionArgs {
    reference: Base64String;
}
```

See also: [Base64String](./wallet.md#type-base64string)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: AbortActionResult

```ts
export interface AbortActionResult {
    aborted: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: AcquireCertificateArgs

```ts
export interface AcquireCertificateArgs {
    type: Base64String;
    certifier: PubKeyHex;
    acquisitionProtocol: AcquisitionProtocol;
    fields: Record<CertificateFieldNameUnder50Bytes, string>;
    serialNumber?: Base64String;
    revocationOutpoint?: OutpointString;
    signature?: HexString;
    certifierUrl?: string;
    keyringRevealer?: KeyringRevealer;
    keyringForSubject?: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    privileged?: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [AcquisitionProtocol](./wallet.md#type-acquisitionprotocol), [Base64String](./wallet.md#type-base64string), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [KeyringRevealer](./wallet.md#type-keyringrevealer), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: AuthenticatedResult

```ts
export interface AuthenticatedResult {
    authenticated: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: BasketInsertion

```ts
export interface BasketInsertion {
    basket: BasketStringUnder300Bytes;
    customInstructions?: string;
    tags?: OutputTagStringUnder300Bytes[];
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CertificateResult

```ts
export interface CertificateResult extends WalletCertificate {
    keyring?: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    verifier?: string;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [WalletCertificate](./wallet.md#interface-walletcertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateActionArgs

```ts
export interface CreateActionArgs {
    description: DescriptionString5to50Bytes;
    inputBEEF?: BEEF;
    inputs?: CreateActionInput[];
    outputs?: CreateActionOutput[];
    lockTime?: PositiveIntegerOrZero;
    version?: PositiveIntegerOrZero;
    labels?: LabelStringUnder300Bytes[];
    options?: CreateActionOptions;
}
```

See also: [BEEF](./wallet.md#type-beef), [CreateActionInput](./wallet.md#interface-createactioninput), [CreateActionOptions](./wallet.md#interface-createactionoptions), [CreateActionOutput](./wallet.md#interface-createactionoutput), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateActionInput

```ts
export interface CreateActionInput {
    outpoint: OutpointString;
    inputDescription: DescriptionString5to50Bytes;
    unlockingScript?: HexString;
    unlockingScriptLength?: PositiveInteger;
    sequenceNumber?: PositiveIntegerOrZero;
}
```

See also: [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateActionOptions

```ts
export interface CreateActionOptions {
    signAndProcess?: BooleanDefaultTrue;
    acceptDelayedBroadcast?: BooleanDefaultTrue;
    trustSelf?: TrustSelf;
    knownTxids?: TXIDHexString[];
    returnTXIDOnly?: BooleanDefaultFalse;
    noSend?: BooleanDefaultFalse;
    noSendChange?: OutpointString[];
    sendWith?: TXIDHexString[];
    randomizeOutputs?: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [OutpointString](./wallet.md#type-outpointstring), [TXIDHexString](./wallet.md#type-txidhexstring), [TrustSelf](./wallet.md#type-trustself)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateActionOutput

```ts
export interface CreateActionOutput {
    lockingScript: HexString;
    satoshis: SatoshiValue;
    outputDescription: DescriptionString5to50Bytes;
    basket?: BasketStringUnder300Bytes;
    customInstructions?: string;
    tags?: OutputTagStringUnder300Bytes[];
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [SatoshiValue](./wallet.md#type-satoshivalue)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateActionResult

```ts
export interface CreateActionResult {
    txid?: TXIDHexString;
    tx?: AtomicBEEF;
    noSendChange?: OutpointString[];
    sendWithResults?: SendWithResult[];
    signableTransaction?: SignableTransaction;
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [OutpointString](./wallet.md#type-outpointstring), [SendWithResult](./wallet.md#interface-sendwithresult), [SignableTransaction](./wallet.md#interface-signabletransaction), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateHmacArgs

```ts
export interface CreateHmacArgs extends WalletEncryptionArgs {
    data: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateHmacResult

```ts
export interface CreateHmacResult {
    hmac: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateSignatureArgs

```ts
export interface CreateSignatureArgs extends WalletEncryptionArgs {
    data?: Byte[];
    hashToDirectlySign?: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CreateSignatureResult

```ts
export interface CreateSignatureResult {
    signature: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: DiscoverByAttributesArgs

```ts
export interface DiscoverByAttributesArgs {
    attributes: Record<CertificateFieldNameUnder50Bytes, string>;
    limit?: PositiveIntegerDefault10Max10000;
    offset?: PositiveIntegerOrZero;
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: DiscoverByIdentityKeyArgs

```ts
export interface DiscoverByIdentityKeyArgs {
    identityKey: PubKeyHex;
    limit?: PositiveIntegerDefault10Max10000;
    offset?: PositiveIntegerOrZero;
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: DiscoverCertificatesResult

```ts
export interface DiscoverCertificatesResult {
    totalCertificates: PositiveIntegerOrZero;
    certificates: IdentityCertificate[];
}
```

See also: [IdentityCertificate](./wallet.md#interface-identitycertificate), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetHeaderArgs

```ts
export interface GetHeaderArgs {
    height: PositiveInteger;
}
```

See also: [PositiveInteger](./wallet.md#type-positiveinteger)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetHeaderResult

```ts
export interface GetHeaderResult {
    header: HexString;
}
```

See also: [HexString](./wallet.md#type-hexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetHeightResult

```ts
export interface GetHeightResult {
    height: PositiveInteger;
}
```

See also: [PositiveInteger](./wallet.md#type-positiveinteger)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetNetworkResult

```ts
export interface GetNetworkResult {
    network: WalletNetwork;
}
```

See also: [WalletNetwork](./wallet.md#type-walletnetwork)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetPublicKeyArgs

When `identityKey` is true, `WalletEncryptionArgs` are not used.

When `identityKey` is undefined, `WalletEncryptionArgs` are required.

```ts
export interface GetPublicKeyArgs extends Partial<WalletEncryptionArgs> {
    identityKey?: true;
    forSelf?: BooleanDefaultFalse;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetPublicKeyResult

```ts
export interface GetPublicKeyResult {
    publicKey: PubKeyHex;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: GetVersionResult

```ts
export interface GetVersionResult {
    version: VersionString7To30Bytes;
}
```

See also: [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityCertificate

```ts
export interface IdentityCertificate extends WalletCertificate {
    certifierInfo: IdentityCertifier;
    publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [IdentityCertifier](./wallet.md#interface-identitycertifier), [WalletCertificate](./wallet.md#interface-walletcertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityCertifier

```ts
export interface IdentityCertifier {
    name: EntityNameStringMax100Bytes;
    iconUrl: EntityIconURLStringMax500Bytes;
    description: DescriptionString5to50Bytes;
    trust: PositiveIntegerMax10;
}
```

See also: [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [EntityIconURLStringMax500Bytes](./wallet.md#type-entityiconurlstringmax500bytes), [EntityNameStringMax100Bytes](./wallet.md#type-entitynamestringmax100bytes), [PositiveIntegerMax10](./wallet.md#type-positiveintegermax10)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: InternalizeActionArgs

```ts
export interface InternalizeActionArgs {
    tx: AtomicBEEF;
    outputs: InternalizeOutput[];
    description: DescriptionString5to50Bytes;
    labels?: LabelStringUnder300Bytes[];
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [InternalizeOutput](./wallet.md#interface-internalizeoutput), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: InternalizeActionResult

```ts
export interface InternalizeActionResult {
    accepted: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: InternalizeOutput

```ts
export interface InternalizeOutput {
    outputIndex: PositiveIntegerOrZero;
    protocol: "wallet payment" | "basket insertion";
    paymentRemittance?: WalletPayment;
    insertionRemittance?: BasketInsertion;
}
```

See also: [BasketInsertion](./wallet.md#interface-basketinsertion), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [WalletPayment](./wallet.md#interface-walletpayment)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KeyDeriverApi

```ts
export interface KeyDeriverApi {
    rootKey: PrivateKey;
    identityKey: string;
    derivePublicKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf?: boolean) => PublicKey;
    derivePrivateKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty) => PrivateKey;
    deriveSymmetricKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty) => SymmetricKey;
    revealCounterpartySecret: (counterparty: Counterparty) => number[];
    revealSpecificSecret: (counterparty: Counterparty, protocolID: WalletProtocol, keyID: string) => number[];
}
```

See also: [Counterparty](./wallet.md#type-counterparty), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property derivePrivateKey

Derives a private key based on protocol ID, key ID, and counterparty.

```ts
derivePrivateKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty) => PrivateKey
```
See also: [Counterparty](./wallet.md#type-counterparty), [PrivateKey](./primitives.md#class-privatekey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property derivePublicKey

Derives a public key based on protocol ID, key ID, and counterparty.

```ts
derivePublicKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf?: boolean) => PublicKey
```
See also: [Counterparty](./wallet.md#type-counterparty), [PublicKey](./primitives.md#class-publickey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property deriveSymmetricKey

Derives a symmetric key based on protocol ID, key ID, and counterparty.
Note: Symmetric keys should not be derivable by everyone due to security risks.

```ts
deriveSymmetricKey: (protocolID: WalletProtocol, keyID: string, counterparty: Counterparty) => SymmetricKey
```
See also: [Counterparty](./wallet.md#type-counterparty), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property identityKey

The identity of this key deriver which is normally the public key associated with the `rootKey`

```ts
identityKey: string
```

#### Property revealCounterpartySecret

Reveals the shared secret between the root key and the counterparty.
Note: This should not be used for 'self'.

```ts
revealCounterpartySecret: (counterparty: Counterparty) => number[]
```
See also: [Counterparty](./wallet.md#type-counterparty)

#### Property revealSpecificSecret

Reveals the specific key association for a given protocol ID, key ID, and counterparty.

```ts
revealSpecificSecret: (counterparty: Counterparty, protocolID: WalletProtocol, keyID: string) => number[]
```
See also: [Counterparty](./wallet.md#type-counterparty), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Property rootKey

The root key from which all other keys are derived.

```ts
rootKey: PrivateKey
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: KeyLinkageResult

```ts
export interface KeyLinkageResult {
    encryptedLinkage: Byte[];
    encryptedLinkageProof: Byte[];
    prover: PubKeyHex;
    verifier: PubKeyHex;
    counterparty: PubKeyHex;
}
```

See also: [Byte](./wallet.md#type-byte), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListActionsArgs

```ts
export interface ListActionsArgs {
    labels: LabelStringUnder300Bytes[];
    labelQueryMode?: "any" | "all";
    includeLabels?: BooleanDefaultFalse;
    includeInputs?: BooleanDefaultFalse;
    includeInputSourceLockingScripts?: BooleanDefaultFalse;
    includeInputUnlockingScripts?: BooleanDefaultFalse;
    includeOutputs?: BooleanDefaultFalse;
    includeOutputLockingScripts?: BooleanDefaultFalse;
    limit?: PositiveIntegerDefault10Max10000;
    offset?: PositiveIntegerOrZero;
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListActionsResult

```ts
export interface ListActionsResult {
    totalActions: PositiveIntegerOrZero;
    actions: WalletAction[];
}
```

See also: [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [WalletAction](./wallet.md#interface-walletaction)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListCertificatesArgs

```ts
export interface ListCertificatesArgs {
    certifiers: PubKeyHex[];
    types: Base64String[];
    limit?: PositiveIntegerDefault10Max10000;
    offset?: PositiveIntegerOrZero;
    privileged?: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [Base64String](./wallet.md#type-base64string), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListCertificatesResult

```ts
export interface ListCertificatesResult {
    totalCertificates: PositiveIntegerOrZero;
    certificates: CertificateResult[];
}
```

See also: [CertificateResult](./wallet.md#interface-certificateresult), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListOutputsArgs

```ts
export interface ListOutputsArgs {
    basket: BasketStringUnder300Bytes;
    tags?: OutputTagStringUnder300Bytes[];
    tagQueryMode?: "all" | "any";
    include?: "locking scripts" | "entire transactions";
    includeCustomInstructions?: BooleanDefaultFalse;
    includeTags?: BooleanDefaultFalse;
    includeLabels?: BooleanDefaultFalse;
    limit?: PositiveIntegerDefault10Max10000;
    offset?: number;
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ListOutputsResult

```ts
export interface ListOutputsResult {
    totalOutputs: PositiveIntegerOrZero;
    BEEF?: BEEF;
    outputs: WalletOutput[];
}
```

See also: [BEEF](./wallet.md#type-beef), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [WalletOutput](./wallet.md#interface-walletoutput)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: OutPoint

Identifies a unique transaction output by its `txid` and index `vout`

```ts
export interface OutPoint {
    txid: string;
    vout: number;
}
```

#### Property txid

Transaction double sha256 hash as big endian hex string

```ts
txid: string
```

#### Property vout

zero based output index within the transaction

```ts
vout: number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ProveCertificateArgs

```ts
export interface ProveCertificateArgs {
    certificate: Partial<WalletCertificate>;
    fieldsToReveal: CertificateFieldNameUnder50Bytes[];
    verifier: PubKeyHex;
    privileged?: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletCertificate](./wallet.md#interface-walletcertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ProveCertificateResult

```ts
export interface ProveCertificateResult {
    keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    certificate?: WalletCertificate;
    verifier?: PubKeyHex;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletCertificate](./wallet.md#interface-walletcertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RelinquishCertificateArgs

```ts
export interface RelinquishCertificateArgs {
    type: Base64String;
    serialNumber: Base64String;
    certifier: PubKeyHex;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RelinquishCertificateResult

```ts
export interface RelinquishCertificateResult {
    relinquished: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RelinquishOutputArgs

```ts
export interface RelinquishOutputArgs {
    basket: BasketStringUnder300Bytes;
    output: OutpointString;
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [OutpointString](./wallet.md#type-outpointstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RelinquishOutputResult

```ts
export interface RelinquishOutputResult {
    relinquished: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RevealCounterpartyKeyLinkageArgs

```ts
export interface RevealCounterpartyKeyLinkageArgs {
    counterparty: PubKeyHex;
    verifier: PubKeyHex;
    privileged?: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RevealCounterpartyKeyLinkageResult

```ts
export interface RevealCounterpartyKeyLinkageResult extends KeyLinkageResult {
    revelationTime: ISOTimestampString;
}
```

See also: [ISOTimestampString](./wallet.md#type-isotimestampstring), [KeyLinkageResult](./wallet.md#interface-keylinkageresult)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RevealSpecificKeyLinkageArgs

```ts
export interface RevealSpecificKeyLinkageArgs {
    counterparty: WalletCounterparty;
    verifier: PubKeyHex;
    protocolID: WalletProtocol;
    keyID: KeyIDStringUnder800Bytes;
    privilegedReason?: DescriptionString5to50Bytes;
    privileged?: BooleanDefaultFalse;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletCounterparty](./wallet.md#type-walletcounterparty), [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RevealSpecificKeyLinkageResult

```ts
export interface RevealSpecificKeyLinkageResult extends KeyLinkageResult {
    protocolID: WalletProtocol;
    keyID: KeyIDStringUnder800Bytes;
    proofType: Byte;
}
```

See also: [Byte](./wallet.md#type-byte), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [KeyLinkageResult](./wallet.md#interface-keylinkageresult), [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ReviewActionResult

```ts
export interface ReviewActionResult {
    txid: TXIDHexString;
    status: ReviewActionResultStatus;
    competingTxs?: string[];
    competingBeef?: number[];
}
```

See also: [ReviewActionResultStatus](./wallet.md#type-reviewactionresultstatus), [TXIDHexString](./wallet.md#type-txidhexstring)

#### Property competingBeef

Merged beef of competingTxs, valid when status is 'doubleSpend'.

```ts
competingBeef?: number[]
```

#### Property competingTxs

Any competing txids reported for this txid, valid when status is 'doubleSpend'.

```ts
competingTxs?: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SendWithResult

```ts
export interface SendWithResult {
    txid: TXIDHexString;
    status: SendWithResultStatus;
}
```

See also: [SendWithResultStatus](./wallet.md#type-sendwithresultstatus), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SignActionArgs

```ts
export interface SignActionArgs {
    spends: Record<PositiveIntegerOrZero, SignActionSpend>;
    reference: Base64String;
    options?: SignActionOptions;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [SignActionOptions](./wallet.md#interface-signactionoptions), [SignActionSpend](./wallet.md#interface-signactionspend)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SignActionOptions

```ts
export interface SignActionOptions {
    acceptDelayedBroadcast?: BooleanDefaultTrue;
    returnTXIDOnly?: BooleanDefaultFalse;
    noSend?: BooleanDefaultFalse;
    sendWith?: TXIDHexString[];
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SignActionResult

```ts
export interface SignActionResult {
    txid?: TXIDHexString;
    tx?: AtomicBEEF;
    sendWithResults?: SendWithResult[];
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [SendWithResult](./wallet.md#interface-sendwithresult), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SignActionSpend

```ts
export interface SignActionSpend {
    unlockingScript: HexString;
    sequenceNumber?: PositiveIntegerOrZero;
}
```

See also: [HexString](./wallet.md#type-hexstring), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SignableTransaction

```ts
export interface SignableTransaction {
    tx: AtomicBEEF;
    reference: Base64String;
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [Base64String](./wallet.md#type-base64string)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidAbortActionArgs

```ts
export interface ValidAbortActionArgs extends ValidWalletSignerArgs {
    reference: Base64String;
}
```

See also: [Base64String](./wallet.md#type-base64string), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidAcquireCertificateArgs

```ts
export interface ValidAcquireCertificateArgs extends ValidWalletSignerArgs {
    acquisitionProtocol: AcquisitionProtocol;
    type: Base64String;
    serialNumber?: Base64String;
    certifier: PubKeyHex;
    revocationOutpoint?: OutpointString;
    fields: Record<CertificateFieldNameUnder50Bytes, string>;
    signature?: HexString;
    certifierUrl?: string;
    keyringRevealer?: KeyringRevealer;
    keyringForSubject?: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    privileged: boolean;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [AcquisitionProtocol](./wallet.md#type-acquisitionprotocol), [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [KeyringRevealer](./wallet.md#type-keyringrevealer), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidAcquireDirectCertificateArgs

```ts
export interface ValidAcquireDirectCertificateArgs extends ValidWalletSignerArgs {
    type: Base64String;
    serialNumber: Base64String;
    certifier: PubKeyHex;
    revocationOutpoint: OutpointString;
    fields: Record<CertificateFieldNameUnder50Bytes, string>;
    signature: HexString;
    subject: PubKeyHex;
    keyringRevealer: KeyringRevealer;
    keyringForSubject: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    privileged: boolean;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [KeyringRevealer](./wallet.md#type-keyringrevealer), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

#### Property subject

validated to an empty string, must be provided by wallet and must
match expectations of keyringForSubject

```ts
subject: PubKeyHex
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidAcquireIssuanceCertificateArgs

```ts
export interface ValidAcquireIssuanceCertificateArgs extends ValidWalletSignerArgs {
    type: Base64String;
    certifier: PubKeyHex;
    certifierUrl: string;
    fields: Record<CertificateFieldNameUnder50Bytes, string>;
    subject: PubKeyHex;
    privileged: boolean;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

#### Property subject

validated to an empty string, must be provided by wallet and must
match expectations of keyringForSubject

```ts
subject: PubKeyHex
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidBasketInsertion

```ts
export interface ValidBasketInsertion {
    basket: BasketStringUnder300Bytes;
    customInstructions?: string;
    tags: BasketStringUnder300Bytes[];
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidCreateActionArgs

```ts
export interface ValidCreateActionArgs extends ValidProcessActionArgs {
    description: DescriptionString5to2000Bytes;
    inputBEEF?: BEEF;
    inputs: ValidCreateActionInput[];
    outputs: ValidCreateActionOutput[];
    lockTime: number;
    version: number;
    labels: string[];
    options: ValidCreateActionOptions;
    isSignAction: boolean;
    randomVals?: number[];
    includeAllSourceTransactions: boolean;
}
```

See also: [BEEF](./wallet.md#type-beef), [DescriptionString5to2000Bytes](./wallet.md#type-descriptionstring5to2000bytes), [ValidCreateActionInput](./wallet.md#interface-validcreateactioninput), [ValidCreateActionOptions](./wallet.md#interface-validcreateactionoptions), [ValidCreateActionOutput](./wallet.md#interface-validcreateactionoutput), [ValidProcessActionArgs](./wallet.md#interface-validprocessactionargs)

#### Property includeAllSourceTransactions

If true, signableTransactions will include sourceTransaction for each input,
including those that do not require signature and those that were also contained
in the inputBEEF.

```ts
includeAllSourceTransactions: boolean
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidCreateActionInput

```ts
export interface ValidCreateActionInput {
    outpoint: OutPoint;
    inputDescription: DescriptionString5to2000Bytes;
    sequenceNumber: PositiveIntegerOrZero;
    unlockingScript?: HexString;
    unlockingScriptLength: PositiveInteger;
}
```

See also: [DescriptionString5to2000Bytes](./wallet.md#type-descriptionstring5to2000bytes), [HexString](./wallet.md#type-hexstring), [OutPoint](./wallet.md#interface-outpoint), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidCreateActionOptions

```ts
export interface ValidCreateActionOptions extends ValidProcessActionOptions {
    signAndProcess: boolean;
    trustSelf?: TrustSelf;
    knownTxids: TXIDHexString[];
    noSendChange: OutPoint[];
    randomizeOutputs: boolean;
}
```

See also: [OutPoint](./wallet.md#interface-outpoint), [TXIDHexString](./wallet.md#type-txidhexstring), [TrustSelf](./wallet.md#type-trustself), [ValidProcessActionOptions](./wallet.md#interface-validprocessactionoptions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidCreateActionOutput

```ts
export interface ValidCreateActionOutput {
    lockingScript: HexString;
    satoshis: SatoshiValue;
    outputDescription: DescriptionString5to2000Bytes;
    basket?: BasketStringUnder300Bytes;
    customInstructions?: string;
    tags: BasketStringUnder300Bytes[];
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [DescriptionString5to2000Bytes](./wallet.md#type-descriptionstring5to2000bytes), [HexString](./wallet.md#type-hexstring), [SatoshiValue](./wallet.md#type-satoshivalue)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidDiscoverByAttributesArgs

```ts
export interface ValidDiscoverByAttributesArgs extends ValidWalletSignerArgs {
    attributes: Record<CertificateFieldNameUnder50Bytes, string>;
    limit: PositiveIntegerDefault10Max10000;
    offset: PositiveIntegerOrZero;
    seekPermission: boolean;
}
```

See also: [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidDiscoverByIdentityKeyArgs

```ts
export interface ValidDiscoverByIdentityKeyArgs extends ValidWalletSignerArgs {
    identityKey: PubKeyHex;
    limit: PositiveIntegerDefault10Max10000;
    offset: PositiveIntegerOrZero;
    seekPermission: boolean;
}
```

See also: [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidInternalizeActionArgs

```ts
export interface ValidInternalizeActionArgs extends ValidWalletSignerArgs {
    tx: AtomicBEEF;
    outputs: InternalizeOutput[];
    description: DescriptionString5to2000Bytes;
    labels: LabelStringUnder300Bytes[];
    seekPermission: BooleanDefaultTrue;
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [DescriptionString5to2000Bytes](./wallet.md#type-descriptionstring5to2000bytes), [InternalizeOutput](./wallet.md#interface-internalizeoutput), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidInternalizeOutput

```ts
export interface ValidInternalizeOutput {
    outputIndex: PositiveIntegerOrZero;
    protocol: "wallet payment" | "basket insertion";
    paymentRemittance?: ValidWalletPayment;
    insertionRemittance?: ValidBasketInsertion;
}
```

See also: [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ValidBasketInsertion](./wallet.md#interface-validbasketinsertion), [ValidWalletPayment](./wallet.md#interface-validwalletpayment)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidListActionsArgs

```ts
export interface ValidListActionsArgs extends ValidWalletSignerArgs {
    labels: LabelStringUnder300Bytes[];
    labelQueryMode: "any" | "all";
    includeLabels: BooleanDefaultFalse;
    includeInputs: BooleanDefaultFalse;
    includeInputSourceLockingScripts: BooleanDefaultFalse;
    includeInputUnlockingScripts: BooleanDefaultFalse;
    includeOutputs: BooleanDefaultFalse;
    includeOutputLockingScripts: BooleanDefaultFalse;
    limit: PositiveIntegerDefault10Max10000;
    offset: PositiveIntegerOrZero;
    seekPermission: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidListCertificatesArgs

```ts
export interface ValidListCertificatesArgs extends ValidWalletSignerArgs {
    partial?: {
        type?: Base64String;
        serialNumber?: Base64String;
        certifier?: PubKeyHex;
        subject?: PubKeyHex;
        revocationOutpoint?: OutpointString;
        signature?: HexString;
    };
    certifiers: PubKeyHex[];
    types: Base64String[];
    limit: PositiveIntegerDefault10Max10000;
    offset: PositiveIntegerOrZero;
    privileged: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [Base64String](./wallet.md#type-base64string), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidListOutputsArgs

```ts
export interface ValidListOutputsArgs extends ValidWalletSignerArgs {
    basket: BasketStringUnder300Bytes;
    tags: OutputTagStringUnder300Bytes[];
    tagQueryMode: "all" | "any";
    includeLockingScripts: boolean;
    includeTransactions: boolean;
    includeCustomInstructions: BooleanDefaultFalse;
    includeTags: BooleanDefaultFalse;
    includeLabels: BooleanDefaultFalse;
    limit: PositiveIntegerDefault10Max10000;
    offset: number;
    seekPermission: BooleanDefaultTrue;
    knownTxids: string[];
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidProcessActionArgs

```ts
export interface ValidProcessActionArgs extends ValidWalletSignerArgs {
    options: ValidProcessActionOptions;
    isSendWith: boolean;
    isNewTx: boolean;
    isRemixChange: boolean;
    isNoSend: boolean;
    isDelayed: boolean;
    isTestWerrReviewActions: boolean;
}
```

See also: [ValidProcessActionOptions](./wallet.md#interface-validprocessactionoptions), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidProcessActionOptions

```ts
export interface ValidProcessActionOptions {
    acceptDelayedBroadcast: BooleanDefaultTrue;
    returnTXIDOnly: BooleanDefaultFalse;
    noSend: BooleanDefaultFalse;
    sendWith: TXIDHexString[];
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidProveCertificateArgs

```ts
export interface ValidProveCertificateArgs extends ValidWalletSignerArgs {
    type?: Base64String;
    serialNumber?: Base64String;
    certifier?: PubKeyHex;
    subject?: PubKeyHex;
    revocationOutpoint?: OutpointString;
    signature?: HexString;
    fieldsToReveal: CertificateFieldNameUnder50Bytes[];
    verifier: PubKeyHex;
    privileged: boolean;
    privilegedReason?: DescriptionString5to50Bytes;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidRelinquishCertificateArgs

```ts
export interface ValidRelinquishCertificateArgs extends ValidWalletSignerArgs {
    type: Base64String;
    serialNumber: Base64String;
    certifier: PubKeyHex;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PubKeyHex](./wallet.md#type-pubkeyhex), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidRelinquishOutputArgs

```ts
export interface ValidRelinquishOutputArgs extends ValidWalletSignerArgs {
    basket: BasketStringUnder300Bytes;
    output: OutpointString;
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [OutpointString](./wallet.md#type-outpointstring), [ValidWalletSignerArgs](./wallet.md#interface-validwalletsignerargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidSignActionArgs

```ts
export interface ValidSignActionArgs extends ValidProcessActionArgs {
    spends: Record<PositiveIntegerOrZero, SignActionSpend>;
    reference: Base64String;
    options: ValidSignActionOptions;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [SignActionSpend](./wallet.md#interface-signactionspend), [ValidProcessActionArgs](./wallet.md#interface-validprocessactionargs), [ValidSignActionOptions](./wallet.md#interface-validsignactionoptions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidSignActionOptions

```ts
export interface ValidSignActionOptions extends ValidProcessActionOptions {
    acceptDelayedBroadcast: boolean;
    returnTXIDOnly: boolean;
    noSend: boolean;
    sendWith: TXIDHexString[];
}
```

See also: [TXIDHexString](./wallet.md#type-txidhexstring), [ValidProcessActionOptions](./wallet.md#interface-validprocessactionoptions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidWalletPayment

```ts
export interface ValidWalletPayment {
    derivationPrefix: Base64String;
    derivationSuffix: Base64String;
    senderIdentityKey: PubKeyHex;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ValidWalletSignerArgs

```ts
export interface ValidWalletSignerArgs {
    logger?: WalletLoggerInterface;
}
```

See also: [WalletLoggerInterface](./wallet.md#interface-walletloggerinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: VerifyHmacArgs

```ts
export interface VerifyHmacArgs extends WalletEncryptionArgs {
    data: Byte[];
    hmac: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: VerifyHmacResult

```ts
export interface VerifyHmacResult {
    valid: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: VerifySignatureArgs

```ts
export interface VerifySignatureArgs extends WalletEncryptionArgs {
    data?: Byte[];
    hashToDirectlyVerify?: Byte[];
    signature: Byte[];
    forSelf?: BooleanDefaultFalse;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: VerifySignatureResult

```ts
export interface VerifySignatureResult {
    valid: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletAction

```ts
export interface WalletAction {
    txid: TXIDHexString;
    satoshis: SatoshiValue;
    status: ActionStatus;
    isOutgoing: boolean;
    description: DescriptionString5to50Bytes;
    labels?: LabelStringUnder300Bytes[];
    version: PositiveIntegerOrZero;
    lockTime: PositiveIntegerOrZero;
    inputs?: WalletActionInput[];
    outputs?: WalletActionOutput[];
}
```

See also: [ActionStatus](./wallet.md#type-actionstatus), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [SatoshiValue](./wallet.md#type-satoshivalue), [TXIDHexString](./wallet.md#type-txidhexstring), [WalletActionInput](./wallet.md#interface-walletactioninput), [WalletActionOutput](./wallet.md#interface-walletactionoutput)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletActionInput

```ts
export interface WalletActionInput {
    sourceOutpoint: OutpointString;
    sourceSatoshis: SatoshiValue;
    sourceLockingScript?: HexString;
    unlockingScript?: HexString;
    inputDescription: DescriptionString5to50Bytes;
    sequenceNumber: PositiveIntegerOrZero;
}
```

See also: [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [SatoshiValue](./wallet.md#type-satoshivalue)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletActionOutput

```ts
export interface WalletActionOutput {
    satoshis: SatoshiValue;
    lockingScript?: HexString;
    spendable: boolean;
    customInstructions?: string;
    tags: OutputTagStringUnder300Bytes[];
    outputIndex: PositiveIntegerOrZero;
    outputDescription: DescriptionString5to50Bytes;
    basket: BasketStringUnder300Bytes;
}
```

See also: [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [HexString](./wallet.md#type-hexstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [SatoshiValue](./wallet.md#type-satoshivalue)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletCertificate

```ts
export interface WalletCertificate {
    type: Base64String;
    subject: PubKeyHex;
    serialNumber: Base64String;
    certifier: PubKeyHex;
    revocationOutpoint: OutpointString;
    signature: HexString;
    fields: Record<CertificateFieldNameUnder50Bytes, string>;
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletDecryptArgs

```ts
export interface WalletDecryptArgs extends WalletEncryptionArgs {
    ciphertext: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletDecryptResult

```ts
export interface WalletDecryptResult {
    plaintext: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletEncryptArgs

```ts
export interface WalletEncryptArgs extends WalletEncryptionArgs {
    plaintext: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte), [WalletEncryptionArgs](./wallet.md#interface-walletencryptionargs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletEncryptResult

```ts
export interface WalletEncryptResult {
    ciphertext: Byte[];
}
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletEncryptionArgs

```ts
export interface WalletEncryptionArgs {
    protocolID: WalletProtocol;
    keyID: KeyIDStringUnder800Bytes;
    counterparty?: WalletCounterparty;
    privileged?: BooleanDefaultFalse;
    privilegedReason?: DescriptionString5to50Bytes;
    seekPermission?: BooleanDefaultTrue;
}
```

See also: [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [WalletCounterparty](./wallet.md#type-walletcounterparty), [WalletProtocol](./wallet.md#type-walletprotocol)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletErrorObject

Every method of the `Wallet` interface has a return value of the form `Promise<object>`.
When errors occur, an exception object may be thrown which must conform to the `WalletErrorObject` interface.
Serialization layers can rely on the `isError` property being unique to error objects.
Deserialization should rethrow `WalletErrorObject` conforming objects.

```ts
export interface WalletErrorObject extends Error {
    isError: true;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletInterface

The Wallet interface defines a wallet capable of various tasks including transaction creation and signing,
encryption, decryption, identity certificate management, identity verification, and communication
with applications as per the BRC standards. This interface allows applications to interact with
the wallet for a range of functionalities aligned with the Babbage architectural principles.

Error Handling

Every method of the `Wallet` interface has a return value of the form `Promise<object>`.
When an error occurs, an exception object may be thrown which must conform to the `WalletErrorObject` interface.
Serialization layers can rely on the `isError` property being unique to error objects to
deserialize and rethrow `WalletErrorObject` conforming objects.

```ts
export interface WalletInterface {
    getPublicKey: (args: GetPublicKeyArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetPublicKeyResult>;
    revealCounterpartyKeyLinkage: (args: RevealCounterpartyKeyLinkageArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RevealCounterpartyKeyLinkageResult>;
    revealSpecificKeyLinkage: (args: RevealSpecificKeyLinkageArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RevealSpecificKeyLinkageResult>;
    encrypt: (args: WalletEncryptArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletEncryptResult>;
    decrypt: (args: WalletDecryptArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletDecryptResult>;
    createHmac: (args: CreateHmacArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateHmacResult>;
    verifyHmac: (args: VerifyHmacArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<VerifyHmacResult>;
    createSignature: (args: CreateSignatureArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateSignatureResult>;
    verifySignature: (args: VerifySignatureArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<VerifySignatureResult>;
    createAction: (args: CreateActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateActionResult>;
    signAction: (args: SignActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<SignActionResult>;
    abortAction: (args: AbortActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AbortActionResult>;
    listActions: (args: ListActionsArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListActionsResult>;
    internalizeAction: (args: InternalizeActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<InternalizeActionResult>;
    listOutputs: (args: ListOutputsArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListOutputsResult>;
    relinquishOutput: (args: RelinquishOutputArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RelinquishOutputResult>;
    acquireCertificate: (args: AcquireCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletCertificate>;
    listCertificates: (args: ListCertificatesArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListCertificatesResult>;
    proveCertificate: (args: ProveCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ProveCertificateResult>;
    relinquishCertificate: (args: RelinquishCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RelinquishCertificateResult>;
    discoverByIdentityKey: (args: DiscoverByIdentityKeyArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<DiscoverCertificatesResult>;
    discoverByAttributes: (args: DiscoverByAttributesArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<DiscoverCertificatesResult>;
    isAuthenticated: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AuthenticatedResult>;
    waitForAuthentication: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AuthenticatedResult>;
    getHeight: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetHeightResult>;
    getHeaderForHeight: (args: GetHeaderArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetHeaderResult>;
    getNetwork: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetNetworkResult>;
    getVersion: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetVersionResult>;
}
```

See also: [AbortActionArgs](./wallet.md#interface-abortactionargs), [AbortActionResult](./wallet.md#interface-abortactionresult), [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [AuthenticatedResult](./wallet.md#interface-authenticatedresult), [CreateActionArgs](./wallet.md#interface-createactionargs), [CreateActionResult](./wallet.md#interface-createactionresult), [CreateHmacArgs](./wallet.md#interface-createhmacargs), [CreateHmacResult](./wallet.md#interface-createhmacresult), [CreateSignatureArgs](./wallet.md#interface-createsignatureargs), [CreateSignatureResult](./wallet.md#interface-createsignatureresult), [DiscoverByAttributesArgs](./wallet.md#interface-discoverbyattributesargs), [DiscoverByIdentityKeyArgs](./wallet.md#interface-discoverbyidentitykeyargs), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [GetHeaderArgs](./wallet.md#interface-getheaderargs), [GetHeaderResult](./wallet.md#interface-getheaderresult), [GetHeightResult](./wallet.md#interface-getheightresult), [GetNetworkResult](./wallet.md#interface-getnetworkresult), [GetPublicKeyArgs](./wallet.md#interface-getpublickeyargs), [GetPublicKeyResult](./wallet.md#interface-getpublickeyresult), [GetVersionResult](./wallet.md#interface-getversionresult), [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [InternalizeActionResult](./wallet.md#interface-internalizeactionresult), [ListActionsArgs](./wallet.md#interface-listactionsargs), [ListActionsResult](./wallet.md#interface-listactionsresult), [ListCertificatesArgs](./wallet.md#interface-listcertificatesargs), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ProveCertificateResult](./wallet.md#interface-provecertificateresult), [RelinquishCertificateArgs](./wallet.md#interface-relinquishcertificateargs), [RelinquishCertificateResult](./wallet.md#interface-relinquishcertificateresult), [RelinquishOutputArgs](./wallet.md#interface-relinquishoutputargs), [RelinquishOutputResult](./wallet.md#interface-relinquishoutputresult), [RevealCounterpartyKeyLinkageArgs](./wallet.md#interface-revealcounterpartykeylinkageargs), [RevealCounterpartyKeyLinkageResult](./wallet.md#interface-revealcounterpartykeylinkageresult), [RevealSpecificKeyLinkageArgs](./wallet.md#interface-revealspecifickeylinkageargs), [RevealSpecificKeyLinkageResult](./wallet.md#interface-revealspecifickeylinkageresult), [SignActionArgs](./wallet.md#interface-signactionargs), [SignActionResult](./wallet.md#interface-signactionresult), [VerifyHmacArgs](./wallet.md#interface-verifyhmacargs), [VerifyHmacResult](./wallet.md#interface-verifyhmacresult), [VerifySignatureArgs](./wallet.md#interface-verifysignatureargs), [VerifySignatureResult](./wallet.md#interface-verifysignatureresult), [WalletCertificate](./wallet.md#interface-walletcertificate), [WalletDecryptArgs](./wallet.md#interface-walletdecryptargs), [WalletDecryptResult](./wallet.md#interface-walletdecryptresult), [WalletEncryptArgs](./wallet.md#interface-walletencryptargs), [WalletEncryptResult](./wallet.md#interface-walletencryptresult), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

#### Property abortAction

Aborts a transaction that is in progress and has not yet been finalized or sent to the network.

```ts
abortAction: (args: AbortActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AbortActionResult>
```
See also: [AbortActionArgs](./wallet.md#interface-abortactionargs), [AbortActionResult](./wallet.md#interface-abortactionresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property acquireCertificate

Acquires an identity certificate, whether by acquiring one from the certifier or by directly receiving it.

```ts
acquireCertificate: (args: AcquireCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletCertificate>
```
See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [WalletCertificate](./wallet.md#interface-walletcertificate)

#### Property createAction

Creates a new Bitcoin transaction based on the provided inputs, outputs, labels, locks, and other options.

```ts
createAction: (args: CreateActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateActionResult>
```
See also: [CreateActionArgs](./wallet.md#interface-createactionargs), [CreateActionResult](./wallet.md#interface-createactionresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property createHmac

Creates an HMAC (Hash-based Message Authentication Code) based on the provided data, protocol, key ID, counterparty, and other factors.

```ts
createHmac: (args: CreateHmacArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateHmacResult>
```
See also: [CreateHmacArgs](./wallet.md#interface-createhmacargs), [CreateHmacResult](./wallet.md#interface-createhmacresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property createSignature

Creates a digital signature for the provided data or hash using a specific protocol, key, and optionally considering privilege and counterparty.

```ts
createSignature: (args: CreateSignatureArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<CreateSignatureResult>
```
See also: [CreateSignatureArgs](./wallet.md#interface-createsignatureargs), [CreateSignatureResult](./wallet.md#interface-createsignatureresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property decrypt

Decrypts the provided ciphertext using derived keys, based on the protocol ID, key ID, counterparty, and other factors.

```ts
decrypt: (args: WalletDecryptArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletDecryptResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [WalletDecryptArgs](./wallet.md#interface-walletdecryptargs), [WalletDecryptResult](./wallet.md#interface-walletdecryptresult)

#### Property discoverByAttributes

Discovers identity certificates belonging to other users, where the documents contain specific attributes, issued by a trusted entity.

```ts
discoverByAttributes: (args: DiscoverByAttributesArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<DiscoverCertificatesResult>
```
See also: [DiscoverByAttributesArgs](./wallet.md#interface-discoverbyattributesargs), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property discoverByIdentityKey

Discovers identity certificates, issued to a given identity key by a trusted entity.

```ts
discoverByIdentityKey: (args: DiscoverByIdentityKeyArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<DiscoverCertificatesResult>
```
See also: [DiscoverByIdentityKeyArgs](./wallet.md#interface-discoverbyidentitykeyargs), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property encrypt

Encrypts the provided plaintext data using derived keys, based on the protocol ID, key ID, counterparty, and other factors.

```ts
encrypt: (args: WalletEncryptArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<WalletEncryptResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [WalletEncryptArgs](./wallet.md#interface-walletencryptargs), [WalletEncryptResult](./wallet.md#interface-walletencryptresult)

#### Property getHeaderForHeight

Retrieves the block header of a block at a specified height.

```ts
getHeaderForHeight: (args: GetHeaderArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetHeaderResult>
```
See also: [GetHeaderArgs](./wallet.md#interface-getheaderargs), [GetHeaderResult](./wallet.md#interface-getheaderresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property getHeight

Retrieves the current height of the blockchain.

```ts
getHeight: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetHeightResult>
```
See also: [GetHeightResult](./wallet.md#interface-getheightresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property getNetwork

Retrieves the Bitcoin network the client is using (mainnet or testnet).

```ts
getNetwork: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetNetworkResult>
```
See also: [GetNetworkResult](./wallet.md#interface-getnetworkresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property getPublicKey

Retrieves a derived or identity public key based on the requested protocol, key ID, counterparty, and other factors.

```ts
getPublicKey: (args: GetPublicKeyArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetPublicKeyResult>
```
See also: [GetPublicKeyArgs](./wallet.md#interface-getpublickeyargs), [GetPublicKeyResult](./wallet.md#interface-getpublickeyresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property getVersion

Retrieves the current version string of the wallet.

```ts
getVersion: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<GetVersionResult>
```
See also: [GetVersionResult](./wallet.md#interface-getversionresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property internalizeAction

Submits a transaction to be internalized and optionally labeled, outputs paid to the wallet balance, inserted into baskets, and/or tagged.

```ts
internalizeAction: (args: InternalizeActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<InternalizeActionResult>
```
See also: [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [InternalizeActionResult](./wallet.md#interface-internalizeactionresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property isAuthenticated

Checks the authentication status of the user.

```ts
isAuthenticated: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AuthenticatedResult>
```
See also: [AuthenticatedResult](./wallet.md#interface-authenticatedresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property listActions

Lists all transactions matching the specified labels.

```ts
listActions: (args: ListActionsArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListActionsResult>
```
See also: [ListActionsArgs](./wallet.md#interface-listactionsargs), [ListActionsResult](./wallet.md#interface-listactionsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property listCertificates

Lists identity certificates belonging to the user, filtered by certifier(s) and type(s).

```ts
listCertificates: (args: ListCertificatesArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListCertificatesResult>
```
See also: [ListCertificatesArgs](./wallet.md#interface-listcertificatesargs), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property listOutputs

Lists the spendable outputs kept within a specific basket, optionally tagged with specific labels.

```ts
listOutputs: (args: ListOutputsArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ListOutputsResult>
```
See also: [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property proveCertificate

Proves select fields of an identity certificate, as specified, when requested by a verifier.

```ts
proveCertificate: (args: ProveCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<ProveCertificateResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ProveCertificateResult](./wallet.md#interface-provecertificateresult)

#### Property relinquishCertificate

Relinquishes an identity certificate, removing it from the wallet regardless of whether the revocation outpoint has become spent.

```ts
relinquishCertificate: (args: RelinquishCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RelinquishCertificateResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RelinquishCertificateArgs](./wallet.md#interface-relinquishcertificateargs), [RelinquishCertificateResult](./wallet.md#interface-relinquishcertificateresult)

#### Property relinquishOutput

Relinquish an output out of a basket, removing it from tracking without spending it.

```ts
relinquishOutput: (args: RelinquishOutputArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RelinquishOutputResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RelinquishOutputArgs](./wallet.md#interface-relinquishoutputargs), [RelinquishOutputResult](./wallet.md#interface-relinquishoutputresult)

#### Property revealCounterpartyKeyLinkage

Reveals the key linkage between ourselves and a counterparty, to a particular verifier, across all interactions with the counterparty.

```ts
revealCounterpartyKeyLinkage: (args: RevealCounterpartyKeyLinkageArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RevealCounterpartyKeyLinkageResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RevealCounterpartyKeyLinkageArgs](./wallet.md#interface-revealcounterpartykeylinkageargs), [RevealCounterpartyKeyLinkageResult](./wallet.md#interface-revealcounterpartykeylinkageresult)

#### Property revealSpecificKeyLinkage

Reveals the key linkage between ourselves and a counterparty, to a particular verifier, with respect to a specific interaction.

```ts
revealSpecificKeyLinkage: (args: RevealSpecificKeyLinkageArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<RevealSpecificKeyLinkageResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RevealSpecificKeyLinkageArgs](./wallet.md#interface-revealspecifickeylinkageargs), [RevealSpecificKeyLinkageResult](./wallet.md#interface-revealspecifickeylinkageresult)

#### Property signAction

Signs a transaction previously created using `createAction`.

```ts
signAction: (args: SignActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<SignActionResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [SignActionArgs](./wallet.md#interface-signactionargs), [SignActionResult](./wallet.md#interface-signactionresult)

#### Property verifyHmac

Verifies an HMAC (Hash-based Message Authentication Code) based on the provided data, protocol, key ID, counterparty, and other factors.

```ts
verifyHmac: (args: VerifyHmacArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<VerifyHmacResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [VerifyHmacArgs](./wallet.md#interface-verifyhmacargs), [VerifyHmacResult](./wallet.md#interface-verifyhmacresult)

#### Property verifySignature

Verifies a digital signature for the provided data or hash using a specific protocol, key, and optionally considering privilege and counterparty.

```ts
verifySignature: (args: VerifySignatureArgs, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<VerifySignatureResult>
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [VerifySignatureArgs](./wallet.md#interface-verifysignatureargs), [VerifySignatureResult](./wallet.md#interface-verifysignatureresult)

#### Property waitForAuthentication

Continuously waits until the user is authenticated, returning the result once confirmed.

```ts
waitForAuthentication: (args: object, originator?: OriginatorDomainNameStringUnder250Bytes) => Promise<AuthenticatedResult>
```
See also: [AuthenticatedResult](./wallet.md#interface-authenticatedresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletLoggerInterface

A console-like interface for logging within wallet operations.

Intended to reflect a subset of standard `Console` interface methods used by `Wallet`

```ts
export interface WalletLoggerInterface {
    group: (...label: any[]) => void;
    groupEnd: () => void;
    log: (message?: any, ...optionalParams: any[]) => void;
    error: (message?: any, ...optionalParams: any[]) => void;
    flush?: () => object | undefined;
    merge?: (log: WalletLoggerInterface) => void;
    level?: "error" | "warn" | "info" | "debug" | "trace";
    indent?: number;
    isOrigin?: boolean;
    isError?: boolean;
    logs?: WalletLoggerLog[];
}
```

See also: [WalletLoggerLog](./wallet.md#interface-walletloggerlog)

#### Property error

Log an error message.

```ts
error: (message?: any, ...optionalParams: any[]) => void
```

#### Property flush

Loggers may accumulate data instead of immediately handling it.

Loggers that do not accumulate should not implement this method.

```ts
flush?: () => object | undefined
```

#### Property group

Increases indentation of subsequent lines.

If one or more `label`s are provided, those are printed first without the
additional indentation.

```ts
group: (...label: any[]) => void
```

#### Property groupEnd

Decreases indentation of subsequent lines.

```ts
groupEnd: () => void
```

#### Property indent

Valid if an accumulating logger. Count of `group` calls without matching `groupEnd`.

```ts
indent?: number
```

#### Property isError

True if this is an accumulating logger and an error was logged.

```ts
isError?: boolean
```

#### Property isOrigin

True if this is an accumulating logger and the logger belongs to the object servicing the initial request.

```ts
isOrigin?: boolean
```

#### Property level

Optional. Logging levels that may influence what is logged.

'error' Only requests resulting in an exception should be logged.
'warn' Also log requests that succeed but with an abnormal condition.
'info' Also log normal successful requests.
'debug' Add input parm and result details where possible.
'trace' Instead of adding debug details, focus on execution path and timing.

```ts
level?: "error" | "warn" | "info" | "debug" | "trace"
```

#### Property log

Log a message.

```ts
log: (message?: any, ...optionalParams: any[]) => void
```

#### Property logs

Optional array of accumulated logged data and errors.

```ts
logs?: WalletLoggerLog[]
```
See also: [WalletLoggerLog](./wallet.md#interface-walletloggerlog)

#### Property merge

Merge log data from another logger.

Typically used to merge log data from network request.

```ts
merge?: (log: WalletLoggerInterface) => void
```
See also: [WalletLoggerInterface](./wallet.md#interface-walletloggerinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletLoggerLog

```ts
export interface WalletLoggerLog {
    when: number;
    indent: number;
    log: string;
    isError?: boolean;
    isBegin?: boolean;
    isEnd?: boolean;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletOutput

```ts
export interface WalletOutput {
    satoshis: SatoshiValue;
    lockingScript?: HexString;
    spendable: boolean;
    customInstructions?: string;
    tags?: OutputTagStringUnder300Bytes[];
    outpoint: OutpointString;
    labels?: LabelStringUnder300Bytes[];
}
```

See also: [HexString](./wallet.md#type-hexstring), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [OutpointString](./wallet.md#type-outpointstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [SatoshiValue](./wallet.md#type-satoshivalue)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletPayment

```ts
export interface WalletPayment {
    derivationPrefix: Base64String;
    derivationSuffix: Base64String;
    senderIdentityKey: PubKeyHex;
}
```

See also: [Base64String](./wallet.md#type-base64string), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WalletWire

A Wallet Wire is an abstraction over a raw transport medium where binary data can be sent to and subsequently received from a wallet.

```ts
export default interface WalletWire {
    transmitToWallet: (message: number[]) => Promise<number[]>;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| | |
| --- | --- |
| [CachedKeyDeriver](#class-cachedkeyderiver) | [WERR_REVIEW_ACTIONS](#class-werr_review_actions) |
| [HTTPWalletJSON](#class-httpwalletjson) | [WalletClient](#class-walletclient) |
| [HTTPWalletWire](#class-httpwalletwire) | [WalletError](#class-walleterror) |
| [KeyDeriver](#class-keyderiver) | [WalletWireProcessor](#class-walletwireprocessor) |
| [ProtoWallet](#class-protowallet) | [WalletWireTransceiver](#class-walletwiretransceiver) |
| [ReactNativeWebView](#class-reactnativewebview) | [WindowCWISubstrate](#class-windowcwisubstrate) |
| [WERR_INSUFFICIENT_FUNDS](#class-werr_insufficient_funds) | [XDMSubstrate](#class-xdmsubstrate) |
| [WERR_INVALID_PARAMETER](#class-werr_invalid_parameter) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: CachedKeyDeriver

A cached version of KeyDeriver that caches the results of key derivation methods.
This is useful for optimizing performance when the same keys are derived multiple times.
It supports configurable cache size with sane defaults and maintains cache entries using LRU (Least Recently Used) eviction policy.

```ts
export default class CachedKeyDeriver implements KeyDeriverApi {
    rootKey: PrivateKey;
    identityKey: string;
    constructor(rootKey: PrivateKey | "anyone", options?: {
        maxCacheSize?: number;
    }) 
    derivePublicKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf: boolean = false): PublicKey 
    derivePrivateKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): PrivateKey 
    deriveSymmetricKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): SymmetricKey 
    revealCounterpartySecret(counterparty: Counterparty): number[] 
    revealSpecificSecret(counterparty: Counterparty, protocolID: WalletProtocol, keyID: string): number[] 
}
```

See also: [Counterparty](./wallet.md#type-counterparty), [KeyDeriverApi](./wallet.md#interface-keyderiverapi), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Constructor

Initializes the CachedKeyDeriver instance with a root private key and optional cache settings.

```ts
constructor(rootKey: PrivateKey | "anyone", options?: {
    maxCacheSize?: number;
}) 
```
See also: [PrivateKey](./primitives.md#class-privatekey)

Argument Details

+ **rootKey**
  + The root private key or the string 'anyone'.
+ **options**
  + Optional settings for the cache.

#### Property identityKey

The identity of this key deriver which is normally the public key associated with the `rootKey`

```ts
identityKey: string
```

#### Property rootKey

The root key from which all other keys are derived.

```ts
rootKey: PrivateKey
```
See also: [PrivateKey](./primitives.md#class-privatekey)

#### Method derivePrivateKey

Derives a private key based on protocol ID, key ID, and counterparty.
Caches the result for future calls with the same parameters.

```ts
derivePrivateKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): PrivateKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [PrivateKey](./primitives.md#class-privatekey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived private key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

#### Method derivePublicKey

Derives a public key based on protocol ID, key ID, and counterparty.
Caches the result for future calls with the same parameters.

```ts
derivePublicKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf: boolean = false): PublicKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [PublicKey](./primitives.md#class-publickey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived public key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').
+ **forSelf**
  + Whether deriving for self.

#### Method deriveSymmetricKey

Derives a symmetric key based on protocol ID, key ID, and counterparty.
Caches the result for future calls with the same parameters.

```ts
deriveSymmetricKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): SymmetricKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived symmetric key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

Throws

- Throws an error if attempting to derive a symmetric key for 'anyone'.

#### Method revealCounterpartySecret

Reveals the shared secret between the root key and the counterparty.
Caches the result for future calls with the same parameters.

```ts
revealCounterpartySecret(counterparty: Counterparty): number[] 
```
See also: [Counterparty](./wallet.md#type-counterparty)

Returns

- The shared secret as a number array.

Argument Details

+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

Throws

- Throws an error if attempting to reveal a shared secret for 'self'.

#### Method revealSpecificSecret

Reveals the specific key association for a given protocol ID, key ID, and counterparty.
Caches the result for future calls with the same parameters.

```ts
revealSpecificSecret(counterparty: Counterparty, protocolID: WalletProtocol, keyID: string): number[] 
```
See also: [Counterparty](./wallet.md#type-counterparty), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The specific key association as a number array.

Argument Details

+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').
+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: HTTPWalletJSON

```ts
export default class HTTPWalletJSON implements WalletInterface {
    baseUrl: string;
    httpClient: typeof fetch;
    originator: OriginatorDomainNameStringUnder250Bytes | undefined;
    api: (call: string, args: object) => Promise<unknown>;
    constructor(originator: OriginatorDomainNameStringUnder250Bytes | undefined, baseUrl: string = "http://localhost:3321", httpClient = fetch) 
    async createAction(args: CreateActionArgs): Promise<CreateActionResult> 
    async signAction(args: SignActionArgs): Promise<SignActionResult> 
    async abortAction(args: {
        reference: Base64String;
    }): Promise<{
        aborted: true;
    }> 
    async listActions(args: ListActionsArgs): Promise<ListActionsResult> 
    async internalizeAction(args: InternalizeActionArgs): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: ListOutputsArgs): Promise<ListOutputsResult> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        seekPermission?: BooleanDefaultTrue;
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: number[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        seekPermission?: BooleanDefaultTrue;
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        seekPermission?: BooleanDefaultTrue;
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        seekPermission?: BooleanDefaultTrue;
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        seekPermission?: BooleanDefaultTrue;
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        seekPermission?: BooleanDefaultTrue;
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        seekPermission?: BooleanDefaultTrue;
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: AcquireCertificateArgs): Promise<AcquireCertificateResult> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<ListCertificatesResult> 
    async proveCertificate(args: ProveCertificateArgs): Promise<ProveCertificateResult> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        seekPermission?: BooleanDefaultTrue;
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<DiscoverCertificatesResult> 
    async discoverByAttributes(args: {
        seekPermission?: BooleanDefaultTrue;
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<DiscoverCertificatesResult> 
    async isAuthenticated(args: object): Promise<{
        authenticated: true;
    }> 
    async waitForAuthentication(args: object): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: object): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: object): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: object): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [AcquireCertificateResult](./wallet.md#type-acquirecertificateresult), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [Byte](./wallet.md#type-byte), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [CreateActionArgs](./wallet.md#interface-createactionargs), [CreateActionResult](./wallet.md#interface-createactionresult), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [ListActionsArgs](./wallet.md#interface-listactionsargs), [ListActionsResult](./wallet.md#interface-listactionsresult), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [OutpointString](./wallet.md#type-outpointstring), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ProveCertificateResult](./wallet.md#interface-provecertificateresult), [PubKeyHex](./wallet.md#type-pubkeyhex), [SecurityLevel](./wallet.md#type-securitylevel), [SignActionArgs](./wallet.md#interface-signactionargs), [SignActionResult](./wallet.md#interface-signactionresult), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: HTTPWalletWire

```ts
export default class HTTPWalletWire implements WalletWire {
    baseUrl: string;
    httpClient: typeof fetch;
    originator: string | undefined;
    constructor(originator: string | undefined, baseUrl: string = "http://localhost:3301", httpClient = fetch) 
    async transmitToWallet(message: number[]): Promise<number[]> 
}
```

See also: [WalletWire](./wallet.md#interface-walletwire)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: KeyDeriver

Class responsible for deriving various types of keys using a root private key.
It supports deriving public and private keys, symmetric keys, and revealing key linkages.

```ts
export class KeyDeriver implements KeyDeriverApi {
    rootKey: PrivateKey;
    identityKey: string;
    constructor(rootKey: PrivateKey | "anyone", private readonly cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), private readonly retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))) 
    derivePublicKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf: boolean = false): PublicKey 
    derivePrivateKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): PrivateKey 
    deriveSymmetricKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): SymmetricKey 
    revealCounterpartySecret(counterparty: Counterparty): number[] 
    revealSpecificSecret(counterparty: Counterparty, protocolID: WalletProtocol, keyID: string): number[] 
}
```

See also: [Counterparty](./wallet.md#type-counterparty), [KeyDeriverApi](./wallet.md#interface-keyderiverapi), [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey), [PublicKey](./primitives.md#class-publickey), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

#### Constructor

Initializes the KeyDeriver instance with a root private key.

```ts
constructor(rootKey: PrivateKey | "anyone", private readonly cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void), private readonly retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))) 
```
See also: [Point](./primitives.md#class-point), [PrivateKey](./primitives.md#class-privatekey)

Argument Details

+ **rootKey**
  + The root private key or the string 'anyone'.

#### Method derivePrivateKey

Derives a private key based on protocol ID, key ID, and counterparty.

```ts
derivePrivateKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): PrivateKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [PrivateKey](./primitives.md#class-privatekey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived private key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

#### Method derivePublicKey

Derives a public key based on protocol ID, key ID, and counterparty.

```ts
derivePublicKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty, forSelf: boolean = false): PublicKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [PublicKey](./primitives.md#class-publickey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived public key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').
+ **forSelf**
  + Whether deriving for self.

#### Method deriveSymmetricKey

Derives a symmetric key based on protocol ID, key ID, and counterparty.
Note: Symmetric keys should not be derivable by everyone due to security risks.

```ts
deriveSymmetricKey(protocolID: WalletProtocol, keyID: string, counterparty: Counterparty): SymmetricKey 
```
See also: [Counterparty](./wallet.md#type-counterparty), [SymmetricKey](./primitives.md#class-symmetrickey), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The derived symmetric key.

Argument Details

+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.
+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

#### Method revealCounterpartySecret

Reveals the shared secret between the root key and the counterparty.
Note: This should not be used for 'self'.

```ts
revealCounterpartySecret(counterparty: Counterparty): number[] 
```
See also: [Counterparty](./wallet.md#type-counterparty)

Returns

- The shared secret as a number array.

Argument Details

+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').

Throws

- Throws an error if attempting to reveal a shared secret for 'self'.

#### Method revealSpecificSecret

Reveals the specific key association for a given protocol ID, key ID, and counterparty.

```ts
revealSpecificSecret(counterparty: Counterparty, protocolID: WalletProtocol, keyID: string): number[] 
```
See also: [Counterparty](./wallet.md#type-counterparty), [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

- The specific key association as a number array.

Argument Details

+ **counterparty**
  + The counterparty's public key or a predefined value ('self' or 'anyone').
+ **protocolID**
  + The protocol ID including a security level and protocol name.
+ **keyID**
  + The key identifier.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: ProtoWallet

A ProtoWallet is precursor to a full wallet, capable of performing all foundational cryptographic operations.
It can derive keys, create signatures, facilitate encryption and HMAC operations, and reveal key linkages.

However, ProtoWallet does not create transactions, manage outputs, interact with the blockchain,
enable the management of identity certificates, or store any data. It is also not concerned with privileged keys.

```ts
export class ProtoWallet {
    keyDeriver?: KeyDeriverApi;
    constructor(rootKeyOrKeyDeriver?: PrivateKey | "anyone" | KeyDeriverApi) 
    async getPublicKey(args: GetPublicKeyArgs): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: RevealCounterpartyKeyLinkageArgs): Promise<RevealCounterpartyKeyLinkageResult> 
    async revealSpecificKeyLinkage(args: RevealSpecificKeyLinkageArgs): Promise<RevealSpecificKeyLinkageResult> 
    async encrypt(args: WalletEncryptArgs): Promise<WalletEncryptResult> 
    async decrypt(args: WalletDecryptArgs, originator?: string): Promise<WalletDecryptResult> 
    async createHmac(args: CreateHmacArgs): Promise<CreateHmacResult> 
    async verifyHmac(args: VerifyHmacArgs): Promise<VerifyHmacResult> 
    async createSignature(args: CreateSignatureArgs): Promise<CreateSignatureResult> 
    async verifySignature(args: VerifySignatureArgs): Promise<VerifySignatureResult> 
}
```

See also: [CreateHmacArgs](./wallet.md#interface-createhmacargs), [CreateHmacResult](./wallet.md#interface-createhmacresult), [CreateSignatureArgs](./wallet.md#interface-createsignatureargs), [CreateSignatureResult](./wallet.md#interface-createsignatureresult), [GetPublicKeyArgs](./wallet.md#interface-getpublickeyargs), [KeyDeriverApi](./wallet.md#interface-keyderiverapi), [PrivateKey](./primitives.md#class-privatekey), [PubKeyHex](./wallet.md#type-pubkeyhex), [RevealCounterpartyKeyLinkageArgs](./wallet.md#interface-revealcounterpartykeylinkageargs), [RevealCounterpartyKeyLinkageResult](./wallet.md#interface-revealcounterpartykeylinkageresult), [RevealSpecificKeyLinkageArgs](./wallet.md#interface-revealspecifickeylinkageargs), [RevealSpecificKeyLinkageResult](./wallet.md#interface-revealspecifickeylinkageresult), [VerifyHmacArgs](./wallet.md#interface-verifyhmacargs), [VerifyHmacResult](./wallet.md#interface-verifyhmacresult), [VerifySignatureArgs](./wallet.md#interface-verifysignatureargs), [VerifySignatureResult](./wallet.md#interface-verifysignatureresult), [WalletDecryptArgs](./wallet.md#interface-walletdecryptargs), [WalletDecryptResult](./wallet.md#interface-walletdecryptresult), [WalletEncryptArgs](./wallet.md#interface-walletencryptargs), [WalletEncryptResult](./wallet.md#interface-walletencryptresult), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: ReactNativeWebView

Facilitates wallet operations over cross-document messaging.

```ts
export default class ReactNativeWebView implements WalletInterface {
    constructor(domain: string = "*") 
    async invoke(call: CallType, args: any): Promise<any> 
    async createAction(args: {
        description: DescriptionString5to50Bytes;
        inputs?: Array<{
            tx?: BEEF;
            outpoint: OutpointString;
            unlockingScript?: HexString;
            unlockingScriptLength?: PositiveInteger;
            inputDescription: DescriptionString5to50Bytes;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        outputs?: Array<{
            lockingScript: HexString;
            satoshis: SatoshiValue;
            outputDescription: DescriptionString5to50Bytes;
            basket?: BasketStringUnder300Bytes;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
        }>;
        lockTime?: PositiveIntegerOrZero;
        version?: PositiveIntegerOrZero;
        labels?: LabelStringUnder300Bytes[];
        options?: {
            signAndProcess?: BooleanDefaultTrue;
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            trustSelf?: "known";
            knownTxids?: TXIDHexString[];
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith?: TXIDHexString[];
        };
    }): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
        signableTransaction?: {
            tx: BEEF;
            reference: Base64String;
        };
    }> 
    async signAction(args: {
        spends: Record<PositiveIntegerOrZero, {
            unlockingScript: HexString;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        reference: Base64String;
        options?: {
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith: TXIDHexString[];
        };
    }): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
    }> 
    async abortAction(args: {
        reference: Base64String;
    }): Promise<{
        aborted: true;
    }> 
    async listActions(args: {
        labels: LabelStringUnder300Bytes[];
        labelQueryMode?: "any" | "all";
        includeLabels?: BooleanDefaultFalse;
        includeInputs?: BooleanDefaultFalse;
        includeInputSourceLockingScripts?: BooleanDefaultFalse;
        includeInputUnlockingScripts?: BooleanDefaultFalse;
        includeOutputs?: BooleanDefaultFalse;
        includeOutputLockingScripts?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalActions: PositiveIntegerOrZero;
        actions: Array<{
            txid: TXIDHexString;
            satoshis: SatoshiValue;
            status: "completed" | "unprocessed" | "sending" | "unproven" | "unsigned" | "nosend" | "nonfinal";
            isOutgoing: boolean;
            description: DescriptionString5to50Bytes;
            labels?: LabelStringUnder300Bytes[];
            version: PositiveIntegerOrZero;
            lockTime: PositiveIntegerOrZero;
            inputs?: Array<{
                sourceOutpoint: OutpointString;
                sourceSatoshis: SatoshiValue;
                sourceLockingScript?: HexString;
                unlockingScript?: HexString;
                inputDescription: DescriptionString5to50Bytes;
                sequenceNumber: PositiveIntegerOrZero;
            }>;
            outputs?: Array<{
                outputIndex: PositiveIntegerOrZero;
                satoshis: SatoshiValue;
                lockingScript?: HexString;
                spendable: boolean;
                outputDescription: DescriptionString5to50Bytes;
                basket: BasketStringUnder300Bytes;
                tags: OutputTagStringUnder300Bytes[];
                customInstructions?: string;
            }>;
        }>;
    }> 
    async internalizeAction(args: {
        tx: BEEF;
        outputs: Array<{
            outputIndex: PositiveIntegerOrZero;
            protocol: "wallet payment" | "basket insertion";
            paymentRemittance?: {
                derivationPrefix: Base64String;
                derivationSuffix: Base64String;
                senderIdentityKey: PubKeyHex;
            };
            insertionRemittance?: {
                basket: BasketStringUnder300Bytes;
                customInstructions?: string;
                tags?: OutputTagStringUnder300Bytes[];
            };
        }>;
        description: DescriptionString5to50Bytes;
        labels?: LabelStringUnder300Bytes[];
    }): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: {
        basket: BasketStringUnder300Bytes;
        tags?: OutputTagStringUnder300Bytes[];
        tagQueryMode?: "all" | "any";
        include?: "locking scripts" | "entire transactions";
        includeCustomInstructions?: BooleanDefaultFalse;
        includeTags?: BooleanDefaultFalse;
        includeLabels?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalOutputs: PositiveIntegerOrZero;
        outputs: Array<{
            outpoint: OutpointString;
            satoshis: SatoshiValue;
            lockingScript?: HexString;
            tx?: BEEF;
            spendable: boolean;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
            labels?: LabelStringUnder300Bytes[];
        }>;
    }> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: {
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
        certifier: PubKeyHex;
        keyringRevealer: PubKeyHex | "certifier";
        keyringForSubject: Record<CertificateFieldNameUnder50Bytes, Base64String>;
        acquisitionProtocol: "direct" | "issuance";
        certifierUrl?: string;
    }): Promise<{
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        certifier: PubKeyHex;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
    }> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async proveCertificate(args: {
        certificate: {
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        };
        fieldsToReveal: CertificateFieldNameUnder50Bytes[];
        verifier: PubKeyHex;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<{
        keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    }> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async discoverByAttributes(args: {
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async isAuthenticated(args: {}): Promise<{
        authenticated: true;
    }> 
    async waitForAuthentication(args: {}): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: {}): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: {}): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: {}): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [BEEF](./wallet.md#type-beef), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [Byte](./wallet.md#type-byte), [CallType](./wallet.md#type-calltype), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [EntityIconURLStringMax500Bytes](./wallet.md#type-entityiconurlstringmax500bytes), [EntityNameStringMax100Bytes](./wallet.md#type-entitynamestringmax100bytes), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [OutpointString](./wallet.md#type-outpointstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerMax10](./wallet.md#type-positiveintegermax10), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [SatoshiValue](./wallet.md#type-satoshivalue), [SecurityLevel](./wallet.md#type-securitylevel), [TXIDHexString](./wallet.md#type-txidhexstring), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WERR_INSUFFICIENT_FUNDS

Insufficient funds in the available inputs to cover the cost of the required outputs
and the transaction fee (${moreSatoshisNeeded} more satoshis are needed,
for a total of ${totalSatoshisNeeded}), plus whatever would be required in order
to pay the fee to unlock and spend the outputs used to provide the additional satoshis.

```ts
export class WERR_INSUFFICIENT_FUNDS extends Error {
    code: number;
    isError: boolean = true;
    constructor(public totalSatoshisNeeded: number, public moreSatoshisNeeded: number) 
}
```

#### Constructor

```ts
constructor(public totalSatoshisNeeded: number, public moreSatoshisNeeded: number) 
```

Argument Details

+ **totalSatoshisNeeded**
  + Total satoshis required to fund transactions after net of required inputs and outputs.
+ **moreSatoshisNeeded**
  + Shortfall on total satoshis required to fund transactions after net of required inputs and outputs.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WERR_INVALID_PARAMETER

The ${parameter} parameter is invalid.

This is an example of an error object with a custom property `parameter` and templated `message`.

```ts
export class WERR_INVALID_PARAMETER extends Error {
    code: number;
    isError: boolean = true;
    constructor(public parameter: string, mustBe?: string) 
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WERR_REVIEW_ACTIONS

When a `createAction` or `signAction` is completed in undelayed mode (`acceptDelayedBroadcast`: false),
any unsucccessful result will return the results by way of this exception to ensure attention is
paid to processing errors.

```ts
export class WERR_REVIEW_ACTIONS extends Error {
    code: number;
    isError: boolean = true;
    constructor(public reviewActionResults: ReviewActionResult[], public sendWithResults: SendWithResult[], public txid?: TXIDHexString, public tx?: AtomicBEEF, public noSendChange?: OutpointString[]) 
}
```

See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [OutpointString](./wallet.md#type-outpointstring), [ReviewActionResult](./wallet.md#interface-reviewactionresult), [SendWithResult](./wallet.md#interface-sendwithresult), [TXIDHexString](./wallet.md#type-txidhexstring)

#### Constructor

All parameters correspond to their comparable `createAction` or `signSction` results
with the exception of `reviewActionResults`;
which contains more details, particularly for double spend results.

```ts
constructor(public reviewActionResults: ReviewActionResult[], public sendWithResults: SendWithResult[], public txid?: TXIDHexString, public tx?: AtomicBEEF, public noSendChange?: OutpointString[]) 
```
See also: [AtomicBEEF](./wallet.md#type-atomicbeef), [OutpointString](./wallet.md#type-outpointstring), [ReviewActionResult](./wallet.md#interface-reviewactionresult), [SendWithResult](./wallet.md#interface-sendwithresult), [TXIDHexString](./wallet.md#type-txidhexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WalletClient

The SDK is how applications communicate with wallets over a communications substrate.

```ts
export default class WalletClient implements WalletInterface {
    public substrate: "auto" | WalletInterface;
    originator?: OriginatorDomainNameStringUnder250Bytes;
    constructor(substrate: "auto" | "Cicada" | "XDM" | "window.CWI" | "json-api" | "react-native" | "secure-json-api" | WalletInterface = "auto", originator?: OriginatorDomainNameStringUnder250Bytes) 
    async connectToSubstrate(): Promise<void> 
    async createAction(args: CreateActionArgs): Promise<CreateActionResult> 
    async signAction(args: SignActionArgs): Promise<SignActionResult> 
    async abortAction(args: {
        reference: Base64String;
    }): Promise<{
        aborted: true;
    }> 
    async listActions(args: ListActionsArgs): Promise<ListActionsResult> 
    async internalizeAction(args: InternalizeActionArgs): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: ListOutputsArgs): Promise<ListOutputsResult> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: AcquireCertificateArgs): Promise<AcquireCertificateResult> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<ListCertificatesResult> 
    async proveCertificate(args: ProveCertificateArgs): Promise<ProveCertificateResult> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<DiscoverCertificatesResult> 
    async discoverByAttributes(args: {
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<DiscoverCertificatesResult> 
    async isAuthenticated(args: object = {}): Promise<AuthenticatedResult> 
    async waitForAuthentication(args: object = {}): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: object = {}): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: object = {}): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: object = {}): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [AcquireCertificateResult](./wallet.md#type-acquirecertificateresult), [AuthenticatedResult](./wallet.md#interface-authenticatedresult), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [Byte](./wallet.md#type-byte), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [CreateActionArgs](./wallet.md#interface-createactionargs), [CreateActionResult](./wallet.md#interface-createactionresult), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [ListActionsArgs](./wallet.md#interface-listactionsargs), [ListActionsResult](./wallet.md#interface-listactionsresult), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [OutpointString](./wallet.md#type-outpointstring), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ProveCertificateResult](./wallet.md#interface-provecertificateresult), [PubKeyHex](./wallet.md#type-pubkeyhex), [SecurityLevel](./wallet.md#type-securitylevel), [SignActionArgs](./wallet.md#interface-signactionargs), [SignActionResult](./wallet.md#interface-signactionresult), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WalletError

```ts
export class WalletError extends Error {
    code: number;
    isError: boolean = true;
    constructor(message: string, code = 1, stack?: string) 
    static unknownToJson(error: any): string 
}
```

#### Method unknownToJson

Safely serializes a WalletError (including special cases), Error or unknown error to JSON.

Safely means avoiding deep, large, circular issues.

Example deserialization can be found in HTTPWalletJSON.ts of bsv ts-sdk.

```ts
static unknownToJson(error: any): string 
```

Returns

stringified JSON representation of the error such that it can be deserialized to a WalletError.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WalletWireProcessor

Processes incoming wallet calls received over a wallet wire, with a given wallet.

```ts
export default class WalletWireProcessor implements WalletWire {
    wallet: WalletInterface;
    constructor(wallet: WalletInterface) 
    async transmitToWallet(message: number[]): Promise<number[]> 
}
```

See also: [WalletInterface](./wallet.md#interface-walletinterface), [WalletWire](./wallet.md#interface-walletwire)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WalletWireTransceiver

A way to make remote calls to a wallet over a wallet wire.

```ts
export default class WalletWireTransceiver implements WalletInterface {
    wire: WalletWire;
    constructor(wire: WalletWire) 
    async createAction(args: CreateActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<CreateActionResult> 
    async signAction(args: SignActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<SignActionResult> 
    async abortAction(args: {
        reference: Base64String;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        aborted: true;
    }> 
    async listActions(args: ListActionsArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<ListActionsResult> 
    async internalizeAction(args: InternalizeActionArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: ListOutputsArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<ListOutputsResult> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        seekPermission?: BooleanDefaultTrue;
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: number[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        seekPermission?: BooleanDefaultTrue;
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        seekPermission?: BooleanDefaultTrue;
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        seekPermission?: BooleanDefaultTrue;
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        seekPermission?: BooleanDefaultTrue;
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        seekPermission?: BooleanDefaultTrue;
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        seekPermission?: BooleanDefaultTrue;
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: AcquireCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<AcquireCertificateResult> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<ListCertificatesResult> 
    async proveCertificate(args: ProveCertificateArgs, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<ProveCertificateResult> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        seekPermission?: BooleanDefaultTrue;
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<DiscoverCertificatesResult> 
    async discoverByAttributes(args: {
        seekPermission?: BooleanDefaultTrue;
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<DiscoverCertificatesResult> 
    async isAuthenticated(args: {}, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        authenticated: true;
    }> 
    async waitForAuthentication(args: {}, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: {}, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: {}, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: {}, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [AcquireCertificateResult](./wallet.md#type-acquirecertificateresult), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [Byte](./wallet.md#type-byte), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [CreateActionArgs](./wallet.md#interface-createactionargs), [CreateActionResult](./wallet.md#interface-createactionresult), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [ListActionsArgs](./wallet.md#interface-listactionsargs), [ListActionsResult](./wallet.md#interface-listactionsresult), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [OutpointString](./wallet.md#type-outpointstring), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ProveCertificateResult](./wallet.md#interface-provecertificateresult), [PubKeyHex](./wallet.md#type-pubkeyhex), [SecurityLevel](./wallet.md#type-securitylevel), [SignActionArgs](./wallet.md#interface-signactionargs), [SignActionResult](./wallet.md#interface-signactionresult), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [WalletWire](./wallet.md#interface-walletwire), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WindowCWISubstrate

Facilitates wallet operations over the window.CWI interface.

```ts
export default class WindowCWISubstrate implements WalletInterface {
    constructor() 
    async createAction(args: {
        description: DescriptionString5to50Bytes;
        inputs?: Array<{
            tx?: BEEF;
            outpoint: OutpointString;
            unlockingScript?: HexString;
            unlockingScriptLength?: PositiveInteger;
            inputDescription: DescriptionString5to50Bytes;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        outputs?: Array<{
            lockingScript: HexString;
            satoshis: SatoshiValue;
            outputDescription: DescriptionString5to50Bytes;
            basket?: BasketStringUnder300Bytes;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
        }>;
        lockTime?: PositiveIntegerOrZero;
        version?: PositiveIntegerOrZero;
        labels?: LabelStringUnder300Bytes[];
        options?: {
            signAndProcess?: BooleanDefaultTrue;
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            trustSelf?: "known";
            knownTxids?: TXIDHexString[];
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith?: TXIDHexString[];
        };
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
        signableTransaction?: {
            tx: BEEF;
            reference: Base64String;
        };
    }> 
    async signAction(args: {
        spends: Record<PositiveIntegerOrZero, {
            unlockingScript: HexString;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        reference: Base64String;
        options?: {
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith: TXIDHexString[];
        };
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
    }> 
    async abortAction(args: {
        reference: Base64String;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        aborted: true;
    }> 
    async listActions(args: {
        labels: LabelStringUnder300Bytes[];
        labelQueryMode?: "any" | "all";
        includeLabels?: BooleanDefaultFalse;
        includeInputs?: BooleanDefaultFalse;
        includeInputSourceLockingScripts?: BooleanDefaultFalse;
        includeInputUnlockingScripts?: BooleanDefaultFalse;
        includeOutputs?: BooleanDefaultFalse;
        includeOutputLockingScripts?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        totalActions: PositiveIntegerOrZero;
        actions: Array<{
            txid: TXIDHexString;
            satoshis: SatoshiValue;
            status: "completed" | "unprocessed" | "sending" | "unproven" | "unsigned" | "nosend" | "nonfinal" | "failed";
            isOutgoing: boolean;
            description: DescriptionString5to50Bytes;
            labels?: LabelStringUnder300Bytes[];
            version: PositiveIntegerOrZero;
            lockTime: PositiveIntegerOrZero;
            inputs?: Array<{
                sourceOutpoint: OutpointString;
                sourceSatoshis: SatoshiValue;
                sourceLockingScript?: HexString;
                unlockingScript?: HexString;
                inputDescription: DescriptionString5to50Bytes;
                sequenceNumber: PositiveIntegerOrZero;
            }>;
            outputs?: Array<{
                outputIndex: PositiveIntegerOrZero;
                satoshis: SatoshiValue;
                lockingScript?: HexString;
                spendable: boolean;
                outputDescription: DescriptionString5to50Bytes;
                basket: BasketStringUnder300Bytes;
                tags: OutputTagStringUnder300Bytes[];
                customInstructions?: string;
            }>;
        }>;
    }> 
    async internalizeAction(args: {
        tx: BEEF;
        outputs: Array<{
            outputIndex: PositiveIntegerOrZero;
            protocol: "wallet payment" | "basket insertion";
            paymentRemittance?: {
                derivationPrefix: Base64String;
                derivationSuffix: Base64String;
                senderIdentityKey: PubKeyHex;
            };
            insertionRemittance?: {
                basket: BasketStringUnder300Bytes;
                customInstructions?: string;
                tags?: OutputTagStringUnder300Bytes[];
            };
        }>;
        description: DescriptionString5to50Bytes;
        labels?: LabelStringUnder300Bytes[];
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: {
        basket: BasketStringUnder300Bytes;
        tags?: OutputTagStringUnder300Bytes[];
        tagQueryMode?: "all" | "any";
        include?: "locking scripts" | "entire transactions";
        includeCustomInstructions?: BooleanDefaultFalse;
        includeTags?: BooleanDefaultFalse;
        includeLabels?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        totalOutputs: PositiveIntegerOrZero;
        outputs: Array<{
            outpoint: OutpointString;
            satoshis: SatoshiValue;
            lockingScript?: HexString;
            tx?: BEEF;
            spendable: boolean;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
            labels?: LabelStringUnder300Bytes[];
        }>;
    }> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: {
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
        certifier: PubKeyHex;
        keyringRevealer: PubKeyHex | "certifier";
        keyringForSubject: Record<CertificateFieldNameUnder50Bytes, Base64String>;
        acquisitionProtocol: "direct" | "issuance";
        certifierUrl?: string;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        certifier: PubKeyHex;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
    }> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async proveCertificate(args: {
        certificate: {
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        };
        fieldsToReveal: CertificateFieldNameUnder50Bytes[];
        verifier: PubKeyHex;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    }> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async discoverByAttributes(args: {
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async isAuthenticated(args: object, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        authenticated: true;
    }> 
    async waitForAuthentication(args: object, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: object, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: object, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: object, originator?: OriginatorDomainNameStringUnder250Bytes): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [BEEF](./wallet.md#type-beef), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [Byte](./wallet.md#type-byte), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [EntityIconURLStringMax500Bytes](./wallet.md#type-entityiconurlstringmax500bytes), [EntityNameStringMax100Bytes](./wallet.md#type-entitynamestringmax100bytes), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [OutpointString](./wallet.md#type-outpointstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerMax10](./wallet.md#type-positiveintegermax10), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [SatoshiValue](./wallet.md#type-satoshivalue), [SecurityLevel](./wallet.md#type-securitylevel), [TXIDHexString](./wallet.md#type-txidhexstring), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: XDMSubstrate

Facilitates wallet operations over cross-document messaging.

```ts
export default class XDMSubstrate implements WalletInterface {
    constructor(domain: string = "*") 
    async invoke(call: CallType, args: any): Promise<any> 
    async createAction(args: {
        description: DescriptionString5to50Bytes;
        inputs?: Array<{
            tx?: BEEF;
            outpoint: OutpointString;
            unlockingScript?: HexString;
            unlockingScriptLength?: PositiveInteger;
            inputDescription: DescriptionString5to50Bytes;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        outputs?: Array<{
            lockingScript: HexString;
            satoshis: SatoshiValue;
            outputDescription: DescriptionString5to50Bytes;
            basket?: BasketStringUnder300Bytes;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
        }>;
        lockTime?: PositiveIntegerOrZero;
        version?: PositiveIntegerOrZero;
        labels?: LabelStringUnder300Bytes[];
        options?: {
            signAndProcess?: BooleanDefaultTrue;
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            trustSelf?: "known";
            knownTxids?: TXIDHexString[];
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith?: TXIDHexString[];
        };
    }): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
        signableTransaction?: {
            tx: BEEF;
            reference: Base64String;
        };
    }> 
    async signAction(args: {
        spends: Record<PositiveIntegerOrZero, {
            unlockingScript: HexString;
            sequenceNumber?: PositiveIntegerOrZero;
        }>;
        reference: Base64String;
        options?: {
            acceptDelayedBroadcast?: BooleanDefaultTrue;
            returnTXIDOnly?: BooleanDefaultFalse;
            noSend?: BooleanDefaultFalse;
            noSendChange?: OutpointString[];
            sendWith: TXIDHexString[];
        };
    }): Promise<{
        txid?: TXIDHexString;
        tx?: BEEF;
        noSendChange?: OutpointString[];
        sendWithResults?: Array<{
            txid: TXIDHexString;
            status: "unproven" | "sending" | "failed";
        }>;
    }> 
    async abortAction(args: {
        reference: Base64String;
    }): Promise<{
        aborted: true;
    }> 
    async listActions(args: {
        labels: LabelStringUnder300Bytes[];
        labelQueryMode?: "any" | "all";
        includeLabels?: BooleanDefaultFalse;
        includeInputs?: BooleanDefaultFalse;
        includeInputSourceLockingScripts?: BooleanDefaultFalse;
        includeInputUnlockingScripts?: BooleanDefaultFalse;
        includeOutputs?: BooleanDefaultFalse;
        includeOutputLockingScripts?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalActions: PositiveIntegerOrZero;
        actions: Array<{
            txid: TXIDHexString;
            satoshis: SatoshiValue;
            status: "completed" | "unprocessed" | "sending" | "unproven" | "unsigned" | "nosend" | "nonfinal";
            isOutgoing: boolean;
            description: DescriptionString5to50Bytes;
            labels?: LabelStringUnder300Bytes[];
            version: PositiveIntegerOrZero;
            lockTime: PositiveIntegerOrZero;
            inputs?: Array<{
                sourceOutpoint: OutpointString;
                sourceSatoshis: SatoshiValue;
                sourceLockingScript?: HexString;
                unlockingScript?: HexString;
                inputDescription: DescriptionString5to50Bytes;
                sequenceNumber: PositiveIntegerOrZero;
            }>;
            outputs?: Array<{
                outputIndex: PositiveIntegerOrZero;
                satoshis: SatoshiValue;
                lockingScript?: HexString;
                spendable: boolean;
                outputDescription: DescriptionString5to50Bytes;
                basket: BasketStringUnder300Bytes;
                tags: OutputTagStringUnder300Bytes[];
                customInstructions?: string;
            }>;
        }>;
    }> 
    async internalizeAction(args: {
        tx: BEEF;
        outputs: Array<{
            outputIndex: PositiveIntegerOrZero;
            protocol: "wallet payment" | "basket insertion";
            paymentRemittance?: {
                derivationPrefix: Base64String;
                derivationSuffix: Base64String;
                senderIdentityKey: PubKeyHex;
            };
            insertionRemittance?: {
                basket: BasketStringUnder300Bytes;
                customInstructions?: string;
                tags?: OutputTagStringUnder300Bytes[];
            };
        }>;
        description: DescriptionString5to50Bytes;
        labels?: LabelStringUnder300Bytes[];
    }): Promise<{
        accepted: true;
    }> 
    async listOutputs(args: {
        basket: BasketStringUnder300Bytes;
        tags?: OutputTagStringUnder300Bytes[];
        tagQueryMode?: "all" | "any";
        include?: "locking scripts" | "entire transactions";
        includeCustomInstructions?: BooleanDefaultFalse;
        includeTags?: BooleanDefaultFalse;
        includeLabels?: BooleanDefaultFalse;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalOutputs: PositiveIntegerOrZero;
        outputs: Array<{
            outpoint: OutpointString;
            satoshis: SatoshiValue;
            lockingScript?: HexString;
            tx?: BEEF;
            spendable: boolean;
            customInstructions?: string;
            tags?: OutputTagStringUnder300Bytes[];
            labels?: LabelStringUnder300Bytes[];
        }>;
    }> 
    async relinquishOutput(args: {
        basket: BasketStringUnder300Bytes;
        output: OutpointString;
    }): Promise<{
        relinquished: true;
    }> 
    async getPublicKey(args: {
        identityKey?: true;
        protocolID?: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID?: KeyIDStringUnder800Bytes;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
    }): Promise<{
        publicKey: PubKeyHex;
    }> 
    async revealCounterpartyKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        revelationTime: ISOTimestampString;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
    }> 
    async revealSpecificKeyLinkage(args: {
        counterparty: PubKeyHex;
        verifier: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        prover: PubKeyHex;
        verifier: PubKeyHex;
        counterparty: PubKeyHex;
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        encryptedLinkage: Byte[];
        encryptedLinkageProof: Byte[];
        proofType: Byte;
    }> 
    async encrypt(args: {
        plaintext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        ciphertext: Byte[];
    }> 
    async decrypt(args: {
        ciphertext: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        plaintext: Byte[];
    }> 
    async createHmac(args: {
        data: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        hmac: Byte[];
    }> 
    async verifyHmac(args: {
        data: Byte[];
        hmac: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async createSignature(args: {
        data?: Byte[];
        hashToDirectlySign?: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        signature: Byte[];
    }> 
    async verifySignature(args: {
        data?: Byte[];
        hashToDirectlyVerify?: Byte[];
        signature: Byte[];
        protocolID: [
            SecurityLevel,
            ProtocolString5To400Bytes
        ];
        keyID: KeyIDStringUnder800Bytes;
        privilegedReason?: DescriptionString5to50Bytes;
        counterparty?: PubKeyHex | "self" | "anyone";
        forSelf?: BooleanDefaultFalse;
        privileged?: BooleanDefaultFalse;
    }): Promise<{
        valid: true;
    }> 
    async acquireCertificate(args: {
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
        certifier: PubKeyHex;
        keyringRevealer: PubKeyHex | "certifier";
        keyringForSubject: Record<CertificateFieldNameUnder50Bytes, Base64String>;
        acquisitionProtocol: "direct" | "issuance";
        certifierUrl?: string;
    }): Promise<{
        type: Base64String;
        subject: PubKeyHex;
        serialNumber: Base64String;
        certifier: PubKeyHex;
        revocationOutpoint: OutpointString;
        signature: HexString;
        fields: Record<CertificateFieldNameUnder50Bytes, string>;
    }> 
    async listCertificates(args: {
        certifiers: PubKeyHex[];
        types: Base64String[];
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async proveCertificate(args: {
        certificate: {
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, string>;
        };
        fieldsToReveal: CertificateFieldNameUnder50Bytes[];
        verifier: PubKeyHex;
        privileged?: BooleanDefaultFalse;
        privilegedReason?: DescriptionString5to50Bytes;
    }): Promise<{
        keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    }> 
    async relinquishCertificate(args: {
        type: Base64String;
        serialNumber: Base64String;
        certifier: PubKeyHex;
    }): Promise<{
        relinquished: true;
    }> 
    async discoverByIdentityKey(args: {
        identityKey: PubKeyHex;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async discoverByAttributes(args: {
        attributes: Record<CertificateFieldNameUnder50Bytes, string>;
        limit?: PositiveIntegerDefault10Max10000;
        offset?: PositiveIntegerOrZero;
    }): Promise<{
        totalCertificates: PositiveIntegerOrZero;
        certificates: Array<{
            type: Base64String;
            subject: PubKeyHex;
            serialNumber: Base64String;
            certifier: PubKeyHex;
            revocationOutpoint: OutpointString;
            signature: HexString;
            fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            certifierInfo: {
                name: EntityNameStringMax100Bytes;
                iconUrl: EntityIconURLStringMax500Bytes;
                description: DescriptionString5to50Bytes;
                trust: PositiveIntegerMax10;
            };
            publiclyRevealedKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
            decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>;
        }>;
    }> 
    async isAuthenticated(args: {}): Promise<{
        authenticated: true;
    }> 
    async waitForAuthentication(args: {}): Promise<{
        authenticated: true;
    }> 
    async getHeight(args: {}): Promise<{
        height: PositiveInteger;
    }> 
    async getHeaderForHeight(args: {
        height: PositiveInteger;
    }): Promise<{
        header: HexString;
    }> 
    async getNetwork(args: {}): Promise<{
        network: "mainnet" | "testnet";
    }> 
    async getVersion(args: {}): Promise<{
        version: VersionString7To30Bytes;
    }> 
}
```

See also: [BEEF](./wallet.md#type-beef), [Base64String](./wallet.md#type-base64string), [BasketStringUnder300Bytes](./wallet.md#type-basketstringunder300bytes), [BooleanDefaultFalse](./wallet.md#type-booleandefaultfalse), [BooleanDefaultTrue](./wallet.md#type-booleandefaulttrue), [Byte](./wallet.md#type-byte), [CallType](./wallet.md#type-calltype), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [DescriptionString5to50Bytes](./wallet.md#type-descriptionstring5to50bytes), [EntityIconURLStringMax500Bytes](./wallet.md#type-entityiconurlstringmax500bytes), [EntityNameStringMax100Bytes](./wallet.md#type-entitynamestringmax100bytes), [HexString](./wallet.md#type-hexstring), [ISOTimestampString](./wallet.md#type-isotimestampstring), [KeyIDStringUnder800Bytes](./wallet.md#type-keyidstringunder800bytes), [LabelStringUnder300Bytes](./wallet.md#type-labelstringunder300bytes), [OutpointString](./wallet.md#type-outpointstring), [OutputTagStringUnder300Bytes](./wallet.md#type-outputtagstringunder300bytes), [PositiveInteger](./wallet.md#type-positiveinteger), [PositiveIntegerDefault10Max10000](./wallet.md#type-positiveintegerdefault10max10000), [PositiveIntegerMax10](./wallet.md#type-positiveintegermax10), [PositiveIntegerOrZero](./wallet.md#type-positiveintegerorzero), [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [PubKeyHex](./wallet.md#type-pubkeyhex), [SatoshiValue](./wallet.md#type-satoshivalue), [SecurityLevel](./wallet.md#type-securitylevel), [TXIDHexString](./wallet.md#type-txidhexstring), [VersionString7To30Bytes](./wallet.md#type-versionstring7to30bytes), [WalletInterface](./wallet.md#interface-walletinterface), [decrypt](./messages.md#variable-decrypt), [encrypt](./messages.md#variable-encrypt)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

| | | |
| --- | --- | --- |
| [isHexString](#function-ishexstring) | [validateCreateActionOutput](#function-validatecreateactionoutput) | [validateOriginator](#function-validateoriginator) |
| [parseWalletOutpoint](#function-parsewalletoutpoint) | [validateDiscoverByAttributesArgs](#function-validatediscoverbyattributesargs) | [validateOutpointString](#function-validateoutpointstring) |
| [toOriginHeader](#function-tooriginheader) | [validateDiscoverByIdentityKeyArgs](#function-validatediscoverbyidentitykeyargs) | [validatePositiveIntegerOrZero](#function-validatepositiveintegerorzero) |
| [validateAbortActionArgs](#function-validateabortactionargs) | [validateInteger](#function-validateinteger) | [validateProveCertificateArgs](#function-validateprovecertificateargs) |
| [validateAcquireDirectCertificateArgs](#function-validateacquiredirectcertificateargs) | [validateInternalizeActionArgs](#function-validateinternalizeactionargs) | [validateRelinquishCertificateArgs](#function-validaterelinquishcertificateargs) |
| [validateAcquireIssuanceCertificateArgs](#function-validateacquireissuancecertificateargs) | [validateInternalizeOutput](#function-validateinternalizeoutput) | [validateRelinquishOutputArgs](#function-validaterelinquishoutputargs) |
| [validateBase64String](#function-validatebase64string) | [validateListActionsArgs](#function-validatelistactionsargs) | [validateSatoshis](#function-validatesatoshis) |
| [validateBasketInsertion](#function-validatebasketinsertion) | [validateListCertificatesArgs](#function-validatelistcertificatesargs) | [validateSignActionArgs](#function-validatesignactionargs) |
| [validateCreateActionArgs](#function-validatecreateactionargs) | [validateListOutputsArgs](#function-validatelistoutputsargs) | [validateSignActionOptions](#function-validatesignactionoptions) |
| [validateCreateActionInput](#function-validatecreateactioninput) | [validateOptionalInteger](#function-validateoptionalinteger) | [validateStringLength](#function-validatestringlength) |
| [validateCreateActionOptions](#function-validatecreateactionoptions) | [validateOptionalOutpointString](#function-validateoptionaloutpointstring) | [validateWalletPayment](#function-validatewalletpayment) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Function: isHexString

Check whether a string is a valid hex string (even length and hex characters).

```ts
export function isHexString(s: string): boolean 
```

Returns

true when s is a valid hex string

Argument Details

+ **s**
  + input string

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: parseWalletOutpoint

```ts
export function parseWalletOutpoint(outpoint: string): {
    txid: string;
    vout: number;
} 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: toOriginHeader

```ts
export function toOriginHeader(originator: string, fallbackScheme = "http"): string | undefined 
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateAbortActionArgs

Validate AbortActionArgs (ensures reference is a valid base64 string).

```ts
export function validateAbortActionArgs(args: AbortActionArgs): ValidAbortActionArgs 
```

See also: [AbortActionArgs](./wallet.md#interface-abortactionargs), [ValidAbortActionArgs](./wallet.md#interface-validabortactionargs)

Returns

ValidAbortActionArgs

Argument Details

+ **args**
  + AbortActionArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateAcquireDirectCertificateArgs

Validate direct-acquisition-specific acquire certificate args.

```ts
export function validateAcquireDirectCertificateArgs(args: AcquireCertificateArgs): ValidAcquireDirectCertificateArgs 
```

See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [ValidAcquireDirectCertificateArgs](./wallet.md#interface-validacquiredirectcertificateargs)

Returns

ValidAcquireDirectCertificateArgs

Argument Details

+ **args**
  + AcquireCertificateArgs with acquisitionProtocol === 'direct'

Throws

when args contain fields invalid for direct acquisition

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateAcquireIssuanceCertificateArgs

Validate issuance-specific acquire certificate args.

```ts
export function validateAcquireIssuanceCertificateArgs(args: AcquireCertificateArgs): ValidAcquireIssuanceCertificateArgs 
```

See also: [AcquireCertificateArgs](./wallet.md#interface-acquirecertificateargs), [ValidAcquireIssuanceCertificateArgs](./wallet.md#interface-validacquireissuancecertificateargs)

Returns

ValidAcquireIssuanceCertificateArgs

Argument Details

+ **args**
  + AcquireCertificateArgs with acquisitionProtocol === 'issuance'

Throws

when args contain fields invalid for issuance

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateBase64String

Validate a Base64 string (structure and decoded size).

```ts
export function validateBase64String(s: string, name: string, min?: number, max?: number): string 
```

Returns

validated base64 string

Argument Details

+ **s**
  + base64 string
+ **name**
  + parameter name used in error messages
+ **min**
  + optional minimum decoded byte length
+ **max**
  + optional maximum decoded byte length

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateBasketInsertion

Validate a BasketInsertion structure (basket, custom instructions, tags).

```ts
export function validateBasketInsertion(args?: BasketInsertion): ValidBasketInsertion | undefined 
```

See also: [BasketInsertion](./wallet.md#interface-basketinsertion), [ValidBasketInsertion](./wallet.md#interface-validbasketinsertion)

Returns

ValidBasketInsertion or undefined

Argument Details

+ **args**
  + BasketInsertion or undefined

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateCreateActionArgs

Validate the arguments for creating a new action.

```ts
export function validateCreateActionArgs(args: CreateActionArgs, logger?: WalletLoggerInterface): ValidCreateActionArgs 
```

See also: [CreateActionArgs](./wallet.md#interface-createactionargs), [ValidCreateActionArgs](./wallet.md#interface-validcreateactionargs), [WalletLoggerInterface](./wallet.md#interface-walletloggerinterface)

Returns

validated arguments

Throws

primarily WERR_INVALID_PARAMETER if args are invalid.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateCreateActionInput

Validate a CreateActionInput structure.

Ensures either unlockingScript or unlockingScriptLength is provided and consistent,
validates outpoint, description length, and sequence number.

```ts
export function validateCreateActionInput(i: CreateActionInput): ValidCreateActionInput 
```

See also: [CreateActionInput](./wallet.md#interface-createactioninput), [ValidCreateActionInput](./wallet.md#interface-validcreateactioninput)

Returns

ValidCreateActionInput

Argument Details

+ **i**
  + CreateActionInput to validate

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateCreateActionOptions

Normalize and validate CreateActionOptions, applying defaults for booleans/numbers/arrays.

```ts
export function validateCreateActionOptions(options?: CreateActionOptions): ValidCreateActionOptions 
```

See also: [CreateActionOptions](./wallet.md#interface-createactionoptions), [ValidCreateActionOptions](./wallet.md#interface-validcreateactionoptions)

Returns

ValidCreateActionOptions with defaults applied

Argument Details

+ **options**
  + CreateActionOptions or undefined

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateCreateActionOutput

Validate CreateActionOutput fields: locking script, satoshis, description, basket, tags.

```ts
export function validateCreateActionOutput(o: CreateActionOutput): ValidCreateActionOutput 
```

See also: [CreateActionOutput](./wallet.md#interface-createactionoutput), [ValidCreateActionOutput](./wallet.md#interface-validcreateactionoutput)

Returns

ValidCreateActionOutput

Argument Details

+ **o**
  + CreateActionOutput to validate

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateDiscoverByAttributesArgs

Validate DiscoverByAttributesArgs: attributes, limit, offset, and permission flag.

```ts
export function validateDiscoverByAttributesArgs(args: DiscoverByAttributesArgs): ValidDiscoverByAttributesArgs 
```

See also: [DiscoverByAttributesArgs](./wallet.md#interface-discoverbyattributesargs), [ValidDiscoverByAttributesArgs](./wallet.md#interface-validdiscoverbyattributesargs)

Returns

ValidDiscoverByAttributesArgs

Argument Details

+ **args**
  + DiscoverByAttributesArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateDiscoverByIdentityKeyArgs

Validate DiscoverByIdentityKeyArgs, enforcing identity key length and defaults.

```ts
export function validateDiscoverByIdentityKeyArgs(args: DiscoverByIdentityKeyArgs): ValidDiscoverByIdentityKeyArgs 
```

See also: [DiscoverByIdentityKeyArgs](./wallet.md#interface-discoverbyidentitykeyargs), [ValidDiscoverByIdentityKeyArgs](./wallet.md#interface-validdiscoverbyidentitykeyargs)

Returns

ValidDiscoverByIdentityKeyArgs

Argument Details

+ **args**
  + DiscoverByIdentityKeyArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateInteger

Validate an integer, applying an optional default.

```ts
export function validateInteger(v: number | undefined, name: string, defaultValue?: number, min?: number, max?: number): number 
```

Returns

validated integer

Argument Details

+ **v**
  + value to validate (may be undefined)
+ **name**
  + parameter name used in error messages
+ **defaultValue**
  + value to return when v is undefined
+ **min**
  + optional minimum allowed value
+ **max**
  + optional maximum allowed value

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateInternalizeActionArgs

Validate InternalizeActionArgs: tx, outputs, description, labels, permission flag.

```ts
export function validateInternalizeActionArgs(args: InternalizeActionArgs): ValidInternalizeActionArgs 
```

See also: [InternalizeActionArgs](./wallet.md#interface-internalizeactionargs), [ValidInternalizeActionArgs](./wallet.md#interface-validinternalizeactionargs)

Returns

ValidInternalizeActionArgs

Argument Details

+ **args**
  + InternalizeActionArgs to validate

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateInternalizeOutput

Validate an InternalizeOutput entry.

```ts
export function validateInternalizeOutput(args: InternalizeOutput): ValidInternalizeOutput 
```

See also: [InternalizeOutput](./wallet.md#interface-internalizeoutput), [ValidInternalizeOutput](./wallet.md#interface-validinternalizeoutput)

Returns

ValidInternalizeOutput

Argument Details

+ **args**
  + InternalizeOutput to validate

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateListActionsArgs

```ts
export function validateListActionsArgs(args: ListActionsArgs): ValidListActionsArgs 
```

See also: [ListActionsArgs](./wallet.md#interface-listactionsargs), [ValidListActionsArgs](./wallet.md#interface-validlistactionsargs)

Argument Details

+ **args.labels**
  + An array of labels used to filter actions.
+ **args.labelQueryMode**
  + Optional. Specifies how to match labels (default is any which matches any of the labels).
+ **args.includeLabels**
  + Optional. Whether to include transaction labels in the result set.
+ **args.includeInputs**
  + Optional. Whether to include input details in the result set.
+ **args.includeInputSourceLockingScripts**
  + Optional. Whether to include input source locking scripts in the result set.
+ **args.includeInputUnlockingScripts**
  + Optional. Whether to include input unlocking scripts in the result set.
+ **args.includeOutputs**
  + Optional. Whether to include output details in the result set.
+ **args.includeOutputLockingScripts**
  + Optional. Whether to include output locking scripts in the result set.
+ **args.limit**
  + Optional. The maximum number of transactions to retrieve.
+ **args.offset**
  + Optional. Number of transactions to skip before starting to return the results.
+ **args.seekPermission**
  + — Optional. Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateListCertificatesArgs

Validate ListCertificatesArgs: certifiers, types, paging, and optional privileged reason.

```ts
export function validateListCertificatesArgs(args: ListCertificatesArgs): ValidListCertificatesArgs 
```

See also: [ListCertificatesArgs](./wallet.md#interface-listcertificatesargs), [ValidListCertificatesArgs](./wallet.md#interface-validlistcertificatesargs)

Returns

ValidListCertificatesArgs

Argument Details

+ **args**
  + ListCertificatesArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateListOutputsArgs

```ts
export function validateListOutputsArgs(args: ListOutputsArgs): ValidListOutputsArgs 
```

See also: [ListOutputsArgs](./wallet.md#interface-listoutputsargs), [ValidListOutputsArgs](./wallet.md#interface-validlistoutputsargs)

Argument Details

+ **args.basket**
  + Required. The associated basket name whose outputs should be listed.
+ **args.tags**
  + Optional. Filter outputs based on these tags.
+ **args.tagQueryMode**
  + Optional. Filter mode, defining whether all or any of the tags must match. By default, any tag can match.
+ **args.include**
  + Optional. Whether to include locking scripts (with each output) or entire transactions (as aggregated BEEF, at the top level) in the result. By default, unless specified, neither are returned.
+ **args.includeEntireTransactions**
  + Optional. Whether to include the entire transaction(s) in the result.
+ **args.includeCustomInstructions**
  + Optional. Whether custom instructions should be returned in the result.
+ **args.includeTags**
  + Optional. Whether the tags associated with the output should be returned.
+ **args.includeLabels**
  + Optional. Whether the labels associated with the transaction containing the output should be returned.
+ **args.limit**
  + Optional limit on the number of outputs to return.
+ **args.offset**
  + If positive or zero: Number of outputs to skip before starting to return results, oldest first.
If negative: Outputs are returned newest first and offset of -1 is the newest output.
When using negative offsets, caution is required as new outputs may be added between calls,
potentially causing outputs to be duplicated across calls.
+ **args.seekPermission**
  + — Optional. Whether to seek permission from the user for this operation if required. Default true, will return an error rather than proceed if set to false.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateOptionalInteger

Validate an optional integer. Returns undefined or the validated integer.

```ts
export function validateOptionalInteger(v: number | undefined, name: string, min?: number, max?: number): number | undefined 
```

Returns

validated integer or undefined

Argument Details

+ **v**
  + value to validate (may be undefined)
+ **name**
  + parameter name used in error messages
+ **min**
  + optional minimum value
+ **max**
  + optional maximum value

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateOptionalOutpointString

Validate an optional outpoint string (txid.vout).

```ts
export function validateOptionalOutpointString(outpoint: string | undefined, name: string): string | undefined 
```

Returns

validated outpoint string or undefined

Argument Details

+ **outpoint**
  + outpoint string or undefined
+ **name**
  + parameter name used in error messages

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateOriginator

Validate originator string (trim/lowercase and part length checks).

```ts
export function validateOriginator(s?: string): string | undefined 
```

Returns

normalized originator or undefined

Argument Details

+ **s**
  + originator string or undefined

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateOutpointString

Validate an outpoint string of the form txid.vout.

```ts
export function validateOutpointString(outpoint: string, name: string): string 
```

Returns

normalized outpoint string (validated txid and vout)

Argument Details

+ **outpoint**
  + outpoint string
+ **name**
  + parameter name used in error messages

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validatePositiveIntegerOrZero

Validate a non-negative integer (zero allowed).

```ts
export function validatePositiveIntegerOrZero(v: number, name: string): number 
```

Returns

validated integer

Argument Details

+ **v**
  + value to validate
+ **name**
  + parameter name used in error messages

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateProveCertificateArgs

Validate ProveCertificateArgs including optional certificate fields and reveal list.

```ts
export function validateProveCertificateArgs(args: ProveCertificateArgs): ValidProveCertificateArgs 
```

See also: [ProveCertificateArgs](./wallet.md#interface-provecertificateargs), [ValidProveCertificateArgs](./wallet.md#interface-validprovecertificateargs)

Returns

ValidProveCertificateArgs

Argument Details

+ **args**
  + ProveCertificateArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateRelinquishCertificateArgs

Validate RelinquishCertificateArgs (type, serialNumber, certifier).

```ts
export function validateRelinquishCertificateArgs(args: RelinquishCertificateArgs): ValidRelinquishCertificateArgs 
```

See also: [RelinquishCertificateArgs](./wallet.md#interface-relinquishcertificateargs), [ValidRelinquishCertificateArgs](./wallet.md#interface-validrelinquishcertificateargs)

Returns

ValidRelinquishCertificateArgs

Argument Details

+ **args**
  + RelinquishCertificateArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateRelinquishOutputArgs

Validate RelinquishOutputArgs (basket and output).

```ts
export function validateRelinquishOutputArgs(args: RelinquishOutputArgs): ValidRelinquishOutputArgs 
```

See also: [RelinquishOutputArgs](./wallet.md#interface-relinquishoutputargs), [ValidRelinquishOutputArgs](./wallet.md#interface-validrelinquishoutputargs)

Returns

ValidRelinquishOutputArgs

Argument Details

+ **args**
  + RelinquishOutputArgs

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateSatoshis

Validate a satoshi amount.

```ts
export function validateSatoshis(v: number | undefined, name: string, min?: number): number 
```

Returns

validated satoshi number

Argument Details

+ **v**
  + value to validate (integer number of satoshis)
+ **name**
  + parameter name used in error messages
+ **min**
  + optional minimum allowed satoshi value

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateSignActionArgs

Validate SignActionArgs and apply defaults/flags.

```ts
export function validateSignActionArgs(args: SignActionArgs): ValidSignActionArgs 
```

See also: [SignActionArgs](./wallet.md#interface-signactionargs), [ValidSignActionArgs](./wallet.md#interface-validsignactionargs)

Returns

ValidSignActionArgs

Argument Details

+ **args**
  + SignActionArgs to validate

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateSignActionOptions

Set all default true/false booleans to true or false if undefined.
Set all possibly undefined numbers to their default values.
Set all possibly undefined arrays to empty arrays.
Convert string outpoints to `{ txid: string, vout: number }`

```ts
export function validateSignActionOptions(options?: SignActionOptions): ValidSignActionOptions 
```

See also: [SignActionOptions](./wallet.md#interface-signactionoptions), [ValidSignActionOptions](./wallet.md#interface-validsignactionoptions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateStringLength

Validate string length in bytes for UTF-8 encoded string.

```ts
export function validateStringLength(s: string, name: string, min?: number, max?: number): string 
```

Returns

the original string when valid

Argument Details

+ **s**
  + string to validate
+ **name**
  + parameter name used in error messages
+ **min**
  + optional minimum byte length
+ **max**
  + optional maximum byte length

Throws

WERR_INVALID_PARAMETER when invalid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: validateWalletPayment

Validate wallet payment remittance structure.

```ts
export function validateWalletPayment(args?: WalletPayment): ValidWalletPayment | undefined 
```

See also: [ValidWalletPayment](./wallet.md#interface-validwalletpayment), [WalletPayment](./wallet.md#interface-walletpayment)

Returns

ValidWalletPayment or undefined

Argument Details

+ **args**
  + WalletPayment or undefined

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Types

| | | |
| --- | --- | --- |
| [AcquireCertificateResult](#type-acquirecertificateresult) | [EntityIconURLStringMax500Bytes](#type-entityiconurlstringmax500bytes) | [PositiveIntegerMax10](#type-positiveintegermax10) |
| [AcquisitionProtocol](#type-acquisitionprotocol) | [EntityNameStringMax100Bytes](#type-entitynamestringmax100bytes) | [PositiveIntegerOrZero](#type-positiveintegerorzero) |
| [ActionStatus](#type-actionstatus) | [ErrorCodeString10To40Bytes](#type-errorcodestring10to40bytes) | [ProtocolString5To400Bytes](#type-protocolstring5to400bytes) |
| [AtomicBEEF](#type-atomicbeef) | [ErrorDescriptionString20To200Bytes](#type-errordescriptionstring20to200bytes) | [PubKeyHex](#type-pubkeyhex) |
| [BEEF](#type-beef) | [HexString](#type-hexstring) | [ReviewActionResultStatus](#type-reviewactionresultstatus) |
| [Base64String](#type-base64string) | [ISOTimestampString](#type-isotimestampstring) | [SatoshiValue](#type-satoshivalue) |
| [BasketStringUnder300Bytes](#type-basketstringunder300bytes) | [KeyIDStringUnder800Bytes](#type-keyidstringunder800bytes) | [SecurityLevel](#type-securitylevel) |
| [BooleanDefaultFalse](#type-booleandefaultfalse) | [KeyringRevealer](#type-keyringrevealer) | [SendWithResultStatus](#type-sendwithresultstatus) |
| [BooleanDefaultTrue](#type-booleandefaulttrue) | [LabelStringUnder300Bytes](#type-labelstringunder300bytes) | [TXIDHexString](#type-txidhexstring) |
| [Byte](#type-byte) | [MakeWalletLogger](#type-makewalletlogger) | [TrustSelf](#type-trustself) |
| [CallType](#type-calltype) | [OriginatorDomainNameStringUnder250Bytes](#type-originatordomainnamestringunder250bytes) | [VersionString7To30Bytes](#type-versionstring7to30bytes) |
| [CertificateFieldNameUnder50Bytes](#type-certificatefieldnameunder50bytes) | [OutpointString](#type-outpointstring) | [WalletCounterparty](#type-walletcounterparty) |
| [Counterparty](#type-counterparty) | [OutputTagStringUnder300Bytes](#type-outputtagstringunder300bytes) | [WalletErrorCode](#type-walleterrorcode) |
| [DescriptionString5to2000Bytes](#type-descriptionstring5to2000bytes) | [PositiveInteger](#type-positiveinteger) | [WalletNetwork](#type-walletnetwork) |
| [DescriptionString5to50Bytes](#type-descriptionstring5to50bytes) | [PositiveIntegerDefault10Max10000](#type-positiveintegerdefault10max10000) | [WalletProtocol](#type-walletprotocol) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Type: AcquireCertificateResult

```ts
export type AcquireCertificateResult = WalletCertificate
```

See also: [WalletCertificate](./wallet.md#interface-walletcertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: AcquisitionProtocol

```ts
export type AcquisitionProtocol = "direct" | "issuance"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ActionStatus

```ts
export type ActionStatus = "completed" | "unprocessed" | "sending" | "unproven" | "unsigned" | "nosend" | "nonfinal" | "failed"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: AtomicBEEF

```ts
export type AtomicBEEF = Byte[]
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: BEEF

```ts
export type BEEF = Byte[]
```

See also: [Byte](./wallet.md#type-byte)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: Base64String

```ts
export type Base64String = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: BasketStringUnder300Bytes

```ts
export type BasketStringUnder300Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: BooleanDefaultFalse

```ts
export type BooleanDefaultFalse = boolean
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: BooleanDefaultTrue

```ts
export type BooleanDefaultTrue = boolean
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: Byte

```ts
export type Byte = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: CallType

```ts
export type CallType = keyof typeof calls
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: CertificateFieldNameUnder50Bytes

```ts
export type CertificateFieldNameUnder50Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: Counterparty

```ts
export type Counterparty = PublicKey | PubKeyHex | "self" | "anyone"
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [PublicKey](./primitives.md#class-publickey)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: DescriptionString5to2000Bytes

DescriptionString5to2000Bytes alias type (documented).

```ts
export type DescriptionString5to2000Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: DescriptionString5to50Bytes

```ts
export type DescriptionString5to50Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: EntityIconURLStringMax500Bytes

```ts
export type EntityIconURLStringMax500Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: EntityNameStringMax100Bytes

```ts
export type EntityNameStringMax100Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ErrorCodeString10To40Bytes

```ts
export type ErrorCodeString10To40Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ErrorDescriptionString20To200Bytes

```ts
export type ErrorDescriptionString20To200Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: HexString

```ts
export type HexString = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ISOTimestampString

```ts
export type ISOTimestampString = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: KeyIDStringUnder800Bytes

```ts
export type KeyIDStringUnder800Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: KeyringRevealer

```ts
export type KeyringRevealer = PubKeyHex | "certifier"
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: LabelStringUnder300Bytes

```ts
export type LabelStringUnder300Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: MakeWalletLogger

```ts
export type MakeWalletLogger = (log?: string | WalletLoggerInterface) => WalletLoggerInterface
```

See also: [WalletLoggerInterface](./wallet.md#interface-walletloggerinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: OriginatorDomainNameStringUnder250Bytes

```ts
export type OriginatorDomainNameStringUnder250Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: OutpointString

```ts
export type OutpointString = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: OutputTagStringUnder300Bytes

```ts
export type OutputTagStringUnder300Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: PositiveInteger

```ts
export type PositiveInteger = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: PositiveIntegerDefault10Max10000

```ts
export type PositiveIntegerDefault10Max10000 = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: PositiveIntegerMax10

```ts
export type PositiveIntegerMax10 = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: PositiveIntegerOrZero

```ts
export type PositiveIntegerOrZero = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ProtocolString5To400Bytes

```ts
export type ProtocolString5To400Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: PubKeyHex

```ts
export type PubKeyHex = HexString
```

See also: [HexString](./wallet.md#type-hexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ReviewActionResultStatus

Indicates status of a new Action following a `createAction` or `signAction` in immediate mode:
When `acceptDelayedBroadcast` is falses.

'success': The action has been broadcast and accepted by the bitcoin processing network.
'doulbeSpend': The action has been confirmed to double spend one or more inputs, and by the "first-seen-rule" is the loosing transaction.
'invalidTx': The action was rejected by the processing network as an invalid bitcoin transaction.
'serviceError': The broadcast services are currently unable to reach the bitcoin network. The action is now queued for delayed retries.

```ts
export type ReviewActionResultStatus = "success" | "doubleSpend" | "serviceError" | "invalidTx"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: SatoshiValue

```ts
export type SatoshiValue = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: SecurityLevel


SecurityLevel for protocols.
0 = Silently grants the request with no user interation.
1 = Requires user approval for every application.
2 = Requires user approval per counterparty per application.

```ts
export type SecurityLevel = 0 | 1 | 2
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: SendWithResultStatus

```ts
export type SendWithResultStatus = "unproven" | "sending" | "failed"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: TXIDHexString

```ts
export type TXIDHexString = HexString
```

See also: [HexString](./wallet.md#type-hexstring)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: TrustSelf

Controls behavior of input BEEF validation.

If `known`, input transactions may omit supporting validity proof data for all TXIDs known to this wallet.

If undefined, input BEEFs must be complete and valid.

```ts
export type TrustSelf = "known"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: VersionString7To30Bytes

```ts
export type VersionString7To30Bytes = string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: WalletCounterparty

```ts
export type WalletCounterparty = PubKeyHex | "self" | "anyone"
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: WalletErrorCode

```ts
export type WalletErrorCode = keyof typeof walletErrors
```

See also: [walletErrors](./wallet.md#enum-walleterrors)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: WalletNetwork

```ts
export type WalletNetwork = "mainnet" | "testnet"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: WalletProtocol

```ts
export type WalletProtocol = [
    SecurityLevel,
    ProtocolString5To400Bytes
]
```

See also: [ProtocolString5To400Bytes](./wallet.md#type-protocolstring5to400bytes), [SecurityLevel](./wallet.md#type-securitylevel)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Enums

| |
| --- |
| [SecurityLevels](#enum-securitylevels) |
| [walletErrors](#enum-walleterrors) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Enum: SecurityLevels

```ts
export enum SecurityLevels {
    Silent = 0,
    App = 1,
    Counterparty = 2
}
```

See also: [Counterparty](./wallet.md#type-counterparty)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Enum: walletErrors

```ts
export enum walletErrors {
    unknownError = 1,
    unsupportedAction = 2,
    invalidHmac = 3,
    invalidSignature = 4,
    reviewActions = 5,
    invalidParameter = 6,
    insufficientFunds = 7
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Variables

### Variable: specOpThrowReviewActions

```ts
specOpThrowReviewActions = "a496e747fc3ad5fabdd4ae8f91184e71f87539bd3d962aa2548942faaaf0047a"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
