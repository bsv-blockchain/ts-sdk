# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| |
| --- |
| [AuthMessage](#interface-authmessage) |
| [PeerSession](#interface-peersession) |
| [RequestedCertificateSet](#interface-requestedcertificateset) |
| [RequestedCertificateTypeIDAndFieldList](#interface-requestedcertificatetypeidandfieldlist) |
| [Transport](#interface-transport) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: AuthMessage

```ts
export interface AuthMessage {
    version: string;
    messageType: "initialRequest" | "initialResponse" | "certificateRequest" | "certificateResponse" | "general";
    identityKey: string;
    nonce?: string;
    initialNonce?: string;
    yourNonce?: string;
    certificates?: VerifiableCertificate[];
    requestedCertificates?: RequestedCertificateSet;
    payload?: number[];
    signature?: number[];
}
```

See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [VerifiableCertificate](./auth.md#class-verifiablecertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: PeerSession

```ts
export interface PeerSession {
    isAuthenticated: boolean;
    sessionNonce?: string;
    peerNonce?: string;
    peerIdentityKey?: string;
    lastUpdate: number;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RequestedCertificateSet

```ts
export interface RequestedCertificateSet {
    certifiers: string[];
    types: RequestedCertificateTypeIDAndFieldList;
}
```

See also: [RequestedCertificateTypeIDAndFieldList](./auth.md#interface-requestedcertificatetypeidandfieldlist)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RequestedCertificateTypeIDAndFieldList

```ts
export interface RequestedCertificateTypeIDAndFieldList {
    [certificateTypeID: string]: string[];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Transport

```ts
export interface Transport {
    send: (message: AuthMessage) => Promise<void>;
    onData: (callback: (message: AuthMessage) => Promise<void>) => Promise<void>;
}
```

See also: [AuthMessage](./auth.md#interface-authmessage)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [AuthFetch](#class-authfetch) |
| [Certificate](#class-certificate) |
| [CompletedProtoWallet](#class-completedprotowallet) |
| [MasterCertificate](#class-mastercertificate) |
| [Peer](#class-peer) |
| [SessionManager](#class-sessionmanager) |
| [SimplifiedFetchTransport](#class-simplifiedfetchtransport) |
| [VerifiableCertificate](#class-verifiablecertificate) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: AuthFetch

AuthFetch provides a lightweight fetch client for interacting with servers
over a simplified HTTP transport mechanism. It integrates session management, peer communication,
and certificate handling to enable secure and mutually-authenticated requests.

Additionally, it automatically handles 402 Payment Required responses by creating
and sending BSV payment transactions when necessary.

```ts
export class AuthFetch {
    peers: Record<string, AuthPeer> = {};
    constructor(wallet: WalletInterface, requestedCertificates?: RequestedCertificateSet, sessionManager?: SessionManager) 
    async fetch(url: string, config: SimplifiedFetchRequestOptions = {}): Promise<Response> 
    async sendCertificateRequest(baseUrl: string, certificatesToRequest: RequestedCertificateSet): Promise<VerifiableCertificate[]> 
    public consumeReceivedCertificates(): VerifiableCertificate[] 
}
```

See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [SessionManager](./auth.md#class-sessionmanager), [VerifiableCertificate](./auth.md#class-verifiablecertificate), [WalletInterface](./wallet.md#interface-walletinterface)

#### Constructor

Constructs a new AuthFetch instance.

```ts
constructor(wallet: WalletInterface, requestedCertificates?: RequestedCertificateSet, sessionManager?: SessionManager) 
```
See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [SessionManager](./auth.md#class-sessionmanager), [WalletInterface](./wallet.md#interface-walletinterface)

Argument Details

+ **wallet**
  + The wallet instance for signing and authentication.
+ **requestedCertificates**
  + Optional set of certificates to request from peers.

#### Method consumeReceivedCertificates

Return any certificates we've collected thus far, then clear them out.

```ts
public consumeReceivedCertificates(): VerifiableCertificate[] 
```
See also: [VerifiableCertificate](./auth.md#class-verifiablecertificate)

#### Method fetch

Mutually authenticates and sends a HTTP request to a server.

1) Attempt the request.
2) If 402 Payment Required, automatically create and send payment.
3) Return the final response.

```ts
async fetch(url: string, config: SimplifiedFetchRequestOptions = {}): Promise<Response> 
```

Returns

A promise that resolves with the server's response, structured as a Response-like object.

Argument Details

+ **url**
  + The URL to send the request to.
+ **config**
  + Configuration options for the request, including method, headers, and body.

Throws

Will throw an error if unsupported headers are used or other validation fails.

#### Method sendCertificateRequest

Request Certificates from a Peer

```ts
async sendCertificateRequest(baseUrl: string, certificatesToRequest: RequestedCertificateSet): Promise<VerifiableCertificate[]> 
```
See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [VerifiableCertificate](./auth.md#class-verifiablecertificate)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Certificate

Represents an Identity Certificate as per the Wallet interface specifications.

This class provides methods to serialize and deserialize certificates, as well as signing and verifying the certificate's signature.

```ts
export default class Certificate {
    type: Base64String;
    serialNumber: Base64String;
    subject: PubKeyHex;
    certifier: PubKeyHex;
    revocationOutpoint: OutpointString;
    fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    signature?: HexString;
    constructor(type: Base64String, serialNumber: Base64String, subject: PubKeyHex, certifier: PubKeyHex, revocationOutpoint: OutpointString, fields: Record<CertificateFieldNameUnder50Bytes, string>, signature?: HexString) 
    toBinary(includeSignature: boolean = true): number[] 
    static fromBinary(bin: number[]): Certificate 
    async verify(): Promise<boolean> 
    async sign(certifierWallet: ProtoWallet): Promise<void> 
    static getCertificateFieldEncryptionDetails(fieldName: string, serialNumber?: string): {
        protocolID: WalletProtocol;
        keyID: string;
    } 
}
```

See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [ProtoWallet](./wallet.md#class-protowallet), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletProtocol](./wallet.md#type-walletprotocol), [sign](./compat.md#variable-sign), [verify](./compat.md#variable-verify)

#### Constructor

Constructs a new Certificate.

```ts
constructor(type: Base64String, serialNumber: Base64String, subject: PubKeyHex, certifier: PubKeyHex, revocationOutpoint: OutpointString, fields: Record<CertificateFieldNameUnder50Bytes, string>, signature?: HexString) 
```
See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex)

Argument Details

+ **type**
  + Type identifier for the certificate, base64 encoded string, 32 bytes.
+ **serialNumber**
  + Unique serial number of the certificate, base64 encoded string, 32 bytes.
+ **subject**
  + The public key belonging to the certificate's subject, compressed public key hex string.
+ **certifier**
  + Public key of the certifier who issued the certificate, compressed public key hex string.
+ **revocationOutpoint**
  + The outpoint used to confirm that the certificate has not been revoked (TXID.OutputIndex), as a string.
+ **fields**
  + All the fields present in the certificate.
+ **signature**
  + Certificate signature by the certifier's private key, DER encoded hex string.

#### Property certifier

Public key of the certifier who issued the certificate, compressed public key hex string.

```ts
certifier: PubKeyHex
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Property fields

All the fields present in the certificate, with field names as keys and encrypted field values as Base64 strings.

```ts
fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
```
See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes)

#### Property revocationOutpoint

The outpoint used to confirm that the certificate has not been revoked (TXID.OutputIndex), as a string.

```ts
revocationOutpoint: OutpointString
```
See also: [OutpointString](./wallet.md#type-outpointstring)

#### Property serialNumber

Unique serial number of the certificate, base64 encoded string, 32 bytes.

```ts
serialNumber: Base64String
```
See also: [Base64String](./wallet.md#type-base64string)

#### Property signature

Certificate signature by the certifier's private key, DER encoded hex string.

```ts
signature?: HexString
```
See also: [HexString](./wallet.md#type-hexstring)

#### Property subject

The public key belonging to the certificate's subject, compressed public key hex string.

```ts
subject: PubKeyHex
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Property type

Type identifier for the certificate, base64 encoded string, 32 bytes.

```ts
type: Base64String
```
See also: [Base64String](./wallet.md#type-base64string)

#### Method fromBinary

Deserializes a certificate from binary format.

```ts
static fromBinary(bin: number[]): Certificate 
```
See also: [Certificate](./auth.md#class-certificate)

Returns

- The deserialized Certificate object.

Argument Details

+ **bin**
  + The binary data representing the certificate.

#### Method getCertificateFieldEncryptionDetails

Helper function which retrieves the protocol ID and key ID for certificate field encryption.

For master certificate creation, no serial number is provided because entropy is required
from both the client and the certifier. In this case, the `keyID` is simply the `fieldName`.

For VerifiableCertificates verifier keyring creation, both the serial number and field name are available,
so the `keyID` is formed by concatenating the `serialNumber` and `fieldName`.

```ts
static getCertificateFieldEncryptionDetails(fieldName: string, serialNumber?: string): {
    protocolID: WalletProtocol;
    keyID: string;
} 
```
See also: [WalletProtocol](./wallet.md#type-walletprotocol)

Returns

An object containing:
- `protocolID` (WalletProtocol): The protocol ID for certificate field encryption.
- `keyID` (string): A unique key identifier. It is the `fieldName` if `serialNumber` is undefined,
otherwise it is a combination of `serialNumber` and `fieldName`.

Argument Details

+ **fieldName**
  + The name of the field within the certificate to be encrypted.
+ **serialNumber**
  + (Optional) The serial number of the certificate.

#### Method sign

Signs the certificate using the provided certifier wallet.

```ts
async sign(certifierWallet: ProtoWallet): Promise<void> 
```
See also: [ProtoWallet](./wallet.md#class-protowallet)

Argument Details

+ **certifierWallet**
  + The wallet representing the certifier.

#### Method toBinary

Serializes the certificate into binary format, with or without a signature.

```ts
toBinary(includeSignature: boolean = true): number[] 
```

Returns

- The serialized certificate in binary format.

Argument Details

+ **includeSignature**
  + Whether to include the signature in the serialization.

#### Method verify

Verifies the certificate's signature.

```ts
async verify(): Promise<boolean> 
```

Returns

- A promise that resolves to true if the signature is valid.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: CompletedProtoWallet

```ts
export class CompletedProtoWallet extends ProtoWallet implements WalletInterface {
    keyDeriver: KeyDeriver;
    constructor(rootKeyOrKeyDeriver: PrivateKey | "anyone" | KeyDeriverApi) 
    async isAuthenticated(): Promise<AuthenticatedResult> 
    async waitForAuthentication(): Promise<AuthenticatedResult> 
    async getNetwork(): Promise<GetNetworkResult> 
    async getVersion(): Promise<GetVersionResult> 
    async getPublicKey(args: GetPublicKeyArgs): Promise<{
        publicKey: PubKeyHex;
    }> 
    async createAction(): Promise<CreateActionResult> 
    async signAction(): Promise<SignActionResult> 
    async abortAction(): Promise<AbortActionResult> 
    async listActions(): Promise<ListActionsResult> 
    async internalizeAction(): Promise<InternalizeActionResult> 
    async listOutputs(): Promise<ListOutputsResult> 
    async relinquishOutput(): Promise<RelinquishOutputResult> 
    async acquireCertificate(): Promise<AcquireCertificateResult> 
    async listCertificates(): Promise<ListCertificatesResult> 
    async proveCertificate(): Promise<ProveCertificateResult> 
    async relinquishCertificate(): Promise<RelinquishCertificateResult> 
    async discoverByIdentityKey(): Promise<DiscoverCertificatesResult> 
    async discoverByAttributes(): Promise<DiscoverCertificatesResult> 
    async getHeight(): Promise<GetHeightResult> 
    async getHeaderForHeight(): Promise<GetHeaderResult> 
}
```

See also: [AbortActionResult](./wallet.md#interface-abortactionresult), [AcquireCertificateResult](./wallet.md#type-acquirecertificateresult), [AuthenticatedResult](./wallet.md#interface-authenticatedresult), [CreateActionResult](./wallet.md#interface-createactionresult), [DiscoverCertificatesResult](./wallet.md#interface-discovercertificatesresult), [GetHeaderResult](./wallet.md#interface-getheaderresult), [GetHeightResult](./wallet.md#interface-getheightresult), [GetNetworkResult](./wallet.md#interface-getnetworkresult), [GetPublicKeyArgs](./wallet.md#interface-getpublickeyargs), [GetVersionResult](./wallet.md#interface-getversionresult), [InternalizeActionResult](./wallet.md#interface-internalizeactionresult), [KeyDeriver](./wallet.md#class-keyderiver), [KeyDeriverApi](./wallet.md#interface-keyderiverapi), [ListActionsResult](./wallet.md#interface-listactionsresult), [ListCertificatesResult](./wallet.md#interface-listcertificatesresult), [ListOutputsResult](./wallet.md#interface-listoutputsresult), [PrivateKey](./primitives.md#class-privatekey), [ProtoWallet](./wallet.md#class-protowallet), [ProveCertificateResult](./wallet.md#interface-provecertificateresult), [PubKeyHex](./wallet.md#type-pubkeyhex), [RelinquishCertificateResult](./wallet.md#interface-relinquishcertificateresult), [RelinquishOutputResult](./wallet.md#interface-relinquishoutputresult), [SignActionResult](./wallet.md#interface-signactionresult), [WalletInterface](./wallet.md#interface-walletinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: MasterCertificate

MasterCertificate extends the base Certificate class to manage a master keyring, enabling the creation of verifiable certificates.

It allows for the selective disclosure of certificate fields by creating a `VerifiableCertificate` for a specific verifier.
The `MasterCertificate` can securely decrypt each master key and re-encrypt it for a verifier, creating a customized
keyring containing only the keys necessary for the verifier to access designated fields.

```ts
export class MasterCertificate extends Certificate {
    declare type: Base64String;
    declare serialNumber: Base64String;
    declare subject: PubKeyHex;
    declare certifier: PubKeyHex;
    declare revocationOutpoint: OutpointString;
    declare fields: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    declare signature?: HexString;
    masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    constructor(type: Base64String, serialNumber: Base64String, subject: PubKeyHex, certifier: PubKeyHex, revocationOutpoint: OutpointString, fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, signature?: HexString) 
    static async createCertificateFields(creatorWallet: ProtoWallet, certifierOrSubject: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, string>, privileged?: boolean, privilegedReason?: string): Promise<CreateCertificateFieldsResult> 
    static async createKeyringForVerifier(subjectWallet: ProtoWallet, certifier: WalletCounterparty, verifier: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, fieldsToReveal: string[], masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, serialNumber: Base64String, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
    static async issueCertificateForSubject(certifierWallet: ProtoWallet, subject: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, string>, certificateType: string, getRevocationOutpoint = async (_serial: string): Promise<string> => {
        void _serial;
        return "Certificate revocation not tracked.";
    }, serialNumber?: string): Promise<MasterCertificate> 
    static async decryptFields(subjectOrCertifierWallet: ProtoWallet, masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, counterparty: WalletCounterparty, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
    static async decryptField(subjectOrCertifierWallet: ProtoWallet, masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, fieldName: Base64String, fieldValue: Base64String, counterparty: WalletCounterparty, privileged?: boolean, privilegedReason?: string): Promise<{
        fieldRevelationKey: number[];
        decryptedFieldValue: string;
    }> 
}
```

See also: [Base64String](./wallet.md#type-base64string), [Certificate](./auth.md#class-certificate), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [ProtoWallet](./wallet.md#class-protowallet), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletCounterparty](./wallet.md#type-walletcounterparty)

#### Method createCertificateFields

Encrypts certificate fields for a subject and generates a master keyring.
This method returns a master keyring tied to a specific certifier or subject who will validate
and sign off on the fields, along with the encrypted certificate fields.

```ts
static async createCertificateFields(creatorWallet: ProtoWallet, certifierOrSubject: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, string>, privileged?: boolean, privilegedReason?: string): Promise<CreateCertificateFieldsResult> 
```
See also: [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [ProtoWallet](./wallet.md#class-protowallet), [WalletCounterparty](./wallet.md#type-walletcounterparty)

Returns

A promise resolving to an object containing:
- `certificateFields` {Record<CertificateFieldNameUnder50Bytes, Base64String>}:
The encrypted certificate fields.
- `masterKeyring` {Record<CertificateFieldNameUnder50Bytes, Base64String>}:
The master keyring containing encrypted revelation keys for each field.

Argument Details

+ **creatorWallet**
  + The wallet of the creator responsible for encrypting the fields.
+ **certifierOrSubject**
  + The certifier or subject who will validate the certificate fields.
+ **fields**
  + A record of certificate field names (under 50 bytes) mapped to their values.
+ **privileged**
  + Whether this is a privileged request.
+ **privilegedReason**
  + Reason provided for privileged access, required if this is a privileged operation.   *

#### Method createKeyringForVerifier

Creates a keyring for a verifier, enabling them to decrypt specific certificate fields.
This method decrypts the master field keys for the specified fields and re-encrypts them
for the verifier's identity key. The result is a keyring containing the keys necessary
for the verifier to access the designated fields.

```ts
static async createKeyringForVerifier(subjectWallet: ProtoWallet, certifier: WalletCounterparty, verifier: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, fieldsToReveal: string[], masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, serialNumber: Base64String, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
```
See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [ProtoWallet](./wallet.md#class-protowallet), [WalletCounterparty](./wallet.md#type-walletcounterparty)

Returns

- A keyring mapping field names to encrypted field revelation keys, allowing the verifier to decrypt specified fields.

Argument Details

+ **subjectWallet**
  + The wallet instance of the subject, used to decrypt and re-encrypt field keys.
+ **verifier**
  + The verifier who will receive access to the selectively revealed fields. Can be an identity key as hex, 'anyone', or 'self'.
+ **fieldsToReveal**
  + An array of field names to be revealed to the verifier. Must be a subset of the certificate's fields.
+ **originator**
  + Optional originator identifier, used if additional context is needed for decryption and encryption operations.
+ **privileged**
  + Whether this is a privileged request.
+ **privilegedReason**
  + Reason provided for privileged access, required if this is a privileged operation.   *

Throws

Throws an error if:
- fieldsToReveal is not an array of strings.
- A field in `fieldsToReveal` does not exist in the certificate.
- The decrypted master field key fails to decrypt the corresponding field (indicating an invalid key).

#### Method decryptFields

Decrypts all fields in the MasterCertificate using the subject's or certifier's wallet.

This method allows the subject or certifier to decrypt the `masterKeyring` and retrieve
the encryption keys for each field, which are then used to decrypt the corresponding field values.
The counterparty used for decryption depends on how the certificate fields were created:
- If the certificate is self-signed, the counterparty should be set to 'self'.
- Otherwise, the counterparty should always be the other party involved in the certificate issuance process (the subject or certifier).

```ts
static async decryptFields(subjectOrCertifierWallet: ProtoWallet, masterKeyring: Record<CertificateFieldNameUnder50Bytes, Base64String>, fields: Record<CertificateFieldNameUnder50Bytes, Base64String>, counterparty: WalletCounterparty, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
```
See also: [Base64String](./wallet.md#type-base64string), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [ProtoWallet](./wallet.md#class-protowallet), [WalletCounterparty](./wallet.md#type-walletcounterparty)

Returns

A promise resolving to a record of field names and their decrypted values in plaintext.

Argument Details

+ **subjectOrCertifierWallet**
  + The wallet of the subject or certifier, used to decrypt the master keyring and field values.
+ **masterKeyring**
  + A record containing encrypted keys for each field.
+ **fields**
  + A record of encrypted field names and their values.
+ **counterparty**
  + The counterparty responsible for creating or signing the certificate. For self-signed certificates, use 'self'.
+ **privileged**
  + Whether this is a privileged request.
+ **privilegedReason**
  + Reason provided for privileged access, required if this is a privileged operation.

Throws

Throws an error if the `masterKeyring` is invalid or if decryption fails for any field.

#### Method issueCertificateForSubject

Issues a new MasterCertificate for a specified subject.

This method generates a certificate containing encrypted fields and a keyring
for the subject to decrypt all fields. Each field is encrypted with a randomly
generated symmetric key, which is then encrypted for the subject. The certificate
can also includes a revocation outpoint to manage potential revocation.

```ts
static async issueCertificateForSubject(certifierWallet: ProtoWallet, subject: WalletCounterparty, fields: Record<CertificateFieldNameUnder50Bytes, string>, certificateType: string, getRevocationOutpoint = async (_serial: string): Promise<string> => {
    void _serial;
    return "Certificate revocation not tracked.";
}, serialNumber?: string): Promise<MasterCertificate> 
```
See also: [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [MasterCertificate](./auth.md#class-mastercertificate), [ProtoWallet](./wallet.md#class-protowallet), [WalletCounterparty](./wallet.md#type-walletcounterparty)

Returns

- A signed MasterCertificate instance containing the encrypted fields and subject specific keyring.

Argument Details

+ **certifierWallet**
  + The wallet of the certifier, used to sign the certificate and encrypt field keys.
+ **subject**
  + The subject for whom the certificate is issued.
+ **fields**
  + Unencrypted certificate fields to include, with their names and values.
+ **certificateType**
  + The type of certificate being issued.
+ **getRevocationOutpoint**
  + -
Optional function to obtain a revocation outpoint for the certificate. Defaults to a placeholder.
+ **updateProgress**
  + Optional callback for reporting progress updates during the operation. Defaults to a no-op.

Throws

Throws an error if any operation (e.g., encryption, signing) fails during certificate issuance.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Peer

Represents a peer capable of performing mutual authentication.
Manages sessions, handles authentication handshakes, certificate requests and responses,
and sending and receiving general messages over a transport layer.

This version supports multiple concurrent sessions per peer identityKey.

```ts
export class Peer {
    public sessionManager: SessionManager;
    certificatesToRequest: RequestedCertificateSet;
    constructor(wallet: WalletInterface, transport: Transport, certificatesToRequest?: RequestedCertificateSet, sessionManager?: SessionManager, autoPersistLastSession?: boolean) 
    async toPeer(message: number[], identityKey?: string, maxWaitTime?: number): Promise<void> 
    async requestCertificates(certificatesToRequest: RequestedCertificateSet, identityKey?: string, maxWaitTime = 10000): Promise<void> 
    async getAuthenticatedSession(identityKey?: string, maxWaitTime?: number): Promise<PeerSession> 
    listenForGeneralMessages(callback: (senderPublicKey: string, payload: number[]) => void): number 
    stopListeningForGeneralMessages(callbackID: number): void 
    listenForCertificatesReceived(callback: (senderPublicKey: string, certs: VerifiableCertificate[]) => void): number 
    stopListeningForCertificatesReceived(callbackID: number): void 
    listenForCertificatesRequested(callback: (senderPublicKey: string, requestedCertificates: RequestedCertificateSet) => void): number 
    stopListeningForCertificatesRequested(callbackID: number): void 
    async sendCertificateResponse(verifierIdentityKey: string, certificates: VerifiableCertificate[]): Promise<void> 
}
```

See also: [PeerSession](./auth.md#interface-peersession), [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [SessionManager](./auth.md#class-sessionmanager), [Transport](./auth.md#interface-transport), [VerifiableCertificate](./auth.md#class-verifiablecertificate), [WalletInterface](./wallet.md#interface-walletinterface)

#### Constructor

Creates a new Peer instance

```ts
constructor(wallet: WalletInterface, transport: Transport, certificatesToRequest?: RequestedCertificateSet, sessionManager?: SessionManager, autoPersistLastSession?: boolean) 
```
See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [SessionManager](./auth.md#class-sessionmanager), [Transport](./auth.md#interface-transport), [WalletInterface](./wallet.md#interface-walletinterface)

Argument Details

+ **wallet**
  + The wallet instance used for cryptographic operations.
+ **transport**
  + The transport mechanism used for sending and receiving messages.
+ **certificatesToRequest**
  + Optional set of certificates to request from a peer during the initial handshake.
+ **sessionManager**
  + Optional SessionManager to be used for managing peer sessions.
+ **autoPersistLastSession**
  + Whether to auto-persist the session with the last-interacted-with peer. Defaults to true.

#### Method getAuthenticatedSession

Retrieves an authenticated session for a given peer identity. If no session exists
or the session is not authenticated, initiates a handshake to create or authenticate the session.

- If `identityKey` is provided, we look up any existing session for that identity key.
- If none is found or not authenticated, we do a new handshake.
- If `identityKey` is not provided, but we have a `lastInteractedWithPeer`, we try that key.

```ts
async getAuthenticatedSession(identityKey?: string, maxWaitTime?: number): Promise<PeerSession> 
```
See also: [PeerSession](./auth.md#interface-peersession)

Returns

- A promise that resolves with an authenticated `PeerSession`.

Argument Details

+ **identityKey**
  + The identity public key of the peer.
+ **maxWaitTime**
  + The maximum time in milliseconds to wait for the handshake.

#### Method listenForCertificatesReceived

Registers a callback to listen for certificates received from peers.

```ts
listenForCertificatesReceived(callback: (senderPublicKey: string, certs: VerifiableCertificate[]) => void): number 
```
See also: [VerifiableCertificate](./auth.md#class-verifiablecertificate)

Returns

The ID of the callback listener.

Argument Details

+ **callback**
  + The function to call when certificates are received.

#### Method listenForCertificatesRequested

Registers a callback to listen for certificates requested from peers.

```ts
listenForCertificatesRequested(callback: (senderPublicKey: string, requestedCertificates: RequestedCertificateSet) => void): number 
```
See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset)

Returns

The ID of the callback listener.

Argument Details

+ **callback**
  + The function to call when a certificate request is received

#### Method listenForGeneralMessages

Registers a callback to listen for general messages from peers.

```ts
listenForGeneralMessages(callback: (senderPublicKey: string, payload: number[]) => void): number 
```

Returns

The ID of the callback listener.

Argument Details

+ **callback**
  + The function to call when a general message is received.

#### Method requestCertificates

Sends a request for certificates to a peer.
This method allows a peer to dynamically request specific certificates after
an initial handshake or message has been exchanged.

```ts
async requestCertificates(certificatesToRequest: RequestedCertificateSet, identityKey?: string, maxWaitTime = 10000): Promise<void> 
```
See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset)

Returns

Resolves if the certificate request message is successfully sent.

Argument Details

+ **certificatesToRequest**
  + Specifies the certifiers and types of certificates required from the peer.
+ **identityKey**
  + The identity public key of the peer. If not provided, the current or last session identity is used.
+ **maxWaitTime**
  + Maximum time in milliseconds to wait for the peer session to be authenticated.

Throws

Will throw an error if the peer session is not authenticated or if sending the request fails.

#### Method sendCertificateResponse

Sends a certificate response message containing the specified certificates to a peer.

```ts
async sendCertificateResponse(verifierIdentityKey: string, certificates: VerifiableCertificate[]): Promise<void> 
```
See also: [VerifiableCertificate](./auth.md#class-verifiablecertificate)

Argument Details

+ **verifierIdentityKey**
  + The identity key of the peer requesting the certificates.
+ **certificates**
  + The list of certificates to include in the response.

Throws

Will throw an error if the transport fails to send the message.

#### Method stopListeningForCertificatesReceived

Cancels and unsubscribes a certificatesReceived listener.

```ts
stopListeningForCertificatesReceived(callbackID: number): void 
```

Argument Details

+ **callbackID**
  + The ID of the certificates received callback to cancel.

#### Method stopListeningForCertificatesRequested

Cancels and unsubscribes a certificatesRequested listener.

```ts
stopListeningForCertificatesRequested(callbackID: number): void 
```

Argument Details

+ **callbackID**
  + The ID of the requested certificates callback to cancel.

#### Method stopListeningForGeneralMessages

Removes a general message listener.

```ts
stopListeningForGeneralMessages(callbackID: number): void 
```

Argument Details

+ **callbackID**
  + The ID of the callback to remove.

#### Method toPeer

Sends a general message to a peer, and initiates a handshake if necessary.

```ts
async toPeer(message: number[], identityKey?: string, maxWaitTime?: number): Promise<void> 
```

Argument Details

+ **message**
  + The message payload to send.
+ **identityKey**
  + The identity public key of the peer. If not provided, uses lastInteractedWithPeer (if any).
+ **maxWaitTime**
  + optional max wait time in ms

Throws

Will throw an error if the message fails to send.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SessionManager

Manages sessions for peers, allowing multiple concurrent sessions
per identity key. Primary lookup is always by `sessionNonce`.

```ts
export class SessionManager {
    constructor() 
    addSession(session: PeerSession): void 
    updateSession(session: PeerSession): void 
    getSession(identifier: string): PeerSession | undefined 
    removeSession(session: PeerSession): void 
    hasSession(identifier: string): boolean 
}
```

See also: [PeerSession](./auth.md#interface-peersession)

#### Method addSession

Adds a session to the manager, associating it with its sessionNonce,
and also with its peerIdentityKey (if any).

This does NOT overwrite existing sessions for the same peerIdentityKey,
allowing multiple concurrent sessions for the same peer.

```ts
addSession(session: PeerSession): void 
```
See also: [PeerSession](./auth.md#interface-peersession)

Argument Details

+ **session**
  + The peer session to add.

#### Method getSession

Retrieves a session based on a given identifier, which can be:
 - A sessionNonce, or
 - A peerIdentityKey.

If it is a `sessionNonce`, returns that exact session.
If it is a `peerIdentityKey`, returns the "best" (e.g. most recently updated,
authenticated) session associated with that peer, if any.

```ts
getSession(identifier: string): PeerSession | undefined 
```
See also: [PeerSession](./auth.md#interface-peersession)

Returns

- The matching peer session, or undefined if not found.

Argument Details

+ **identifier**
  + The identifier for the session (sessionNonce or peerIdentityKey).

#### Method hasSession

Checks if a session exists for a given identifier (either sessionNonce or identityKey).

```ts
hasSession(identifier: string): boolean 
```

Returns

- True if the session exists, false otherwise.

Argument Details

+ **identifier**
  + The identifier to check.

#### Method removeSession

Removes a session from the manager by clearing all associated identifiers.

```ts
removeSession(session: PeerSession): void 
```
See also: [PeerSession](./auth.md#interface-peersession)

Argument Details

+ **session**
  + The peer session to remove.

#### Method updateSession

Updates a session in the manager (primarily by re-adding it),
ensuring we record the latest data (e.g., isAuthenticated, lastUpdate, etc.).

```ts
updateSession(session: PeerSession): void 
```
See also: [PeerSession](./auth.md#interface-peersession)

Argument Details

+ **session**
  + The peer session to update.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SimplifiedFetchTransport

Implements an HTTP-specific transport for handling Peer mutual authentication messages.
This class integrates with fetch to send and receive authenticated messages between peers.

```ts
export class SimplifiedFetchTransport implements Transport {
    fetchClient: typeof fetch;
    baseUrl: string;
    constructor(baseUrl: string, fetchClient = defaultFetch) 
    async send(message: AuthMessage): Promise<void> 
    async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> 
    deserializeRequestPayload(payload: number[]): {
        method: string;
        urlPostfix: string;
        headers: Record<string, string>;
        body: number[];
        requestId: string;
    } 
}
```

See also: [AuthMessage](./auth.md#interface-authmessage), [Transport](./auth.md#interface-transport)

#### Constructor

Constructs a new instance of SimplifiedFetchTransport.

```ts
constructor(baseUrl: string, fetchClient = defaultFetch) 
```

Argument Details

+ **baseUrl**
  + The base URL for all HTTP requests made by this transport.
+ **fetchClient**
  + A fetch implementation to use for HTTP requests (default: global fetch).

#### Method deserializeRequestPayload

Deserializes a request payload from a byte array into an HTTP request-like structure.

```ts
deserializeRequestPayload(payload: number[]): {
    method: string;
    urlPostfix: string;
    headers: Record<string, string>;
    body: number[];
    requestId: string;
} 
```

Returns

An object representing the deserialized request, including the method,
URL postfix (path and query string), headers, body, and request ID.

Argument Details

+ **payload**
  + The serialized payload to deserialize.

#### Method onData

Registers a callback to handle incoming messages.
This must be called before sending any messages to ensure responses can be processed.

```ts
async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> 
```
See also: [AuthMessage](./auth.md#interface-authmessage)

Returns

A promise that resolves once the callback is set.

Argument Details

+ **callback**
  + A function to invoke when an incoming AuthMessage is received.

#### Method send

Sends a message to an HTTP server using the transport mechanism.
Handles both general and authenticated message types. For general messages,
the payload is deserialized and sent as an HTTP request. For other message types,
the message is sent as a POST request to the `/auth` endpoint.

```ts
async send(message: AuthMessage): Promise<void> 
```
See also: [AuthMessage](./auth.md#interface-authmessage)

Returns

A promise that resolves when the message is successfully sent.

Argument Details

+ **message**
  + The AuthMessage to send.

Throws

Will throw an error if no listener has been registered via `onData`.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: VerifiableCertificate

VerifiableCertificate extends the Certificate class, adding functionality to manage a verifier-specific keyring.
This keyring allows selective decryption of certificate fields for authorized verifiers.

```ts
export class VerifiableCertificate extends Certificate {
    declare type: Base64String;
    declare serialNumber: Base64String;
    declare subject: PubKeyHex;
    declare certifier: PubKeyHex;
    declare revocationOutpoint: OutpointString;
    declare fields: Record<CertificateFieldNameUnder50Bytes, string>;
    declare signature?: HexString;
    keyring: Record<CertificateFieldNameUnder50Bytes, string>;
    decryptedFields?: Record<CertificateFieldNameUnder50Bytes, Base64String>;
    constructor(type: Base64String, serialNumber: Base64String, subject: PubKeyHex, certifier: PubKeyHex, revocationOutpoint: OutpointString, fields: Record<CertificateFieldNameUnder50Bytes, string>, keyring: Record<CertificateFieldNameUnder50Bytes, string>, signature?: HexString, decryptedFields?: Record<CertificateFieldNameUnder50Bytes, Base64String>) 
    static fromCertificate(certificate: WalletCertificate, keyring: Record<CertificateFieldNameUnder50Bytes, string>): VerifiableCertificate 
    async decryptFields(verifierWallet: ProtoWallet, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
}
```

See also: [Base64String](./wallet.md#type-base64string), [Certificate](./auth.md#class-certificate), [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [ProtoWallet](./wallet.md#class-protowallet), [PubKeyHex](./wallet.md#type-pubkeyhex), [WalletCertificate](./wallet.md#interface-walletcertificate)

#### Method decryptFields

Decrypts selectively revealed certificate fields using the provided keyring and verifier wallet

```ts
async decryptFields(verifierWallet: ProtoWallet, privileged?: boolean, privilegedReason?: string): Promise<Record<CertificateFieldNameUnder50Bytes, string>> 
```
See also: [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [ProtoWallet](./wallet.md#class-protowallet)

Returns

- A promise that resolves to an object where each key is a field name and each value is the decrypted field value as a string.

Argument Details

+ **verifierWallet**
  + The wallet instance of the certificate's verifier, used to decrypt field keys.
+ **privileged**
  + Whether this is a privileged request.
+ **privilegedReason**
  + Reason provided for privileged access, required if this is a privileged operation.

Throws

Throws an error if any of the decryption operations fail, with a message indicating the failure context.

#### Method fromCertificate

```ts
static fromCertificate(certificate: WalletCertificate, keyring: Record<CertificateFieldNameUnder50Bytes, string>): VerifiableCertificate 
```
See also: [CertificateFieldNameUnder50Bytes](./wallet.md#type-certificatefieldnameunder50bytes), [VerifiableCertificate](./auth.md#class-verifiablecertificate), [WalletCertificate](./wallet.md#interface-walletcertificate)

Returns

– A fully-formed instance containing the
original certificate data plus the supplied keyring.

Argument Details

+ **certificate**
  + – The source certificate that was issued and signed by the certifier.
+ **keyring**
  + – A allows the verifier to decrypt selected certificate fields.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

| |
| --- |
| [createNonce](#function-createnonce) |
| [verifyNonce](#function-verifynonce) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Function: createNonce

Creates a nonce derived from a wallet

```ts
export async function createNonce(wallet: WalletInterface, counterparty: WalletCounterparty = "self"): Promise<Base64String> 
```

See also: [Base64String](./wallet.md#type-base64string), [WalletCounterparty](./wallet.md#type-walletcounterparty), [WalletInterface](./wallet.md#interface-walletinterface)

Returns

A random nonce derived with a wallet

Argument Details

+ **counterparty**
  + The counterparty to the nonce creation. Defaults to 'self'.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: verifyNonce

Verifies a nonce derived from a wallet

```ts
export async function verifyNonce(nonce: Base64String, wallet: WalletInterface, counterparty: WalletCounterparty = "self"): Promise<boolean> 
```

See also: [Base64String](./wallet.md#type-base64string), [WalletCounterparty](./wallet.md#type-walletcounterparty), [WalletInterface](./wallet.md#interface-walletinterface)

Returns

The status of the validation

Argument Details

+ **nonce**
  + A nonce to verify as a base64 string.
+ **counterparty**
  + The counterparty to the nonce creation. Defaults to 'self'.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Types

## Enums

## Variables

| |
| --- |
| [getVerifiableCertificates](#variable-getverifiablecertificates) |
| [validateCertificates](#variable-validatecertificates) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: getVerifiableCertificates

```ts
getVerifiableCertificates = async (wallet: WalletInterface, requestedCertificates: RequestedCertificateSet, verifierIdentityKey: string): Promise<VerifiableCertificate[]> => {
    const matchingCertificates = await wallet.listCertificates({
        certifiers: requestedCertificates.certifiers,
        types: Object.keys(requestedCertificates.types)
    });
    return await Promise.all(matchingCertificates.certificates.map(async (certificate) => {
        const { keyringForVerifier } = await wallet.proveCertificate({
            certificate,
            fieldsToReveal: requestedCertificates.types[certificate.type],
            verifier: verifierIdentityKey
        });
        return new VerifiableCertificate(certificate.type, certificate.serialNumber, certificate.subject, certificate.certifier, certificate.revocationOutpoint, certificate.fields, keyringForVerifier, certificate.signature);
    }));
}
```

See also: [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [VerifiableCertificate](./auth.md#class-verifiablecertificate), [WalletInterface](./wallet.md#interface-walletinterface)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: validateCertificates

```ts
validateCertificates = async (verifierWallet: WalletInterface, message: AuthMessage, certificatesRequested?: RequestedCertificateSet): Promise<void> => {
    if ((message.certificates == null) || message.certificates.length === 0) {
        throw new Error("No certificates were provided in the AuthMessage.");
    }
    await Promise.all(message.certificates.map(async (incomingCert: VerifiableCertificate) => {
        if (incomingCert.subject !== message.identityKey) {
            throw new Error(`The subject of one of your certificates ("${incomingCert.subject}") is not the same as the request sender ("${message.identityKey}").`);
        }
        const certToVerify = new VerifiableCertificate(incomingCert.type, incomingCert.serialNumber, incomingCert.subject, incomingCert.certifier, incomingCert.revocationOutpoint, incomingCert.fields, incomingCert.keyring, incomingCert.signature);
        const isValidCert = await certToVerify.verify();
        if (!isValidCert) {
            throw new Error(`The signature for the certificate with serial number ${certToVerify.serialNumber} is invalid!`);
        }
        if (certificatesRequested != null) {
            const { certifiers, types } = certificatesRequested;
            if (!certifiers.includes(certToVerify.certifier)) {
                throw new Error(`Certificate with serial number ${certToVerify.serialNumber} has an unrequested certifier: ${certToVerify.certifier}`);
            }
            const requestedFields = types[certToVerify.type];
            if (requestedFields == null) {
                throw new Error(`Certificate with type ${certToVerify.type} was not requested`);
            }
        }
        await certToVerify.decryptFields(verifierWallet);
    }));
}
```

See also: [AuthMessage](./auth.md#interface-authmessage), [Certificate](./auth.md#class-certificate), [RequestedCertificateSet](./auth.md#interface-requestedcertificateset), [VerifiableCertificate](./auth.md#class-verifiablecertificate), [WalletInterface](./wallet.md#interface-walletinterface), [verify](./compat.md#variable-verify)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
