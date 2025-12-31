# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| | |
| --- | --- |
| [Amount](#interface-amount) | [PeerMessage](#interface-peermessage) |
| [CommsLayer](#interface-commslayer) | [Receipt](#interface-receipt) |
| [ComposeInvoiceInput](#interface-composeinvoiceinput) | [RemittanceEnvelope](#interface-remittanceenvelope) |
| [IdentityLayer](#interface-identitylayer) | [RemittanceManagerConfig](#interface-remittancemanagerconfig) |
| [IdentityVerificationAcknowledgment](#interface-identityverificationacknowledgment) | [RemittanceManagerRuntimeOptions](#interface-remittancemanagerruntimeoptions) |
| [IdentityVerificationRequest](#interface-identityverificationrequest) | [RemittanceManagerState](#interface-remittancemanagerstate) |
| [IdentityVerificationResponse](#interface-identityverificationresponse) | [RemittanceModule](#interface-remittancemodule) |
| [InstrumentBase](#interface-instrumentbase) | [Settlement](#interface-settlement) |
| [Invoice](#interface-invoice) | [Termination](#interface-termination) |
| [LineItem](#interface-lineitem) | [Thread](#interface-thread) |
| [LoggerLike](#interface-loggerlike) | [Unit](#interface-unit) |
| [ModuleContext](#interface-modulecontext) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: Amount

```ts
export interface Amount {
    value: string;
    unit: Unit;
}
```

See also: [Unit](./remittance.md#interface-unit)

#### Property value

Decimal string. Avoid floats at the protocol layer.

```ts
value: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: CommsLayer

Abstract communications layer.

This intentionally mirrors the essential subset of message-box-client / MessageBoxClient.
RemittanceManager never talks directly to HTTP/WebSockets – it only uses this interface.

```ts
export interface CommsLayer {
    sendMessage: (args: {
        recipient: PubKeyHex;
        messageBox: string;
        body: string;
    }, hostOverride?: string) => Promise<string>;
    sendLiveMessage?: (args: {
        recipient: PubKeyHex;
        messageBox: string;
        body: string;
    }, hostOverride?: string) => Promise<string>;
    listMessages: (args: {
        messageBox: string;
        host?: string;
    }) => Promise<PeerMessage[]>;
    acknowledgeMessage: (args: {
        messageIds: string[];
    }) => Promise<void>;
    listenForLiveMessages?: (args: {
        messageBox: string;
        overrideHost?: string;
        onMessage: (msg: PeerMessage) => void;
    }) => Promise<void>;
}
```

See also: [PeerMessage](./remittance.md#interface-peermessage), [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Property acknowledgeMessage

Acknowledges messages (deletes them from the server / inbox).

```ts
acknowledgeMessage: (args: {
    messageIds: string[];
}) => Promise<void>
```

#### Property listMessages

Lists pending messages for a message box.

```ts
listMessages: (args: {
    messageBox: string;
    host?: string;
}) => Promise<PeerMessage[]>
```
See also: [PeerMessage](./remittance.md#interface-peermessage)

#### Property listenForLiveMessages

Optional live listener.

```ts
listenForLiveMessages?: (args: {
    messageBox: string;
    overrideHost?: string;
    onMessage: (msg: PeerMessage) => void;
}) => Promise<void>
```
See also: [PeerMessage](./remittance.md#interface-peermessage)

#### Property sendLiveMessage

Sends a message over the live channel (e.g. WebSocket). Returns the transport messageId.
Implementers may throw if live sending is not possible.
RemittanceManager will fall back to sendMessage where appropriate.

```ts
sendLiveMessage?: (args: {
    recipient: PubKeyHex;
    messageBox: string;
    body: string;
}, hostOverride?: string) => Promise<string>
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Property sendMessage

Sends a message over the store-and-forward channel. Returns the transport messageId.

```ts
sendMessage: (args: {
    recipient: PubKeyHex;
    messageBox: string;
    body: string;
}, hostOverride?: string) => Promise<string>
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ComposeInvoiceInput

```ts
export interface ComposeInvoiceInput {
    note?: string;
    lineItems: Invoice["lineItems"];
    total: Invoice["total"];
    invoiceNumber?: string;
    arbitrary?: Record<string, unknown>;
}
```

See also: [Invoice](./remittance.md#interface-invoice)

#### Property lineItems

Line items.

```ts
lineItems: Invoice["lineItems"]
```
See also: [Invoice](./remittance.md#interface-invoice)

#### Property note

Human note/memo.

```ts
note?: string
```

#### Property total

Total amount.

```ts
total: Invoice["total"]
```
See also: [Invoice](./remittance.md#interface-invoice)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityLayer

The Identity Layer handles identity certificate exchange and verification.
It is optional and pluggable.
Modules can use it to request/verify identity before accepting settlements.

The runtime configuration can be used to determine whether and at what point identity
exchange occurs: before invoicing, before settlement, etc.

Makers and takers can both implement this layer as needed, and request/respond to
identity verification at different points in the protocol.

```ts
export interface IdentityLayer {
    determineCertificatesToRequest: (args: {
        counterparty: PubKeyHex;
        threadId: ThreadId;
    }, ctx: ModuleContext) => Promise<IdentityVerificationRequest>;
    respondToRequest: (args: {
        counterparty: PubKeyHex;
        threadId: ThreadId;
        request: IdentityVerificationRequest;
    }, ctx: ModuleContext) => Promise<{
        action: "respond";
        response: IdentityVerificationResponse;
    } | {
        action: "terminate";
        termination: Termination;
    }>;
    assessReceivedCertificateSufficiency: (counterparty: PubKeyHex, received: IdentityVerificationResponse, threadId: ThreadId) => Promise<IdentityVerificationAcknowledgment | Termination>;
}
```

See also: [IdentityVerificationAcknowledgment](./remittance.md#interface-identityverificationacknowledgment), [IdentityVerificationRequest](./remittance.md#interface-identityverificationrequest), [IdentityVerificationResponse](./remittance.md#interface-identityverificationresponse), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Property assessReceivedCertificateSufficiency

Assess whether received certificates satisfy the requirements for transaction settlement.

```ts
assessReceivedCertificateSufficiency: (counterparty: PubKeyHex, received: IdentityVerificationResponse, threadId: ThreadId) => Promise<IdentityVerificationAcknowledgment | Termination>
```
See also: [IdentityVerificationAcknowledgment](./remittance.md#interface-identityverificationacknowledgment), [IdentityVerificationResponse](./remittance.md#interface-identityverificationresponse), [PubKeyHex](./wallet.md#type-pubkeyhex), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Property determineCertificatesToRequest

Determine which certificates to request from a counterparty.

```ts
determineCertificatesToRequest: (args: {
    counterparty: PubKeyHex;
    threadId: ThreadId;
}, ctx: ModuleContext) => Promise<IdentityVerificationRequest>
```
See also: [IdentityVerificationRequest](./remittance.md#interface-identityverificationrequest), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [ThreadId](./remittance.md#type-threadid)

#### Property respondToRequest

Respond to an incoming identity verification request.

```ts
respondToRequest: (args: {
    counterparty: PubKeyHex;
    threadId: ThreadId;
    request: IdentityVerificationRequest;
}, ctx: ModuleContext) => Promise<{
    action: "respond";
    response: IdentityVerificationResponse;
} | {
    action: "terminate";
    termination: Termination;
}>
```
See also: [IdentityVerificationRequest](./remittance.md#interface-identityverificationrequest), [IdentityVerificationResponse](./remittance.md#interface-identityverificationresponse), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityVerificationAcknowledgment

An identity verification acknowledgment.

A simple ack message indicating that a requested identity verification has been completed successfully.

```ts
export interface IdentityVerificationAcknowledgment {
    kind: "identityVerificationAcknowledgment";
    threadId: ThreadId;
}
```

See also: [ThreadId](./remittance.md#type-threadid)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityVerificationRequest

An identity certificate request.

Contains a list of requested certificate types, fields from each, plus acceptable certifiers.

```ts
export interface IdentityVerificationRequest {
    kind: "identityVerificationRequest";
    threadId: ThreadId;
    request: {
        types: Record<string, string[]>;
        certifiers: PubKeyHex[];
    };
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [ThreadId](./remittance.md#type-threadid)

#### Property request

Details of the requested certificates.

```ts
request: {
    types: Record<string, string[]>;
    certifiers: PubKeyHex[];
}
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: IdentityVerificationResponse

An identity certificate response.

Contains certificates issued by the certifiers named in the corresponding request, with fields revealed to the counterparty.

```ts
export interface IdentityVerificationResponse {
    kind: "identityVerificationResponse";
    threadId: ThreadId;
    certificates: Array<{
        type: Base64String;
        certifier: PubKeyHex;
        subject: PubKeyHex;
        fields: Record<string, Base64String>;
        signature: HexString;
        serialNumber: Base64String;
        revocationOutpoint: OutpointString;
        keyringForVerifier: Record<string, Base64String>;
    }>;
}
```

See also: [Base64String](./wallet.md#type-base64string), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex), [ThreadId](./remittance.md#type-threadid)

#### Property certificates

List of certificates issued by the certifiers named in the corresponding request, with fields revealed to the counterparty.

```ts
certificates: Array<{
    type: Base64String;
    certifier: PubKeyHex;
    subject: PubKeyHex;
    fields: Record<string, Base64String>;
    signature: HexString;
    serialNumber: Base64String;
    revocationOutpoint: OutpointString;
    keyringForVerifier: Record<string, Base64String>;
}>
```
See also: [Base64String](./wallet.md#type-base64string), [HexString](./wallet.md#type-hexstring), [OutpointString](./wallet.md#type-outpointstring), [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: InstrumentBase

Shared commercial/metadata fields for invoice and receipt-like instruments.

NOTE: "payee" and "payer" are identity keys, not addresses.
Payment addresses / scripts are settlement-module concerns.

```ts
export interface InstrumentBase {
    threadId: ThreadId;
    payee: PubKeyHex;
    payer: PubKeyHex;
    note?: string;
    lineItems: LineItem[];
    total: Amount;
    invoiceNumber: string;
    createdAt: UnixMillis;
    arbitrary?: Record<string, unknown>;
}
```

See also: [Amount](./remittance.md#interface-amount), [LineItem](./remittance.md#interface-lineitem), [PubKeyHex](./wallet.md#type-pubkeyhex), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Invoice

Invoice (solicitation) that contains N remittance options.

Each remittance option is keyed by a module id.
The payload for each option is module-defined and opaque to the core.

This is where “UTXO offers” live: a module option payload can include a partial tx template,
UTXO references, scripts, overlay anchors, SPV, etc. The manager does not interpret them.

```ts
export interface Invoice extends InstrumentBase {
    kind: "invoice";
    expiresAt?: UnixMillis;
    options: Record<RemittanceOptionId, unknown>;
}
```

See also: [InstrumentBase](./remittance.md#interface-instrumentbase), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [UnixMillis](./remittance.md#type-unixmillis)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: LineItem

```ts
export interface LineItem {
    id?: string;
    description: string;
    quantity?: string;
    unitPrice?: Amount;
    amount?: Amount;
    metadata?: Record<string, unknown>;
}
```

See also: [Amount](./remittance.md#interface-amount)

#### Property amount

Total amount for the line (optional if derivable).

```ts
amount?: Amount
```
See also: [Amount](./remittance.md#interface-amount)

#### Property quantity

Decimal string, e.g. '1', '2', '0.5'.

```ts
quantity?: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: LoggerLike

Simple logger interface.

```ts
export interface LoggerLike {
    log: (...args: any[]) => void;
    warn: (...args: any[]) => void;
    error: (...args: any[]) => void;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ModuleContext

Context object passed to module methods.

```ts
export interface ModuleContext {
    wallet: WalletInterface;
    originator?: unknown;
    now: () => number;
    logger?: LoggerLike;
}
```

See also: [LoggerLike](./remittance.md#interface-loggerlike), [WalletInterface](./wallet.md#interface-walletinterface)

#### Property originator

Optional originator domain forwarded to wallet methods.

```ts
originator?: unknown
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: PeerMessage

Transport message format expected from the CommsLayer.

It closely matches the message-box-client shapes:
messageId, sender, body, etc.

```ts
export interface PeerMessage {
    messageId: string;
    sender: PubKeyHex;
    recipient: PubKeyHex;
    messageBox: string;
    body: string;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Receipt

Receipt issued by the payee (or service provider).

A receipt could be a PDF, a photo/oroof-of-delivery, a copy of the payment transaction, etc.

A receipt should NOT be issued when a settlement is rejected/failed. Use a Termination instead.

```ts
export interface Receipt {
    kind: "receipt";
    threadId: ThreadId;
    moduleId: RemittanceOptionId;
    optionId: RemittanceOptionId;
    payee: PubKeyHex;
    payer: PubKeyHex;
    createdAt: UnixMillis;
    receiptData: unknown;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RemittanceEnvelope

Protocol envelope.

This is what RemittanceManager serializes into the CommsLayer message body.

```ts
export interface RemittanceEnvelope<K extends RemittanceKind = RemittanceKind, P = unknown> {
    v: 1;
    id: string;
    kind: K;
    threadId: ThreadId;
    createdAt: UnixMillis;
    payload: P;
}
```

See also: [RemittanceKind](./remittance.md#type-remittancekind), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

#### Property id

Envelope id (idempotency key). Not the transport messageId.

```ts
id: string
```

#### Property v

Protocol version.

```ts
v: 1
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RemittanceManagerConfig

```ts
export interface RemittanceManagerConfig {
    messageBox?: string;
    originator?: OriginatorDomainNameStringUnder250Bytes;
    logger?: LoggerLike;
    options?: Partial<RemittanceManagerRuntimeOptions>;
    remittanceModules: Array<RemittanceModule<any, any, any>>;
    identityLayer?: IdentityLayer;
    stateSaver?: (state: RemittanceManagerState) => Promise<void> | void;
    stateLoader?: () => Promise<RemittanceManagerState | undefined> | RemittanceManagerState | undefined;
    now?: () => UnixMillis;
    threadIdFactory?: () => ThreadId;
}
```

See also: [IdentityLayer](./remittance.md#interface-identitylayer), [LoggerLike](./remittance.md#interface-loggerlike), [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes), [RemittanceManagerRuntimeOptions](./remittance.md#interface-remittancemanagerruntimeoptions), [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate), [RemittanceModule](./remittance.md#interface-remittancemodule), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

#### Property identityLayer

Optional identity layer for exchanging certificates before transacting.

```ts
identityLayer?: IdentityLayer
```
See also: [IdentityLayer](./remittance.md#interface-identitylayer)

#### Property logger

Provide a logger. If omitted, RemittanceManager stays quiet.

The manager itself never throws on network/message parsing errors; it will mark threads as errored.

```ts
logger?: LoggerLike
```
See also: [LoggerLike](./remittance.md#interface-loggerlike)

#### Property messageBox

Optional message box name to use for communication.

```ts
messageBox?: string
```

#### Property now

Injectable clock for tests.

```ts
now?: () => UnixMillis
```
See also: [UnixMillis](./remittance.md#type-unixmillis)

#### Property options

Runtime options that influence core behavior.

```ts
options?: Partial<RemittanceManagerRuntimeOptions>
```
See also: [RemittanceManagerRuntimeOptions](./remittance.md#interface-remittancemanagerruntimeoptions)

#### Property originator

Optional originator forwarded to wallet APIs.

```ts
originator?: OriginatorDomainNameStringUnder250Bytes
```
See also: [OriginatorDomainNameStringUnder250Bytes](./wallet.md#type-originatordomainnamestringunder250bytes)

#### Property remittanceModules

Modules (remittance options) available to this manager.

```ts
remittanceModules: Array<RemittanceModule<any, any, any>>
```
See also: [RemittanceModule](./remittance.md#interface-remittancemodule)

#### Property stateLoader

Load manager state (threads).

```ts
stateLoader?: () => Promise<RemittanceManagerState | undefined> | RemittanceManagerState | undefined
```
See also: [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate)

#### Property stateSaver

Persist manager state (threads).

```ts
stateSaver?: (state: RemittanceManagerState) => Promise<void> | void
```
See also: [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate)

#### Property threadIdFactory

Injectable thread id factory for tests.

```ts
threadIdFactory?: () => ThreadId
```
See also: [ThreadId](./remittance.md#type-threadid)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RemittanceManagerRuntimeOptions

```ts
export interface RemittanceManagerRuntimeOptions {
    identityOptions?: {
        makerRequestIdentity?: "never" | "beforeInvoicing" | "beforeSettlement";
        takerRequestIdentity?: "never" | "beforeInvoicing" | "beforeSettlement";
    };
    receiptProvided: boolean;
    autoIssueReceipt: boolean;
    invoiceExpirySeconds: number;
    identityTimeoutMs: number;
    identityPollIntervalMs: number;
}
```

#### Property autoIssueReceipt

If true, manager auto-sends receipts as soon as a settlement is processed.

```ts
autoIssueReceipt: boolean
```

#### Property identityOptions

Identity verification options.

```ts
identityOptions?: {
    makerRequestIdentity?: "never" | "beforeInvoicing" | "beforeSettlement";
    takerRequestIdentity?: "never" | "beforeInvoicing" | "beforeSettlement";
}
```

#### Property identityPollIntervalMs

Identity verification poll interval in milliseconds.

```ts
identityPollIntervalMs: number
```

#### Property identityTimeoutMs

Identity verification timeout in milliseconds.

```ts
identityTimeoutMs: number
```

#### Property invoiceExpirySeconds

Invoice expiry in seconds, or -1 for no expiry.

```ts
invoiceExpirySeconds: number
```

#### Property receiptProvided

If true, payees are expected to send receipts.

```ts
receiptProvided: boolean
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RemittanceManagerState

```ts
export interface RemittanceManagerState {
    v: 1;
    threads: Thread[];
    defaultPaymentOptionId?: string;
}
```

See also: [Thread](./remittance.md#interface-thread)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: RemittanceModule

A remittance module implements a specific settlement system.

The RemittanceManager core uses module ids as the only “capability mechanism”:
if an invoice contains an option with module id X, a payer can only satisfy it
if they are configured with module X.

```ts
export interface RemittanceModule<TOptionTerms = unknown, TSettlementArtifact = unknown, TReceiptData = unknown> {
    id: RemittanceOptionId;
    name: string;
    allowUnsolicitedSettlements: boolean;
    createOption?: (args: {
        threadId: ThreadId;
        invoice: Invoice;
    }, ctx: ModuleContext) => Promise<TOptionTerms>;
    buildSettlement: (args: {
        threadId: ThreadId;
        invoice?: Invoice;
        option: TOptionTerms;
        note?: string;
    }, ctx: ModuleContext) => Promise<{
        action: "settle";
        artifact: TSettlementArtifact;
    } | {
        action: "terminate";
        termination: Termination;
    }>;
    acceptSettlement: (args: {
        threadId: ThreadId;
        invoice?: Invoice;
        settlement: TSettlementArtifact;
        sender: PubKeyHex;
    }, ctx: ModuleContext) => Promise<{
        action: "accept";
        receiptData?: TReceiptData;
    } | {
        action: "terminate";
        termination: Termination;
    }>;
    processReceipt?: (args: {
        threadId: ThreadId;
        invoice?: Invoice;
        receiptData: TReceiptData;
        sender: PubKeyHex;
    }, ctx: ModuleContext) => Promise<void>;
    processTermination?: (args: {
        threadId: ThreadId;
        invoice?: Invoice;
        settlement?: Settlement;
        termination: Termination;
        sender: PubKeyHex;
    }, ctx: ModuleContext) => Promise<void>;
}
```

See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [Settlement](./remittance.md#interface-settlement), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Property acceptSettlement

Accepts a settlement artifact on the payee side.

The module should validate and internalize/store whatever it needs.
The manager will wrap the returned value as receipt.receiptData.

If the settlement is invalid, the module should return either a termination or receiptData (possibly with a refund or indicating the failure), depending how the module chooses to handle it.

```ts
acceptSettlement: (args: {
    threadId: ThreadId;
    invoice?: Invoice;
    settlement: TSettlementArtifact;
    sender: PubKeyHex;
}, ctx: ModuleContext) => Promise<{
    action: "accept";
    receiptData?: TReceiptData;
} | {
    action: "terminate";
    termination: Termination;
}>
```
See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Property allowUnsolicitedSettlements

Whether this module allows unsolicited settlements (i.e. settlement without an invoice).

If true, the payer can build a settlement without an invoice being provided by the payee.
In this case, the option terms provided to `buildSettlement` may be used in lieu of an invoice.

If false, an invoice must always be provided to `buildSettlement`.

```ts
allowUnsolicitedSettlements: boolean
```

#### Property buildSettlement

Builds the settlement artifact for a chosen option.

For UTXO settlement systems, this is usually a transaction (or partially-signed tx) to be broadcast.

For unsolicited settlements, an invoice may not always be provided and the option terms may be used in lieu of an invoice to settle against.

For example, the option terms may include a tx template with outputs to fulfill the settlement.

When `allowUnsolicitedSettlements` is false, an invoice will always be provided.

Termination can be returned to abort the protocol with a reason.

```ts
buildSettlement: (args: {
    threadId: ThreadId;
    invoice?: Invoice;
    option: TOptionTerms;
    note?: string;
}, ctx: ModuleContext) => Promise<{
    action: "settle";
    artifact: TSettlementArtifact;
} | {
    action: "terminate";
    termination: Termination;
}>
```
See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Property createOption

Creates module-defined option terms that will be embedded into the invoice.

In UTXO-ish offers, these option terms may include a partially-signed transaction template.

Optional because some modules may not require any option data, or may only support unsolicited settlements.

However, a module MAY still create option terms/invoices even if it can sometimes support unsolicited settlements.

```ts
createOption?: (args: {
    threadId: ThreadId;
    invoice: Invoice;
}, ctx: ModuleContext) => Promise<TOptionTerms>
```
See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [ThreadId](./remittance.md#type-threadid)

#### Property id

Unique id used as the invoice.options key and as settlement.moduleId.

```ts
id: RemittanceOptionId
```
See also: [RemittanceOptionId](./remittance.md#type-remittanceoptionid)

#### Property name

Human-readable name for UIs.

```ts
name: string
```

#### Property processReceipt

Processes a receipt on the payer side.

This is where a module can automatically internalize a refund, mark a local order fulfilled, receive goods and services, etc.

```ts
processReceipt?: (args: {
    threadId: ThreadId;
    invoice?: Invoice;
    receiptData: TReceiptData;
    sender: PubKeyHex;
}, ctx: ModuleContext) => Promise<void>
```
See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [ThreadId](./remittance.md#type-threadid)

#### Property processTermination

Processes a termination on either side.

This is where a module can clean up any internal state, reverse provisional actions, take refunds, etc.

```ts
processTermination?: (args: {
    threadId: ThreadId;
    invoice?: Invoice;
    settlement?: Settlement;
    termination: Termination;
    sender: PubKeyHex;
}, ctx: ModuleContext) => Promise<void>
```
See also: [Invoice](./remittance.md#interface-invoice), [ModuleContext](./remittance.md#interface-modulecontext), [PubKeyHex](./wallet.md#type-pubkeyhex), [Settlement](./remittance.md#interface-settlement), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Settlement

A settlement attempt.

This is module-agnostic: "artifact" can be a transaction, a partial transaction,
a stablecoin transfer result, even a fiat card-payment approval code, etc.

```ts
export interface Settlement {
    kind: "settlement";
    threadId: ThreadId;
    moduleId: RemittanceOptionId;
    optionId: RemittanceOptionId;
    sender: PubKeyHex;
    createdAt: UnixMillis;
    artifact: unknown;
    note?: string;
}
```

See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Termination

Termination details for failed operations.

```ts
export interface Termination {
    code: string;
    message: string;
    details?: unknown;
}
```

#### Property code

Reason code (module-specific).

```ts
code: string
```

#### Property details

Optional module-specific details or refund information.

```ts
details?: unknown
```

#### Property message

Human-readable message.

```ts
message: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Thread

```ts
export interface Thread {
    threadId: ThreadId;
    counterparty: PubKeyHex;
    myRole: "maker" | "taker";
    theirRole: "maker" | "taker";
    createdAt: UnixMillis;
    updatedAt: UnixMillis;
    processedMessageIds: string[];
    protocolLog: Array<{
        direction: "in" | "out";
        envelope: RemittanceEnvelope;
        transportMessageId: string;
    }>;
    identity: {
        certsSent: IdentityVerificationResponse["certificates"];
        certsReceived: IdentityVerificationResponse["certificates"];
        requestSent: boolean;
        responseSent: boolean;
        acknowledgmentSent: boolean;
        acknowledgmentReceived: boolean;
    };
    invoice?: Invoice;
    settlement?: Settlement;
    receipt?: Receipt;
    termination?: Termination;
    flags: {
        hasIdentified: boolean;
        hasInvoiced: boolean;
        hasPaid: boolean;
        hasReceipted: boolean;
        error: boolean;
    };
    lastError?: {
        message: string;
        at: UnixMillis;
    };
}
```

See also: [IdentityVerificationResponse](./remittance.md#interface-identityverificationresponse), [Invoice](./remittance.md#interface-invoice), [PubKeyHex](./wallet.md#type-pubkeyhex), [Receipt](./remittance.md#interface-receipt), [RemittanceEnvelope](./remittance.md#interface-remittanceenvelope), [Settlement](./remittance.md#interface-settlement), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid), [UnixMillis](./remittance.md#type-unixmillis)

#### Property processedMessageIds

Transport messageIds processed for this thread (dedupe across retries).

```ts
processedMessageIds: string[]
```

#### Property protocolLog

Protocol envelopes received/sent (for debugging/audit).

```ts
protocolLog: Array<{
    direction: "in" | "out";
    envelope: RemittanceEnvelope;
    transportMessageId: string;
}>
```
See also: [RemittanceEnvelope](./remittance.md#interface-remittanceenvelope)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Unit

```ts
export interface Unit {
    namespace: string;
    code: string;
    decimals?: number;
}
```

#### Property code

Unit code within the namespace, e.g. 'sat', 'USD', 'mnee'.

```ts
code: string
```

#### Property decimals

Optional decimal places for display/normalization.

```ts
decimals?: number
```

#### Property namespace

Namespace for disambiguation, e.g. 'bsv', 'iso4217', 'token'.

```ts
namespace: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [InvoiceHandle](#class-invoicehandle) |
| [RemittanceManager](#class-remittancemanager) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: InvoiceHandle

A lightweight wrapper around a thread's invoice, with convenience methods.

```ts
export class InvoiceHandle {
    constructor(private readonly manager: RemittanceManager, public readonly threadId: ThreadId) 
    get thread(): Thread 
    get invoice(): Invoice 
    async pay(optionId?: string): Promise<Receipt | Termination | undefined> 
    async waitForReceipt(opts?: {
        timeoutMs?: number;
        pollIntervalMs?: number;
    }): Promise<Receipt | Termination> 
}
```

See also: [Invoice](./remittance.md#interface-invoice), [Receipt](./remittance.md#interface-receipt), [RemittanceManager](./remittance.md#class-remittancemanager), [Termination](./remittance.md#interface-termination), [Thread](./remittance.md#interface-thread), [ThreadId](./remittance.md#type-threadid)

#### Method pay

Pays the invoice using the selected remittance option.

```ts
async pay(optionId?: string): Promise<Receipt | Termination | undefined> 
```
See also: [Receipt](./remittance.md#interface-receipt), [Termination](./remittance.md#interface-termination)

#### Method waitForReceipt

Waits for a receipt for this invoice's thread.

```ts
async waitForReceipt(opts?: {
    timeoutMs?: number;
    pollIntervalMs?: number;
}): Promise<Receipt | Termination> 
```
See also: [Receipt](./remittance.md#interface-receipt), [Termination](./remittance.md#interface-termination)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: RemittanceManager

RemittanceManager.

Responsibilities:
- message transport via CommsLayer
- thread lifecycle and persistence (via stateSaver/stateLoader)
- invoice creation and transmission (when invoices are used)
- settlement and settlement routing to the appropriate module
- receipt issuance and receipt routing to the appropriate module
- identity and identity certificate exchange (when identity layer is used)

Non-responsibilities (left to modules):
- transaction structure (whether UTXO “offer” formats, token logic, BRC-98/99 specifics, etc.)
- validation rules for settlement (e.g. partial tx templates, UTXO validity, etc.)
- on-chain broadcasting strategy or non-chain settlement specifics (like legacy payment protocols)
- Providing option terms for invoices
- Building settlement artifacts
- Accepting/rejecting settlements
- Deciding which identity certificates to request
- Deciding about sufficiency of identity certificates
- Preparing/processing specific receipt formats
- Internal business logic like order fulfillment, refunds, etc.

```ts
export class RemittanceManager {
    readonly wallet: WalletInterface;
    readonly comms: CommsLayer;
    readonly cfg: RemittanceManagerConfig;
    threads: Thread[];
    constructor(cfg: RemittanceManagerConfig, wallet: WalletInterface, commsLayer: CommsLayer, threads: Thread[] = []) 
    async init(): Promise<void> 
    preselectPaymentOption(optionId: string): void 
    saveState(): RemittanceManagerState 
    loadState(state: RemittanceManagerState): void 
    async persistState(): Promise<void> 
    async syncThreads(hostOverride?: string): Promise<void> 
    async sendInvoice(to: PubKeyHex, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> 
    async sendInvoiceForThread(threadId: ThreadId, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> 
    findInvoicesPayable(counterparty?: PubKeyHex): InvoiceHandle[] 
    findReceivableInvoices(counterparty?: PubKeyHex): InvoiceHandle[] 
    async pay(threadId: ThreadId, optionId?: string, hostOverride?: string): Promise<Receipt | Termination | undefined> 
    async waitForReceipt(threadId: ThreadId, opts: {
        timeoutMs?: number;
        pollIntervalMs?: number;
    } = {}): Promise<Receipt | Termination> 
    async sendUnsolicitedSettlement(to: PubKeyHex, args: {
        moduleId: RemittanceOptionId;
        option: unknown;
        optionId?: RemittanceOptionId;
        note?: string;
    }, hostOverride?: string): Promise<ThreadId> 
    getThread(threadId: ThreadId): Thread | undefined 
    getThreadOrThrow(threadId: ThreadId): Thread 
}
```

See also: [CommsLayer](./remittance.md#interface-commslayer), [ComposeInvoiceInput](./remittance.md#interface-composeinvoiceinput), [InvoiceHandle](./remittance.md#class-invoicehandle), [PubKeyHex](./wallet.md#type-pubkeyhex), [Receipt](./remittance.md#interface-receipt), [RemittanceManagerConfig](./remittance.md#interface-remittancemanagerconfig), [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [Termination](./remittance.md#interface-termination), [Thread](./remittance.md#interface-thread), [ThreadId](./remittance.md#type-threadid), [WalletInterface](./wallet.md#interface-walletinterface)

#### Property threads

Mutable threads list (persisted via stateSaver).

```ts
threads: Thread[]
```
See also: [Thread](./remittance.md#interface-thread)

#### Method findInvoicesPayable

Returns invoice handles that this manager can pay (we are the taker/payer).

```ts
findInvoicesPayable(counterparty?: PubKeyHex): InvoiceHandle[] 
```
See also: [InvoiceHandle](./remittance.md#class-invoicehandle), [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Method findReceivableInvoices

Returns invoice handles that we issued and are waiting to receive settlement for.

```ts
findReceivableInvoices(counterparty?: PubKeyHex): InvoiceHandle[] 
```
See also: [InvoiceHandle](./remittance.md#class-invoicehandle), [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Method getThread

Returns a thread by id (if present).

```ts
getThread(threadId: ThreadId): Thread | undefined 
```
See also: [Thread](./remittance.md#interface-thread), [ThreadId](./remittance.md#type-threadid)

#### Method getThreadOrThrow

Returns a thread by id or throws.

Public so helper handles (e.g. InvoiceHandle) can call it.

```ts
getThreadOrThrow(threadId: ThreadId): Thread 
```
See also: [Thread](./remittance.md#interface-thread), [ThreadId](./remittance.md#type-threadid)

#### Method init

Loads persisted state from cfg.stateLoader (if provided).

Safe to call multiple times.

```ts
async init(): Promise<void> 
```

#### Method loadState

Loads state from an object previously produced by saveState().

```ts
loadState(state: RemittanceManagerState): void 
```
See also: [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate)

#### Method pay

Pays an invoice by selecting a remittance option and sending a settlement message.

If receipts are enabled (receiptProvided), this method will optionally wait for a receipt.

```ts
async pay(threadId: ThreadId, optionId?: string, hostOverride?: string): Promise<Receipt | Termination | undefined> 
```
See also: [Receipt](./remittance.md#interface-receipt), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

#### Method persistState

Persists current state via cfg.stateSaver (if provided).

```ts
async persistState(): Promise<void> 
```

#### Method preselectPaymentOption

Sets a default payment option (module id) to use when paying invoices.

```ts
preselectPaymentOption(optionId: string): void 
```

#### Method saveState

Returns an immutable snapshot of current manager state suitable for persistence.

```ts
saveState(): RemittanceManagerState 
```
See also: [RemittanceManagerState](./remittance.md#interface-remittancemanagerstate)

#### Method sendInvoice

Creates, records, and sends an invoice to a counterparty.

Returns a handle you can use to wait for payment/receipt.

```ts
async sendInvoice(to: PubKeyHex, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> 
```
See also: [ComposeInvoiceInput](./remittance.md#interface-composeinvoiceinput), [InvoiceHandle](./remittance.md#class-invoicehandle), [PubKeyHex](./wallet.md#type-pubkeyhex)

#### Method sendInvoiceForThread

Sends an invoice for an existing thread, e.g. after an identity request was received.

```ts
async sendInvoiceForThread(threadId: ThreadId, input: ComposeInvoiceInput, hostOverride?: string): Promise<InvoiceHandle> 
```
See also: [ComposeInvoiceInput](./remittance.md#interface-composeinvoiceinput), [InvoiceHandle](./remittance.md#class-invoicehandle), [ThreadId](./remittance.md#type-threadid)

#### Method sendUnsolicitedSettlement

Sends an unsolicited settlement to a counterparty.

```ts
async sendUnsolicitedSettlement(to: PubKeyHex, args: {
    moduleId: RemittanceOptionId;
    option: unknown;
    optionId?: RemittanceOptionId;
    note?: string;
}, hostOverride?: string): Promise<ThreadId> 
```
See also: [PubKeyHex](./wallet.md#type-pubkeyhex), [RemittanceOptionId](./remittance.md#type-remittanceoptionid), [ThreadId](./remittance.md#type-threadid)

#### Method syncThreads

Syncs threads by fetching pending messages from the comms layer and processing them.

Processing is idempotent using transport messageIds tracked per thread.
Messages are acknowledged after they are successfully applied to local state.

```ts
async syncThreads(hostOverride?: string): Promise<void> 
```

#### Method waitForReceipt

Waits for a receipt to arrive for a thread.

Uses polling via syncThreads because live listeners are optional.

```ts
async waitForReceipt(threadId: ThreadId, opts: {
    timeoutMs?: number;
    pollIntervalMs?: number;
} = {}): Promise<Receipt | Termination> 
```
See also: [Receipt](./remittance.md#interface-receipt), [Termination](./remittance.md#interface-termination), [ThreadId](./remittance.md#type-threadid)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

## Types

| |
| --- |
| [RemittanceKind](#type-remittancekind) |
| [RemittanceOptionId](#type-remittanceoptionid) |
| [ThreadId](#type-threadid) |
| [UnixMillis](#type-unixmillis) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Type: RemittanceKind

Protocol envelope kinds.
Everything runs in “threads” and carries a threadId.

```ts
export type RemittanceKind = "invoice" | "identityVerificationRequest" | "identityVerificationResponse" | "identityVerificationAcknowledgment" | "settlement" | "receipt" | "termination"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: RemittanceOptionId

```ts
export type RemittanceOptionId = Base64String
```

See also: [Base64String](./wallet.md#type-base64string)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: ThreadId

Types for core Remittance protocol.

The goal is to keep the core protocol:
- UTXO-friendly (transactions and partial transactions can be carried as artifacts)
- Denomination-agnostic (amounts are typed, not forced to satoshis)
- Module-oriented (remittance option payloads are opaque to the core)

```ts
export type ThreadId = Base64String
```

See also: [Base64String](./wallet.md#type-base64string)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: UnixMillis

```ts
export type UnixMillis = number
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Enums

## Variables

| |
| --- |
| [DEFAULT_REMITTANCE_MESSAGEBOX](#variable-default_remittance_messagebox) |
| [SAT_UNIT](#variable-sat_unit) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: DEFAULT_REMITTANCE_MESSAGEBOX

```ts
DEFAULT_REMITTANCE_MESSAGEBOX = "remittance_inbox"
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: SAT_UNIT

```ts
SAT_UNIT: Unit = { namespace: "bsv", code: "sat", decimals: 0 }
```

See also: [Unit](./remittance.md#interface-unit)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
