# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| |
| --- |
| [AdmittanceInstructions](#interface-admittanceinstructions) |
| [LookupQuestion](#interface-lookupquestion) |
| [LookupResolverConfig](#interface-lookupresolverconfig) |
| [OverlayBroadcastFacilitator](#interface-overlaybroadcastfacilitator) |
| [OverlayLookupFacilitator](#interface-overlaylookupfacilitator) |
| [SHIPBroadcasterConfig](#interface-shipbroadcasterconfig) |
| [TaggedBEEF](#interface-taggedbeef) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: AdmittanceInstructions

Instructs the Overlay Services Engine about which outputs to admit and which previous outputs to retain. Returned by a Topic Manager.

```ts
export interface AdmittanceInstructions {
    outputsToAdmit: number[];
    coinsToRetain: number[];
    coinsRemoved?: number[];
}
```

#### Property coinsRemoved

The indices of all inputs from the provided transaction which reference previously-admitted outputs,
which are now considered spent and have been removed from the managed topic.

```ts
coinsRemoved?: number[]
```

#### Property coinsToRetain

The indices of all inputs from the provided transaction which spend previously-admitted outputs that should be retained for historical record-keeping.

```ts
coinsToRetain: number[]
```

#### Property outputsToAdmit

The indices of all admissible outputs into the managed topic from the provided transaction.

```ts
outputsToAdmit: number[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: LookupQuestion

The question asked to the Overlay Services Engine when a consumer of state wishes to look up information.

```ts
export interface LookupQuestion {
    service: string;
    query: unknown;
}
```

#### Property query

The query which will be forwarded to the Lookup Service.
Its type depends on that prescribed by the Lookup Service employed.

```ts
query: unknown
```

#### Property service

The identifier for a Lookup Service which the person asking the question wishes to use.

```ts
service: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: LookupResolverConfig

Configuration options for the Lookup resolver.

```ts
export interface LookupResolverConfig {
    networkPreset?: "mainnet" | "testnet" | "local";
    facilitator?: OverlayLookupFacilitator;
    slapTrackers?: string[];
    hostOverrides?: Record<string, string[]>;
    additionalHosts?: Record<string, string[]>;
}
```

See also: [OverlayLookupFacilitator](./overlay-tools.md#interface-overlaylookupfacilitator)

#### Property additionalHosts

Map of lookup service names to arrays of hosts to use in addition to resolving via SLAP.

```ts
additionalHosts?: Record<string, string[]>
```

#### Property facilitator

The facilitator used to make requests to Overlay Services hosts.

```ts
facilitator?: OverlayLookupFacilitator
```
See also: [OverlayLookupFacilitator](./overlay-tools.md#interface-overlaylookupfacilitator)

#### Property hostOverrides

Map of lookup service names to arrays of hosts to use in place of resolving via SLAP.

```ts
hostOverrides?: Record<string, string[]>
```

#### Property networkPreset

The network preset to use, unless other options override it.
- mainnet: use mainnet SLAP trackers and HTTPS facilitator
- testnet: use testnet SLAP trackers and HTTPS facilitator
- local: directly query from localhost:8080 and a facilitator that permits plain HTTP

```ts
networkPreset?: "mainnet" | "testnet" | "local"
```

#### Property slapTrackers

The list of SLAP trackers queried to resolve Overlay Services hosts for a given lookup service.

```ts
slapTrackers?: string[]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: OverlayBroadcastFacilitator

Facilitates transaction broadcasts that return STEAK.

```ts
export interface OverlayBroadcastFacilitator {
    send: (url: string, taggedBEEF: TaggedBEEF) => Promise<STEAK>;
}
```

See also: [STEAK](./overlay-tools.md#type-steak), [TaggedBEEF](./overlay-tools.md#interface-taggedbeef)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: OverlayLookupFacilitator

Facilitates lookups to URLs that return answers.

```ts
export interface OverlayLookupFacilitator {
    lookup: (url: string, question: LookupQuestion, timeout?: number) => Promise<LookupAnswer>;
}
```

See also: [LookupAnswer](./overlay-tools.md#type-lookupanswer), [LookupQuestion](./overlay-tools.md#interface-lookupquestion)

#### Property lookup

Returns a lookup answer for a lookup question

```ts
lookup: (url: string, question: LookupQuestion, timeout?: number) => Promise<LookupAnswer>
```
See also: [LookupAnswer](./overlay-tools.md#type-lookupanswer), [LookupQuestion](./overlay-tools.md#interface-lookupquestion)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: SHIPBroadcasterConfig

Configuration options for the SHIP broadcaster.

```ts
export interface SHIPBroadcasterConfig {
    networkPreset?: "mainnet" | "testnet" | "local";
    facilitator?: OverlayBroadcastFacilitator;
    resolver?: LookupResolver;
    requireAcknowledgmentFromAllHostsForTopics?: "all" | "any" | string[];
    requireAcknowledgmentFromAnyHostForTopics?: "all" | "any" | string[];
    requireAcknowledgmentFromSpecificHostsForTopics?: Record<string, "all" | "any" | string[]>;
}
```

See also: [LookupResolver](./overlay-tools.md#class-lookupresolver), [OverlayBroadcastFacilitator](./overlay-tools.md#interface-overlaybroadcastfacilitator)

#### Property facilitator

The facilitator used to make requests to Overlay Services hosts.

```ts
facilitator?: OverlayBroadcastFacilitator
```
See also: [OverlayBroadcastFacilitator](./overlay-tools.md#interface-overlaybroadcastfacilitator)

#### Property networkPreset

The network preset to use, unless other options override it.
- mainnet: use mainnet resolver and HTTPS facilitator
- testnet: use testnet resolver and HTTPS facilitator
- local: directly send to localhost:8080 and a facilitator that permits plain HTTP

```ts
networkPreset?: "mainnet" | "testnet" | "local"
```

#### Property requireAcknowledgmentFromAllHostsForTopics

Determines which topics (all, any, or a specific list) must be present within all STEAKs received from every host for the broadcast to be considered a success. By default, all hosts must acknowledge all topics.

```ts
requireAcknowledgmentFromAllHostsForTopics?: "all" | "any" | string[]
```

#### Property requireAcknowledgmentFromAnyHostForTopics

Determines which topics (all, any, or a specific list) must be present within STEAK received from at least one host for the broadcast to be considered a success.

```ts
requireAcknowledgmentFromAnyHostForTopics?: "all" | "any" | string[]
```

#### Property requireAcknowledgmentFromSpecificHostsForTopics

Determines a mapping whose keys are specific hosts and whose values are the topics (all, any, or a specific list) that must be present within the STEAK received by the given hosts, in order for the broadcast to be considered a success.

```ts
requireAcknowledgmentFromSpecificHostsForTopics?: Record<string, "all" | "any" | string[]>
```

#### Property resolver

The resolver used to locate suitable hosts with SHIP

```ts
resolver?: LookupResolver
```
See also: [LookupResolver](./overlay-tools.md#class-lookupresolver)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: TaggedBEEF

Tagged BEEF

```ts
export interface TaggedBEEF {
    beef: number[];
    topics: string[];
    offChainValues?: number[];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [HTTPSOverlayBroadcastFacilitator](#class-httpsoverlaybroadcastfacilitator) |
| [HTTPSOverlayLookupFacilitator](#class-httpsoverlaylookupfacilitator) |
| [LookupResolver](#class-lookupresolver) |
| [OverlayAdminTokenTemplate](#class-overlayadmintokentemplate) |
| [TopicBroadcaster](#class-topicbroadcaster) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: HTTPSOverlayBroadcastFacilitator

```ts
export class HTTPSOverlayBroadcastFacilitator implements OverlayBroadcastFacilitator {
    httpClient: typeof fetch;
    allowHTTP: boolean;
    constructor(httpClient = fetch, allowHTTP: boolean = false) 
    async send(url: string, taggedBEEF: TaggedBEEF): Promise<STEAK> 
}
```

See also: [OverlayBroadcastFacilitator](./overlay-tools.md#interface-overlaybroadcastfacilitator), [STEAK](./overlay-tools.md#type-steak), [TaggedBEEF](./overlay-tools.md#interface-taggedbeef)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: HTTPSOverlayLookupFacilitator

```ts
export class HTTPSOverlayLookupFacilitator implements OverlayLookupFacilitator {
    fetchClient: typeof fetch;
    allowHTTP: boolean;
    constructor(httpClient = fetch, allowHTTP: boolean = false) 
    async lookup(url: string, question: LookupQuestion, timeout: number = 5000): Promise<LookupAnswer> 
}
```

See also: [LookupAnswer](./overlay-tools.md#type-lookupanswer), [LookupQuestion](./overlay-tools.md#interface-lookupquestion), [OverlayLookupFacilitator](./overlay-tools.md#interface-overlaylookupfacilitator)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: LookupResolver

Represents an SHIP transaction broadcaster.

```ts
export default class LookupResolver {
    constructor(config: LookupResolverConfig = {}) 
    async query(question: LookupQuestion, timeout?: number): Promise<LookupAnswer> 
}
```

See also: [LookupAnswer](./overlay-tools.md#type-lookupanswer), [LookupQuestion](./overlay-tools.md#interface-lookupquestion), [LookupResolverConfig](./overlay-tools.md#interface-lookupresolverconfig)

#### Method query

Given a LookupQuestion, returns a LookupAnswer. Aggregates across multiple services and supports resiliency.

```ts
async query(question: LookupQuestion, timeout?: number): Promise<LookupAnswer> 
```
See also: [LookupAnswer](./overlay-tools.md#type-lookupanswer), [LookupQuestion](./overlay-tools.md#interface-lookupquestion)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: OverlayAdminTokenTemplate

Script template enabling the creation, unlocking, and decoding of SHIP and SLAP advertisements.

```ts
export default class OverlayAdminTokenTemplate implements ScriptTemplate {
    pushDrop: PushDrop;
    static decode(script: LockingScript): {
        protocol: "SHIP" | "SLAP";
        identityKey: string;
        domain: string;
        topicOrService: string;
    } 
    constructor(wallet: WalletInterface) 
    async lock(protocol: "SHIP" | "SLAP", domain: string, topicOrService: string): Promise<LockingScript> 
    unlock(protocol: "SHIP" | "SLAP"): {
        sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>;
        estimateLength: (tx: Transaction, inputIndex: number) => Promise<number>;
    } 
}
```

See also: [LockingScript](./script.md#class-lockingscript), [PushDrop](./script.md#class-pushdrop), [ScriptTemplate](./script.md#interface-scripttemplate), [Transaction](./transaction.md#class-transaction), [UnlockingScript](./script.md#class-unlockingscript), [WalletInterface](./wallet.md#interface-walletinterface), [sign](./compat.md#variable-sign)

#### Constructor

Constructs a new Overlay Admin template instance

```ts
constructor(wallet: WalletInterface) 
```
See also: [WalletInterface](./wallet.md#interface-walletinterface)

Argument Details

+ **wallet**
  + Wallet to use for locking and unlocking

#### Method decode

Decodes a SHIP or SLAP advertisement from a given locking script.

```ts
static decode(script: LockingScript): {
    protocol: "SHIP" | "SLAP";
    identityKey: string;
    domain: string;
    topicOrService: string;
} 
```
See also: [LockingScript](./script.md#class-lockingscript)

Returns

Decoded SHIP or SLAP advertisement

Argument Details

+ **script**
  + Locking script comprising a SHIP or SLAP token to decode

#### Method lock

Creates a new advertisement locking script

```ts
async lock(protocol: "SHIP" | "SLAP", domain: string, topicOrService: string): Promise<LockingScript> 
```
See also: [LockingScript](./script.md#class-lockingscript)

Returns

Locking script comprising the advertisement token

Argument Details

+ **protocol**
  + SHIP or SLAP
+ **domain**
  + Domain where the topic or service is available
+ **topicOrService**
  + Topic or service to advertise

#### Method unlock

Unlocks an advertisement token as part of a transaction.

```ts
unlock(protocol: "SHIP" | "SLAP"): {
    sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>;
    estimateLength: (tx: Transaction, inputIndex: number) => Promise<number>;
} 
```
See also: [Transaction](./transaction.md#class-transaction), [UnlockingScript](./script.md#class-unlockingscript), [sign](./compat.md#variable-sign)

Returns

Script unlocker capable of unlocking the advertisement token

Argument Details

+ **protocol**
  + SHIP or SLAP, depending on the token to unlock

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: TopicBroadcaster

Broadcasts transactions to one or more overlay topics.

```ts
export default class TopicBroadcaster implements Broadcaster {
    constructor(topics: string[], config: SHIPBroadcasterConfig = {}) 
    async broadcast(tx: Transaction): Promise<BroadcastResponse | BroadcastFailure> 
}
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Broadcaster](./transaction.md#interface-broadcaster), [SHIPBroadcasterConfig](./overlay-tools.md#interface-shipbroadcasterconfig), [Transaction](./transaction.md#class-transaction)

#### Constructor

Constructs an instance of the SHIP broadcaster.

```ts
constructor(topics: string[], config: SHIPBroadcasterConfig = {}) 
```
See also: [SHIPBroadcasterConfig](./overlay-tools.md#interface-shipbroadcasterconfig)

Argument Details

+ **topics**
  + The list of SHIP topic names where transactions are to be sent.
+ **config**
  + Configuration options for the SHIP broadcaster.

#### Method broadcast

Broadcasts a transaction to Overlay Services via SHIP.

```ts
async broadcast(tx: Transaction): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Transaction](./transaction.md#class-transaction)

Returns

A promise that resolves to either a success or failure response.

Argument Details

+ **tx**
  + The transaction to be sent.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

## Types

| |
| --- |
| [LookupAnswer](#type-lookupanswer) |
| [STEAK](#type-steak) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Type: LookupAnswer

How the Overlay Services Engine responds to a Lookup Question.
It may comprise either an output list or a freeform response from the Lookup Service.

```ts
export type LookupAnswer = {
    type: "output-list";
    outputs: Array<{
        beef: number[];
        outputIndex: number;
        context?: number[];
    }>;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: STEAK

Submitted Transaction Execution AcKnowledgment

```ts
export type STEAK = Record<string, AdmittanceInstructions>
```

See also: [AdmittanceInstructions](./overlay-tools.md#interface-admittanceinstructions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Enums

## Variables

| |
| --- |
| [DEFAULT_SLAP_TRACKERS](#variable-default_slap_trackers) |
| [DEFAULT_TESTNET_SLAP_TRACKERS](#variable-default_testnet_slap_trackers) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: DEFAULT_SLAP_TRACKERS

```ts
DEFAULT_SLAP_TRACKERS: string[] = [
    "https://overlay-us-1.bsvb.tech",
    "https://overlay-eu-1.bsvb.tech",
    "https://overlay-ap-1.bsvb.tech",
    "https://users.bapp.dev"
]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: DEFAULT_TESTNET_SLAP_TRACKERS

```ts
DEFAULT_TESTNET_SLAP_TRACKERS: string[] = [
    "https://testnet-users.bapp.dev"
]
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
