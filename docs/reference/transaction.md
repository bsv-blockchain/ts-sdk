# API

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

## Interfaces

| | |
| --- | --- |
| [ArcConfig](#interface-arcconfig) | [HttpClientRequestOptions](#interface-httpclientrequestoptions) |
| [BroadcastFailure](#interface-broadcastfailure) | [HttpsNodejs](#interface-httpsnodejs) |
| [BroadcastResponse](#interface-broadcastresponse) | [MerklePathLeaf](#interface-merklepathleaf) |
| [Broadcaster](#interface-broadcaster) | [NodejsHttpClientRequest](#interface-nodejshttpclientrequest) |
| [ChainTracker](#interface-chaintracker) | [TransactionInput](#interface-transactioninput) |
| [FeeModel](#interface-feemodel) | [TransactionOutput](#interface-transactionoutput) |
| [FetchOptions](#interface-fetchoptions) | [WhatsOnChainConfig](#interface-whatsonchainconfig) |
| [HttpClient](#interface-httpclient) |  |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Interface: ArcConfig

Configuration options for the ARC broadcaster.

```ts
export interface ArcConfig {
    apiKey?: string;
    httpClient?: HttpClient;
    deploymentId?: string;
    callbackUrl?: string;
    callbackToken?: string;
    headers?: Record<string, string>;
}
```

See also: [HttpClient](./transaction.md#interface-httpclient)

#### Property apiKey

Authentication token for the ARC API

```ts
apiKey?: string
```

#### Property callbackToken

default access token for notification callback endpoint. It will be used as a Authorization header for the http callback

```ts
callbackToken?: string
```

#### Property callbackUrl

notification callback endpoint for proofs and double spend notification

```ts
callbackUrl?: string
```

#### Property deploymentId

Deployment id used annotating api calls in XDeployment-ID header - this value will be randomly generated if not set

```ts
deploymentId?: string
```

#### Property headers

additional headers to be attached to all tx submissions.

```ts
headers?: Record<string, string>
```

#### Property httpClient

The HTTP client used to make requests to the ARC API.

```ts
httpClient?: HttpClient
```
See also: [HttpClient](./transaction.md#interface-httpclient)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: BroadcastFailure

Defines the structure of a failed broadcast response.

```ts
export interface BroadcastFailure {
    status: "error";
    code: string;
    txid?: string;
    description: string;
    more?: object;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: BroadcastResponse

Defines the structure of a successful broadcast response.

```ts
export interface BroadcastResponse {
    status: "success";
    txid: string;
    message: string;
    competingTxs?: string[];
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: Broadcaster

Represents the interface for a transaction broadcaster.
This interface defines a standard method for broadcasting transactions.

```ts
export interface Broadcaster {
    broadcast: (transaction: Transaction) => Promise<BroadcastResponse | BroadcastFailure>;
    broadcastMany?: (txs: Transaction[]) => Promise<object[]>;
}
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Transaction](./transaction.md#class-transaction)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: ChainTracker

The Chain Tracker is responsible for verifying the validity of a given Merkle root
for a specific block height within the blockchain.

Chain Trackers ensure the integrity of the blockchain by
validating new headers against the chain's history. They use accumulated
proof-of-work and protocol adherence as metrics to assess the legitimacy of blocks.

Example

```ts
const chainTracker = {
  isValidRootForHeight: async (root, height) => {
    // Implementation to check if the Merkle root is valid for the specified block height.
  }
 currentHeight: async () => {
    // Implementation to get the current block height.
  }
};
```

```ts
export default interface ChainTracker {
    isValidRootForHeight: (root: string, height: number) => Promise<boolean>;
    currentHeight: () => Promise<number>;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: FeeModel

Represents the interface for a transaction fee model.
This interface defines a standard method for computing a fee when given a transaction.

```ts
export default interface FeeModel {
    computeFee: (transaction: Transaction) => Promise<number>;
}
```

See also: [Transaction](./transaction.md#class-transaction)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: FetchOptions

An interface for configuration of the request to be passed to the fetch method
limited to options needed by ts-sdk.

```ts
export interface FetchOptions {
    method?: string;
    headers?: Record<string, string>;
    body?: string | null;
}
```

#### Property body

An object or null to set request's body.

```ts
body?: string | null
```

#### Property headers

An object literal set request's headers.

```ts
headers?: Record<string, string>
```

#### Property method

A string to set request's method.

```ts
method?: string
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: HttpClient

An interface for HTTP client used to make HTTP requests.

```ts
export interface HttpClient {
    request: <T = any, D = any>(url: string, options: HttpClientRequestOptions<D>) => Promise<HttpClientResponse<T>>;
}
```

See also: [HttpClientRequestOptions](./transaction.md#interface-httpclientrequestoptions), [HttpClientResponse](./transaction.md#type-httpclientresponse)

#### Property request

Makes a request to the server.

```ts
request: <T = any, D = any>(url: string, options: HttpClientRequestOptions<D>) => Promise<HttpClientResponse<T>>
```
See also: [HttpClientRequestOptions](./transaction.md#interface-httpclientrequestoptions), [HttpClientResponse](./transaction.md#type-httpclientresponse)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: HttpClientRequestOptions

An interface for configuration of the request to be passed to the request method.

```ts
export interface HttpClientRequestOptions<Data = any> {
    method?: string;
    headers?: Record<string, string>;
    data?: Data;
    signal?: AbortSignal;
}
```

#### Property data

An object or null to set request's body.

```ts
data?: Data
```

#### Property headers

An object literal set request's headers.

```ts
headers?: Record<string, string>
```

#### Property method

A string to set request's method.

```ts
method?: string
```

#### Property signal

An optional AbortSignal to cancel the request, including by explicit timeout.

```ts
signal?: AbortSignal
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: HttpsNodejs

Node Https module interface limited to options needed by ts-sdk

```ts
export interface HttpsNodejs {
    request: (url: string, options: HttpClientRequestOptions, callback: (res: any) => void) => NodejsHttpClientRequest;
}
```

See also: [HttpClientRequestOptions](./transaction.md#interface-httpclientrequestoptions), [NodejsHttpClientRequest](./transaction.md#interface-nodejshttpclientrequest)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: MerklePathLeaf

```ts
export interface MerklePathLeaf {
    offset: number;
    hash?: string;
    txid?: boolean;
    duplicate?: boolean;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: NodejsHttpClientRequest

Nodejs result of the Node https.request call limited to options needed by ts-sdk

```ts
export interface NodejsHttpClientRequest {
    write: (chunk: string) => void;
    on: (event: string, callback: (data: any) => void) => void;
    end: (() => void) & (() => void);
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: TransactionInput

Represents an input to a Bitcoin transaction.
This interface defines the structure and components required to construct
a transaction input in the Bitcoin blockchain.

Example

```ts
// Creating a simple transaction input
let txInput = {
  sourceTXID: '123abc...',
  sourceOutputIndex: 0,
  sequence: 0xFFFFFFFF
};

// Using an unlocking script template
txInput.unlockingScriptTemplate = {
  sign: async (tx, index) => { ... },
  estimateLength: async (tx, index) => { ... }
};
```

```ts
export default interface TransactionInput {
    sourceTransaction?: Transaction;
    sourceTXID?: string;
    sourceOutputIndex: number;
    unlockingScript?: UnlockingScript;
    unlockingScriptTemplate?: {
        sign: (tx: Transaction, inputIndex: number) => Promise<UnlockingScript>;
        estimateLength: (tx: Transaction, inputIndex: number) => Promise<number>;
    };
    sequence?: number;
}
```

See also: [Transaction](./transaction.md#class-transaction), [UnlockingScript](./script.md#class-unlockingscript), [sign](./compat.md#variable-sign)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: TransactionOutput

Represents an output in a Bitcoin transaction.
This interface defines the structure and components necessary to construct
a transaction output, which secures owned Bitcoins to be unlocked later.

Example

```ts
// Creating a simple transaction output
let txOutput = {
  satoshis: 1000,
  lockingScript: LockingScript.fromASM('OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG'),
  change: false
};
```

```ts
export default interface TransactionOutput {
    satoshis?: number;
    lockingScript: LockingScript;
    change?: boolean;
}
```

See also: [LockingScript](./script.md#class-lockingscript)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Interface: WhatsOnChainConfig

Configuration options for the WhatsOnChain ChainTracker.

```ts
export interface WhatsOnChainConfig {
    apiKey?: string;
    httpClient?: HttpClient;
}
```

See also: [HttpClient](./transaction.md#interface-httpclient)

#### Property apiKey

Authentication token for the WhatsOnChain API

```ts
apiKey?: string
```

#### Property httpClient

The HTTP client used to make requests to the API.

```ts
httpClient?: HttpClient
```
See also: [HttpClient](./transaction.md#interface-httpclient)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Classes

| |
| --- |
| [ARC](#class-arc) |
| [Beef](#class-beef) |
| [BeefParty](#class-beefparty) |
| [BeefTx](#class-beeftx) |
| [FetchHttpClient](#class-fetchhttpclient) |
| [LivePolicy](#class-livepolicy) |
| [MerklePath](#class-merklepath) |
| [NodejsHttpClient](#class-nodejshttpclient) |
| [SatoshisPerKilobyte](#class-satoshisperkilobyte) |
| [Transaction](#class-transaction) |
| [WhatsOnChain](#class-whatsonchain) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Class: ARC

Represents an ARC transaction broadcaster.

```ts
export default class ARC implements Broadcaster {
    readonly URL: string;
    readonly apiKey: string | undefined;
    readonly deploymentId: string;
    readonly callbackUrl: string | undefined;
    readonly callbackToken: string | undefined;
    readonly headers: Record<string, string> | undefined;
    constructor(URL: string, config?: ArcConfig);
    constructor(URL: string, apiKey?: string);
    constructor(URL: string, config?: string | ArcConfig) 
    async broadcast(tx: Transaction): Promise<BroadcastResponse | BroadcastFailure> 
    async broadcastMany(txs: Transaction[]): Promise<object[]> 
}
```

See also: [ArcConfig](./transaction.md#interface-arcconfig), [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Broadcaster](./transaction.md#interface-broadcaster), [Transaction](./transaction.md#class-transaction)

#### Constructor

Constructs an instance of the ARC broadcaster.

```ts
constructor(URL: string, config?: ArcConfig)
```
See also: [ArcConfig](./transaction.md#interface-arcconfig)

Argument Details

+ **URL**
  + The URL endpoint for the ARC API.
+ **config**
  + Configuration options for the ARC broadcaster.

#### Constructor

Constructs an instance of the ARC broadcaster.

```ts
constructor(URL: string, apiKey?: string)
```

Argument Details

+ **URL**
  + The URL endpoint for the ARC API.
+ **apiKey**
  + The API key used for authorization with the ARC API.

#### Method broadcast

Broadcasts a transaction via ARC.

```ts
async broadcast(tx: Transaction): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Transaction](./transaction.md#class-transaction)

Returns

A promise that resolves to either a success or failure response.

Argument Details

+ **tx**
  + The transaction to be broadcasted.

#### Method broadcastMany

Broadcasts multiple transactions via ARC.
Handles mixed responses where some transactions succeed and others fail.

```ts
async broadcastMany(txs: Transaction[]): Promise<object[]> 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

A promise that resolves to an array of objects.

Argument Details

+ **txs**
  + Array of transactions to be broadcasted.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Beef

```ts
export class Beef {
    bumps: MerklePath[] = [];
    txs: BeefTx[] = [];
    version: number = BEEF_V2;
    atomicTxid: string | undefined = undefined;
    constructor(version: number = BEEF_V2) 
    findTxid(txid: string): BeefTx | undefined 
    makeTxidOnly(txid: string): BeefTx | undefined 
    findBump(txid: string): MerklePath | undefined 
    findTransactionForSigning(txid: string): Transaction | undefined 
    findAtomicTransaction(txid: string): Transaction | undefined 
    mergeBump(bump: MerklePath): number 
    mergeRawTx(rawTx: number[] | Uint8Array, bumpIndex?: number): BeefTx 
    mergeTransaction(tx: Transaction): BeefTx 
    removeExistingTxid(txid: string): void 
    mergeTxidOnly(txid: string): BeefTx 
    mergeBeefTx(btx: BeefTx): BeefTx 
    mergeBeef(beef: Beef | number[] | Uint8Array): void 
    isValid(allowTxidOnly?: boolean): boolean 
    async verify(chainTracker: ChainTracker, allowTxidOnly?: boolean): Promise<boolean> 
    verifyValid(allowTxidOnly?: boolean): {
        valid: boolean;
        roots: Record<number, string>;
    } 
    toWriter(writer: Writer | WriterUint8Array): void 
    toBinary(): number[] 
    toUint8Array(): Uint8Array 
    toBinaryAtomic(txid: string): number[] 
    toUint8ArrayAtomic(txid: string): Uint8Array 
    toHex(): string 
    static fromReader(br: Reader | ReaderUint8Array): Beef 
    static fromBinary(bin: number[] | Uint8Array): Beef 
    static fromString(s: string, enc: "hex" | "utf8" | "base64" = "hex"): Beef 
    sortTxs(): {
        missingInputs: string[];
        notValid: string[];
        valid: string[];
        withMissingInputs: string[];
        txidOnly: string[];
    } 
    clone(): Beef 
    trimKnownTxids(knownTxids: string[]): void 
    getValidTxids(): string[] 
    toLogString(): string 
    addComputedLeaves(): void 
}
```

See also: [BEEF_V2](./transaction.md#variable-beef_v2), [BeefTx](./transaction.md#class-beeftx), [ChainTracker](./transaction.md#interface-chaintracker), [MerklePath](./transaction.md#class-merklepath), [Reader](./primitives.md#class-reader), [ReaderUint8Array](./primitives.md#class-readeruint8array), [Transaction](./transaction.md#class-transaction), [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array), [toHex](./primitives.md#variable-tohex), [toUint8Array](./primitives.md#variable-touint8array), [verify](./compat.md#variable-verify)

#### Method addComputedLeaves

In some circumstances it may be helpful for the BUMP MerklePaths to include
leaves that can be computed from row zero.

```ts
addComputedLeaves(): void 
```

#### Method clone

```ts
clone(): Beef 
```
See also: [Beef](./transaction.md#class-beef)

Returns

a shallow copy of this beef

#### Method findAtomicTransaction

Builds the proof tree rooted at a specific `Transaction`.

To succeed, the Beef must contain all the required transaction and merkle path data.

```ts
findAtomicTransaction(txid: string): Transaction | undefined 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

Transaction with input `SourceTransaction` and `MerklePath` populated from this Beef.

Argument Details

+ **txid**
  + The id of the target transaction.

#### Method findBump

```ts
findBump(txid: string): MerklePath | undefined 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Returns

`MerklePath` with level zero hash equal to txid or undefined.

#### Method findTransactionForSigning

Finds a Transaction in this `Beef`
and adds any missing input SourceTransactions from this `Beef`.

The result is suitable for signing.

```ts
findTransactionForSigning(txid: string): Transaction | undefined 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

Transaction with all available input `SourceTransaction`s from this Beef.

Argument Details

+ **txid**
  + The id of the target transaction.

#### Method findTxid

```ts
findTxid(txid: string): BeefTx | undefined 
```
See also: [BeefTx](./transaction.md#class-beeftx)

Returns

`BeefTx` in `txs` with `txid`.

Argument Details

+ **txid**
  + of `beefTx` to find

#### Method fromBinary

Constructs an instance of the Beef class based on the provided binary array

```ts
static fromBinary(bin: number[] | Uint8Array): Beef 
```
See also: [Beef](./transaction.md#class-beef)

Returns

An instance of the Beef class constructed from the binary data

Argument Details

+ **bin**
  + The binary array or Uint8Array from which to construct BEEF

#### Method fromString

Constructs an instance of the Beef class based on the provided string

```ts
static fromString(s: string, enc: "hex" | "utf8" | "base64" = "hex"): Beef 
```
See also: [Beef](./transaction.md#class-beef)

Returns

An instance of the Beef class constructed from the string

Argument Details

+ **s**
  + The string value from which to construct BEEF
+ **enc**
  + The encoding of the string value from which BEEF should be constructed

#### Method getValidTxids

```ts
getValidTxids(): string[] 
```

Returns

array of transaction txids that either have a proof or whose inputs chain back to a proven transaction.

#### Method isValid

Sorts `txs` and checks structural validity of beef.

Does NOT verify merkle roots.

Validity requirements:
1. No 'known' txids, unless `allowTxidOnly` is true.
2. All transactions have bumps or their inputs chain back to bumps (or are known).
3. Order of transactions satisfies dependencies before dependents.
4. No transactions with duplicate txids.

```ts
isValid(allowTxidOnly?: boolean): boolean 
```

Argument Details

+ **allowTxidOnly**
  + optional. If true, transaction txid only is assumed valid

#### Method makeTxidOnly

Replaces `BeefTx` for this txid with txidOnly.

Replacement is done so that a `clone()` can be
updated by this method without affecting the
original.

```ts
makeTxidOnly(txid: string): BeefTx | undefined 
```
See also: [BeefTx](./transaction.md#class-beeftx)

Returns

undefined if txid is unknown.

#### Method mergeBump

Merge a MerklePath that is assumed to be fully valid.

```ts
mergeBump(bump: MerklePath): number 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Returns

index of merged bump

#### Method mergeRawTx

Merge a serialized transaction.

Checks that a transaction with the same txid hasn't already been merged.

Replaces existing transaction with same txid.

```ts
mergeRawTx(rawTx: number[] | Uint8Array, bumpIndex?: number): BeefTx 
```
See also: [BeefTx](./transaction.md#class-beeftx)

Returns

txid of rawTx

Argument Details

+ **bumpIndex**
  + Optional. If a number, must be valid index into bumps array.

#### Method mergeTransaction

Merge a `Transaction` and any referenced `merklePath` and `sourceTransaction`, recursifely.

Replaces existing transaction with same txid.

Attempts to match an existing bump to the new transaction.

```ts
mergeTransaction(tx: Transaction): BeefTx 
```
See also: [BeefTx](./transaction.md#class-beeftx), [Transaction](./transaction.md#class-transaction)

Returns

txid of tx

#### Method removeExistingTxid

Removes an existing transaction from the BEEF, given its TXID

```ts
removeExistingTxid(txid: string): void 
```

Argument Details

+ **txid**
  + TXID of the transaction to remove

#### Method sortTxs

Sort the `txs` by input txid dependency order:
- Oldest Tx Anchored by Path or txid only
- Newer Txs depending on Older parents
- Newest Tx

with proof (MerklePath) last, longest chain of dependencies first

```ts
sortTxs(): {
    missingInputs: string[];
    notValid: string[];
    valid: string[];
    withMissingInputs: string[];
    txidOnly: string[];
} 
```

Returns

`{ missingInputs, notValid, valid, withMissingInputs }`

#### Method toBinary

Returns a binary array representing the serialized BEEF

```ts
toBinary(): number[] 
```

Returns

A binary array representing the BEEF

An array of byte values containing binary serialization of the BEEF

#### Method toBinaryAtomic

Serialize this Beef as AtomicBEEF.

`txid` must exist

after sorting, if txid is not last txid, creates a clone and removes newer txs

```ts
toBinaryAtomic(txid: string): number[] 
```

Returns

serialized contents of this Beef with AtomicBEEF prefix.

#### Method toHex

Returns a hex string representing the serialized BEEF

```ts
toHex(): string 
```

Returns

A hex string representing the BEEF

#### Method toLogString

```ts
toLogString(): string 
```

Returns

Summary of `Beef` contents as multi-line string.

#### Method toUint8Array

Returns a binary array representing the serialized BEEF

```ts
toUint8Array(): Uint8Array 
```

Returns

A Uint8Array containing binary serialization of the BEEF

#### Method toUint8ArrayAtomic

Serialize this Beef as AtomicBEEF.

`txid` must exist

after sorting, if txid is not last txid, creates a clone and removes newer txs

```ts
toUint8ArrayAtomic(txid: string): Uint8Array 
```

Returns

serialized contents of this Beef with AtomicBEEF prefix.

#### Method toWriter

Serializes this data to `writer`

```ts
toWriter(writer: Writer | WriterUint8Array): void 
```
See also: [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array)

#### Method trimKnownTxids

Ensure that all the txids in `knownTxids` are txidOnly

```ts
trimKnownTxids(knownTxids: string[]): void 
```

#### Method verify

Sorts `txs` and confirms validity of transaction data contained in beef
by validating structure of this beef and confirming computed merkle roots
using `chainTracker`.

Validity requirements:
1. No 'known' txids, unless `allowTxidOnly` is true.
2. All transactions have bumps or their inputs chain back to bumps (or are known).
3. Order of transactions satisfies dependencies before dependents.
4. No transactions with duplicate txids.

```ts
async verify(chainTracker: ChainTracker, allowTxidOnly?: boolean): Promise<boolean> 
```
See also: [ChainTracker](./transaction.md#interface-chaintracker)

Argument Details

+ **chainTracker**
  + Used to verify computed merkle path roots for all bump txids.
+ **allowTxidOnly**
  + optional. If true, transaction txid is assumed valid

#### Method verifyValid

Sorts `txs` and confirms validity of transaction data contained in beef
by validating structure of this beef.

Returns block heights and merkle root values to be confirmed by a chaintracker.

Validity requirements:
1. No 'known' txids, unless `allowTxidOnly` is true.
2. All transactions have bumps or their inputs chain back to bumps (or are known).
3. Order of transactions satisfies dependencies before dependents.
4. No transactions with duplicate txids.

```ts
verifyValid(allowTxidOnly?: boolean): {
    valid: boolean;
    roots: Record<number, string>;
} 
```

Returns

`valid` is true iff this Beef is structuraly valid.
`roots` is a record where keys are block heights and values are the corresponding merkle roots to be validated.

Argument Details

+ **allowTxidOnly**
  + optional. If true, transaction txid is assumed valid

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: BeefParty

Extends `Beef` that is used to exchange transaction validity data with more than one external party.

Use `addKnownTxidsForParty` to keep track of who knows what to reduce re-transmission of potentially large transactions.

Use `getTrimmedBeefForParty` to obtain a `Beef` trimmed of transaction validity data known to a specific party.

Typical usage scenario:

1. Query a wallet storage provider for spendable outputs.
2. The provider replies with a Beef validating the returned outputs.
3. Construct a new transaction using some of the queried outputs as inputs, including Beef validating all the inputs.
4. Receive new valid raw transaction after processing and Beef validating change outputs added to original inputs.
5. Return to step 1, continuing to build on old and new spendable outputs.

By default, each Beef is required to be complete and valid: All transactions appear as full serialized bitcoin transactions and
each transaction either has a merkle path proof (it has been mined) or all of its input transactions are included.

The size and redundancy of these Beefs becomes a problem when chained transaction creation out-paces the block mining rate.

```ts
export class BeefParty extends Beef {
    knownTo: Record<string, Record<string, boolean>> = {};
    constructor(parties?: string[]) 
    isParty(party: string): boolean 
    addParty(party: string): void 
    getKnownTxidsForParty(party: string): string[] 
    getTrimmedBeefForParty(party: string): Beef 
    addKnownTxidsForParty(party: string, knownTxids: string[]): void 
    mergeBeefFromParty(party: string, beef: number[] | Beef): void 
}
```

See also: [Beef](./transaction.md#class-beef)

#### Constructor

```ts
constructor(parties?: string[]) 
```

Argument Details

+ **parties**
  + Optional array of initial unique party identifiers.

#### Property knownTo

keys are party identifiers.
values are records of txids with truthy value for which the party already has validity proof.

```ts
knownTo: Record<string, Record<string, boolean>> = {}
```

#### Method addKnownTxidsForParty

Make note of additional txids "known" to `party`.

```ts
addKnownTxidsForParty(party: string, knownTxids: string[]): void 
```

Argument Details

+ **party**
  + unique identifier, added if new.

#### Method addParty

Adds a new unique party identifier to this `BeefParty`.

```ts
addParty(party: string): void 
```

#### Method getKnownTxidsForParty

```ts
getKnownTxidsForParty(party: string): string[] 
```

Returns

Array of txids "known" to `party`.

#### Method getTrimmedBeefForParty

```ts
getTrimmedBeefForParty(party: string): Beef 
```
See also: [Beef](./transaction.md#class-beef)

Returns

trimmed beef of unknown transactions and proofs for `party`

#### Method isParty

```ts
isParty(party: string): boolean 
```

Returns

`true` if `party` has already been added to this `BeefParty`.

#### Method mergeBeefFromParty

Merge a `beef` received from a specific `party`.

Updates this `BeefParty` to track all the txids
corresponding to transactions for which `party`
has raw transaction and validity proof data.

```ts
mergeBeefFromParty(party: string, beef: number[] | Beef): void 
```
See also: [Beef](./transaction.md#class-beef)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: BeefTx

A single bitcoin transaction associated with a `Beef` validity proof set.

Simple case is transaction data included directly, either as raw bytes or fully parsed data, or both.

Supports 'known' transactions which are represented by just their txid.
It is assumed that intended consumer of this beef already has validity proof for such a transaction,
which they can merge if necessary to create a valid beef.

```ts
export default class BeefTx {
    _bumpIndex?: number;
    _tx?: Transaction;
    _rawTx?: Uint8Array;
    _txid?: string;
    inputTxids: string[] = [];
    isValid?: boolean = undefined;
    get bumpIndex(): number | undefined 
    set bumpIndex(v: number | undefined) 
    get hasProof(): boolean 
    get isTxidOnly(): boolean 
    get txid(): string 
    get tx(): Transaction | undefined 
    get rawTx(): number[] | undefined 
    get rawTxUint8Array(): Uint8Array | undefined 
    constructor(tx: Transaction | Uint8Array | number[] | string, bumpIndex?: number) 
    static fromTx(tx: Transaction, bumpIndex?: number): BeefTx 
    static fromRawTx(rawTx: Uint8Array | number[], bumpIndex?: number): BeefTx 
    static fromTxid(txid: string, bumpIndex?: number): BeefTx 
    toWriter(writer: Writer | WriterUint8Array, version: number): void 
    static fromReader(br: Reader | ReaderUint8Array, version: number): BeefTx 
}
```

See also: [Reader](./primitives.md#class-reader), [ReaderUint8Array](./primitives.md#class-readeruint8array), [Transaction](./transaction.md#class-transaction), [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array)

#### Constructor

```ts
constructor(tx: Transaction | Uint8Array | number[] | string, bumpIndex?: number) 
```
See also: [Transaction](./transaction.md#class-transaction)

Argument Details

+ **tx**
  + If string, must be a valid txid. If `number[]` must be a valid serialized transaction.
+ **bumpIndex**
  + If transaction already has a proof in the beef to which it will be added.

#### Property isValid

true if `hasProof` or all inputs chain to `hasProof`.

Typically set by sorting transactions by proven dependency chains.

```ts
isValid?: boolean = undefined
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: FetchHttpClient

Adapter for Node Https module to be used as HttpClient

```ts
export class FetchHttpClient implements HttpClient {
    constructor(private readonly fetch: Fetch) 
    async request<D>(url: string, options: HttpClientRequestOptions): Promise<HttpClientResponse<D>> 
}
```

See also: [Fetch](./transaction.md#type-fetch), [HttpClient](./transaction.md#interface-httpclient), [HttpClientRequestOptions](./transaction.md#interface-httpclientrequestoptions), [HttpClientResponse](./transaction.md#type-httpclientresponse)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: LivePolicy

Represents a live fee policy that fetches current rates from ARC GorillaPool.
Extends SatoshisPerKilobyte to reuse transaction size calculation logic.

```ts
export default class LivePolicy extends SatoshisPerKilobyte {
    constructor(cacheValidityMs: number = 5 * 60 * 1000) 
    static getInstance(cacheValidityMs: number = 5 * 60 * 1000): LivePolicy 
    async computeFee(tx: Transaction): Promise<number> 
}
```

See also: [SatoshisPerKilobyte](./transaction.md#class-satoshisperkilobyte), [Transaction](./transaction.md#class-transaction)

#### Constructor

Constructs an instance of the live policy fee model.

```ts
constructor(cacheValidityMs: number = 5 * 60 * 1000) 
```

Argument Details

+ **cacheValidityMs**
  + How long to cache the fee rate in milliseconds (default: 5 minutes)

#### Method computeFee

Computes the fee for a given transaction using the current live rate.
Overrides the parent method to use dynamic rate fetching.

```ts
async computeFee(tx: Transaction): Promise<number> 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

The fee in satoshis for the transaction.

Argument Details

+ **tx**
  + The transaction for which a fee is to be computed.

#### Method getInstance

Gets the singleton instance of LivePolicy to ensure cache sharing across the application.

```ts
static getInstance(cacheValidityMs: number = 5 * 60 * 1000): LivePolicy 
```
See also: [LivePolicy](./transaction.md#class-livepolicy)

Returns

The singleton LivePolicy instance

Argument Details

+ **cacheValidityMs**
  + How long to cache the fee rate in milliseconds (default: 5 minutes)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: MerklePath

Represents a Merkle Path, which is used to provide a compact proof of inclusion for a
transaction in a block. This class encapsulates all the details required for creating
and verifying Merkle Proofs.

Example

```ts
// Creating and verifying a Merkle Path
const merklePath = MerklePath.fromHex('...');
const isValid = merklePath.verify(txid, chainTracker);
```

```ts
export default class MerklePath {
    blockHeight: number;
    path: Array<Array<{
        offset: number;
        hash?: string;
        txid?: boolean;
        duplicate?: boolean;
    }>>;
    static fromHex(hex: string): MerklePath 
    static fromReader(reader: Reader | ReaderUint8Array, legalOffsetsOnly: boolean = true): MerklePath 
    static fromBinary(bump: number[] | Uint8Array): MerklePath 
    static fromCoinbaseTxidAndHeight(txid: string, height: number): MerklePath 
    constructor(blockHeight: number, path: Array<Array<{
        offset: number;
        hash?: string;
        txid?: boolean;
        duplicate?: boolean;
    }>>, legalOffsetsOnly: boolean = true) 
    toWriter(writer: Writer | WriterUint8Array): void 
    toBinary(): number[] 
    toBinaryUint8Array(): Uint8Array 
    toHex(): string 
    computeRoot(txid?: string): string 
    findOrComputeLeaf(height: number, offset: number): MerklePathLeaf | undefined 
    async verify(txid: string, chainTracker: ChainTracker): Promise<boolean> 
    combine(other: MerklePath): void 
    trim(): void 
}
```

See also: [ChainTracker](./transaction.md#interface-chaintracker), [MerklePathLeaf](./transaction.md#interface-merklepathleaf), [Reader](./primitives.md#class-reader), [ReaderUint8Array](./primitives.md#class-readeruint8array), [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array), [toHex](./primitives.md#variable-tohex), [verify](./compat.md#variable-verify)

#### Method combine

Combines this MerklePath with another to create a compound proof.

```ts
combine(other: MerklePath): void 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Argument Details

+ **other**
  + Another MerklePath to combine with this path.

Throws

- If the paths have different block heights or roots.

#### Method computeRoot

Computes the Merkle root from the provided transaction ID.

```ts
computeRoot(txid?: string): string 
```

Returns

- The computed Merkle root as a hexadecimal string.

Argument Details

+ **txid**
  + The transaction ID to compute the Merkle root for. If not provided, the root will be computed from an unspecified branch, and not all branches will be validated!

Throws

- If the transaction ID is not part of the Merkle Path.

#### Method findOrComputeLeaf

Find leaf with `offset` at `height` or compute from level below, recursively.

Does not add computed leaves to path.

```ts
findOrComputeLeaf(height: number, offset: number): MerklePathLeaf | undefined 
```
See also: [MerklePathLeaf](./transaction.md#interface-merklepathleaf)

#### Method fromBinary

Creates a MerklePath instance from a binary array.

```ts
static fromBinary(bump: number[] | Uint8Array): MerklePath 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Returns

- A new MerklePath instance.

Argument Details

+ **bump**
  + The binary array representation of the Merkle Path.

#### Method fromCoinbaseTxidAndHeight

```ts
static fromCoinbaseTxidAndHeight(txid: string, height: number): MerklePath 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Returns

- A new MerklePath instance which assumes the tx is in a block with no other transactions.

Argument Details

+ **txid**
  + The coinbase txid.
+ **height**
  + The height of the block.

#### Method fromHex

Creates a MerklePath instance from a hexadecimal string.

```ts
static fromHex(hex: string): MerklePath 
```
See also: [MerklePath](./transaction.md#class-merklepath)

Returns

- A new MerklePath instance.

Argument Details

+ **hex**
  + The hexadecimal string representation of the Merkle Path.

#### Method toBinary

Converts the MerklePath to a binary array format.

```ts
toBinary(): number[] 
```

Returns

- The binary array representation of the Merkle Path.

#### Method toBinaryUint8Array

Converts the MerklePath to a binary array format.

```ts
toBinaryUint8Array(): Uint8Array 
```

Returns

- The binary array representation of the Merkle Path.

#### Method toHex

Converts the MerklePath to a hexadecimal string format.

```ts
toHex(): string 
```

Returns

- The hexadecimal string representation of the Merkle Path.

#### Method toWriter

Serializes the MerklePath to the writer provided.

```ts
toWriter(writer: Writer | WriterUint8Array): void 
```
See also: [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array)

Argument Details

+ **writer**
  + The writer to which the Merkle Path will be serialized.

#### Method trim

Remove all internal nodes that are not required by level zero txid nodes.
Assumes that at least all required nodes are present.
Leaves all levels sorted by increasing offset.

```ts
trim(): void 
```

#### Method verify

Verifies if the given transaction ID is part of the Merkle tree at the specified block height.

```ts
async verify(txid: string, chainTracker: ChainTracker): Promise<boolean> 
```
See also: [ChainTracker](./transaction.md#interface-chaintracker)

Returns

- True if the transaction ID is valid within the Merkle Path at the specified block height.

Argument Details

+ **txid**
  + The transaction ID to verify.
+ **chainTracker**
  + The ChainTracker instance used to verify the Merkle root.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: NodejsHttpClient

Adapter for Node Https module to be used as HttpClient

```ts
export class NodejsHttpClient implements HttpClient {
    constructor(private readonly https: HttpsNodejs) 
    async request(url: string, requestOptions: HttpClientRequestOptions): Promise<HttpClientResponse> 
}
```

See also: [HttpClient](./transaction.md#interface-httpclient), [HttpClientRequestOptions](./transaction.md#interface-httpclientrequestoptions), [HttpClientResponse](./transaction.md#type-httpclientresponse), [HttpsNodejs](./transaction.md#interface-httpsnodejs)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: SatoshisPerKilobyte

Represents the "satoshis per kilobyte" transaction fee model.

```ts
export default class SatoshisPerKilobyte implements FeeModel {
    value: number;
    constructor(value: number) 
    async computeFee(tx: Transaction): Promise<number> 
}
```

See also: [FeeModel](./transaction.md#interface-feemodel), [Transaction](./transaction.md#class-transaction)

#### Constructor

Constructs an instance of the sat/kb fee model.

```ts
constructor(value: number) 
```

Argument Details

+ **value**
  + The number of satoshis per kilobyte to charge as a fee.

#### Method computeFee

Computes the fee for a given transaction.

```ts
async computeFee(tx: Transaction): Promise<number> 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

The fee in satoshis for the transaction, as a BigNumber.

Argument Details

+ **tx**
  + The transaction for which a fee is to be computed.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: Transaction

Represents a complete Bitcoin transaction. This class encapsulates all the details
required for creating, signing, and processing a Bitcoin transaction, including
inputs, outputs, and various transaction-related methods.

Example

```ts
// Creating a new transaction
let tx = new Transaction();
tx.addInput(...);
tx.addOutput(...);
await tx.fee();
await tx.sign();
await tx.broadcast();
```

```ts
export default class Transaction {
    version: number;
    inputs: TransactionInput[];
    outputs: TransactionOutput[];
    lockTime: number;
    metadata: Record<string, any>;
    merklePath?: MerklePath;
    static fromBEEF(beef: number[] | Uint8Array, txid?: string): Transaction 
    static fromAtomicBEEF(beef: number[] | Uint8Array): Transaction 
    static fromEF(ef: number[] | Uint8Array): Transaction 
    static parseScriptOffsets(bin: number[] | Uint8Array): {
        inputs: Array<{
            vin: number;
            offset: number;
            length: number;
        }>;
        outputs: Array<{
            vout: number;
            offset: number;
            length: number;
        }>;
    } 
    static fromReader(br: Reader | ReaderUint8Array): Transaction 
    static fromBinary(bin: number[] | Uint8Array): Transaction 
    static fromHex(hex: string): Transaction 
    static fromHexEF(hex: string): Transaction 
    static fromHexBEEF(hex: string, txid?: string): Transaction 
    constructor(version: number = 1, inputs: TransactionInput[] = [], outputs: TransactionOutput[] = [], lockTime: number = 0, metadata: Record<string, any> = new Map(), merklePath?: MerklePath) 
    addInput(input: TransactionInput): void 
    addOutput(output: TransactionOutput): void 
    addP2PKHOutput(address: number[] | string, satoshis?: number): void 
    updateMetadata(metadata: Record<string, any>): void 
    async fee(modelOrFee: FeeModel | number = LivePolicy.getInstance(), changeDistribution: "equal" | "random" = "equal"): Promise<void> 
    getFee(): number 
    async sign(): Promise<void> 
    async broadcast(broadcaster: Broadcaster = defaultBroadcaster()): Promise<BroadcastResponse | BroadcastFailure> 
    toBinary(): number[] 
    toUint8Array(): Uint8Array 
    toEF(): number[] 
    toEFUint8Array(): Uint8Array 
    toHexEF(): string 
    toHex(): string 
    toHexBEEF(): string 
    toHexAtomicBEEF(): string 
    hash(enc?: "hex"): number[] | string 
    id(): number[];
    id(enc: "hex"): string;
    id(enc?: "hex"): number[] | string 
    async verify(chainTracker: ChainTracker | "scripts only" = defaultChainTracker(), feeModel?: FeeModel, memoryLimit?: number): Promise<boolean> 
    writeSerializedBEEF(writer: Writer | WriterUint8Array, allowPartial?: boolean): void 
    toBEEF(allowPartial?: boolean): number[] 
    toBEEFUint8Array(allowPartial?: boolean): Uint8Array 
    toAtomicBEEF(allowPartial?: boolean): number[] 
    toAtomicBEEFUint8Array(allowPartial?: boolean): Uint8Array 
}
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Broadcaster](./transaction.md#interface-broadcaster), [ChainTracker](./transaction.md#interface-chaintracker), [FeeModel](./transaction.md#interface-feemodel), [LivePolicy](./transaction.md#class-livepolicy), [MerklePath](./transaction.md#class-merklepath), [Reader](./primitives.md#class-reader), [ReaderUint8Array](./primitives.md#class-readeruint8array), [TransactionInput](./transaction.md#interface-transactioninput), [TransactionOutput](./transaction.md#interface-transactionoutput), [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array), [defaultBroadcaster](./transaction.md#function-defaultbroadcaster), [defaultChainTracker](./transaction.md#function-defaultchaintracker), [sign](./compat.md#variable-sign), [toHex](./primitives.md#variable-tohex), [toUint8Array](./primitives.md#variable-touint8array), [verify](./compat.md#variable-verify)

#### Method addInput

Adds a new input to the transaction.

```ts
addInput(input: TransactionInput): void 
```
See also: [TransactionInput](./transaction.md#interface-transactioninput)

Argument Details

+ **input**
  + The TransactionInput object to add to the transaction.

Throws

- If the input does not have a sourceTXID or sourceTransaction defined.

#### Method addOutput

Adds a new output to the transaction.

```ts
addOutput(output: TransactionOutput): void 
```
See also: [TransactionOutput](./transaction.md#interface-transactionoutput)

Argument Details

+ **output**
  + The TransactionOutput object to add to the transaction.

#### Method addP2PKHOutput

Adds a new P2PKH output to the transaction.

```ts
addP2PKHOutput(address: number[] | string, satoshis?: number): void 
```

Argument Details

+ **address**
  + The P2PKH address of the output.
+ **satoshis**
  + The number of satoshis to send to the address - if not provided, the output is considered a change output.

#### Method broadcast

Broadcasts a transaction.

```ts
async broadcast(broadcaster: Broadcaster = defaultBroadcaster()): Promise<BroadcastResponse | BroadcastFailure> 
```
See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse), [Broadcaster](./transaction.md#interface-broadcaster), [defaultBroadcaster](./transaction.md#function-defaultbroadcaster)

Returns

A BroadcastResponse or BroadcastFailure from the Broadcaster

Argument Details

+ **broadcaster**
  + The Broadcaster instance wwhere the transaction will be sent

#### Method fee

Computes fees prior to signing.
If no fee model is provided, uses a LivePolicy fee model that fetches current rates from ARC.
If fee is a number, the transaction uses that value as fee.

```ts
async fee(modelOrFee: FeeModel | number = LivePolicy.getInstance(), changeDistribution: "equal" | "random" = "equal"): Promise<void> 
```
See also: [FeeModel](./transaction.md#interface-feemodel), [LivePolicy](./transaction.md#class-livepolicy)

Argument Details

+ **modelOrFee**
  + The initialized fee model to use or fixed fee for the transaction
+ **changeDistribution**
  + Specifies how the change should be distributed
amongst the change outputs

#### Method fromAtomicBEEF

Creates a new transaction from an Atomic BEEF (BRC-95) structure.
Extracts the subject transaction and supporting merkle path and source transactions contained in the BEEF data

```ts
static fromAtomicBEEF(beef: number[] | Uint8Array): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

The subject transaction, linked to its associated inputs populated with merkle paths.

Argument Details

+ **beef**
  + A binary representation of an Atomic BEEF structure.

#### Method fromBEEF

Creates a new transaction, linked to its inputs and their associated merkle paths, from a BEEF V1, V2 or Atomic.
Optionally, you can provide a specific TXID to retrieve a particular transaction from the BEEF data.
If the TXID is provided but not found in the BEEF data, an error will be thrown.
If no TXID is provided, the last transaction in the BEEF data is returned, or the atomic txid.

```ts
static fromBEEF(beef: number[] | Uint8Array, txid?: string): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

An anchored transaction, linked to its associated inputs populated with merkle paths.

Argument Details

+ **beef**
  + A binary representation of transactions in BEEF format.
+ **txid**
  + Optional TXID of the transaction to retrieve from the BEEF data.

#### Method fromBinary

Creates a Transaction instance from a binary array.

```ts
static fromBinary(bin: number[] | Uint8Array): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

- A new Transaction instance.

Argument Details

+ **bin**
  + The binary array representation of the transaction.

#### Method fromEF

Creates a new transaction, linked to its inputs and their associated merkle paths, from a EF (BRC-30) structure.

```ts
static fromEF(ef: number[] | Uint8Array): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

An extended transaction, linked to its associated inputs by locking script and satoshis amounts only.

Argument Details

+ **ef**
  + A binary representation of a transaction in EF format.

#### Method fromHex

Creates a Transaction instance from a hexadecimal string.

```ts
static fromHex(hex: string): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

- A new Transaction instance.

Argument Details

+ **hex**
  + The hexadecimal string representation of the transaction.

#### Method fromHexBEEF

Creates a Transaction instance from a hexadecimal string encoded BEEF.
Optionally, you can provide a specific TXID to retrieve a particular transaction from the BEEF data.
If the TXID is provided but not found in the BEEF data, an error will be thrown.
If no TXID is provided, the last transaction in the BEEF data is returned.

```ts
static fromHexBEEF(hex: string, txid?: string): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

- A new Transaction instance.

Argument Details

+ **hex**
  + The hexadecimal string representation of the transaction BEEF.
+ **txid**
  + Optional TXID of the transaction to retrieve from the BEEF data.

#### Method fromHexEF

Creates a Transaction instance from a hexadecimal string encoded EF.

```ts
static fromHexEF(hex: string): Transaction 
```
See also: [Transaction](./transaction.md#class-transaction)

Returns

- A new Transaction instance.

Argument Details

+ **hex**
  + The hexadecimal string representation of the transaction EF.

#### Method getFee

Utility method that returns the current fee based on inputs and outputs

```ts
getFee(): number 
```

Returns

The current transaction fee

#### Method hash

Calculates the transaction's hash.

```ts
hash(enc?: "hex"): number[] | string 
```

Returns

- The hash of the transaction in the specified format.

Argument Details

+ **enc**
  + The encoding to use for the hash. If 'hex', returns a hexadecimal string; otherwise returns a binary array.

#### Method id

Calculates the transaction's ID in binary array.

```ts
id(): number[]
```

Returns

- The ID of the transaction in the binary array format.

#### Method id

Calculates the transaction's ID in hexadecimal format.

```ts
id(enc: "hex"): string
```

Returns

- The ID of the transaction in the hex format.

Argument Details

+ **enc**
  + The encoding to use for the ID. If 'hex', returns a hexadecimal string.

#### Method id

Calculates the transaction's ID.

```ts
id(enc?: "hex"): number[] | string 
```

Returns

- The ID of the transaction in the specified format.

Argument Details

+ **enc**
  + The encoding to use for the ID. If 'hex', returns a hexadecimal string; otherwise returns a binary array.

#### Method parseScriptOffsets

Since the validation of blockchain data is atomically transaction data validation,
any application seeking to validate data in output scripts must store the entire transaction as well.
Since the transaction data includes the output script data, saving a second copy of potentially
large scripts can bloat application storage requirements.

This function efficiently parses binary transaction data to determine the offsets and lengths of each script.
This supports the efficient retreival of script data from transaction data.

```ts
static parseScriptOffsets(bin: number[] | Uint8Array): {
    inputs: Array<{
        vin: number;
        offset: number;
        length: number;
    }>;
    outputs: Array<{
        vout: number;
        offset: number;
        length: number;
    }>;
} 
```

Returns

inputs: { vin: number, offset: number, length: number }[]
outputs: { vout: number, offset: number, length: number }[]
}

Argument Details

+ **bin**
  + binary transaction data

#### Method sign

Signs a transaction, hydrating all its unlocking scripts based on the provided script templates where they are available.

```ts
async sign(): Promise<void> 
```

#### Method toAtomicBEEF

Serializes this transaction and its inputs into the Atomic BEEF (BRC-95) format.
The Atomic BEEF format starts with a 4-byte prefix `0x01010101`, followed by the TXID of the subject transaction,
and then the BEEF data containing only the subject transaction and its dependencies.
This format ensures that the BEEF structure is atomic and contains no unrelated transactions.

```ts
toAtomicBEEF(allowPartial?: boolean): number[] 
```

Returns

- The serialized Atomic BEEF structure.

Argument Details

+ **allowPartial**
  + If true, error will not be thrown if there are any missing sourceTransactions.

Throws

Error if there are any missing sourceTransactions unless `allowPartial` is true.

#### Method toAtomicBEEFUint8Array

Serializes this transaction and its inputs into the Atomic BEEF (BRC-95) format.
The Atomic BEEF format starts with a 4-byte prefix `0x01010101`, followed by the TXID of the subject transaction,
and then the BEEF data containing only the subject transaction and its dependencies.
This format ensures that the BEEF structure is atomic and contains no unrelated transactions.

```ts
toAtomicBEEFUint8Array(allowPartial?: boolean): Uint8Array 
```

Returns

- The serialized Atomic BEEF structure.

Argument Details

+ **allowPartial**
  + If true, error will not be thrown if there are any missing sourceTransactions.

Throws

Error if there are any missing sourceTransactions unless `allowPartial` is true.

#### Method toBEEF

Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.

```ts
toBEEF(allowPartial?: boolean): number[] 
```

Returns

The serialized BEEF structure

Argument Details

+ **allowPartial**
  + If true, error will not be thrown if there are any missing sourceTransactions.

Throws

Error if there are any missing sourceTransactions unless `allowPartial` is true.

#### Method toBEEFUint8Array

Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.

```ts
toBEEFUint8Array(allowPartial?: boolean): Uint8Array 
```

Returns

The serialized BEEF structure

Argument Details

+ **allowPartial**
  + If true, error will not be thrown if there are any missing sourceTransactions.

Throws

Error if there are any missing sourceTransactions unless `allowPartial` is true.

#### Method toBinary

Converts the transaction to a binary array format.

```ts
toBinary(): number[] 
```

Returns

- The binary array representation of the transaction.

#### Method toEF

Converts the transaction to a BRC-30 EF format.

```ts
toEF(): number[] 
```

Returns

- The BRC-30 EF representation of the transaction.

#### Method toEFUint8Array

Converts the transaction to a BRC-30 EF format.

```ts
toEFUint8Array(): Uint8Array 
```

Returns

- The BRC-30 EF representation of the transaction.

#### Method toHex

Converts the transaction to a hexadecimal string format.

```ts
toHex(): string 
```

Returns

- The hexadecimal string representation of the transaction.

#### Method toHexAtomicBEEF

Converts the transaction to a hexadecimal string Atomic BEEF.

```ts
toHexAtomicBEEF(): string 
```

Returns

- The hexadecimal string representation of the transaction Atomic BEEF.

#### Method toHexBEEF

Converts the transaction to a hexadecimal string BEEF.

```ts
toHexBEEF(): string 
```

Returns

- The hexadecimal string representation of the transaction BEEF.

#### Method toHexEF

Converts the transaction to a hexadecimal string EF.

```ts
toHexEF(): string 
```

Returns

- The hexadecimal string representation of the transaction EF.

#### Method updateMetadata

Updates the transaction's metadata.

```ts
updateMetadata(metadata: Record<string, any>): void 
```

Argument Details

+ **metadata**
  + The metadata object to merge into the existing metadata.

#### Method verify

Verifies the legitimacy of the Bitcoin transaction according to the rules of SPV by ensuring all the input transactions link back to valid block headers, the chain of spends for all inputs are valid, and the sum of inputs is not less than the sum of outputs.

```ts
async verify(chainTracker: ChainTracker | "scripts only" = defaultChainTracker(), feeModel?: FeeModel, memoryLimit?: number): Promise<boolean> 
```
See also: [ChainTracker](./transaction.md#interface-chaintracker), [FeeModel](./transaction.md#interface-feemodel), [defaultChainTracker](./transaction.md#function-defaultchaintracker)

Returns

Whether the transaction is valid according to the rules of SPV.

Argument Details

+ **chainTracker**
  + An instance of ChainTracker, a Bitcoin block header tracker. If the value is set to 'scripts only', headers will not be verified. If not provided then the default chain tracker will be used.
+ **feeModel**
  + An instance of FeeModel, a fee model to use for fee calculation. If not provided then the default fee model will be used.
+ **memoryLimit**
  + The maximum memory in bytes usage allowed for script evaluation. If not provided then the default memory limit will be used.

Example

```ts
tx.verify(new WhatsOnChain(), LivePolicy.getInstance())
```

#### Method writeSerializedBEEF

Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.

```ts
writeSerializedBEEF(writer: Writer | WriterUint8Array, allowPartial?: boolean): void 
```
See also: [Writer](./primitives.md#class-writer), [WriterUint8Array](./primitives.md#class-writeruint8array)

Returns

The serialized BEEF structure

Argument Details

+ **allowPartial**
  + If true, error will not be thrown if there are any missing sourceTransactions.

Throws

Error if there are any missing sourceTransactions unless `allowPartial` is true.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Class: WhatsOnChain

Represents a chain tracker based on What's On Chain .

```ts
export default class WhatsOnChain implements ChainTracker {
    readonly network: string;
    readonly apiKey: string;
    protected readonly URL: string;
    protected readonly httpClient: HttpClient;
    constructor(network: "main" | "test" | "stn" = "main", config: WhatsOnChainConfig = {}) 
    async isValidRootForHeight(root: string, height: number): Promise<boolean> 
    async currentHeight(): Promise<number> 
    protected getHttpHeaders(): Record<string, string> 
}
```

See also: [ChainTracker](./transaction.md#interface-chaintracker), [HttpClient](./transaction.md#interface-httpclient), [WhatsOnChainConfig](./transaction.md#interface-whatsonchainconfig)

#### Constructor

Constructs an instance of the WhatsOnChain ChainTracker.

```ts
constructor(network: "main" | "test" | "stn" = "main", config: WhatsOnChainConfig = {}) 
```
See also: [WhatsOnChainConfig](./transaction.md#interface-whatsonchainconfig)

Argument Details

+ **network**
  + The BSV network to use when calling the WhatsOnChain API.
+ **config**
  + Configuration options for the WhatsOnChain ChainTracker.

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Functions

| |
| --- |
| [defaultBroadcaster](#function-defaultbroadcaster) |
| [defaultChainTracker](#function-defaultchaintracker) |
| [defaultHttpClient](#function-defaulthttpclient) |
| [isBroadcastFailure](#function-isbroadcastfailure) |
| [isBroadcastResponse](#function-isbroadcastresponse) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Function: defaultBroadcaster

```ts
export function defaultBroadcaster(isTestnet: boolean = false, config: ArcConfig = {}): Broadcaster 
```

See also: [ArcConfig](./transaction.md#interface-arcconfig), [Broadcaster](./transaction.md#interface-broadcaster)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: defaultChainTracker

```ts
export function defaultChainTracker(): ChainTracker 
```

See also: [ChainTracker](./transaction.md#interface-chaintracker)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: defaultHttpClient

Returns a default HttpClient implementation based on the environment that it is run on.
This method will attempt to use `window.fetch` if available (in browser environments).
If running in a Node environment, it falls back to using the Node `https` module

```ts
export function defaultHttpClient(): HttpClient 
```

See also: [HttpClient](./transaction.md#interface-httpclient)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: isBroadcastFailure

Convenience type guard for response from `Broadcaster.broadcast`

```ts
export function isBroadcastFailure(r: BroadcastResponse | BroadcastFailure): r is BroadcastFailure 
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Function: isBroadcastResponse

Convenience type guard for response from `Broadcaster.broadcast`

```ts
export function isBroadcastResponse(r: BroadcastResponse | BroadcastFailure): r is BroadcastResponse 
```

See also: [BroadcastFailure](./transaction.md#interface-broadcastfailure), [BroadcastResponse](./transaction.md#interface-broadcastresponse)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Types

| |
| --- |
| [Fetch](#type-fetch) |
| [HttpClientResponse](#type-httpclientresponse) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Type: Fetch

fetch function interface limited to options needed by ts-sdk

Makes a request to the server.

```ts
export type Fetch = (url: string, options: FetchOptions) => Promise<Response>
```

See also: [FetchOptions](./transaction.md#interface-fetchoptions)

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Type: HttpClientResponse

An interface for the response returned by the request method.

```ts
export type HttpClientResponse<T = any> = {
    data: T;
    status: number;
    statusText: string;
    ok: true;
} | {
    data: any;
    status: number;
    statusText: string;
    ok: false;
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Enums

### Enum: TX_DATA_FORMAT

```ts
export enum TX_DATA_FORMAT {
    RAWTX = 0,
    RAWTX_AND_BUMP_INDEX = 1,
    TXID_ONLY = 2
}
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
## Variables

| |
| --- |
| [ATOMIC_BEEF](#variable-atomic_beef) |
| [BEEF_V1](#variable-beef_v1) |
| [BEEF_V2](#variable-beef_v2) |

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---

### Variable: ATOMIC_BEEF

```ts
ATOMIC_BEEF = 16843009
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BEEF_V1

```ts
BEEF_V1 = 4022206465
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
### Variable: BEEF_V2

```ts
BEEF_V2 = 4022206466
```

Links: [API](#api), [Interfaces](#interfaces), [Classes](#classes), [Functions](#functions), [Types](#types), [Enums](#enums), [Variables](#variables)

---
