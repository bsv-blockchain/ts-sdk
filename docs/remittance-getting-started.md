# Remittance Getting Started

This guide introduces the remittance subsystem and shows how to wire a maker and taker together using `RemittanceManager`, `CommsLayer`, and a module such as `Brc29RemittanceModule`. Identity verification is manager-managed, not module-managed, and it is always acknowledged before proceeding.

## Concepts

- **RemittanceManager** orchestrates threads, identity exchange, transport, and receipts.
- **RemittanceModule** builds/accepts settlement artifacts for a specific payment method.
- **CommsLayer** delivers protocol envelopes (store-and-forward and/or live).
- **IdentityLayer** handles certificate requests, responses, and acknowledgment.
- **ThreadHandle** gives you waiters (`waitForState`, `waitForSettlement`, `waitForReceipt`) for streaming or async flows.

## Sequence: Invoice to Receipt

```mermaid
sequenceDiagram
  participant Maker
  participant Comms
  participant Taker

  Maker->>Comms: invoice envelope
  Comms->>Taker: invoice envelope
  Taker->>Taker: build settlement via module
  Taker->>Comms: settlement envelope
  Comms->>Maker: settlement envelope
  Maker->>Maker: accept settlement via module
  Maker->>Comms: receipt envelope (optional)
  Comms->>Taker: receipt envelope
```

## Sequence: Identity Exchange (when enabled)

```mermaid
sequenceDiagram
  participant Initiator
  participant Comms
  participant Counterparty

  Initiator->>Comms: identityVerificationRequest
  Comms->>Counterparty: identityVerificationRequest
  Counterparty->>Comms: identityVerificationResponse
  Comms->>Initiator: identityVerificationResponse
  Initiator->>Comms: identityVerificationAcknowledgment
  Comms->>Counterparty: identityVerificationAcknowledgment
```

Identity acknowledgment is required before invoicing/settlement proceeds when configured.

## Basic Setup

```ts
import { RemittanceManager } from '@bsv/sdk/remittance'
import { Brc29RemittanceModule } from '@bsv/sdk/remittance'

const manager = new RemittanceManager(
  {
    remittanceModules: [new Brc29RemittanceModule()],
    options: {
      receiptProvided: true,
      autoIssueReceipt: true,
      identityOptions: { makerRequestIdentity: 'beforeInvoicing', takerRequestIdentity: 'beforeSettlement' }
    }
  },
  walletInterface,
  commsLayer
)

await manager.init()
```

## Maker Flow (create and send invoice)

```ts
const invoiceHandle = await maker.sendInvoice('taker-identity-key', {
  lineItems: [],
  total: { value: '1000', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
  note: 'Order 123'
})

await invoiceHandle.waitForSettlement()
```

## Taker Flow (pay invoice)

```ts
await taker.syncThreads()
const receiptOrTermination = await taker.pay(invoiceHandle.threadId, 'brc29.p2pkh')
```

## Event Hooks

Use `onEvent` or the per-event `events` callbacks to react to each step.

```ts
const manager = new RemittanceManager(
  {
    remittanceModules: [new Brc29RemittanceModule()],
    events: {
      onStateChanged: (event) => console.log('state', event.previous, '->', event.next),
      onSettlementReceived: (event) => console.log('settlement', event.settlement)
    }
  },
  walletInterface,
  commsLayer
)
```

## State Machine and Auditing

Threads follow the `RemittanceThreadState` state machine, and every transition is recorded in `thread.stateLog`.
Use `REMITTANCE_STATE_TRANSITIONS` to validate transitions or to build a visualizer.

```ts
const thread = manager.getThreadOrThrow(threadId)
console.log(thread.state)
console.log(thread.stateLog)
```

## Live / Streaming Mode

If your `CommsLayer` supports `listenForLiveMessages`, call:

```ts
await manager.startListening()
```

This keeps state current while you use `ThreadHandle.waitForState` to await transitions.
