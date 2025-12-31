import {
  RemittanceEnvelope,
  Invoice,
  IdentityVerificationRequest,
  IdentityVerificationResponse,
  IdentityVerificationAcknowledgment,
  Settlement,
  Receipt,
  SAT_UNIT
} from '../types.js'

/** Example invoice envelope. */
const exampleInvoice: RemittanceEnvelope<'invoice', Invoice> = {
  v: 1,
  id: '123',
  kind: 'invoice',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'invoice',
    threadId: 'thread-abc',
    payee: 'identity-key-1',
    payer: 'identity-key-2',
    lineItems: [
      { description: 'Test item', amount: { value: '100', unit: SAT_UNIT } },
      { description: 'Another item', quantity: '3', amount: { value: '50', unit: SAT_UNIT } }
    ],
    note: 'This is a test invoice',
    total: { value: '150', unit: { namespace: 'bsv', code: 'sat', decimals: 0 } },
    invoiceNumber: 'INV-123',
    options: {
      'module-1': { someOptionField: 'someValue' },
      'module-2': { anotherOptionField: 42 }
    },
    createdAt: Date.now(),
  }
}

/** Example identity verification request envelope. */
const exampleIdentityVerificationRequest: RemittanceEnvelope<'identityVerificationRequest', IdentityVerificationRequest> = {
  v: 1,
  id: 'identity-verification-request-123',
  kind: 'identityVerificationRequest',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'identityVerificationRequest',
    threadId: 'thread-abc',
    request: {
      types: { personalId: ['name', 'dob'], businessId: ['duns'] },
      certifiers: ['certifier1', 'certifier2']
    }
  }
}

/** Example identity verification response envelope. */
const exampleIdentityVerificationResponse: RemittanceEnvelope<'identityVerificationResponse', IdentityVerificationResponse> = {
  v: 1,
  id: 'identity-verification-response-123',
  kind: 'identityVerificationResponse',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'identityVerificationResponse',
    threadId: 'thread-abc',
    certificates: [{
      type: 'personalId',
      certifier: 'certifier1',
      subject: 'identity-key-2',
      fields: { name: 'Alice', dob: '1990-01-01' },
      signature: 'signature1',
      serialNumber: 'serial1',
      revocationOutpoint: 'outpoint1',
      keyringForVerifier: {
        name: 'key-for-name'
      }
    }]
  }
}

/** Example identity verification acknowledgment envelope. */
const exampleIdentityVerificationAcknowledgment: RemittanceEnvelope<'identityVerificationAcknowledgment', IdentityVerificationAcknowledgment> = {
  v: 1,
  id: 'identity-verification-ack-123',
  kind: 'identityVerificationAcknowledgment',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'identityVerificationAcknowledgment',
    threadId: 'thread-abc'
  }
}

/** Example settlement envelope. */
const exampleSettlement: RemittanceEnvelope<'settlement', Settlement> = {
  v: 1,
  id: 'settlement-123',
  kind: 'settlement',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'settlement',
    threadId: 'thread-abc',
    moduleId: 'module-1',
    optionId: 'option-1',
    sender: 'identity-key-1',
    createdAt: Date.now(),
    artifact: { txid: 'txid-abc' },
    note: 'Test note'
  }
}

/** Example receipt envelope. */
const exampleReceipt: RemittanceEnvelope<'receipt', Receipt> = {
  v: 1,
  id: 'receipt-123',
  kind: 'receipt',
  threadId: 'thread-abc',
  createdAt: Date.now(),
  payload: {
    kind: 'receipt',
    threadId: 'thread-abc',
    moduleId: 'module-1',
    optionId: 'option-1',
    payee: 'identity-key-1',
    payer: 'identity-key-2',
    createdAt: Date.now(),
    receiptData: { txid: 'txid-abc' }
  }
}
