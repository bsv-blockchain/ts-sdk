import { IdentityKey, Invoice, ModuleContext, RemittanceOptionId, ThreadId } from './types.js'

/**
 * A remittance module implements a specific settlement system.
 *
 * The RemittanceManager core uses module ids as the only “capability mechanism”:
 * if an invoice contains an option with module id X, a payer can only satisfy it
 * if they are configured with module X.
 */
export interface RemittanceModule<
  TOptionTerms = unknown,
  TSettlementArtifact = unknown,
  TReceiptData = unknown,
  TTermination = unknown
> {
  /** Unique id used as the invoice.options key and as settlement.moduleId. */
  id: RemittanceOptionId
  /** Human-readable name for UIs. */
  name: string

  /**
   * Creates module-defined option terms that will be embedded into the invoice.
   *
   * In UTXO-ish offers, these option terms may include a partially-signed transaction template.
   */
  createOption: (args: { threadId: ThreadId; invoice: Invoice }, ctx: ModuleContext) => Promise<TOptionTerms>

  /**
   * Builds the settlement artifact for a chosen option.
   *
   * For UTXO settlement systems, this is usually a transaction (or partially-signed tx) to be broadcast.
   */
  buildSettlement: (
    args: { threadId: ThreadId; invoice: Invoice; option: TOptionTerms; note?: string },
    ctx: ModuleContext
  ) => Promise<TSettlementArtifact>

  /**
   * Accepts a settlement artifact on the payee side.
   *
   * The module should validate and internalize/store whatever it needs.
   * The manager will wrap the returned value as receipt.receiptData.
   * 
   * If the settlement is invalid, the module should return either a termination or receiptData indicating the failure.
   */
  acceptSettlement: (
    args: { threadId: ThreadId; invoice?: Invoice; settlement: TSettlementArtifact; sender: IdentityKey },
    ctx: ModuleContext
  ) => Promise<TReceiptData | TTermination>

  /**
   * Processes a receipt on the payer side.
   *
   * This is where a module can automatically internalize a refund, mark a local order fulfilled, etc.
   */
  processReceipt: (
    args: { threadId: ThreadId; invoice?: Invoice; receiptData: TReceiptData; sender: IdentityKey },
    ctx: ModuleContext
  ) => Promise<void>
}
