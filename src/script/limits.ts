// Interpreter limits and behavioral flags.
export const maxScriptElementSize = 1024 * 1024 * 1024
export const maxMultisigKeyCount = Math.pow(2, 31) - 1
export const maxMultisigKeyCountBigInt = BigInt(maxMultisigKeyCount)
export const requireMinimalPush = true
export const requirePushOnlyUnlockingScripts = true
export const requireLowSSignatures = true
export const requireCleanStack = true
