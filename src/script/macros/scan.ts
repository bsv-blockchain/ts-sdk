import Script from '../Script.js'
import type { ScriptMacroDefinition, ScriptMacroMatch } from './types.js'

export function scanScriptForMacros (
  script: Script,
  macros: ReadonlyArray<ScriptMacroDefinition>,
  ownerId: number
): void {
  if (macros.length === 0) return
  const chunks = script.chunks
  for (let i = 0; i < chunks.length; i++) {
    let bestMatch: { macro: ScriptMacroDefinition, match: ScriptMacroMatch } | null = null
    for (const macro of macros) {
      const match = macro.match(chunks, i)
      if (match == null || match.length <= 0 || i + match.length > chunks.length) continue
      if (bestMatch == null || match.length > bestMatch.match.length) {
        bestMatch = { macro, match }
      }
    }
    if (bestMatch != null) {
      const length = bestMatch.match.length
      for (let offset = 0; offset < length; offset++) {
        chunks[i + offset].macro = {
          name: bestMatch.macro.name,
          length,
          role: offset === 0 ? 'start' : 'body',
          index: offset,
          ownerId,
          meta: offset === 0 ? bestMatch.match.meta : undefined
        }
      }
      i += length - 1
    }
  }
}
