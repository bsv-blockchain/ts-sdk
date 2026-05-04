export type U16 = number
export type U32Bits = number[]
export type U256Limbs = number[]

export interface SecpPoint {
  x: bigint
  y: bigint
  infinity?: boolean
}

export interface Sha256State {
  words: number[]
}
