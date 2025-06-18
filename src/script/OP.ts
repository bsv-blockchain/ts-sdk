/**
 * An object mapping opcode names (such as OP_DUP) to their corresponding numbers (such as 0x76), and vice versa.
 */
const OP = {
  // push value
  OP_FALSE: 0x00,
  OP_0: 0x00,
  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_RESERVED: 0x50,
  OP_TRUE: 0x51,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_8: 0x58,
  OP_9: 0x59,
  OP_10: 0x5a,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_13: 0x5d,
  OP_14: 0x5e,
  OP_15: 0x5f,
  OP_16: 0x60,

  // control
  OP_NOP: 0x61,
  OP_VER: 0x62,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_VERIF: 0x65,
  OP_VERNOTIF: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_RETURN: 0x6a,

  // stack ops
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
  OP_3DUP: 0x6f,
  OP_2OVER: 0x70,
  OP_2ROT: 0x71,
  OP_2SWAP: 0x72,
  OP_IFDUP: 0x73,
  OP_DEPTH: 0x74,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_OVER: 0x78,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_ROT: 0x7b,
  OP_SWAP: 0x7c,
  OP_TUCK: 0x7d,

  // data manipulation ops
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,    // after monolith upgrade (May 2018)
  OP_NUM2BIN: 0x80,  // after monolith upgrade (May 2018)
  OP_BIN2NUM: 0x81,  // after monolith upgrade (May 2018)
  OP_SIZE: 0x82,

  // bit logic
  OP_INVERT: 0x83,
  OP_AND: 0x84,
  OP_OR: 0x85,
  OP_XOR: 0x86,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_RESERVED1: 0x89,
  OP_RESERVED2: 0x8a,

  // numeric
  OP_1ADD: 0x8b,
  OP_1SUB: 0x8c,
  OP_2MUL: 0x8d,
  OP_2DIV: 0x8e,
  OP_NEGATE: 0x8f,
  OP_ABS: 0x90,
  OP_NOT: 0x91,
  OP_0NOTEQUAL: 0x92,

  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_LSHIFT: 0x98,
  OP_RSHIFT: 0x99,

  OP_BOOLAND: 0x9a,
  OP_BOOLOR: 0x9b,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_NUMNOTEQUAL: 0x9e,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHAN: 0xa0,
  OP_LESSTHANOREQUAL: 0xa1,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_MIN: 0xa3,
  OP_MAX: 0xa4,

  OP_WITHIN: 0xa5,

  // crypto
  OP_RIPEMD160: 0xa6,
  OP_SHA1: 0xa7,
  OP_SHA256: 0xa8,
  OP_HASH160: 0xa9,
  OP_HASH256: 0xaa,
  OP_CODESEPARATOR: 0xab,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae,
  OP_CHECKMULTISIGVERIFY: 0xaf,

  // expansion
  OP_NOP1: 0xb0,
  OP_NOP2: 0xb1,    // Used on BTC for OP_CHECKLOCKTIMEVERIFY
  OP_NOP3: 0xb2,    // Used on BTC for OP_CHECKSEQUENCEVERIFY
  OP_NOP4: 0xb3,    // OP_NOP4 allocated to restore OP_SUBSTR in 2025 CHRONICLE upgrade
  OP_SUBSTR: 0xb3,  // OP_NOP4 allocated to restore OP_SUBSTR in 2025 CHRONICLE upgrade
  OP_NOP5: 0xb4,    // OP_NOP5 allocated to restore OP_LEFT in 2025 CHRONICLE upgrade
  OP_LEFT: 0xb4,    // OP_NOP5 allocated to restore OP_LEFT in 2025 CHRONICLE upgrade
  OP_NOP6: 0xb5,    // OP_NOP6 allocated to restore OP_RIGHT in 2025 CHRONICLE upgrade
  OP_RIGHT: 0xb5,   // OP_NOP6 allocated to restore OP_RIGHT in 2025 CHRONICLE upgrade
  OP_NOP7: 0xb6,
  OP_NOP8: 0xb7,
  OP_NOP9: 0xb8,
  OP_NOP10: 0xb9,
  OP_NOP11: 0xba,
  OP_NOP12: 0xbb,
  OP_NOP13: 0xbc,
  OP_NOP14: 0xbd,
  OP_NOP15: 0xbe,
  OP_NOP16: 0xbf,
  OP_NOP17: 0xc0,
  OP_NOP18: 0xc1,
  OP_NOP19: 0xc2,
  OP_NOP20: 0xc3,
  OP_NOP21: 0xc4,
  OP_NOP22: 0xc5,
  OP_NOP23: 0xc6,
  OP_NOP24: 0xc7,
  OP_NOP25: 0xc8,
  OP_NOP26: 0xc9,
  OP_NOP27: 0xca,
  OP_NOP28: 0xcb,
  OP_NOP29: 0xcc,
  OP_NOP30: 0xcd,
  OP_NOP31: 0xce,
  OP_NOP32: 0xcf,
  OP_NOP33: 0xd0,
  OP_NOP34: 0xd1,
  OP_NOP35: 0xd2,
  OP_NOP36: 0xd3,
  OP_NOP37: 0xd4,
  OP_NOP38: 0xd5,
  OP_NOP39: 0xd6,
  OP_NOP40: 0xd7,
  OP_NOP41: 0xd8,
  OP_NOP42: 0xd9,
  OP_NOP43: 0xda,
  OP_NOP44: 0xdb,
  OP_NOP45: 0xdc,
  OP_NOP46: 0xdd,
  OP_NOP47: 0xde,
  OP_NOP48: 0xdf,
  OP_NOP49: 0xe0,
  OP_NOP50: 0xe1,
  OP_NOP51: 0xe2,
  OP_NOP52: 0xe3,
  OP_NOP53: 0xe4,
  OP_NOP54: 0xe5,
  OP_NOP55: 0xe6,
  OP_NOP56: 0xe7,
  OP_NOP57: 0xe8,
  OP_NOP58: 0xe9,
  OP_NOP59: 0xea,
  OP_NOP60: 0xeb,
  OP_NOP61: 0xec,
  OP_NOP62: 0xed,
  OP_NOP63: 0xee,
  OP_NOP64: 0xef,
  OP_NOP65: 0xf0,
  OP_NOP66: 0xf1,
  OP_NOP67: 0xf2,
  OP_NOP68: 0xf3,
  OP_NOP69: 0xf4,
  OP_NOP70: 0xf5,
  OP_NOP71: 0xf6,
  OP_NOP72: 0xf7,
  OP_NOP73: 0xf8,
  OP_NOP77: 0xfc,

  // template matching params
  OP_SMALLDATA: 0xf9,
  OP_SMALLINTEGER: 0xfa,
  OP_PUBKEYS: 0xfb,
  OP_PUBKEYHASH: 0xfd,
  OP_PUBKEY: 0xfe,

  OP_INVALIDOPCODE: 0xff
}

for (const name in OP) {
  OP[OP[name]] = name
}

export default OP
