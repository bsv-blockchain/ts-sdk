import { WalletProtocol } from '../../wallet/index.js'

export const defaultIdentity: DisplayableIdentity = {
  name: 'Unknown Identity',
  avatarURL: 'XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst',
  identityKey: '',
  abbreviatedKey: '',
  badgeIconURL: 'XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG',
  badgeLabel: 'Not verified by anyone you trust.',
  badgeClickURL: 'https://projectbabbage.com/docs/unknown-identity'
}

export interface IdentityClientOptions {
  protocolID: WalletProtocol
  keyID: string
  tokenAmount: number
  outputIndex: number
}
export const DEFAULT_IDENTITY_CLIENT_OPTIONS: IdentityClientOptions = {
  protocolID: [1, 'identity'],
  keyID: '1',
  tokenAmount: 1,
  outputIndex: 0
}

export interface DisplayableIdentity {
  name: string
  avatarURL: string
  abbreviatedKey: string
  identityKey: string
  badgeIconURL: string
  badgeLabel: string
  badgeClickURL: string
}

export const KNOWN_IDENTITY_TYPES = {
  identiCert: 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=',
  discordCert: '2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=',
  phoneCert: 'mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=',
  xCert: 'vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=',
  registrant: 'YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=',
  emailCert: 'exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=',
  anyone: 'mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=',
  self: 'Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=',
  coolCert: 'AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo='
}
