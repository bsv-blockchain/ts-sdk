import { validateCertificates } from '../../../auth/utils/validateCertificates'
import { VerifiableCertificate } from '../../../auth/certificates/VerifiableCertificate'
import { ProtoWallet, WalletInterface } from '../../../wallet/index'
import { PrivateKey } from '../../../primitives/index'
import { AuthMessage } from '../../../auth/types'

let mockVerify = jest.fn(async () => await Promise.resolve(true))
let mockDecryptFields = jest.fn(
  async () => await Promise.resolve({ field1: 'decryptedValue1' })
)
const mockInstances: Array<{
  type: string
  serialNumber: string
  subject: string
  certifier: string
  revocationOutpoint: string
  fields: Record<string, string>
  decryptedFields: Record<string, unknown>
  verify: jest.Mock<Promise<boolean>>
  decryptFields: jest.Mock<Promise<Record<string, string>>> // ✅ Explicit return type
}> = []

jest.mock('../../../auth/certificates/VerifiableCertificate', () => {
  return {
    VerifiableCertificate: jest.fn().mockImplementation(() => {
      const instance = {
        type: 'requested_type',
        serialNumber: 'valid_serial',
        subject: 'valid_subject',
        certifier: 'valid_certifier',
        revocationOutpoint: 'outpoint',
        fields: { field1: 'encryptedData1' },
        decryptedFields: {},
        verify: mockVerify,
        decryptFields: mockDecryptFields
      }
      mockInstances.push(instance)
      return instance
    })
  }
})

describe('validateCertificates', () => {
  let verifierWallet: WalletInterface
  let message: AuthMessage

  beforeEach(() => {
    jest.clearAllMocks()
    mockInstances.length = 0 // Clear tracked instances

    // Reset state
    mockVerify = jest.fn(async () => await Promise.resolve(true))
    mockDecryptFields = jest.fn(
      async () => await Promise.resolve({ field1: 'decryptedValue1' })
    )

    verifierWallet = new ProtoWallet(new PrivateKey(1)) as unknown as WalletInterface
    message = {
      version: '1.0',
      messageType: 'certificateResponse',
      identityKey: 'valid_subject',
      certificates: [
        {
          type: 'requested_type',
          serialNumber: 'valid_serial',
          subject: 'valid_subject',
          certifier: 'valid_certifier',
          revocationOutpoint: 'outpoint',
          fields: { field1: 'encryptedData1' },
          decryptedFields: {}
        } as any
      ]
    }
  })

  it('completes without errors for valid input', async () => {
    await expect(
      validateCertificates(verifierWallet, message)
    ).resolves.not.toThrow()

    expect(VerifiableCertificate).toHaveBeenCalledTimes(
      message.certificates!.length
    )
    expect(mockVerify).toHaveBeenCalledTimes(message.certificates!.length)
    expect(mockDecryptFields).toHaveBeenCalledWith(verifierWallet, undefined, undefined, undefined)
  })

  it('throws an error for mismatched identity key', async () => {
    message.identityKey = 'different_subject'

    await expect(validateCertificates(verifierWallet, message)).rejects.toThrow(
      'The subject of one of your certificates ("valid_subject") is not the same as the request sender ("different_subject").'
    )
  })

  it('throws an error if certificate signature is invalid', async () => {
    mockVerify.mockResolvedValueOnce(false)

    await expect(validateCertificates(verifierWallet, message)).rejects.toThrow(
      'The signature for the certificate with serial number valid_serial is invalid!'
    )
  })

  it('throws an error for unrequested certifier', async () => {
    const certificatesRequested = {
      certifiers: ['another_certifier'],
      types: { requested_type: ['field1'] }
    }

    await expect(
      validateCertificates(verifierWallet, message, certificatesRequested)
    ).rejects.toThrow(
      'Certificate with serial number valid_serial has an unrequested certifier: valid_certifier'
    )
  })

  it('throws an error for unrequested certificate type', async () => {
    const certificatesRequested = {
      certifiers: ['valid_certifier'],
      types: { another_type: ['field1'] }
    }

    await expect(
      validateCertificates(verifierWallet, message, certificatesRequested)
    ).rejects.toThrow('Certificate with type requested_type was not requested')
  })

  it('decrypts fields without throwing errors', async () => {
    await expect(
      validateCertificates(verifierWallet, message)
    ).resolves.not.toThrow()
    for (const instance of mockInstances) {
      expect(instance.decryptFields).toHaveBeenCalledWith(verifierWallet, undefined, undefined, undefined)
    }
  })

  it('throws an error if a field decryption fails', async () => {
    mockDecryptFields.mockRejectedValue(new Error('Decryption failed'))
    await expect(validateCertificates(verifierWallet, message)).rejects.toThrow(
      'Decryption failed'
    )
  })

  it('handles multiple certificates properly', async () => {
    const anotherCertificate = {
      type: 'requested_type',
      serialNumber: 'another_serial',
      subject: 'valid_subject',
      certifier: 'valid_certifier',
      revocationOutpoint: 'outpoint',
      fields: { field1: 'encryptedData1' },
      decryptedFields: {}
    } as any

    message.certificates!.push(anotherCertificate)

    await expect(
      validateCertificates(verifierWallet, message)
    ).resolves.not.toThrow()

    expect(VerifiableCertificate).toHaveBeenCalledTimes(2)
    expect(mockVerify).toHaveBeenCalledTimes(2)
    for (const instance of mockInstances) {
      expect(instance.decryptFields).toHaveBeenCalledWith(verifierWallet, undefined, undefined, undefined)
    }
  })
})
