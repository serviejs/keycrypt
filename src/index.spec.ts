import { Keycrypt } from './index'

describe('keycrypt', () => {
  const secrets = [Buffer.from('secret', 'utf8'), Buffer.from('fallback', 'utf8')]
  const keycrypt = new Keycrypt(secrets)

  it('should throw when selecting an unknown algorithm', () => {
    expect(() => new Keycrypt([], undefined, -1)).toThrowError('Unknown algorithm: -1')
  })

  it('should encrypt and decrypt data', () => {
    const raw = Buffer.from('example', 'utf8')
    const encrypted = keycrypt.encode(raw)
    const decrypted = keycrypt.decode(encrypted)

    expect(decrypted).toEqual(raw)
  })

  it('should fail to decrypt when data is small', () => {
    const result = keycrypt.decode(Buffer.alloc(10))

    expect(result).toEqual(undefined)
  })

  it('should verify the hmac is correct', () => {
    const encrypted = keycrypt.encode(Buffer.from('example', 'utf8'))

    // Mess with HMAC.
    encrypted.set([1, 2, 3], 1)

    const result = keycrypt.decode(encrypted)

    expect(result).toBe(undefined)
  })

  it('should fail to decode if algorithm byte is unknown', () => {
    const encrypted = keycrypt.encode(Buffer.from('example', 'utf8'))

    encrypted.set([55], 0)

    const result = keycrypt.decode(encrypted)

    expect(result).toBe(undefined)
  })

  it('should decrypt with old secret', () => {
    const raw = Buffer.from('super secret message', 'utf8')
    const encrypted = new Keycrypt([secrets[1]]).encode(raw)
    const decrypted = keycrypt.decode(encrypted)

    expect(decrypted).toEqual(raw)
  })
})
