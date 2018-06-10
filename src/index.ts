import { pbkdf2Sync, randomBytes, createCipheriv, createHmac, timingSafeEqual, createDecipheriv } from 'crypto'

/**
 * Algorithm configuration.
 */
export interface Algorithm {
  hmacKeySize: number
  hmacAlgorithm: string
  hmacDigestSize: number
  cipherKeySize: number
  cipherAlgorithm: string
  cipherBlockSize: number
  ivSize: number
}

/**
 * Supported algorithms - using numeric index allows for 256 (1 byte) different
 * algorithms with backward compatibility until a breaking change is required.
 */
export const ALGORITHMS: Algorithm[] = [
  {
    hmacKeySize: 32,
    hmacAlgorithm: 'sha256',
    hmacDigestSize: 32,
    cipherKeySize: 32,
    cipherAlgorithm: 'aes-256-cbc',
    cipherBlockSize: 16,
    ivSize: 16
  }
]

/**
 * Allow key generation to be configured (not highly recommended).
 */
export interface KeyOptions {
  salt: string
  iterations: number
  algorithm: string
}

/**
 * Default key generation configuration - keys should already be secure.
 */
export const DEFAULT_KEY_OPTIONS = {
  salt: 'Keycrypt',
  iterations: 100,
  algorithm: 'sha256'
}

/**
 * Generated keys for encryption.
 */
export interface Key {
  hmac: Buffer
  cipher: Buffer
}

/**
 * Supports a generic interface for iteroperability with other libraries.
 */
export class Keycrypt {

  keys: Array<Key>
  tag: Buffer
  algorithm: number

  constructor (keys: Buffer[], options: KeyOptions = DEFAULT_KEY_OPTIONS, algorithm = 0) {
    if (!(algorithm in ALGORITHMS)) {
      throw new TypeError(`Unknown algorithm: ${Number(algorithm)}`)
    }

    this.tag = Buffer.alloc(1, algorithm)
    this.algorithm = algorithm

    this.keys = keys.map((key) => {
      const { cipherKeySize, hmacKeySize } = ALGORITHMS[this.algorithm]
      const keySize = cipherKeySize + hmacKeySize
      const raw = pbkdf2Sync(key, options.salt, options.iterations, keySize, 'sha512')

      return {
        hmac: raw.slice(0, hmacKeySize),
        cipher: raw.slice(hmacKeySize)
      }
    })
  }

  encode (data: Buffer) {
    const key = this.keys[0]
    const { cipherAlgorithm, hmacAlgorithm, hmacDigestSize, ivSize } = ALGORITHMS[this.algorithm]
    const iv = randomBytes(ivSize)
    const cipher = createCipheriv(cipherAlgorithm, key.cipher, iv)

    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
    const mac = createHmac(hmacAlgorithm, key.hmac).update(iv).update(ciphertext).digest()
    const totalLength = 1 + hmacDigestSize + ivSize + ciphertext.length

    return Buffer.concat([this.tag, mac, iv, ciphertext], totalLength)
  }

  decode (data: Buffer): Buffer | undefined {
    if (!data.length) return undefined

    const index = data.readUInt8(0)
    const algorithm = ALGORITHMS[index]

    // Unknown algorithm input.
    if (!(index in ALGORITHMS)) return undefined

    // Iterate over each key and check.
    for (const key of this.keys) {
      const message = this._decrypt(data, key, algorithm)
      if (message) return message
    }
  }

  private _decrypt (data: Buffer, key: Key, algorithm: Algorithm) {
    const {
      hmacAlgorithm,
      cipherAlgorithm,
      ivSize,
      hmacDigestSize,
      cipherBlockSize
    } = algorithm

    if (data.length < (1 + hmacDigestSize + ivSize + cipherBlockSize)) return undefined

    const mac = data.slice(1, 1 + hmacDigestSize)
    const iv = data.slice(1 + hmacDigestSize, 1 + hmacDigestSize + ivSize)
    const ciphertext = data.slice(1 + hmacDigestSize + ivSize)

    const dataMac = createHmac(hmacAlgorithm, key.hmac).update(iv).update(ciphertext).digest()

    if (!timingSafeEqual(mac, dataMac)) return undefined

    const cipher = createDecipheriv(cipherAlgorithm, key.cipher, iv)
    return Buffer.concat([cipher.update(ciphertext), cipher.final()])
  }

}
