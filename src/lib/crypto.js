import Blowfish from 'egoroof-blowfish'
import { uint8ToString, stringToUint8, hex } from './utils'

const hashCrypto = {
  'sha1': 'sha-1',
  'sha256': 'sha-256',
  'sha512': 'sha-512'
}

const blowfishChainModes = {
  'cbc': Blowfish.MODE.CBC,
  'ecb': Blowfish.MODE.ECB
}

const blowfishPaddingModes = {
  'pkcs5padding': Blowfish.PADDING.PKCS5
}

const aesBlockModes = {
  'cbc': 'AES-CBC'
}

const aesPaddingModes = {
  'pkcs5padding': 'pkcs7padding',
  'pkcs7padding': 'pkcs7padding'
}

const crypto = {
  getPasswordAuthHash (password, serverInfo) {
    return window.crypto.subtle.digest('sha-256', stringToUint8(serverInfo.salt + password))
      .then(hash => hex(hash))
  },

  derivePassword (password, options) {
    options = options || {}

    let iterations = options.iterations || 1000
    let keySize = options.keySize || 256
    let hasher = hashCrypto[options.hasher || 'sha1']

    if (!hasher) throw new Error(`Unsupported hashing method ${options.hasher}`)

    return window.crypto.subtle
      .importKey('raw', stringToUint8(password), { name: 'PBKDF2' }, false, [ 'deriveKey' ])
      .then(key => {
        return window.crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: stringToUint8('\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'),
            iterations,
            hash: hasher
          },
          key,
          { name: 'AES-CBC', length: keySize },
          true,
          [ 'encrypt', 'decrypt' ]
        )
      })
      .then(key => window.crypto.subtle.exportKey('raw', key))
  },

  getPasswordEncryptionHash (password, mode) {
    let options = mode.toLowerCase().split('/')
    let passwordMode = options[0]

    switch (passwordMode) {
      case 'pbkdf2withhmacsha1':
        return this.derivePassword(password, { hasher: 'sha1' })
      case 'pbkdf2withhmacsha256':
        return this.derivePassword(password, { hasher: 'sha256' })
      case 'pbkdf2withhmacsha512':
        return this.derivePassword(password, { hasher: 'sha512' })
      default:
        throw new Error(`Unsupported key derivation algorithm ${passwordMode}`)
    }
  },

  getRandomKey (length) {
    let key = new Uint8Array(length / 8)
    window.crypto.getRandomValues(key)

    return uint8ToString(key)
  },

  encrypt (data, key, mode) {
    let options = mode.toLowerCase().split('/')
    let algorithm = options[0]

    if (algorithm === 'blowfish') {
      let blockMode = blowfishChainModes[options[1]]
      let padding = blowfishPaddingModes[options[2]]

      if (blockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      let bf = new Blowfish(key, blockMode, padding)
      bf.setIv('\0\0\0\0\0\0\0\0')

      return bf.encode(data)
    }

    if (algorithm === 'aes') {
      let blockMode = aesBlockModes[options[1]]
      let padding = aesPaddingModes[options[2]]

      if (blockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      let iv = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

      return window.crypto.subtle
        .importKey('raw', key, { name: blockMode }, false, ['encrypt'])
        .then(importedKey => window.crypto.subtle.encrypt({ name: blockMode, iv }, importedKey, data))
    }

    throw new Error(`Unsuported encryption algorithm ${algorithm}`)
  },

  decrypt (data, key, mode) {
    let options = mode.toLowerCase().split('/')
    let algorithm = options[0]

    data = typeof data === 'string' ? stringToUint8(data) : data

    if (algorithm === 'blowfish') {
      let blockMode = blowfishChainModes[options[1]]
      let padding = blowfishPaddingModes[options[2]]

      if (blockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      let bf = new Blowfish(key, blockMode, padding)
      bf.setIv('\0\0\0\0\0\0\0\0')

      return bf.decode(data, Blowfish.TYPE.UINT8_ARRAY)
    }

    if (algorithm === 'aes') {
      let blockMode = aesBlockModes[options[1]]
      let padding = aesPaddingModes[options[2]]

      if (blockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      let iv = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

      return window.crypto.subtle
        .importKey('raw', key, { name: blockMode }, false, ['decrypt'])
        .then(importedKey => window.crypto.subtle.decrypt({ name: blockMode, iv }, importedKey, data))
    }

    throw new Error(`Unsuported encryption algorithm ${algorithm}`)
  },

  encryptKey (key, password, mode) {
    let options = mode.toLowerCase().split('/')
    if (options.length === 3) {
      options.unshift('pbkdf2withhmacsha1')
    }

    return this.getPasswordEncryptionHash(password, options.join('/'))
      .then(passwordKey => {
        return this.encrypt(
          key,
          passwordKey,
          options.slice(1).join('/')
        )
      })
  },

  decryptKey (key, password, mode) {
    let options = mode.toLowerCase().split('/')
    if (options.length === 3) {
      options.unshift('pbkdf2withhmacsha1')
    }

    return this.getPasswordEncryptionHash(password, options.join('/'))
      .then(passwordKey => {
        return this.decrypt(
          key,
          passwordKey,
          options.slice(1).join('/')
        )
      })
  }
}

export default crypto
