import { sha256 } from 'js-sha256'
import Blowfish from 'egoroof-blowfish'
import CryptoJS from 'crypto-js'
import { uint8ToString, stringToUint8 } from './utils'
import * as aesjs from 'aes-js'

const hashCrypto = {
  'sha1': CryptoJS.algo.SHA1,
  'sha256': CryptoJS.algo.SHA256,
  'sha512': CryptoJS.algo.SHA512
}

const blowfishChainModes = {
  'cbc': Blowfish.MODE.CBC,
  'ecb': Blowfish.MODE.ECB
}

const blowfishPaddingModes = {
  'pkcs5padding': Blowfish.PADDING.PKCS5
}

const aesBlockModes = {
  'cbc': aesjs.ModeOfOperation.cbc
}

const aesPaddingModes = {
  'pkcs5padding': CryptoJS.pad.Pkcs7,
  'pkcs7padding': CryptoJS.pad.Pkcs7
}

const crypto = {
  getPasswordAuthHash (password, serverInfo) {
    return sha256(serverInfo.salt + password)
  },

  derivePassword (password, options) {
    options = options || {}

    let iterations = options.iterations || 1000
    let keySize = options.keySize || 256
    let hasher = hashCrypto[options.hasher || 'sha1']

    if (!hasher) throw new Error(`Unsupported hashing method ${options.hasher}`)

    return stringToUint8(atob(CryptoJS.PBKDF2(password, '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', {
      keySize: keySize / 32,
      iterations,
      hasher
    }).toString(CryptoJS.enc.Base64)))
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
      let BlockMode = aesBlockModes[options[1]]
      let padding = aesPaddingModes[options[2]]

      if (BlockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      return new BlockMode(key, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .encrypt(aesjs.padding.pkcs7.pad(new Uint8Array(data)))
        .buffer
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
      let BlockMode = aesBlockModes[options[1]]
      let padding = aesPaddingModes[options[2]]

      if (BlockMode === undefined) throw new Error(`Unsupported block cipher mode ${options[1]}`)
      if (padding === undefined) throw new Error(`Unsupported padding mode ${options[2]}`)

      return aesjs.padding.pkcs7.strip(new BlockMode(key, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .decrypt(new Uint8Array(data)))
        .buffer
    }

    throw new Error(`Unsuported encryption algorithm ${algorithm}`)
  },

  encryptKey (key, password, mode) {
    let options = mode.toLowerCase().split('/')
    if (options.length === 3) {
      options.unshift('pbkdf2withhmacsha1')
    }

    return this.encrypt(
      key,
      this.getPasswordEncryptionHash(password, options.join('/')),
      options.slice(1).join('/')
    )
  },

  decryptKey (key, password, mode) {
    let options = mode.toLowerCase().split('/')
    if (options.length === 3) {
      options.unshift('pbkdf2withhmacsha1')
    }

    return this.decrypt(
      key,
      this.getPasswordEncryptionHash(password, options.join('/')),
      options.slice(1).join('/')
    )
  }
}

export default crypto
