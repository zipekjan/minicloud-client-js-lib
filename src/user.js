import crypto from './lib/crypto'
import { uint8ToString } from './lib/utils'

export default class User {
  constructor (client, data) {
    this.client = client
    this.original = data

    this.username = data.username
    this.email = data.email
    this.key = atob(data.key)
    this.keyEncryption = data.key_encryption
    this.admin = !!data.admin

    this.password = null
  }

  /**
   * Initializes user key.
   * @param {string} password user password
   * @param {ServerInfo} serverInfo server info
   * @param {*} options key options
   * @returns {Promise<User>}
   */
  initialize (password, serverInfo, options) {
    options = options || {}

    let keyLength = options.keyLength || 256
    let cryptoMode = options.crypto || 'PBKDF2WithHmacSHA1/Blowfish/CBC/PKCS5Padding'

    this.setKey(
      crypto.getRandomKey(keyLength),
      password,
      cryptoMode,
      serverInfo
    )

    return this.client.setUser(this)
  }

  /**
   * Serializes user data, that can be updated.
   * @returns {*}
   */
  getUpdate () {
    let updated = {
      email: this.email,
      key: btoa(this.key),
      keyEncryption: this.keyEncryption
    }

    if (this.password) {
      updated.password = this.password
      this.password = null
    }

    return updated
  }

  /**
   * Sets and encrypts user key.
   * @param {string} key
   * @param {string} password
   * @param {string} encryptionMode
   */
  setKey (key, password, encryptionMode) {
    this.key = btoa(uint8ToString(crypto.encryptKey(key, password, encryptionMode)))
    this.keyEncryption = encryptionMode
  }

  /**
   * Sets user password.
   * @param {string} password
   * @param {ServerInfo} serverInfo
   */
  setPassword (password, serverInfo) {
    this.password = crypto.getPasswordAuthHash(password, serverInfo)
  }

  /**
   * Decrypts and returns user key.
   * @param {string} password user password
   * @returns {ArrayBuffer} decrypted key
   */
  getDecryptedKey (password) {
    return crypto.decryptKey(this.key, password, this.keyEncryption)
  }
}
