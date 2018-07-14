import crypto from './lib/crypto'

export default class File {
  constructor (client, data) {
    this.client = client
    this.original = data

    this.id = data.id
    this.filename = data.filename
    this.size = data.size
    this.mktime = data.mktime ? new Date(data.mktime * 1000) : null
    this.mdtime = data.mdtime ? new Date(data.mdtime * 1000) : null
    this.encryption = data.encryption
    this.checksum = data.checksum
    this.public = !!data.public
    this.extension = data.filename.split('.').slice(-1)[0]
  }

  /**
   * Download file data and decrypt them (if needed)
   * @param {User} user user data
   * @param {string} password user password
   * @returns {Promise<ArrayBuffer>}
   */
  download (user, password) {
    return this.client
      .downloadFileContents(this.id)
      .then(data => {
        if (this.encryption) {
          return crypto.decrypt(data, user.getDecryptedKey(password), this.encryption)
        }
        return data
      })
  }
}
