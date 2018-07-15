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
   * @param {(phase, loaded, total) => void} progressCalback
   * @returns {Promise<ArrayBuffer>}
   */
  download (user, password, progressCalback) {
    return this.client
      .downloadFileContents(this.id, (loaded, total) => {
        progressCalback && progressCalback('download', loaded, total)
      })
      .then(data => {
        if (this.encryption) {
          progressCalback && progressCalback('decrypting', 0, 1)

          return user.getDecryptedKey(password)
            .then(key => crypto.decrypt(data, key, this.encryption))
            .then(data => {
              progressCalback && progressCalback('decrypting', 1, 1)
              return data
            })
        }

        return data
      })
  }
}
