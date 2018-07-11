import axios from 'axios'
import crypto from './lib/crypto'
import { uint8ToString } from './lib/utils'
import { EventEmitter } from 'events'

export class Client extends EventEmitter {
  constructor (server) {
    super()

    this.auth = null
    this.server = server || null
  }

  /**
   * Sets authorization string.
   * @param {string} username
   * @param {string} password
   * @param {ServerInfo} info server info provided by server
   */
  setAuth (username, password, info) {
    this.auth = `${username}:${crypto.getPasswordAuthHash(password, info)}`
  }

  /**
   * Sets server url.
   * @param {string} server
   */
  setServer (server) {
    this.server = server
  }

  /**
   * Requests server info.
   * @returns {Promise<ServerInfo>}
   */
  getServerInfo () {
    return this._request(this._createUrl('get_server_info'), 'server')
  }

  /**
   * Requests info about current user.
   * @returns {Promise<User>}
   */
  getUser () {
    return this._request(this._createUrl('get_user'), 'user')
  }

  /**
   * Saves info about current user.
   * @returns {Promise<User>}
   */
  setUser (user) {
    return this._request(this._createUrl('set_user', user))
  }

  /**
   * Initializes user key used to encrypt files.
   * @param {string} password raw user password
   * @param {ServerInfo} serverInfo server info
   * @param {*} options additional options
   */
  initializeKey (password, serverInfo, options) {
    options = options || {}

    let keyLength = options.keyLength || 256
    let cryptoMode = options.crypto || 'PBKDF2WithHmacSHA1/Blowfish/CBC/PKCS5Padding'

    let key = crypto.getRandomKey(keyLength)
    let encryptedKey = crypto.encryptKey(key, password, cryptoMode)

    return this.setUser({
      password: crypto.getPasswordAuthHash(password, serverInfo),
      key: btoa(uint8ToString(encryptedKey)),
      key_encryption: cryptoMode
    })
  }

  getUserKey (user, password) {
    return crypto.decryptKey(atob(user.key), password, user.key_encryption)
  }

  /**
   * Loads info about path.
   * @param {string?} path path to load (default root)
   * @param {boolean?} recursive load subfolders and subfiles too (default false)
   * @returns {Promise<Path>}
   */
  getPath (path, recursive) {
    return this._request(this._createUrl('get_path', {
      path, recursive
    }), 'path')
  }

  /**
   * Loads all user paths.
   * @returns {Promise<Path[]>}
   */
  getPaths () {
    return this._request(this._createUrl('get_paths'), 'paths')
  }

  _createUrl (action, params) {
    let url = 'action=' + encodeURIComponent(action)

    if (params) {
      Object.keys(params).forEach(key => {
        let value = params[key]
        if (value === null || value === undefined) value = ''
        url += '&' + key + '=' + encodeURIComponent(value)
      })
    }

    return url
  }

  _request (params, expectedType) {
    let headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    if (this.auth) {
      headers['X-Auth'] = this.auth
    }

    return axios.request({
      url: this._getApiUrl(),
      method: 'POST',
      data: params,
      headers
    })
      .catch(err => {
        if (err.response) {
          if (err.response.data && err.response.data.type) {
            if (err.response.status && err.response.status === 401) {
              let error = new Error('Unauthorized access')
              error.response = err.response.data
              error.unauthorized = true

              this.emit('unauthorized', error)
              throw error
            }

            if (err.response.data.type === 'error') {
              let error = new Error('Unauthorized access')
              error.response = err.response.data

              this.emit('error', error)
              throw error
            }
          }
        }
        throw err
      })
      .then(response => {
        return typeof response.data === 'string' ? JSON.parse(response.data) : response.data
      })
      .then(data => {
        if (expectedType && data.type !== expectedType) {
          throw new Error(`Unexpected response type ${data.type}`)
        }
        return data.data
      })
  }

  _getApiUrl () {
    return this.server + '/api.php'
  }
}
