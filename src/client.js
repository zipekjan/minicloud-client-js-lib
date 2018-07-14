import axios from 'axios'
import crypto from './lib/crypto'
import { EventEmitter } from 'events'
import User from './user'
import Path from './path'

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
      .then(raw => new User(this, raw))
  }

  /**
   * Saves info about current user.
   * @returns {Promise<User>}
   */
  setUser (user) {
    return this._request(this._createUrl('set_user', user.getUpdate()))
  }

  /**
   * Loads info about path.
   * @param {string?} path path to load (default root)
   * @param {boolean?} recursive load subfolders and subfiles too (default false)
   * @returns {Promise<Path>}
   */
  getPath (path, recursive) {
    return this._request(
      this._createUrl(
        'get_path',
        { path, recursive }
      ),
      'path'
    ).then(raw => new Path(this, raw))
  }

  /**
   * Loads info about path.
   * @param {number} id path id
   * @param {boolean?} recursive load subfolders and subfiles too (default false)
   * @returns {Promise<Path>}
   */
  getPathById (id, recursive) {
    return this._request(
      this._createUrl(
        'get_path',
        { id, recursive }
      ),
      'path'
    ).then(raw => new Path(this, raw))
  }

  /**
   * Loads all user paths.
   * @returns {Promise<Path[]>}
   */
  getPaths () {
    return this._request(this._createUrl('get_paths'), 'paths')
      .then(paths => paths.map(raw => new Path(this, raw)))
  }

  /**
   * Downloads raw file contents (without decrypting them).
   * @param {number} id
   * @param {(loaded: number, total: number) => void} progressCallback
   * @returns {Promise<ArrayBuffer>}
   */
  downloadFileContents (id, progressCallback) {
    return this._request(this._createUrl('download_file', { id }), null, {
      responseType: 'arraybuffer',
      onDownloadProgress (e) {
        progressCallback && progressCallback(e.loaded, e.total)
      }
    })
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

  _request (params, expectedType, options) {
    let headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    if (this.auth) {
      headers['X-Auth'] = this.auth
    }

    let request = {
      url: this._getApiUrl(),
      method: 'POST',
      data: params,
      headers
    }

    if (options) {
      Object.keys(options).forEach(key => {
        request[key] = options[key]
      })
    }

    return axios.request(request)
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
              let error = new Error(err.response.data.data)
              error.response = err.response.data

              this.emit('error', error)
              throw error
            }
          }
        }
        throw err
      })
      .then(response => {
        if (request.responseType === 'arraybuffer') return response.data
        return typeof response.data === 'string' ? JSON.parse(response.data) : response.data
      })
      .then(data => {
        if (request.responseType === 'arraybuffer') return data
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
