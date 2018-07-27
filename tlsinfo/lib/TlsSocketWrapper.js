const tls = require('tls')
const TimeOutableSocket = require('./TimeOutableSocket')

const punycode = require('../node_modules/punycode')

class TlsSocketWrapper extends TimeOutableSocket {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super()
    /**
     * @protected
     * @type {tls.TLSSocket}
     */
    this.socket = null
    /**
     * @protected
     * @type {tls.ConnectionOptions}
     */
    this.options = null
    if (options) this.updateOptions(options)
    this.timeout = 30000
    /** @type {Error[]} */
    this.errors = []
  }

  /**
   * @param {any} error
   * @param {(reason?: any) => void} reject
   * @param {boolean} selfdestruct
   */
  onError (error, reject = null, selfdestruct = true) {
    this.errors.push(error)
    if (selfdestruct) this.destroySocket(error)
  }

  /**
   * set timeout in ms
   * @param {number} ms
   */
  setTimeout (ms) {
    if (typeof ms === 'number' && ms > 0) this.timeout = ms
  }

  /**
   * @param {tls.ConnectionOptions} options
   */
  static validateOptions (options) {
    if (!options || !options.host) throw new Error('host must be defined')
    if (!options.servername) options.servername = options.host
    if (!options.port) options.port = 443
    if (!options.minDHSize) options.minDHSize = 1
    if (options.rejectUnauthorized === undefined) options.rejectUnauthorized = false
    return options
  }

  /**
   * @param {tls.ConnectionOptions} options
   */
  updateOptions (options) {
    this.options = Object.assign(this.options || { }, TlsSocketWrapper.validateOptions(options))
  }

  resetOptions (options = null) {
    this.options = null
    if (options) this.updateOptions(options)
  }

  setKeepAlive (enable, initialDelay) {
    if (!this.socket) return
    this.socket.setKeepAlive(enable, initialDelay)
  }

  setNoDelay (noDelay) {
    if (!this.socket) return
    this.socket.setNoDelay(noDelay)
  }

  /**
   * @param {number} timeout
   * @param {boolean} selfdestruct
   * @returns {Promise<void>}
   */
  async connect (timeout = -1, selfdestruct = true) {
    if (!this.options) throw new Error('options is not defined, set with constructor or update with updateOptions()')
    this.setTimeout(timeout)

    return new Promise((resolve, reject) => {
      let isResolved = false
      this.options.host = punycode.toASCII(this.options.host)
      this.options.servername = punycode.toASCII(this.options.servername)
      this.setSocket(tls.connect(this.options, () => {
        isResolved = true
        if (selfdestruct) this.destroySocket()
        resolve()
      }))
      this.options.host = punycode.toUnicode(this.options.host)
      this.options.servername = punycode.toUnicode(this.options.servername)

      this.socket.on('error', error => {
        this.onError(error, reject, selfdestruct)
      })
      this.socket.once('close', () => {
        if (selfdestruct) this.destroySocket()
        if (!isResolved) this.errors.push(new Error('socket hang up'))
        if (this.errors.length > 0) {
          reject(this.errors)
          this.errors = []
          return
        }
        this.errors = []
      })

      this.setKeepAlive(false)
      this.setNoDelay(true)
      this.setTimeout(this.timeout)
    })
  }
}

module.exports = TlsSocketWrapper
