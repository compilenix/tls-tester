const tls = require('tls')
const TimeOutableSocket = require('./TimeOutableSocket')

const punycode = require('../node_modules/punycode')

class TlsSocketWrapper extends TimeOutableSocket {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super()
    /** @type {tls.TLSSocket} */
    this.socket = null
    /** @type {tls.ConnectionOptions} */
    this.options = null
    if (options) this.updateOptions(options)
    this.timeout = 30000
    /** @type {Error[]} */
    this.errors = []
  }

  /**
   * @param {(reason?: any) => void} reject
   * @param {any} error
   */
  onError (error, reject = null) {
    this.errors.push(error)
    this.destroySocket(error)
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
  updateOptions (options) {
    if (!options || !options.host) throw new Error('host must be defined')

    this.options = Object.assign(this.options || { }, options)

    if (!options.servername) this.options.servername = this.options.host
    if (!this.options.port) this.options.port = 443
    if (!this.options.minDHSize) this.options.minDHSize = 1
    if (this.options.rejectUnauthorized === undefined) this.options.rejectUnauthorized = false
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
   * @returns {Promise<tls.TLSSocket>}
   */
  async connect (timeout = -1) {
    if (!this.options) throw new Error('options is not defined, set with constructor or update with updateOptions()')
    this.setTimeout(timeout)

    return new Promise((resolve, reject) => {
      this.options.host = punycode.toASCII(this.options.host)
      this.options.servername = punycode.toASCII(this.options.servername)
      this.setSocket(tls.connect(this.options, () => {
        this.destroySocket()
      }))
      this.options.host = punycode.toUnicode(this.options.host)
      this.options.servername = punycode.toUnicode(this.options.servername)

      this.socket.on('error', error => {
        this.onError(error, reject)
      })
      this.socket.on('close', () => {
        this.destroySocket()
        if (this.errors.length > 0) {
          reject(this.errors)
          this.errors = []
          return
        }
        this.errors = []
        resolve()
      })

      this.setKeepAlive(false)
      this.setNoDelay(true)
      this.setTimeout(this.timeout)
    })
  }
}

module.exports = TlsSocketWrapper
