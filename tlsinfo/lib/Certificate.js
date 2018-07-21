const tls = require('tls')
const x509 = require('x509')
const EventEmitter = require('events')

const punycode = require('../node_modules/punycode')

class CertificateResult {
  constructor () {
    this.host = ''
    this.port = 0
    /** @type {x509.X509} */
    this.cert = null
    this.certPem = ''
    /** @type {x509.X509} */
    this.certCa = null
    this.certCaPem = ''
  }
}

class Certificate extends EventEmitter {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super()
    /** @type {tls.TLSSocket} */
    this.socket = null
    /** @type {tls.ConnectionOptions} */
    this.options = null
    if (options) this.setOptions(options)
    this.timeout = 30000
    this.on('timeout', () => this.onTimeout())
  }

  destroySocket (error = null) {
    if (this.socket && !this.socket.destroyed) this.socket.destroy(error)
    this.socket = null
  }

  /**
   * @private
   */
  onTimeout () {
    this.destroySocket('timeout')
  }

  /**
   * @param {(reason?: any) => void} reject
   * @param {any} error
   * @param {NodeJS.Timer} timer
   */
  onError (error, timer = null, reject = null) {
    if (timer) clearTimeout(timer)
    this.destroySocket('error')
    if (reject) reject(error)
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
  setOptions (options) {
    if (!options || !options.host) throw new Error('host must be defined')

    this.options = Object.assign(this.options || { }, options)

    if (!options.servername) this.options.servername = this.options.host
    if (!this.options.port) this.options.port = 443
    if (!this.options.minDHSize) this.options.minDHSize = 1
    if (this.options.rejectUnauthorized === undefined) this.options.rejectUnauthorized = false
  }

  resetOptions (options = null) {
    this.options = null
    if (options) this.setOptions(options)
  }

  /**
   * @static
   * @param {string} certRaw in pem format without: -----BEGIN CERTIFICATE-----
   * @returns {x509.X509} X509 certificate
   */
  parseRawPemCertificate (certRaw) {
    return this.parsePemCertificate(`-----BEGIN CERTIFICATE-----\n${certRaw}\n-----END CERTIFICATE-----`)
  }

  /**
   * @static
   * @param {string} cert in pem format with: -----BEGIN CERTIFICATE-----
   * @returns {x509.X509} X509 certificate
   */
  parsePemCertificate (cert) {
    return x509.parseCert(cert)
  }

  /**
   * @param {number} timeout
   * @returns {Promise<CertificateResult>}
   */
  async get (timeout = -1) {
    this.setTimeout(timeout)
    let timeoutTimer

    return new Promise((resolve, reject) => {
      this.options.host = punycode.toASCII(this.options.host)
      this.options.servername = punycode.toASCII(this.options.servername)
      this.socket = tls.connect(this.options, () => {
        let result = new CertificateResult()
        result.host = this.options.host
        result.port = this.options.port

        try {
          result.certPem = this.socket.getPeerCertificate().raw.toString('base64')
          if (this.socket.getPeerCertificate(true).issuerCertificate) result.certCaPem = this.socket.getPeerCertificate(true).issuerCertificate.raw.toString('base64')
          result.cert = this.parseRawPemCertificate(result.certPem)
          if (result.certCaPem) result.certCa = this.parseRawPemCertificate(result.certCaPem)
        } catch (error) {
          return this.onError(error, timeoutTimer, reject)
        }

        this.destroySocket()
        resolve(result)
      })
      this.options.host = punycode.toUnicode(this.options.host)
      this.options.servername = punycode.toUnicode(this.options.servername)

      this.socket.on('error', error => this.onError(error, timeoutTimer, reject))

      this.socket.setKeepAlive(false)
      this.socket.setNoDelay(true)
      this.socket.setTimeout(this.timeout, () => {
        this.emit('timeout')
        reject(new Error('timeout'))
      })
    })
  }
}

module.exports.Certificate = Certificate
