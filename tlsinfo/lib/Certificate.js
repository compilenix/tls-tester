const tls = require('tls')
const x509 = require('x509')
const EventEmitter = require('events')

class CertificateResult {
  constructor () {
    this.host = ''
    this.port = 0
    this.cert = { } // X509
    this.certPEM = ''
    this.certCa = { } // ?X509
    this.certCaPem = ''
    this.protocols = { } // TlsProtocol[]
    this.ciphers = { } // Cipher
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
    this.options = options
    this.timeout = 30000
    this.on('timeout', () => setImmediate(() => this.onTimeout()))
  }

  destroySocket (error = null) {
    if (this.socket && !this.socket.destroyed) this.socket.destroy(error)
  }

  /**
   * @private
   */
  onTimeout () {
    this.destroySocket('timeout')
  }

  /**
   * set timeout in ms
   * @param {number} ms
   */
  setTimeout (ms) {
    if (typeof ms === 'number' && ms > 0) this.timeout = ms
  }

  /**
   * @static
   * @param {string} certRaw
   */
  parsePemCertificate (certRaw) {
    return x509.parseCert(`-----BEGIN CERTIFICATE-----\n${certRaw}\n-----END CERTIFICATE-----`)
  }

  /**
   * @returns {Promise<CertificateResult>}
   */
  async get (timeout = -1) {
    this.setTimeout(timeout)
    let timeoutTimer
    if (this.timeout !== Infinity && this.timeout > 0) {
      timeoutTimer = setTimeout(() => this.emit('timeout'), this.timeout)
    }

    /**
     * @param {(reason?: any) => void} reject
     * @param {any} error
     * @param {NodeJS.Timer} timer
     */
    function onError (reject, error, timer) {
      clearTimeout(timer)
      setImmediate(() => this.destroySocket('error'))
      reject(error)
    }

    return new Promise((resolve, reject) => {
      /** @type {CertificateResult} */
      let result = new CertificateResult()

      this.socket = tls.connect(this.options, () => {
        result.host = this.options.host
        result.port = this.options.port

        try {
          // TODO:
          result.certPEM = this.socket.getPeerCertificate().raw.toString('base64')
          if (this.socket.getPeerCertificate(true).issuerCertificate) result.certCaPem = this.socket.getPeerCertificate(true).issuerCertificate.raw.toString('base64')
          result.cert = this.parsePemCertificate(result.certPEM)
          if (result.certCaPem) result.certCa = this.parsePemCertificate(result.certCaPem)
        } catch (error) {
          return onError(reject, error, timeoutTimer)
        }

        clearTimeout(timeoutTimer)
        resolve(result)
      })

      this.socket.on('error', error => onError(reject, error, timeoutTimer))

      this.socket.setKeepAlive(false)
      this.socket.setNoDelay(true)
      this.socket.setTimeout(this.timeout, () => {
        clearTimeout(timeoutTimer)
        this.emit('timeout')
        reject(new Error('timeout'))
      })
    })
  }
}

module.exports.Certificate = Certificate
module.exports.CertificateResult = CertificateResult
