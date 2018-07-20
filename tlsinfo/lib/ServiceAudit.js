const tls = require('tls')
const x509 = require('x509')
const EventEmitter = require('events')

const { Certificate, CertificateResult } = require('./Certificate')

class ServiceAuditResult {
  constructor () {
    /** @type {tlsinfo.CertificateResult} */
    this.certificate = null
  }
}

class ServiceAudit extends EventEmitter {
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

  async run () {
    let result = new ServiceAuditResult()
    let cert = new Certificate(this.options)
    result.certificate = await cert.get(this.timeout)
  }
}

module.exports.ServiceAudit = ServiceAudit
module.exports.ServiceAuditResult = ServiceAuditResult
