const tls = require('tls')
const x509 = require('x509')

const { Certificate, CertificateResult } = require('./Certificate')

class ServiceAuditResult {
  constructor () {
    /** @type {CertificateResult} */
    this.certificate = null
  }
}

class ServiceAudit {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    this.setTimeout(this.timeout * 10) // if Certificate.timeout has 30 seconds this will be at 5 minutes
  }

  async run (timeout = -1, timeoutPerConnection = -1) {
    this.setTimeout(timeout)
    this.setTimeoutPerConnection(timeoutPerConnection)

    return new Promise(async (resolve, reject) => {
      const result = new ServiceAuditResult()
      result.certificate = await this.fetch(this.timeoutPerConnection)
    })
  }
}

module.exports.ServiceAudit = ServiceAudit
module.exports.ServiceAuditResult = ServiceAuditResult
