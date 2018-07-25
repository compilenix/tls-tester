const tls = require('tls') // eslint-disable-line

const {
  TlsSocketWrapper,
  DnsHelper,
  Certificate,
  CertificateResult, // eslint-disable-line
  HostAddressSpecificCertificateResult, // eslint-disable-line
  Cipher,
  CipherResult, // eslint-disable-line
  ProtocolVersion,
  ProtocolVersionResult // eslint-disable-line
} = require('../index')

class TlsServiceAuditResult {
  constructor () {
    /** @type {HostAddressSpecificCertificateResult[]} */
    this.certificates = null
    /** @type {CipherResult[]} */
    this.ciphers = null
    /** @type {ProtocolVersionResult[]} */
    this.protocols = null
  }
}

class TlsServiceAudit {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    if (options) this.updateOptions(options)
  }

  updateOptions (options) {
    this.options = TlsSocketWrapper.validateOptions(options)
  }

  async run (timeout = -1, ipVersions = [4, 6], addresses = []) {
    return new Promise(async (resolve, reject) => {
      try {
        if (!addresses || addresses.length === 0) {
          addresses = await DnsHelper.lookup(this.options.host)
        }
        const result = new TlsServiceAuditResult()

        const cert = new Certificate(Object.assign({ }, this.options))
        const protocol = new ProtocolVersion(Object.assign({ }, this.options))
        const cipher = new Cipher(Object.assign({ }, this.options))

        result.certificates = await cert.fetch(timeout, ipVersions, addresses)
        result.protocols = await protocol.testMultiple(ProtocolVersion.getSupportedProtocols(), timeout, ipVersions, addresses)
        result.ciphers = await cipher.testMultiple(Cipher.suites, ProtocolVersion.getSupportedProtocols(), timeout, ipVersions, addresses)

        resolve(result)
      } catch (error) {
        reject(error)
      }
    })
  }
}

module.exports.TlsServiceAudit = TlsServiceAudit
module.exports.TlsServiceAuditResult = TlsServiceAuditResult
