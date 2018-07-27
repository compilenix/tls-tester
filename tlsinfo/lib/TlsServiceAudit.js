const tls = require('tls') // eslint-disable-line

const {
  HostAddressResult, // eslint-disable-line
  HostAddressSpecificCertificateResult, // eslint-disable-line
  CipherResult, // eslint-disable-line
  ProtocolVersionResult // eslint-disable-line
} = require('tlsinfo')

class TlsServiceAuditResult {
  constructor () {
    /** @type {HostAddressSpecificCertificateResult[]} */
    this.certificates = []
    /** @type {CipherResult[]} */
    this.ciphers = []
    /** @type {ProtocolVersionResult[]} */
    this.protocols = []
  }
}

class TlsServiceAudit {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null, protocols = null, ciphers = null) {
    if (options) this.updateOptions(options)
    this.protocols = protocols
    this.ciphers = ciphers
  }

  updateOptions (options) {
    this.options = require('tlsinfo').TlsSocketWrapper.validateOptions(options)
  }

  /**
   * @param {string[]} protocols
   * @see {ProtocolVersion.protocols}
   */
  setProtocols (protocols) {
    this.protocols = protocols
  }

  /**
   * @param {string[]} ciphers
   * @see {Cipher.suites}
   */
  setCiphers (ciphers) {
    this.ciphers = ciphers
  }

  /**
   * @param {number} timeout
   * @param {[4, 6] | [4] | [6]} ipVersions
   * @param {HostAddressResult[]} addresses
   * @see {DnsHelper}
   * @returns {Promise<TlsServiceAuditResult>}
   */
  async run (timeout = -1, ipVersions = [4, 6], addresses = []) {
    const {
      DnsHelper,
      Certificate,
      Cipher,
      ProtocolVersion
    } = require('tlsinfo')

    return new Promise(async (resolve, reject) => {
      try {
        if (!addresses || addresses.length === 0) {
          addresses = await DnsHelper.lookup(this.options.host)
        }
        if (this.protocols === null) this.protocols = ProtocolVersion.getSupportedProtocols()
        if (this.ciphers === null) this.ciphers = Cipher.suites
        const result = new TlsServiceAuditResult()

        const cert = new Certificate(Object.assign({ }, this.options))
        const protocol = new ProtocolVersion(Object.assign({ }, this.options))
        const cipher = new Cipher(Object.assign({ }, this.options))

        result.certificates = await cert.fetch(timeout, ipVersions, addresses)
        result.protocols = await protocol.testMultiple(this.protocols, timeout, ipVersions, addresses)
        result.ciphers = await cipher.testMultiple(this.ciphers, this.protocols, timeout, ipVersions, addresses)

        resolve(result)
      } catch (error) {
        reject(error)
      }
    })
  }
}

module.exports.TlsServiceAudit = TlsServiceAudit
module.exports.TlsServiceAuditResult = TlsServiceAuditResult
