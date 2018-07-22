const tls = require('tls') // eslint-disable-line
const x509 = require('x509')

const TlsSocketWrapper = require('./TlsSocketWrapper')

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

class Certificate extends TlsSocketWrapper {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super(options)
  }

  /**
   * @static
   * @param {string} certRaw in pem format without: -----BEGIN CERTIFICATE-----
   * @returns {x509.X509} X509 certificate
   */
  static parseRawPemCertificate (certRaw) {
    return this.parsePemCertificate(`-----BEGIN CERTIFICATE-----\n${certRaw}\n-----END CERTIFICATE-----`)
  }

  /**
   * @static
   * @param {string} cert in pem format with: -----BEGIN CERTIFICATE-----
   * @returns {x509.X509} X509 certificate
   */
  static parsePemCertificate (cert) {
    return x509.parseCert(cert)
  }

  /**
   * @param {number} timeout
   * @returns {Promise<CertificateResult>}
   */
  async fetch (timeout = -1) {
    return new Promise(async (resolve, reject) => {
      const result = new CertificateResult()

      try {
        await this.connect(timeout)

        result.host = this.options.host
        result.port = this.options.port

        const peerCertificate = this.socket.getPeerCertificate(true)
        result.certPem = peerCertificate.raw.toString('base64')
        if (peerCertificate.issuerCertificate) result.certCaPem = peerCertificate.issuerCertificate.raw.toString('base64')
        result.cert = Certificate.parseRawPemCertificate(result.certPem)
        if (result.certCaPem) result.certCa = Certificate.parseRawPemCertificate(result.certCaPem)
      } catch (error) {
        return this.onError(error, reject)
      }

      this.destroySocket()
      resolve(result)
    })
  }
}

module.exports.Certificate = Certificate
module.exports.CertificateResult = CertificateResult
