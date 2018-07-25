const tls = require('tls') // eslint-disable-line
const x509 = require('x509')
const dns = require('dns') // eslint-disable-line

const TlsSocketWrapper = require('./TlsSocketWrapper')
const { DnsHelper, HostAddressResult } = require('./DnsHelper') // eslint-disable-line

class HostAddressSpecificCertificateResult {
  constructor () {
    /** @type {HostAddressResult} */
    this.address = null
    /** @type {CertificateResult} */
    this.certificateResult = null
  }
}

class CertificateResult {
  constructor () {
    this.servername = ''
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
   * @param {number[]} ipVersions default is [4, 6]
   * @param {HostAddressResult[]} addresses
   * @returns {Promise<HostAddressSpecificCertificateResult[]>}
   */
  async fetch (timeout = -1, ipVersions = [4, 6], addresses = []) {
    return new Promise(async (resolve, reject) => {
      /** @type {HostAddressSpecificCertificateResult[]} */
      const results = []
      const resultTemplate = new CertificateResult()
      resultTemplate.servername = this.options.servername
      resultTemplate.port = this.options.port

      try {
        if (!addresses || addresses.length === 0) {
          addresses = await DnsHelper.lookup(this.options.host)
        }

        for (const address of addresses) {
          const addressResult = new HostAddressSpecificCertificateResult()
          addressResult.address = address
          addressResult.certificateResult = Object.assign({ }, resultTemplate)
          results.push(addressResult)
        }
      } catch (error) {
        reject(error)
      }

      try {
        for (const result of results) {
          this.options.host = result.address.address

          // set false to prevent socket self-destruct (default) to be able to receive peer certificates
          await this.connect(timeout, false)

          const peerCertificate = this.socket.getPeerCertificate(true)
          result.certificateResult.certPem = peerCertificate.raw.toString('base64')

          await new Promise((resolve, reject) => {
            try {
              // TODO: change result.certCa into result.certChain which contains all issuer certificates sent by the server
              if (peerCertificate.issuerCertificate) result.certificateResult.certCaPem = peerCertificate.issuerCertificate.raw.toString('base64')
              result.certificateResult.cert = Certificate.parseRawPemCertificate(result.certificateResult.certPem)
              if (result.certificateResult.certCaPem) result.certificateResult.certCa = Certificate.parseRawPemCertificate(result.certificateResult.certCaPem)
              resolve()
            } catch (error) {
              reject(error)
            }
          })
          this.destroySocket()
        }
      } catch (error) {
        this.destroySocket(error)
        return reject(error)
      } finally {
        this.options.host = this.options.servername
      }

      resolve(results)
    })
  }
}

module.exports.Certificate = Certificate
module.exports.CertificateResult = CertificateResult
module.exports.HostAddressSpecificCertificateResult = HostAddressSpecificCertificateResult
