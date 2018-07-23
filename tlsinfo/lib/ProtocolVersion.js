const tls = require('tls') // eslint-disable-line
const crypto = require('crypto')
const semver = require('semver')
const dns = require('dns') // eslint-disable-line

const TlsSocketWrapper = require('./TlsSocketWrapper')
const { DnsHelper, HostAddressResult } = require('./DnsHelper') // eslint-disable-line

class HostAddressSpecificProtocolVersionResult {
  constructor () {
    /** @type {HostAddressResult} */
    this.address = null
    this.protocol = ''
  }
}

class ProtocolVersionResult {
  constructor () {
    this.host = ''
    this.port = 443
    /** @type {HostAddressResult[]} */
    this.ipAddress = null
    this.protocol = ''
    /**
     * Protocols that are supported by the current Node.JS version and accepted by the Service
     * @type {HostAddressSpecificProtocolVersionResult[]}
     */
    this.enabled = []
    /**
     * Protocols that are supported by the current Node.JS version but NOT accepted by the Service
     * @type {HostAddressSpecificProtocolVersionResult[]}
     */
    this.disabled = []
    /**
     * Protocols that are NOT supported by the current Node.JS version
     * @type {HostAddressSpecificProtocolVersionResult[]}
     */
    this.unsupported = []
    /**
     * Warnings; I.e. host has multiple ip addresses
     * @type {string[]}
     */
    this.warnings = []
  }
}

class ProtocolVersion extends TlsSocketWrapper {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super(options)
  }

  /**
   * @static
   * @protected
   * @param {string} protocol I.e.: TLSv1_2
   */
  static map (protocol) {
    switch (protocol) {
      case 'SSLv2':
        return 'SSLv2_method'
      case 'SSLv3':
        return 'SSLv3_method'
      case 'TLSv1':
        return 'TLSv1_method'
      case 'TLSv1_1':
        return 'TLSv1_1_method'
      case 'TLSv1_2':
        return 'TLSv1_2_method'
      case 'TLSv1_3':
        return 'TLSv1_3_method'
      default:
        return ''
    }
  }

  static getSupportedProtocols () {
    const version = semver.coerce(process.versions.node)
    if (semver.lt(version, semver.coerce('4'))) return [ 'SSLv3', 'TLSv1' ]
    if (semver.satisfies(version, '4 - 9')) return [ 'TLSv1', 'TLSv1_1', 'TLSv1_2' ]
    if (semver.gte(semver.coerce(process.versions.openssl), '1.1.1')) return ['TLSv1', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3']
    return []
  }

  /**
   * @param {string} protocol I.e.: TLSv1_2
   * @param {number} timeout -1 is default, which means: don't change the current timeout value
   * @see {ProtocolVersion.setTimeout}
   * @param {number[]} ipVersions default is [4, 6]
   * @returns {Promise<ProtocolVersionResult>} {ProtocolVersionResult[]}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async test (protocol, timeout = -1, ipVersions = [4, 6]) {
    const result = new ProtocolVersionResult()
    if (!protocol) throw new Error('protocol must be defined')

    result.protocol = protocol
    result.host = this.options.host
    result.port = this.options.port
    try {
      const { addresses, warnings } = await DnsHelper.lookup(this.options.host)
      result.ipAddress = addresses
      for (const warning of warnings) {
        result.warnings.push(warning)
      }
    } catch (error) {
      throw error
    }

    const supportedProtocolsByThisNodeVersion = ProtocolVersion.getSupportedProtocols()
    for (const protocol of ProtocolVersion.protocols) {
      if (supportedProtocolsByThisNodeVersion.includes(protocol)) continue

      for (const address of result.ipAddress) {
        const hostSpecificResult = new HostAddressSpecificProtocolVersionResult()
        hostSpecificResult.address = address
        hostSpecificResult.protocol = protocol
        result.unsupported.push(hostSpecificResult)
      }
    }

    if (!ProtocolVersion.getSupportedProtocols().includes(protocol)) {
      result.warnings.push(`This version of Node.JS does not support ${protocol}`)
      return result
    }

    this.options.secureProtocol = ProtocolVersion.map(protocol)
    if (!this.options.secureOptions) {
      this.options.secureOptions = crypto.constants.SSL_OP_ALL
    } else {
      this.options.secureOptions = 0
    }

    this.options.secureOptions |= crypto.constants.SSL_OP_NO_SSLv2
    this.options.secureOptions |= crypto.constants.SSL_OP_NO_SSLv3
    this.options.secureOptions |= crypto.constants.SSL_OP_NO_TLSv1
    this.options.secureOptions |= crypto.constants.SSL_OP_NO_TLSv1_1
    this.options.secureOptions |= crypto.constants.SSL_OP_NO_TLSv1_2
    if (crypto.constants.SSL_OP_NO_TLSv1_3) {
      this.options.secureOptions |= crypto.constants.SSL_OP_NO_TLSv1_3
    }

    switch (protocol) {
      case 'SSLv2':
        this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_SSLv2
        break
      case 'SSLv3':
        this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_SSLv3
        break
      case 'TLSv1':
        this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_TLSv1
        break
      case 'TLSv1_1':
        this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_TLSv1_1
        break
      case 'TLSv1_2':
        this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_TLSv1_2
        break
      case 'TLSv1_3':
        if (crypto.constants.SSL_OP_NO_TLSv1_3) {
          this.options.secureOptions &= ~crypto.constants.SSL_OP_NO_TLSv1_3
        }
        break
      default:
        break
    }

    // virtually every cipher under the sun
    this.options.ciphers = 'ADH-AES128-GCM-SHA256:ADH-AES128-SHA:ADH-AES128-SHA256:ADH-AES256-GCM-SHA384:ADH-AES256-SHA:ADH-AES256-SHA256:ADH-CAMELLIA128-SHA:ADH-CAMELLIA128-SHA256:ADH-CAMELLIA256-SHA:ADH-CAMELLIA256-SHA256:ADH-DES-CBC3-SHA:ADH-RC4-MD5:ADH-SEED-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA:AECDH-DES-CBC3-SHA:AECDH-RC4-SHA:AES128-CCM:AES128-CCM8:AES128-GCM-SHA256:AES128-SHA:AES128-SHA256:AES256-CCM:AES256-CCM8:AES256-GCM-SHA384:AES256-SHA:AES256-SHA256:CAMELLIA128-SHA:CAMELLIA128-SHA256:CAMELLIA256-SHA:CAMELLIA256-SHA256:DES-CBC3-SHA:DH-DSS-AES128-GCM-SHA256:DH-DSS-AES128-SHA:DH-DSS-AES128-SHA256:DH-DSS-AES256-GCM-SHA384:DH-DSS-AES256-SHA:DH-DSS-AES256-SHA256:DH-DSS-CAMELLIA128-SHA:DH-DSS-CAMELLIA256-SHA:DH-DSS-DES-CBC3-SHA:DH-DSS-SEED-SHA:DH-RSA-AES128-GCM-SHA256:DH-RSA-AES128-SHA:DH-RSA-AES128-SHA256:DH-RSA-AES256-GCM-SHA384:DH-RSA-AES256-SHA:DH-RSA-AES256-SHA256:DH-RSA-CAMELLIA128-SHA:DH-RSA-CAMELLIA256-SHA:DH-RSA-DES-CBC3-SHA:DH-RSA-SEED-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-GCM-SHA384:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA256:DHE-DSS-DES-CBC3-SHA:DHE-DSS-SEED-SHA:DHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CCM:DHE-PSK-AES128-CCM8:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CCM:DHE-PSK-AES256-CCM8:DHE-PSK-AES256-GCM-SHA384:DHE-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA256-SHA384:DHE-PSK-CHACHA20-POLY1305:DHE-RSA-AES128-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA256-SHA:DHE-RSA-CAMELLIA256-SHA256:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-DES-CBC3-SHA:DHE-RSA-SEED-SHA:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA:ECDH-RSA-AES256-SHA384:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-RC4-SHA:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-PSK-3DES-EDE-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES256-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-CAMELLIA128-SHA256:ECDHE-PSK-CAMELLIA256-SHA384:ECDHE-PSK-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA256-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-RC4-SHA:EDH-DSS-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:IDEA-CBC-SHA:PSK-3DES-EDE-CBC-SHA:PSK-AES128-CBC-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CCM:PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES256-CBC-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CCM:PSK-AES256-CCM8:PSK-AES256-GCM-SHA384:PSK-CAMELLIA128-SHA256:PSK-CAMELLIA256-SHA384:PSK-CHACHA20-POLY1305:PSK-RC4-SHA:RC4-MD5:RC4-SHA:RSA-PSK-3DES-EDE-CBC-SHA:RSA-PSK-AES128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-GCM-SHA256:RSA-PSK-AES256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-GCM-SHA384:RSA-PSK-CAMELLIA128-SHA256:RSA-PSK-CAMELLIA256-SHA384:RSA-PSK-CHACHA20-POLY1305:SEED-SHA:SRP-3DES-EDE-CBC-SHA:SRP-AES-128-CBC-SHA:SRP-AES-256-CBC-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-RSA-AES-256-CBC-SHA'

    return new Promise(async (resolve, reject) => {
      const originalHost = this.options.host
      /** @type {Error[]} */
      const hostErrors = []

      try {
        for (const hostAddress of result.ipAddress) {
          if (!ipVersions.includes(hostAddress.family)) continue
          this.options.host = hostAddress.address
          const hostSpecificResult = new HostAddressSpecificProtocolVersionResult()
          hostSpecificResult.address = hostAddress
          hostSpecificResult.protocol = protocol

          try {
            await this.connect(timeout)
            result.enabled.push(hostSpecificResult)
          } catch (errors) {
            const knownAndOkErrors = [
              'no ciphers available',
              'wrong version number',
              'methods disabled',
              'unsupported protocol',
              'socket hang up',
              'ECONNRESET',
              'handshake failure',
              'dh key too small',
              'excessive message size'
            ]

            let hostAddedToDisabled = false
            for (const error of errors) {
              let knownAndOkError = false
              /** @type {string} */
              const errorString = error.toString()
              for (const knownError of knownAndOkErrors) {
                if (errorString.match(knownError)) {
                  knownAndOkError = true
                  break
                }
              }

              if (knownAndOkError) {
                hostAddedToDisabled = true
                continue
              }

              hostErrors.push(error)
            }

            if (hostAddedToDisabled) result.disabled.push(hostSpecificResult)
          }
        }
      } catch (error) {
        throw error
      } finally {
        delete this.options.secureProtocol
        delete this.options.secureOptions
      }

      this.options.host = originalHost
      hostErrors.length > 0 ? reject(hostErrors) : resolve(result)
    })
  }

  /**
   * @param {string[]} protocols I.e.: [ TLSv1', 'TLSv1_1' ]
   * @param {number} timeout -1 is default, which means: don't change the current timeout value
   * @see {ProtocolVersion.setTimeout}
   * @param {number[]} ipVersions default is [4, 6]
   * @returns {Promise<ProtocolVersionResult[]>} {ProtocolVersionResult[]}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async testMultiple (protocols, timeout = -1, ipVersions = [4, 6]) {
    if (!protocols || !protocols.length || protocols.length === 0) throw new Error('protocols must be defined, a array / list like object and must have at least one element')

    /** @type {ProtocolVersionResult[]} */
    const results = []

    return new Promise(async (resolve, reject) => {
      try {
        for (const protocol of protocols) {
          const result = await this.test(protocol, timeout, ipVersions)
          results.push(result)
        }

        resolve(results)
      } catch (error) {
        reject(error)
      }
    })
  }
}

ProtocolVersion.protocols = [
  'SSLv2',
  'SSLv3',
  'TLSv1',
  'TLSv1_1',
  'TLSv1_2',
  'TLSv1_3'
]

module.exports.ProtocolVersion = ProtocolVersion
