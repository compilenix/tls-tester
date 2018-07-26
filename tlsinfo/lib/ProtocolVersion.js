const tls = require('tls') // eslint-disable-line
const crypto = require('crypto')
const semver = require('semver')

const TlsSocketWrapper = require('./TlsSocketWrapper')
const { DnsHelper, HostAddressResult } = require('./DnsHelper') // eslint-disable-line
const { Cipher } = require('./Cipher')

class ProtocolVersionResult {
  constructor () {
    this.host = ''
    this.port = 443
    this.protocol = ''
    /** @type {HostAddressResult[]} */
    this.ipAddress = []
    /**
     * Protocols that are supported by the current Node.JS version and accepted by the Service
     * @type {HostAddressResult[]}
     */
    this.enabled = []
    /**
     * Protocols that are supported by the current Node.JS version but NOT accepted by the Service
     * @type {HostAddressResult[]}
     */
    this.disabled = []
    /**
     * Protocols that are NOT supported by the current Node.JS version
     * @type {HostAddressResult[]}
     */
    this.unsupported = []
    /**
     * Warnings; I.e. host has multiple ip addresses
     * @type {string[]}
     * @deprecated
     */
    this.warnings = []
  }

  inspect () {
    const res = `${this.protocol}${this.enabled.length > 0 ? ` -> ${this.enabled.length} [` : ''}` +
    (
      this.enabled.length === 0 ? '' : this.enabled.map(
        addr => ` { IPv${addr.family}: ${addr.address} },`
      ).join('')
    )
    if (res.endsWith(',')) {
      return res.slice(0, res.length - 1) + ' ]'
    }
    return res
  }

  toString () {
    const res = `\n${this.protocol} count: ${this.enabled.length}` +
    (
      this.enabled.length === 0 ? '' : this.enabled.map(
        addr => `\n\tIPv${addr.family} ${addr.address}`
      ).join('')
    )
    return res
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
    // TODO: move into static lookup table
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
   * @param {HostAddressResult[]} addresses
   * @returns {Promise<ProtocolVersionResult>} {ProtocolVersionResult}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async test (protocol, timeout = -1, ipVersions = [4, 6], addresses = []) {
    const result = new ProtocolVersionResult()
    if (!protocol) throw new Error('protocol must be defined')

    result.protocol = protocol
    result.host = this.options.host
    result.port = this.options.port

    try {
      if (!addresses || addresses.length === 0) {
        const resolvedAddrs = await DnsHelper.lookup(this.options.host)
        result.ipAddress = resolvedAddrs
      }
    } catch (error) {
      throw error
    }

    const supportedProtocolsByThisNodeVersion = ProtocolVersion.getSupportedProtocols()
    if (!supportedProtocolsByThisNodeVersion.includes(protocol)) {
      result.warnings.push(`This version of Node.JS does not support ${protocol}`)
      for (const address of result.ipAddress) {
        result.unsupported.push(address)
      }
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
    this.options.ciphers = Cipher.suites.join(':')

    return new Promise(async (resolve, reject) => {
      /** @type {Error[]} */
      const hostErrors = []

      try {
        for (const hostAddress of result.ipAddress) {
          if (!ipVersions.includes(hostAddress.family)) continue
          this.options.host = hostAddress.address

          try {
            await this.connect(timeout)
            result.enabled.push(hostAddress)
          } catch (errors) {
            const knownAndOkErrors = [ // these errors indicate disabled
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

            let addHostToDisabled = false
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
                addHostToDisabled = true
                continue
              }

              hostErrors.push(error)
            }

            if (addHostToDisabled) result.disabled.push(hostAddress)
          }
        }
      } catch (error) {
        return reject(error)
      } finally {
        this.options.host = this.options.servername
      }

      hostErrors.length > 0 ? reject(hostErrors) : resolve(result)
    })
  }

  /**
   * @param {string[]} protocols I.e.: [ TLSv1', 'TLSv1_1' ]
   * @param {number} timeout -1 is default, which means: don't change the current timeout value
   * @see {ProtocolVersion.setTimeout}
   * @param {number[]} ipVersions default is [4, 6]
   * @param {HostAddressResult[]} addresses
   * @returns {Promise<ProtocolVersionResult[]>} {ProtocolVersionResult[]}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async testMultiple (protocols, timeout = -1, ipVersions = [4, 6], addresses = []) {
    if (!protocols || !protocols.length || protocols.length === 0) throw new Error('protocols must be defined, a array / list like object and must have at least one element')

    /** @type {ProtocolVersionResult[]} */
    const results = []

    try {
      if (!addresses || addresses.length === 0) {
        addresses = await DnsHelper.lookup(this.options.host)
      }
    } catch (error) {
      throw error
    }

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

ProtocolVersion.protocolName = {
  SSLv2: 'SSLv2',
  SSLv3: 'SSLv3',
  TLSv1: 'TLSv1',
  TLSv1_1: 'TLSv1_1',
  TLSv1_2: 'TLSv1_2',
  TLSv1_3: 'TLSv1_3'
}

module.exports.ProtocolVersion = ProtocolVersion
module.exports.ProtocolVersionResult = ProtocolVersionResult
