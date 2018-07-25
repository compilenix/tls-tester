const tls = require('tls') // eslint-disable-line
const crypto = require('crypto')

const TlsSocketWrapper = require('./TlsSocketWrapper')
const { DnsHelper, HostAddressResult } = require('./DnsHelper') // eslint-disable-line

class ProtocolVersionSpecificCipherResult {
  constructor () {
    this.protocol = ''
    /** @type {HostAddressResult[]} */
    this.enabled = []
    /** @type {HostAddressResult[]} */
    this.disabled = []
    /** @type {HostAddressResult[]} */
    this.unsupported = []
  }
}

class CipherResult {
  constructor () {
    this.host = ''
    this.port = 443
    this.cipher = ''
    /** @type {HostAddressResult[]} */
    this.ipAddress = []
    /** @type {ProtocolVersionSpecificCipherResult[]} */
    this.protocolSpecificResults = []
  }

  inspect () {
    const res = `${this.cipher}` +
    this.protocolSpecificResults.map(
      proto => `${proto.enabled.length > 0 ? ` { ${proto.protocol}:` : ''}` + proto.enabled.map(
        addr => ` IPv${addr.family}: ${addr.address}`
      ) + `${proto.enabled.length > 0 ? ` },` : ''}`
    ).join('')
    if (res.endsWith(',')) {
      return res.slice(0, res.length - 1)
    }
    return res
  }

  toString () {
    const res = `${this.cipher}\n` +
    this.protocolSpecificResults.map(
      proto => proto.enabled.map(
        addr => `\t${proto.protocol}\t-> IPv${addr.family} ${addr.address}\n`
      )
    ).join('')
    return res
  }
}

class Cipher extends TlsSocketWrapper {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super(options)
  }

  /**
   * @param {string[]} list
   */
  static getCipherSuitesString (list = []) {
    if (list && list.length && typeof list.length === 'function' && list.length > 0) {
      return list.join(':')
    }

    if (!Cipher.suitesString) Cipher.suitesString = Cipher.suites.join(':')
    return Cipher.suitesString
  }

  /**
   * @param {string} cipher I.e.: 'AES128-GCM-SHA256'
   * @param {string[]} protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
   * @see {ProtocolVersion.setTimeout}
   * @param {number} timeout -1 is default, which means: don't change the current timeout value
   * @param {number[]} ipVersions default is [4, 6]
   * @param {HostAddressResult[]} addresses
   * @returns {Promise<CipherResult>} {CipherResult}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async test (cipher, protocols = [], timeout = -1, ipVersions = [4, 6], addresses = []) {
    const { ProtocolVersion } = require('./ProtocolVersion')
    if (!cipher || typeof cipher !== 'string') throw new Error('cipher must be defined and type of string')
    if (!protocols || protocols.length === 0) protocols = ProtocolVersion.getSupportedProtocols()
    const result = new CipherResult()
    result.cipher = cipher
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

    /** @type {ProtocolVersionSpecificCipherResult[]} */
    const protocolSpecificResults = []

    const supportedProtocolsByThisNodeVersion = ProtocolVersion.getSupportedProtocols()
    for (const protocol of ProtocolVersion.protocols) {
      const protocolSpecificResult = new ProtocolVersionSpecificCipherResult()
      protocolSpecificResult.protocol = protocol

      for (const address of result.ipAddress) {
        if (!supportedProtocolsByThisNodeVersion.includes(protocol)) {
          protocolSpecificResult.unsupported.push(address)
          continue
        }
      }
      protocolSpecificResults.push(protocolSpecificResult)
    }

    let isAnyProtocolSupported = false
    for (const protocol of protocols) {
      if (supportedProtocolsByThisNodeVersion.includes(protocol)) {
        isAnyProtocolSupported = true
        break
      }
    }
    if (!isAnyProtocolSupported) {
      throw new Error(`This version of Node.JS does not support (any of) the specified protocol/s: ${protocols}`)
    }

    return new Promise(async (resolve, reject) => {
      /** @type {Error[]} */
      const hostErrors = []

      for (const protocol of protocols) {
        if (!supportedProtocolsByThisNodeVersion.includes(protocol)) continue
        const protocolSpecificResultIndex = protocolSpecificResults.findIndex(result => result.protocol === protocol)
        const protocolSpecificResult = protocolSpecificResults[protocolSpecificResultIndex]

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

        this.options.ciphers = cipher

        try {
          for (const hostAddress of result.ipAddress) {
            if (!ipVersions.includes(hostAddress.family)) continue
            this.options.host = hostAddress.address

            try {
              const supportedCiphersByThisNodeVersion = tls.getCiphers()
              if (!supportedCiphersByThisNodeVersion.includes(cipher.toLowerCase())) {
                protocolSpecificResult.unsupported.push(hostAddress)
                continue
              }

              await this.connect(timeout)
              protocolSpecificResult.enabled.push(hostAddress)
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

              if (addHostToDisabled) {
                protocolSpecificResult.disabled.push(hostAddress)
              }
            }
          }

          result.protocolSpecificResults.push(protocolSpecificResult)
        } catch (error) {
          this.options.host = this.options.servername
          return reject(error)
        }

        this.options.host = this.options.servername
        hostErrors.length > 0 ? reject(hostErrors) : resolve(result)
      }
    })
  }

  /**
   * @param {string[]} ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
   * @param {string[]} protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
   * @see {ProtocolVersion.setTimeout}
   * @param {number} timeout -1 is default, which means: don't change the current timeout value
   * @param {number[]} ipVersions default is [4, 6]
   * @param {HostAddressResult[]} addresses
   * @returns {Promise<CipherResult[]>} {CipherResult}
   * @see {ProtocolVersion.getSupportedProtocols}
   */
  async testMultiple (ciphers, protocols = [], timeout = -1, ipVersions = [4, 6], addresses = []) {
    if (!ciphers || !ciphers.length || ciphers.length === 0) throw new Error('ciphers must be defined, a array / list like object and must have at least one element')

    /** @type {CipherResult[]} */
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
        for (const cipher of ciphers) {
          this.options.host = this.options.servername
          const result = await this.test(cipher, protocols, timeout, ipVersions)
          results.push(result)
        }

        resolve(results)
      } catch (error) {
        reject(error)
      }
    })
  }

  /**
   * @param {CipherResult[]} cipherResults
   */
  static filterEnabled (cipherResults) {
    return cipherResults.filter(result => result.protocolSpecificResults.find(protocol => protocol.enabled.length > 0) !== undefined)
  }

  /**
   * @param {CipherResult[]} cipherResults
   */
  static filterDisabled (cipherResults) {
    return cipherResults.filter(result => result.protocolSpecificResults.find(protocol => protocol.disabled.length > 0) !== undefined)
  }

  /**
   * @param {CipherResult[]} cipherResults
   */
  static filterUnsupported (cipherResults) {
    return cipherResults.filter(result => result.protocolSpecificResults.find(protocol => protocol.unsupported.length > 0) !== undefined)
  }
}

Cipher.suitesString = ''
Cipher.suites = [
  // SSL v3.0 cipher suites
  'NULL-MD5', // SSL_RSA_WITH_NULL_MD5
  'NULL-SHA', // SSL_RSA_WITH_NULL_SHA
  'RC4-MD5', // SSL_RSA_WITH_RC4_128_MD5
  'RC4-SHA', // SSL_RSA_WITH_RC4_128_SHA
  'IDEA-CBC-SHA', // SSL_RSA_WITH_IDEA_CBC_SHA
  'DES-CBC3-SHA', // SSL_RSA_WITH_3DES_EDE_CBC_SHA
  'DH-DSS-DES-CBC3-SHA', // SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
  'DH-RSA-DES-CBC3-SHA', // SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
  'DHE-DSS-DES-CBC3-SHA', // SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
  'DHE-RSA-DES-CBC3-SHA', // SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  'ADH-RC4-MD5', // SSL_DH_anon_WITH_RC4_128_MD5
  'ADH-DES-CBC3-SHA', // SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
  // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_NULL_SHA
  // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
  // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_RC4_128_SHA

  // TLS v1.0 cipher suites
  'EXP-RC4-MD5', // TLS_RSA_EXPORT_WITH_RC4_40_MD5
  'EXP-RC2-CBC-MD5', // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
  'EXP-DES-CBC-SHA', // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
  'DES-CBC-SHA', // TLS_RSA_WITH_DES_CBC_SHA
  // 'Not implemented.', // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
  // 'Not implemented.', // TLS_DH_DSS_WITH_DES_CBC_SHA
  // 'Not implemented.', // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
  // 'Not implemented.', // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
  // 'Not implemented.', // TLS_DH_RSA_WITH_DES_CBC_SHA
  // 'Not implemented.', // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
  'EXP-EDH-DSS-DES-CBC-SHA', // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
  'EDH-DSS-CBC-SHA', // TLS_DHE_DSS_WITH_DES_CBC_SHA
  'EDH-DSS-DES-CBC3-SHA', // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
  'EXP-EDH-RSA-DES-CBC-SHA', // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
  'EDH-RSA-DES-CBC-SHA', // TLS_DHE_RSA_WITH_DES_CBC_SHA
  'EDH-RSA-DES-CBC3-SHA', // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  'EXP-ADH-RC4-MD5', // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
  'EXP-ADH-DES-CBC-SHA', // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
  'ADH-DES-CBC-SHA', // TLS_DH_anon_WITH_DES_CBC_SHA

  // AES ciphersuites from RFC3268
  'AES128-SHA', // TLS_RSA_WITH_AES_128_CBC_SHA
  'AES256-SHA', // TLS_RSA_WITH_AES_256_CBC_SHA
  'DH-DSS-AES128-SHA', // TLS_DH_DSS_WITH_AES_128_CBC_SHA
  'DH-DSS-AES256-SHA', // TLS_DH_DSS_WITH_AES_256_CBC_SHA
  'DH-RSA-AES128-SHA', // TLS_DH_RSA_WITH_AES_128_CBC_SHA
  'DH-RSA-AES256-SHA', // TLS_DH_RSA_WITH_AES_256_CBC_SHA
  'DHE-DSS-AES128-SHA', // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
  'DHE-DSS-AES256-SHA', // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
  'DHE-RSA-AES128-SHA', // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  'DHE-RSA-AES256-SHA', // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
  'ADH-AES128-SHA', // TLS_DH_anon_WITH_AES_128_CBC_SHA
  'ADH-AES256-SHA', // TLS_DH_anon_WITH_AES_256_CBC_SHA

  // Camellia ciphersuites from RFC4132
  'CAMELLIA128-SHA', // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
  'CAMELLIA256-SHA', // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
  'DH-DSS-CAMELLIA128-SHA', // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
  'DH-DSS-CAMELLIA256-SHA', // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
  'DH-RSA-CAMELLIA128-SHA', // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
  'DH-RSA-CAMELLIA256-SHA', // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
  'DHE-DSS-CAMELLIA128-SHA', // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
  'DHE-DSS-CAMELLIA256-SHA', // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
  'DHE-RSA-CAMELLIA128-SHA', // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
  'DHE-RSA-CAMELLIA256-SHA', // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
  'ADH-CAMELLIA128-SHA', // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
  'ADH-CAMELLIA256-SHA', // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA

  // SEED ciphersuites from RFC4162
  'SEED-SHA', // TLS_RSA_WITH_SEED_CBC_SHA
  'DH-DSS-SEED-SHA', // TLS_DH_DSS_WITH_SEED_CBC_SHA
  'DH-RSA-SEED-SHA', // TLS_DH_RSA_WITH_SEED_CBC_SHA
  'DHE-DSS-SEED-SHA', // TLS_DHE_DSS_WITH_SEED_CBC_SHA
  'DHE-RSA-SEED-SHA', // TLS_DHE_RSA_WITH_SEED_CBC_SHA
  'ADH-SEED-SHA', // TLS_DH_anon_WITH_SEED_CBC_SHA

  // GOST ciphersuites from draft-chudov-cryptopro-cptls
  // 'GOST94-GOST89-GOST89', // TLS_GOSTR341094_WITH_28147_CNT_IMIT
  // 'GOST2001-GOST89-GOST89', // TLS_GOSTR341001_WITH_28147_CNT_IMIT
  // 'GOST94-NULL-GOST94', // TLS_GOSTR341094_WITH_NULL_GOSTR3411
  // 'GOST2001-NULL-GOST94', // TLS_GOSTR341001_WITH_NULL_GOSTR3411

  // Additional Export 1024 and other cipher suites
  'EXP1024-DES-CBC-SHA', // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
  'EXP1024-RC4-SHA', // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
  'EXP1024-DHE-DSS-DES-CBC-SHA', // TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
  'EXP1024-DHE-DSS-RC4-SHA', // TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
  'DHE-DSS-RC4-SHA', // TLS_DHE_DSS_WITH_RC4_128_SHA

  // Elliptic curve cipher suites
  'ECDH-RSA-NULL-SHA', // TLS_ECDH_RSA_WITH_NULL_SHA
  'ECDH-RSA-RC4-SHA', // TLS_ECDH_RSA_WITH_RC4_128_SHA
  'ECDH-RSA-DES-CBC3-SHA', // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
  'ECDH-RSA-AES128-SHA', // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
  'ECDH-RSA-AES256-SHA', // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
  'ECDH-ECDSA-NULL-SHA', // TLS_ECDH_ECDSA_WITH_NULL_SHA
  'ECDH-ECDSA-RC4-SHA', // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
  'ECDH-ECDSA-DES-CBC3-SHA', // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
  'ECDH-ECDSA-AES128-SHA', // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
  'ECDH-ECDSA-AES256-SHA', // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
  'ECDHE-RSA-NULL-SHA', // TLS_ECDHE_RSA_WITH_NULL_SHA
  'ECDHE-RSA-RC4-SHA', // TLS_ECDHE_RSA_WITH_RC4_128_SHA
  'ECDHE-RSA-DES-CBC3-SHA', // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  'ECDHE-RSA-AES128-SHA', // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  'ECDHE-RSA-AES256-SHA', // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  'ECDHE-ECDSA-NULL-SHA', // TLS_ECDHE_ECDSA_WITH_NULL_SHA
  'ECDHE-ECDSA-RC4-SHA', // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
  'ECDHE-ECDSA-DES-CBC3-SHA', // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  'ECDHE-ECDSA-AES128-SHA', // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  'ECDHE-ECDSA-AES256-SHA', // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  'AECDH-NULL-SHA', // TLS_ECDH_anon_WITH_NULL_SHA
  'AECDH-RC4-SHA', // TLS_ECDH_anon_WITH_RC4_128_SHA
  'AECDH-DES-CBC3-SHA', // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
  'AECDH-AES128-SHA', // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
  'AECDH-AES256-SHA', // TLS_ECDH_anon_WITH_AES_256_CBC_SHA

  // TLS v1.2 cipher suites
  'NULL-SHA256', // TLS_RSA_WITH_NULL_SHA256
  'AES128-SHA256', // TLS_RSA_WITH_AES_128_CBC_SHA256
  'AES256-SHA256', // TLS_RSA_WITH_AES_256_CBC_SHA256
  'AES128-GCM-SHA256', // TLS_RSA_WITH_AES_128_GCM_SHA256
  'AES256-GCM-SHA384', // TLS_RSA_WITH_AES_256_GCM_SHA384
  'DH-RSA-AES128-SHA256', // TLS_DH_RSA_WITH_AES_128_CBC_SHA256
  'DH-RSA-AES256-SHA256', // TLS_DH_RSA_WITH_AES_256_CBC_SHA256
  'DH-RSA-AES128-GCM-SHA256', // TLS_DH_RSA_WITH_AES_128_GCM_SHA256
  'DH-RSA-AES256-GCM-SHA384', // TLS_DH_RSA_WITH_AES_256_GCM_SHA384
  'DH-DSS-AES128-SHA256', // TLS_DH_DSS_WITH_AES_128_CBC_SHA256
  'DH-DSS-AES256-SHA256', // TLS_DH_DSS_WITH_AES_256_CBC_SHA256
  'DH-DSS-AES128-GCM-SHA256', // TLS_DH_DSS_WITH_AES_128_GCM_SHA256
  'DH-DSS-AES256-GCM-SHA384', // TLS_DH_DSS_WITH_AES_256_GCM_SHA384
  'DHE-RSA-AES128-SHA256', // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  'DHE-RSA-AES256-SHA256', // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  'DHE-RSA-AES128-GCM-SHA256', // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
  'DHE-RSA-AES256-GCM-SHA384', // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
  'DHE-DSS-AES128-SHA256', // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
  'DHE-DSS-AES256-SHA256', // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
  'DHE-DSS-AES128-GCM-SHA256', // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
  'DHE-DSS-AES256-GCM-SHA384', // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
  'ECDH-RSA-AES128-SHA256', // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
  'ECDH-RSA-AES256-SHA384', // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
  'ECDH-RSA-AES128-GCM-SHA256', // TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
  'ECDH-RSA-AES256-GCM-SHA384', // TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
  'ECDH-ECDSA-AES128-SHA256', // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
  'ECDH-ECDSA-AES256-SHA384', // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
  'ECDH-ECDSA-AES128-GCM-SHA256', // TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
  'ECDH-ECDSA-AES256-GCM-SHA384', // TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
  'ECDHE-RSA-AES128-SHA256', // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  'ECDHE-RSA-AES256-SHA384', // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  'ECDHE-RSA-AES128-GCM-SHA256', // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  'ECDHE-RSA-AES256-GCM-SHA384', // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  'ECDHE-ECDSA-AES128-SHA256', // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
  'ECDHE-ECDSA-AES256-SHA384', // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
  'ECDHE-ECDSA-AES128-GCM-SHA256', // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  'ECDHE-ECDSA-AES256-GCM-SHA384', // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  'ADH-AES128-SHA256', // TLS_DH_anon_WITH_AES_128_CBC_SHA256
  'ADH-AES256-SHA256', // TLS_DH_anon_WITH_AES_256_CBC_SHA256
  'ADH-AES128-GCM-SHA256', // TLS_DH_anon_WITH_AES_128_GCM_SHA256
  'ADH-AES256-GCM-SHA384', // TLS_DH_anon_WITH_AES_256_GCM_SHA384
  'AES128-CCM', // RSA_WITH_AES_128_CCM
  'AES256-CCM', // RSA_WITH_AES_256_CCM
  'DHE-RSA-AES128-CCM', // DHE_RSA_WITH_AES_128_CCM
  'DHE-RSA-AES256-CCM', // DHE_RSA_WITH_AES_256_CCM
  'AES128-CCM8', // RSA_WITH_AES_128_CCM_8
  'AES256-CCM8', // RSA_WITH_AES_256_CCM_8
  'DHE-RSA-AES128-CCM8', // DHE_RSA_WITH_AES_128_CCM_8
  'DHE-RSA-AES256-CCM8', // DHE_RSA_WITH_AES_256_CCM_8
  'ECDHE-ECDSA-AES128-CCM', // ECDHE_ECDSA_WITH_AES_128_CCM
  'ECDHE-ECDSA-AES256-CCM', // ECDHE_ECDSA_WITH_AES_256_CCM
  'ECDHE-ECDSA-AES128-CCM8', // ECDHE_ECDSA_WITH_AES_128_CCM_8
  'ECDHE-ECDSA-AES256-CCM8', // ECDHE_ECDSA_WITH_AES_256_CCM_8

  // Pre shared keying (PSK) cipheruites
  'PSK-NULL-SHA', // PSK_WITH_NULL_SHA
  'DHE-PSK-NULL-SHA', // DHE_PSK_WITH_NULL_SHA
  'RSA-PSK-NULL-SHA', // RSA_PSK_WITH_NULL_SHA
  'PSK-RC4-SHA', // PSK_WITH_RC4_128_SHA
  'PSK-3DES-EDE-CBC-SHA', // PSK_WITH_3DES_EDE_CBC_SHA
  'PSK-AES128-CBC-SHA', // PSK_WITH_AES_128_CBC_SHA
  'PSK-AES256-CBC-SHA', // PSK_WITH_AES_256_CBC_SHA
  'DHE-PSK-RC4-SHA', // DHE_PSK_WITH_RC4_128_SHA
  'DHE-PSK-3DES-EDE-CBC-SHA', // DHE_PSK_WITH_3DES_EDE_CBC_SHA
  'DHE-PSK-AES128-CBC-SHA', // DHE_PSK_WITH_AES_128_CBC_SHA
  'DHE-PSK-AES256-CBC-SHA', // DHE_PSK_WITH_AES_256_CBC_SHA
  'RSA-PSK-RC4-SHA', // RSA_PSK_WITH_RC4_128_SHA
  'RSA-PSK-3DES-EDE-CBC-SHA', // RSA_PSK_WITH_3DES_EDE_CBC_SHA
  'RSA-PSK-AES128-CBC-SHA', // RSA_PSK_WITH_AES_128_CBC_SHA
  'RSA-PSK-AES256-CBC-SHA', // RSA_PSK_WITH_AES_256_CBC_SHA
  'DHE-PSK-AES128-GCM-SHA256', // DHE_PSK_WITH_AES_128_GCM_SHA256
  'DHE-PSK-AES256-GCM-SHA384', // DHE_PSK_WITH_AES_256_GCM_SHA384
  'RSA-PSK-AES128-GCM-SHA256', // RSA_PSK_WITH_AES_128_GCM_SHA256
  'RSA-PSK-AES256-GCM-SHA384', // RSA_PSK_WITH_AES_256_GCM_SHA384
  'PSK-AES128-CBC-SHA256', // PSK_WITH_AES_128_CBC_SHA256
  'PSK-AES256-CBC-SHA384', // PSK_WITH_AES_256_CBC_SHA384
  'PSK-NULL-SHA256', // PSK_WITH_NULL_SHA256
  'PSK-NULL-SHA384', // PSK_WITH_NULL_SHA384
  'DHE-PSK-AES128-CBC-SHA256', // DHE_PSK_WITH_AES_128_CBC_SHA256
  'DHE-PSK-AES256-CBC-SHA384', // DHE_PSK_WITH_AES_256_CBC_SHA384
  'DHE-PSK-NULL-SHA256', // DHE_PSK_WITH_NULL_SHA256
  'DHE-PSK-NULL-SHA384', // DHE_PSK_WITH_NULL_SHA384
  'RSA-PSK-AES128-CBC-SHA256', // RSA_PSK_WITH_AES_128_CBC_SHA256
  'RSA-PSK-AES256-CBC-SHA384', // RSA_PSK_WITH_AES_256_CBC_SHA384
  'RSA-PSK-NULL-SHA256', // RSA_PSK_WITH_NULL_SHA256
  'RSA-PSK-NULL-SHA384', // RSA_PSK_WITH_NULL_SHA384
  'PSK-AES128-GCM-SHA256', // PSK_WITH_AES_128_GCM_SHA256
  'PSK-AES256-GCM-SHA384', // PSK_WITH_AES_256_GCM_SHA384
  'ECDHE-PSK-RC4-SHA', // ECDHE_PSK_WITH_RC4_128_SHA
  'ECDHE-PSK-3DES-EDE-CBC-SHA', // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
  'ECDHE-PSK-AES128-CBC-SHA', // ECDHE_PSK_WITH_AES_128_CBC_SHA
  'ECDHE-PSK-AES256-CBC-SHA', // ECDHE_PSK_WITH_AES_256_CBC_SHA
  'ECDHE-PSK-AES128-CBC-SHA256', // ECDHE_PSK_WITH_AES_128_CBC_SHA256
  'ECDHE-PSK-AES256-CBC-SHA384', // ECDHE_PSK_WITH_AES_256_CBC_SHA384
  'ECDHE-PSK-NULL-SHA', // ECDHE_PSK_WITH_NULL_SHA
  'ECDHE-PSK-NULL-SHA256', // ECDHE_PSK_WITH_NULL_SHA256
  'ECDHE-PSK-NULL-SHA384', // ECDHE_PSK_WITH_NULL_SHA384
  'PSK-CAMELLIA128-SHA256', // PSK_WITH_CAMELLIA_128_CBC_SHA256
  'PSK-CAMELLIA256-SHA384', // PSK_WITH_CAMELLIA_256_CBC_SHA384
  'DHE-PSK-CAMELLIA128-SHA256', // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
  'DHE-PSK-CAMELLIA256-SHA384', // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
  'RSA-PSK-CAMELLIA128-SHA256', // RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
  'RSA-PSK-CAMELLIA256-SHA384', // RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
  'ECDHE-PSK-CAMELLIA128-SHA256', // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
  'ECDHE-PSK-CAMELLIA256-SHA384', // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
  'PSK-AES128-CCM', // PSK_WITH_AES_128_CCM
  'PSK-AES256-CCM', // PSK_WITH_AES_256_CCM
  'DHE-PSK-AES128-CCM', // DHE_PSK_WITH_AES_128_CCM
  'DHE-PSK-AES256-CCM', // DHE_PSK_WITH_AES_256_CCM
  'PSK-AES128-CCM8', // PSK_WITH_AES_128_CCM_8
  'PSK-AES256-CCM8', // PSK_WITH_AES_256_CCM_8
  'DHE-PSK-AES128-CCM8', // DHE_PSK_WITH_AES_128_CCM_8
  'DHE-PSK-AES256-CCM8', // DHE_PSK_WITH_AES_256_CCM_8

  // Camellia HMAC-Based ciphersuites from RFC6367
  'ECDHE-ECDSA-CAMELLIA128-SHA256', // TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
  'ECDHE-ECDSA-CAMELLIA256-SHA384', // TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
  'ECDHE-RSA-CAMELLIA128-SHA256', // TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
  'ECDHE-RSA-CAMELLIA256-SHA384', // TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384

  // ChaCha20-Poly1305 cipher suites
  'ECDHE-RSA-CHACHA20-POLY1305', // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  'ECDHE-ECDSA-CHACHA20-POLY1305', // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  'DHE-RSA-CHACHA20-POLY1305', // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  'PSK-CHACHA20-POLY1305', // TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
  'ECDHE-PSK-CHACHA20-POLY1305', // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
  'DHE-PSK-CHACHA20-POLY1305', // TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
  'RSA-PSK-CHACHA20-POLY1305' // TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
]

module.exports.Cipher = Cipher
module.exports.ProtocolVersionSpecificCipherResult = ProtocolVersionSpecificCipherResult
module.exports.CipherResult = CipherResult
