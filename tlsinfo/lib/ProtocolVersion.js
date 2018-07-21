const tls = require('tls')
const crypto = require('crypto')

const TlsSocketWrapper = require('./TlsSocketWrapper')

class ProtocolVersionResult {
  constructor () {
    /** @type {string[]} */
    this.enabled = []
    /** @type {string[]} */
    this.disabled = []
    /** @type {string[]} */
    this.unsupported = []
  }
}

class ProtocolVersion extends TlsSocketWrapper {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super(options)
    this.setTimeoutPerConnection(this.timeout)
    this.setTimeout(this.timeout * 10) // if Certificate.timeout has 30 seconds this will be at 5 minutes
  }

  /**
   * @param {number} ms
   */
  setTimeoutPerConnection (ms) {
    if (typeof ms === 'number' && ms > 0) this.timeoutPerConnection = ms
  }

  /**
   * @static
   * @protected
   * @param {string} protocol I.e.: TLSv1.2
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
    const version = process.versions.openssl
    if (Number.parseFloat(version.slice(0, 5)) < 0.9) return []
    if (version.startsWith('0.9') || version.startsWith('1.0.0')) {
      return [
        'SSLv2',
        'SSLv3',
        'TLSv1'
      ]
    }
    if (/1\.0\.[12]/.test(version)) {
      return [
        'SSLv2',
        'SSLv3',
        'TLSv1',
        'TLSv1.1',
        'TLSv1.2'
      ]
    }
    if (version.startsWith('1.1.0')) {
      return [
        'SSLv3',
        'TLSv1',
        'TLSv1.1',
        'TLSv1.2'
      ]
    }
    if (version.startsWith('1.1.1')) {
      return [
        'SSLv3',
        'TLSv1',
        'TLSv1.1',
        'TLSv1.2',
        'TLSv1.3'
      ]
    }
    if (version.startsWith('1.1')) return [ 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3' ]
  }

  async test (protocol, timeout = -1) {
    if (!protocol) throw new Error('protocol must be defined')
    this.options.secureProtocol = ProtocolVersion.map(protocol)
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

    // TODO: set all allowed cipher suites for the selected protocol?

    return new Promise(async (resolve, reject) => {
      const result = new ProtocolVersionResult()
      const resultConnect = await this.connect(this.timeout)
      delete this.options.secureProtocol
      delete this.options.secureOptions
    })
  }
}

ProtocolVersion.protocols = [
  'SSLv2',
  'SSLv3',
  'TLSv1',
  'TLSv1.1',
  'TLSv1.2',
  'TLSv1.3'
]

module.exports.ProtocolVersion = ProtocolVersion
