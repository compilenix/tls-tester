const tls = require('tls')

const TlsSocketWrapper = require('./TlsSocketWrapper')
const ProtocolVersion = require('./ProtocolVersion')

class CipherResult {
  constructor () {
    this.protocol = ''
    /** @type {string[]} */
    this.enabled = []
    /** @type {string[]} */
    this.disabled = []
    /** @type {string[]} */
    this.unsupported = []
  }
}

class Cipher extends TlsSocketWrapper {
  /**
   * @param {tls.ConnectionOptions} options
   */
  constructor (options = null) {
    super(options)
    this.setTimeout((this.timeout * Cipher.suites.length) + this.timeout)
  }

  async test (timeout = -1, timeoutPerConnection = -1) {
    this.setTimeout(timeout)

    return new Promise(async (resolve, reject) => {
      const result = new CipherResult()
      // result.certificate = await this.fetch(this.timeoutPerConnection)
    })
  }
}

Cipher.suites = [
  'NULL-MD5',
  'NULL-SHA',
  'EXP-RC4-MD5',
  'RC4-MD5',
  'RC4-SHA',
  'EXP-RC2-CBC-MD5',
  'IDEA-CBC-SHA',
  'EXP-DES-CBC-SHA',
  'DES-CBC-SHA',
  'DES-CBC3-SHA',
  'EXP-DHE-DSS-DES-CBC-SHA',
  'DHE-DSS-CBC-SHA',
  'DHE-DSS-DES-CBC3-SHA',
  'EXP-DHE-RSA-DES-CBC-SHA',
  'DHE-RSA-DES-CBC-SHA',
  'DHE-RSA-DES-CBC3-SHA',
  'EXP-ADH-RC4-MD5',
  'ADH-RC4-MD5',
  'EXP-ADH-DES-CBC-SHA',
  'ADH-DES-CBC-SHA',
  'ADH-DES-CBC3-SHA',
  'EXP1024-DES-CBC-SHA',
  'EXP1024-RC4-SHA',
  'EXP1024-DHE-DSS-DES-CBC-SHA',
  'EXP1024-DHE-DSS-RC4-SHA',
  'DHE-DSS-RC4-SHA'
]

module.exports.Cipher = Cipher
