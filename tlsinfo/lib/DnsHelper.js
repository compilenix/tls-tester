const dns = require('dns')

const punycode = require('../node_modules/punycode')

class HostAddressResult {
  constructor () {
    this.host = ''
    this.address = ''
    this.family = 0
  }

  toString () {
    return this.address
  }

  inspect () {
    return this.address
  }
}

class DnsHelper {
  /**
   * @param {string} host
   * @returns {Promise<HostAddressResult[]>}
   */
  static async lookup (host) {
    return new Promise((resolve, reject) => {
      dns.lookup(punycode.toASCII(host), { all: true }, (error, addresses) => {
        if (error) return reject(error)
        /** @type {HostAddressResult[]} */
        const addressResult = []
        for (const address of addresses) {
          const result = new HostAddressResult()
          result.host = host
          result.address = address.address
          result.family = address.family
          addressResult.push(result)
        }
        resolve(addressResult)
      })
    })
  }
}

module.exports.HostAddressResult = HostAddressResult
module.exports.DnsHelper = DnsHelper
