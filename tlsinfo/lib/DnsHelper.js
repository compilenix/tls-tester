const dns = require('dns')

const punycode = require('../node_modules/punycode')

class HostAddressResult {
  constructor () {
    this.host = ''
    this.address = ''
    this.family = 0
  }
}

class DnsHelper {
  /**
   * @param {string} host
   * @returns {Promise<{ addresses: HostAddressResult[], warnings: string[] }>}
   */
  static async lookup (host) {
    return new Promise((resolve, reject) => {
      dns.lookup(punycode.toASCII(host), { all: true }, (error, addresses) => {
        const warnings = []
        if (error) return reject(error)
        if (addresses.length > 1) warnings.push(`${host} resolves to more than one ip address`)
        /** @type {HostAddressResult[]} */
        const addressResult = []
        for (const address of addresses) {
          const result = new HostAddressResult()
          result.host = host
          result.address = address.address
          result.family = address.family
          addressResult.push(result)
        }
        resolve({ addresses: addressResult, warnings })
      })
    })
  }
}

module.exports.HostAddressResult = HostAddressResult
module.exports.DnsHelper = DnsHelper
