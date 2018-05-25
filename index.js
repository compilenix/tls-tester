const sslinfo = require('sslinfo')
const fs = require('fs-extra')
const moment = require('moment')

// if (!fs.existsSync('./config.js')) {
fs.copySync('./config.example.js', './config.js')
// }

let config = require('./config.js')

/**
 * @param {ServerResult} result
 */
function checkServerResult(result) {
  const thresholdDate = moment(result.cert.notAfter).subtract(config.validUntilDays, 'days')
  // const thresholdDate = moment().subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = moment(result.cert.notAfter).diff(moment(), 'days')

  if (validUntilDaysVolaited) {
    console.log(`The certificate on ${result.host} is about to expire!!`)
    console.log(`It's valid until ${result.cert.notAfter} and therefore volates the threshold of ${config.validUntilDays} days by ${daysDifference} days`)
  }

  console.log(result)
}

async function run () {
  for (const domain of config.domains) {
    const port = domain.port || 443
    const host = domain.host || domain

    checkServerResult(await sslinfo.getServerResults({
      host: host,
      port: port
    }))
  }

  console.log('done')
}

(async () => {
  await run()
})()
