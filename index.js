/// <reference path="typings/index.d.ts"/>

const sslinfo = require('sslinfo')
const fs = require('fs-extra')
const moment = require('moment')
const Slack = require('slack-node')
const punycode = require('./node_modules/punycode')

if (!fs.existsSync('./config.js')) {
  fs.copySync('./config.example.js', './config.js')
}

let config = require('./config.js')
let slack = new Slack()
let messagesToSend = []

function uniqueArray (arr) {
  return Array.from(new Set(arr))
}

function sleep (/** @type {Number} */ ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function sendReport () {
  let payloads = []
  let attachments = []
  for (let index = 0; index < messagesToSend.length; index++) {
    const { message, ts } = messagesToSend[index]
    const attachment = {
      footer: config.botName || undefined,
      footer_icon: config.botIcon || undefined,
      color: '#c4463d'
    }
    if (attachment.footer === undefined) delete attachment.footer
    if (attachment.footer_icon === undefined) delete attachment.footer_icon

    attachment.fallback = `${message}`
    attachment.text = attachment.fallback
    attachment.ts = ts
    attachments.push(attachment)

    if (attachments.length > 18 || index === messagesToSend.length - 1) {
      let payload = {
        channel: config.slackChannel || undefined,
        username: config.slackUsername || undefined,
        attachments: attachments
      }
      attachments = []

      if (payload.channel === undefined) delete payload.channel
      if (payload.username === undefined) delete payload.username
      payloads.push(payload)
    }
  }

  for (let index = 0; index < payloads.length; index++) {
    const payload = payloads[index]
    slack.webhook(payload, (err, response) => {
      if (err) console.log(err, response)
    })
    await sleep(1000)
  }
}

/**
 * @param {string} message
 * @param {string} host
 * @param {number} port
 */
function addMessage (message, host, port) {
  messagesToSend.push({
    message: `${host}:${port} -> ${message}\n`,
    ts: Date.now() / 1000
  })
}

/**
 * @param {string[]} ciphers
 * @param {string} host
 * @param {number} port
 */
function checkWeakCipherUsage (ciphers, host, port) {
  if (ciphers.findIndex(x => x.indexOf('NULL') >= 0) >= 0) {
    addMessage(`Weak cipher usage of NULL`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('RC') >= 0) >= 0) {
    addMessage(`Weak cipher usage of RC2/4/5`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('IDEA') >= 0) >= 0) {
    addMessage(`Weak cipher usage of IDEA`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('DSS') >= 0) >= 0) {
    addMessage(`Weak cipher usage of DSS`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('ADH') >= 0) >= 0) {
    addMessage(`Weak cipher usage of ADH`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('CAMELLIA') >= 0) >= 0) {
    addMessage(`Weak cipher usage of CAMELLIA`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('SEED') >= 0) >= 0) {
    addMessage(`Weak cipher usage of SEED`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('AECDH') >= 0) >= 0) {
    addMessage(`Weak cipher usage of AECDH`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('MD5') >= 0) >= 0) {
    addMessage(`Weak cipher usage of MD5`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('SRP') >= 0) >= 0) {
    addMessage(`Weak cipher usage of SRP`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('DES') >= 0) >= 0) {
    addMessage(`Weak cipher usage of DES`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('3DES') >= 0) >= 0) {
    addMessage(`Weak cipher usage of 3DES`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('ARIA') >= 0) >= 0) {
    addMessage(`Weak cipher usage of ARIA`, host, port)
  }
  if (ciphers.findIndex(x => x.indexOf('PSK') >= 0) >= 0) {
    addMessage(`Weak cipher usage of PSK`, host, port)
  }
  if (ciphers.includes('AES128-SHA')) {
    addMessage(`Weak cipher usage of AES128-SHA`, host, port)
  }
  if (ciphers.includes('AES256-SHA')) {
    addMessage(`Weak cipher usage of AES256-SHA`, host, port)
  }
  if (ciphers.includes('AES128-SHA256')) {
    addMessage(`Weak cipher usage of AES128-SHA256`, host, port)
  }
  if (ciphers.includes('AES256-SHA256')) {
    addMessage(`Weak cipher usage of AES256-SHA256`, host, port)
  }
  if (ciphers.includes('AES256-GCM-SHA384')) {
    addMessage(`Weak cipher usage of AES256-GCM-SHA384`, host, port)
  }
  if (ciphers.includes('AES128-GCM-SHA256')) {
    addMessage(`Weak cipher usage of AES128-GCM-SHA256`, host, port)
  }
}

/**
 * @param {ServerResult} result
 */
function checkServerResult (result) {
  const asciiHostname = result.host
  result.host = punycode.toUnicode(result.host)
  const thresholdDate = moment(result.cert.notAfter).subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = Math.abs(moment(result.cert.notAfter).diff(moment(), 'days'))

  if (validUntilDaysVolaited) {
    addMessage(`Is valid until "${result.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays} days by ${daysDifference} days`, result.host, result.port)
  }

  if (moment(result.cert.notBefore) > moment()) {
    addMessage(`Is not yet valid; notBefore ${result.cert.notBefore}`, result.host, result.port)
  }

  if (!result.cert.altNames || result.cert.altNames.length === 0) {
    addMessage(`Does not have any altName`, result.host, result.port)
  }

  if (result.cert.altNames.indexOf(asciiHostname) === -1 && result.cert.altNames.indexOf('*') >= 0) {
    addMessage(`Does not match ${result.host}.\nWe got "${result.cert.altNames}"`, result.host, result.port)
  }

  if (result.cert.publicKey.bitSize < 4096) {
    addMessage(`Public key size of ${result.cert.publicKey.bitSize} is < 4096`, result.host, result.port)
  }

  if (result.cert.signatureAlgorithm.startsWith('sha1')) {
    addMessage(`Weak signature algorithm (sha1): ${result.cert.signatureAlgorithm}`, result.host, result.port)
  }

  if (result.ciphers.SSLv3_method) {
    addMessage(`Weak / Outdated protocol supported: SSLv3`, result.host, result.port)
  }

  if (result.ciphers.SSLv2_method) {
    addMessage(`Weak / Outdated protocol supported: SSLv2`, result.host, result.port)
  }

  let ciphers = []
  if (result.ciphers.TLSv1_method && result.ciphers.TLSv1_method.enabled.length > 0) {
    ciphers = ciphers.concat(result.ciphers.TLSv1_method.enabled)
  }
  if (result.ciphers.TLSv1_1_method && result.ciphers.TLSv1_1_method.enabled.length > 0) {
    ciphers = ciphers.concat(result.ciphers.TLSv1_1_method.enabled)
  }
  if (result.ciphers.TLSv1_2_method && result.ciphers.TLSv1_2_method.enabled.length > 0) {
    ciphers = ciphers.concat(result.ciphers.TLSv1_2_method.enabled)
  }
  ciphers = uniqueArray(ciphers)

  checkWeakCipherUsage(ciphers, result.host, result.port)
}

async function run () {
  for (const domain of config.domains) {
    if (!domain.host) {
      addMessage(`host not defined for ${domain}`, domain.host, domain.port)
      continue
    }
    if (!domain.port) {
      addMessage(`port not defined for ${domain}`, domain.host, domain.port)
      continue
    }

    console.log(`${domain.host}:${domain.port}`)
    domain.host = punycode.toASCII(domain.host)

    try {
      checkServerResult(await sslinfo.getServerResults({
        host: domain.host,
        port: domain.port,
        // @ts-ignore
        servername: domain.host
      }))
    } catch (e) {
      let error = e
      domain.host = punycode.toUnicode(domain.host)
      if (error.error && error.error.code) error = error.error
      switch (error.code) {
        case 'ECONNRESET':
          addMessage(`Connection reset`, domain.host, domain.port)
          break
        case 'ECONNREFUSED':
          addMessage(`Connection refused`, domain.host, domain.port)
          break
        case 'ETIMEDOUT':
          addMessage(`Connection timed-out`, domain.host, domain.port)
          break
        case 'ENOTFOUND':
          addMessage(`Host cann't be resolved`, domain.host, domain.port)
          break
        default:
          addMessage(`\n\`\`\`${JSON.stringify(error, null, 4)}\`\`\``, domain.host, domain.port)
          break
      }
    }

    await sleep(100)
  }
}

(async () => {
  slack.setWebhook(config.slackWebHookUri)
  await run()
  await sendReport()
  console.log('done')
})()
