/// <reference path="typings/index.d.ts"/>

const sslinfo = require('sslinfo')
const fs = require('fs-extra')
const moment = require('moment')
const Slack = require('slack-node')

if (!fs.existsSync('./config.js')) {
  fs.copySync('./config.example.js', './config.js')
}

let config = require('./config.js')
let slack = new Slack()

function sleep (/** @type {Number} */ ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * @param {ServerResult} result
 */
function checkServerResult (result) {
  let shouldReport = false
  let message = ''
  const thresholdDate = moment(result.cert.notAfter).subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = Math.abs(moment(result.cert.notAfter).diff(moment(), 'days'))

  if (validUntilDaysVolaited) {
    shouldReport = true
    message += `The certificate on ${result.host} is valid until "${result.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays} days by ${daysDifference} days\n`
    console.log(`The certificate on ${result.host} is valid until "${result.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays} days by ${daysDifference} days`)
  }

  if (shouldReport) {
    let payload = {
      channel: config.slackChannel || undefined,
      username: config.slackUsername || undefined,
      attachments: [{
        footer: config.botName || undefined,
        footer_icon: config.botIcon || undefined,
        color: '#c4463d',
        mrkdwn_in: ['text', 'pretext']
      }]
    }

    if (payload.channel === undefined) delete payload.channel
    if (payload.username === undefined) delete payload.username
    if (payload.attachments[0].footer === undefined) delete payload.attachments[0].footer
    if (payload.attachments[0].footer_icon === undefined) delete payload.attachments[0].footer_icon

    payload.attachments[0].fallback = `${message}`
    payload.attachments[0].text = payload.attachments[0].fallback
    payload.attachments[0].ts = Date.now() / 1000

    slack.webhook(payload, (err, response) => {
      if (err) console.log(err, response)
    })
  }
}

async function run () {
  for (const domain of config.domains) {
    if (!domain.host) {
      console.warn(`host not defined for ${domain}`)
      continue
    }
    if (!domain.port) {
      console.warn(`port not defined for ${domain}`)
      continue
    }

    console.log(domain)

    checkServerResult(await sslinfo.getServerResults({
      host: domain.host,
      port: domain.port,
      // @ts-ignore
      servername: domain.host
    }))
    await sleep(1000)
  }

  console.log('done')
}

(async () => {
  slack.setWebhook(config.slackWebHookUri)
  await run()
})()
