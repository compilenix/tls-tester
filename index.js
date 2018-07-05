/// <reference path="typings/index.d.ts"/>

const http = require('http')
const https = require('https')
const url = require('url')
const { URL: Url } = url
const os = require('os')

const sslinfo = require('sslinfo')
const fs = require('fs-extra')
const moment = require('moment')
const Slack = require('slack-node')
const punycode = require('./node_modules/punycode')
const argv = require('minimist')(process.argv.slice(2))
const uuidv4 = require('uuid/v4')

if (!fs.existsSync('./config.js')) {
  fs.copySync('./config.example.js', './config.js')
}

let config = require('./config.js')
let slack = new Slack()
let messagesToSend = []
/** @type {TaskResult} */
let taskResult = null
let isFirstMessageOfItem = true
let isFirstOveralMessage = true
let taskRunning = false
/** @type {Task[]} */
let tasks = []
/** @type {Task[]} */
let tasksToEnqueue = []

function uniqueArray (arr) {
  return Array.from(new Set(arr))
}

function sleep (/** @type {Number} */ ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * @param {string} value
 * @param {string} pattern
 * @returns {boolean}
 */
function matchesWildcardExpression (value, pattern) {
  const transformRegex = pattern.replace(/\*/g, '([^*]+)')
  const expression = new RegExp(transformRegex, 'g')
  const doesMatch = expression.test(value)
  return doesMatch
}

function overrideOptionsFromCommandLineArguments () {
  if (process.argv.length < 3) return
  let domainList = ''
  let ignoreList = ''

  for (var propertyName in argv) {
    if (config[propertyName] === undefined) continue
    const propertyValue = argv[propertyName]

    if (config[propertyName] === true || config[propertyName] === false) {
      if (config[propertyName] === 'true') config[propertyName] = true
      if (config[propertyName] === 'false') config[propertyName] = false
    } else {
      config[propertyName] = propertyValue
    }

    if (propertyName === 'domains') {
      domainList = propertyValue
    }
    if (propertyName === 'ignore') {
      ignoreList = propertyValue
    }
  }

  if (ignoreList !== '') {
    const ignore = ignoreList.split(',')
    config.ignore = ignore
  }

  if (domainList !== '') {
    config.domains = []
    const domains = domainList.split(`,`)
    for (let index = 0; index < domains.length; index++) {
      const host = domains[index]
      config.domains.push({
        host: host,
        port: config.defaultPort || 443
      })
    }
  }
}

/**
 * @param {string} warning
 * @param {ServerResult} result
 */
function isReportingEnabled (warning, result = undefined) {
  const containsReportingPredicate = /** @param {string} x */ x => x === warning
  const isIgnoredOnAllDomains = config.ignore.some(containsReportingPredicate)
  const isIgnoredOnThisHost = (result !== undefined && result.ignoreReports.some(containsReportingPredicate))
  return !isIgnoredOnAllDomains && !isIgnoredOnThisHost
}

/**
 * @param {string} uri
 */
async function sendReportWebook (uri) {
  if (uri) {
    slack.setWebhook(uri)
  }

  let payloads = []
  let attachments = []
  for (let index = 0; index < messagesToSend.length; index++) {
    const { message, ts, color } = messagesToSend[index]
    const attachment = {
      footer: config.botName || undefined,
      footer_icon: config.botIcon || undefined,
      color: color
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

  slack.setWebhook(config.slackWebHookUri)
}

/**
 * @param {Task} task
 */
async function sendReportCallback (task) {
  const callback = new Url(task.callback)
  let requestOptions = {
    timeout: 2500,
    protocol: callback.protocol,
    href: callback.href,
    method: 'POST',
    host: callback.host,
    port: callback.port,
    hostname: callback.hostname,
    pathname: callback.pathname,
    path: `${callback.pathname}${callback.search}`,
    search: callback.search,
    hash: callback.hash
  }

  /** @type {http.ClientRequest} */
  let req
  return new Promise((resolve, reject) => {
    switch (callback.protocol.toLowerCase()) {
      case 'http:':
        req = http.request(requestOptions, res => {
          // ignore
        })
        break
      case 'https:':
        req = https.request(requestOptions, res => {
          // ignore
        })
        break
      default:
        break
    }

    req.setTimeout(2500)
    setTimeout(() => {
      req.emit('close')
    }, 2550)
    const resultText = JSON.stringify(taskResult, null, 4)
    req.setHeader('content-type', 'application/json; charset=utf8')
    req.end(resultText, 'utf8')
    req.on('close', () => {
      resolve()
    })
    req.on('error', (e) => {
      resolve()
    })
  })
}

/**
 * @param {Task} task
 */
async function sendReport (task) {
  if (task && task.callback) await sendReportCallback(task)
  if ((config.enableSlack && config.slackWebHookUri) || task.webhook) await sendReportWebook(task && task.webhook ? task.webhook : null)
}

/**
 * @param {string} message
 * @param {string} host
 * @param {number} port
 * @param {Task} task
 * @param {string} level
 */
function addMessage (message, host, port, task, level = 'error') {
  if (config.enableConsoleLog) {
    if (isFirstMessageOfItem) {
      let newLine = '\n'
      if (isFirstOveralMessage) newLine = ''
      console.log(`${newLine}${host}:${port}`)
    }

    console.log(`[${new Date().toUTCString()}] ${host}:${port} -> ${message}`)
    isFirstMessageOfItem = false
  }

  if (task && task.callback) {
    if (taskResult === null) {
      taskResult = {
        host: host,
        port: port,
        id: task.id,
        items: [message]
      }
    } else {
      taskResult.items.push(message)
    }
  }

  if (!config.enableSlack && !task.webhook) {
    return
  }

  let color = '#d50200' // error
  switch (level) {
    case 'warn':
      color = '#de9e31'
      break
  }
  messagesToSend.push({
    message: `${host}:${port} -> ${message}\n`,
    ts: Date.now() / 1000,
    color: color
  })
}

/**
 * @param {string[]} ciphers
 * @param {ServerResult} result
 * @param {string} host
 * @param {number} port
 * @param {Task} task
 */
function checkWeakCipherUsage (ciphers, result, host, port, task) {
  if (ciphers.findIndex(x => x.indexOf('NULL') >= 0) >= 0 && isReportingEnabled('HasCipherNULL', result)) {
    addMessage(`Weak cipher usage of NULL`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('RC') >= 0) >= 0 && isReportingEnabled('HasCipherRC', result)) {
    addMessage(`Weak cipher usage of RC2/4/5`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('IDEA') >= 0) >= 0 && isReportingEnabled('HasCipherIDEA', result)) {
    addMessage(`Weak cipher usage of IDEA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('DSS') >= 0) >= 0 && isReportingEnabled('HasCipherDSS', result)) {
    addMessage(`Weak cipher usage of DSS`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('ADH') >= 0) >= 0 && isReportingEnabled('HasCipherADH', result)) {
    addMessage(`Weak cipher usage of ADH`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('CAMELLIA') >= 0) >= 0 && isReportingEnabled('HasCipherCAMELLIA', result)) {
    addMessage(`Weak cipher usage of CAMELLIA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('SEED') >= 0) >= 0 && isReportingEnabled('HasCipherSEED', result)) {
    addMessage(`Weak cipher usage of SEED`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('AECDH') >= 0) >= 0 && isReportingEnabled('HasCipherAECDH', result)) {
    addMessage(`Weak cipher usage of AECDH`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('MD5') >= 0) >= 0 && isReportingEnabled('HasCipherMD5', result)) {
    addMessage(`Weak cipher usage of MD5`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('SRP') >= 0) >= 0 && isReportingEnabled('HasCipherSRP', result)) {
    addMessage(`Weak cipher usage of SRP`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('DES') >= 0) >= 0 && isReportingEnabled('HasCipherDES', result)) {
    addMessage(`Weak cipher usage of DES`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('3DES') >= 0) >= 0 && isReportingEnabled('HasCipherDES', result)) {
    addMessage(`Weak cipher usage of 3DES`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('ARIA') >= 0) >= 0 && isReportingEnabled('HasCipherARIA', result)) {
    addMessage(`Weak cipher usage of ARIA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('PSK') >= 0) >= 0 && isReportingEnabled('HasCipherPSK', result)) {
    addMessage(`Weak cipher usage of PSK`, host, port, task)
  }
  if (ciphers.includes('AES128-SHA') && isReportingEnabled('AES128-SHA', result)) {
    addMessage(`Weak cipher usage of AES128-SHA`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-SHA') && isReportingEnabled('AES256-SHA', result)) {
    addMessage(`Weak cipher usage of AES256-SHA`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES128-SHA256') && isReportingEnabled('AES128-SHA256', result)) {
    addMessage(`Weak cipher usage of AES128-SHA256`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-SHA256') && isReportingEnabled('AES256-SHA256', result)) {
    addMessage(`Weak cipher usage of AES256-SHA256`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-GCM-SHA384') && isReportingEnabled('AES256-GCM-SHA384', result)) {
    addMessage(`Weak cipher usage of AES256-GCM-SHA384`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES128-GCM-SHA256') && isReportingEnabled('AES128-GCM-SHA256', result)) {
    addMessage(`Weak cipher usage of AES128-GCM-SHA256`, host, port, task, 'warn')
  }
}

/**
 * @param {ServerResult} result
 * @param {Task} task
 */
function checkServerResult (result, task) {
  const asciiHostname = result.host
  result.host = punycode.toUnicode(result.host)
  const thresholdDate = moment(result.cert.notAfter).subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = Math.abs(moment(result.cert.notAfter).diff(moment(), 'days'))

  if (validUntilDaysVolaited && isReportingEnabled('Expire', result)) {
    addMessage(`Is valid until "${result.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays}. days difference to expiration date: ${daysDifference} days`, result.host, result.port, task)
  }

  if (moment(result.cert.notBefore) > moment() && isReportingEnabled('NotYetValid', result)) {
    addMessage(`Is not yet valid; notBefore ${result.cert.notBefore}`, result.host, result.port, task)
  }

  if ((!result.cert.altNames || result.cert.altNames.length === 0) && isReportingEnabled('NoAltName', result)) {
    addMessage(`Does not have any altName`, result.host, result.port, task)
  }

  if (result.cert.altNames.indexOf(asciiHostname) === -1) {
    const message = `Does not match ${result.host}. We got "${result.cert.altNames}"`
    if ((!result.cert.altNames.some(x => x.indexOf('*') >= 0)) && isReportingEnabled('CommonNameInvalid', result)) {
      addMessage(message, result.host, result.port, task)
    } else {
      let matchesAnyWildcard = false
      if (result.cert.altNames.some(x => x.indexOf('*') >= 0)) {
        for (let index = 0; index < result.cert.altNames.length; index++) {
          const element = result.cert.altNames[index]
          if (matchesWildcardExpression(asciiHostname, element)) matchesAnyWildcard = true
        }
      }

      if (!matchesAnyWildcard && isReportingEnabled('CommonNameInvalid', result)) addMessage(message, result.host, result.port, task)
    }
  }

  if (result.cert.publicKey.bitSize < 4096 && isReportingEnabled('PubKeySize', result)) {
    addMessage(`Public key size of ${result.cert.publicKey.bitSize} is < 4096`, result.host, result.port, task, 'warn')
  }

  if (result.cert.signatureAlgorithm.startsWith('md') && isReportingEnabled('HasSomeMessageDigestAlgorithm', result)) {
    addMessage(`Weak signature algorithm (md): ${result.cert.signatureAlgorithm}`, result.host, result.port, task)
  }

  if (result.cert.signatureAlgorithm.startsWith('sha1') && isReportingEnabled('SHA1', result)) {
    addMessage(`Weak signature algorithm (sha1): ${result.cert.signatureAlgorithm}`, result.host, result.port, task)
  }

  if (result.ciphers.SSLv3_method && isReportingEnabled('SSLv3', result)) {
    addMessage(`Weak / Outdated protocol supported: SSLv3`, result.host, result.port, task)
  }

  if (result.ciphers.SSLv2_method && isReportingEnabled('SSLv2', result)) {
    addMessage(`Weak / Outdated protocol supported: SSLv2`, result.host, result.port, task)
  }

  if (!result.ciphers.TLSv1_2_method && isReportingEnabled('NoTLSv1.2', result)) {
    addMessage(`Modern protocol NOT supported: TLS 1.2`, result.host, result.port, task)
  }

  if (!result.cert.extensions.cTPrecertificateSCTs && isReportingEnabled('NoCertificateTransparency', result)) {
    addMessage(`No Certificate Transparency`, result.host, result.port, task, 'warn')
  }

  if (result.certCa) {
    if (result.certCa.signatureAlgorithm.startsWith('md') && isReportingEnabled('HasSomeMessageDigestAlgorithmOnCA', result)) {
      addMessage(`Weak signature algorithm of CA (md): ${result.certCa.signatureAlgorithm} ${result.certCa.subject.commonName}`, result.host, result.port, task)
    }

    if (result.certCa.signatureAlgorithm.startsWith('sha1') && isReportingEnabled('SHA1OnCA', result)) {
      addMessage(`Weak signature algorithm of CA (sha1): ${result.certCa.signatureAlgorithm} ${result.certCa.subject.commonName}`, result.host, result.port, task)
    }

    if (result.certCa.publicKey.bitSize < 2048 && isReportingEnabled('PubKeySizeOnCA', result)) {
      addMessage(`Public key size of ${result.cert.publicKey.bitSize} is < 2048 from CA ${result.certCa.subject.commonName}`, result.host, result.port, task)
    }
  }

  /** @type {string[]} */
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
  for (let index = 0; index < ciphers.length; index++) {
    ciphers[index] = ciphers[index].toUpperCase()
  }

  checkWeakCipherUsage(ciphers, result, result.host, result.port, task)
}

/**
 * @param {Task} task
 */
async function processDomain (task) {
  if (!task.host) {
    addMessage(`host not defined for ${task}`, task.host, task.port, task)
    return
  }
  if (!task.port) {
    task.port = config.defaultPort || 443
  }

  isFirstMessageOfItem = true
  task.host = punycode.toASCII(task.host)

  return new Promise(async (resolve, reject) => {
    let timeout = setTimeout(() => {
      addMessage(`Connection timed-out`, task.host, task.port, task)
      resolve()
    }, (config.connectionTimeoutSeconds || 60) * 1000)

    try {
      const result = await sslinfo.getServerResults({
        host: task.host,
        servername: task.host,
        port: task.port,
        minDHSize: 1
      })
      result.ignoreReports = task.ignore || []
      checkServerResult(result, task)
    } catch (e) {
      let error = e
      task.host = punycode.toUnicode(task.host)
      if (error.error && error.error.code) error = error.error
      switch (error.code) {
        case 'ECONNRESET':
          addMessage(`Connection reset`, task.host, task.port, task)
          break
        case 'ECONNREFUSED':
          addMessage(`Connection refused (ip: ${error.address || error.message || undefined})`, task.host, task.port, task)
          break
        case 'ETIMEDOUT':
          addMessage(`Connection timed-out`, task.host, task.port, task)
          break
        case 'ENOTFOUND':
          addMessage(`Host can't be resolved / found -> ENOTFOUND`, task.host, task.port, task)
          break
        case 'EAI_AGAIN':
          addMessage(`Host can't be resolved -> EAI_AGAIN`, task.host, task.port, task)
          break
        default:
          addMessage(`\n\`\`\`${JSON.stringify(error, null, 4)}\`\`\``, task.host, task.port, task)
          break
      }
    }

    isFirstOveralMessage = false
    clearTimeout(timeout)
    resolve()
  })
}

/**
 * @param {http.IncomingMessage} request
 * @param {http.ServerResponse} response
 */
async function handleApiRequest (request, response) {
  return new Promise(async (resolve, reject) => {
    let { path } = url.parse(request.url)
    path = path.toLocaleLowerCase()

    if (path === '/api/enqueue') {
      if (request.method !== 'POST') {
        const message = JSON.stringify({ message: 'Method not allowed' })
        response.statusCode = 405
        response.setHeader('content-type', 'application/json; charset=utf8')
        response.end(message, 'utf8')
        return resolve()
      }

      let isImplemented = request.headers['content-type'] && request.headers['content-type'].toLocaleLowerCase().indexOf('json') >= 0

      if (!isImplemented) {
        const message = JSON.stringify({ message: 'any other content-type than json is not implemented' })
        response.statusCode = 501
        response.setHeader('content-type', 'application/json; charset=utf8')
        response.end(message, 'utf8')
        return resolve()
      }

      request.setEncoding('utf8')
      let hasError = false
      let body = ''
      request.on('data', postData => {
        // reading http POST body
        if (body.length + postData.length < 10e6) { // ~10 Megabytes
          body += postData
        } else {
          const message = JSON.stringify({ message: 'Payload lager than 10e6 (~ 10MB)' })
          response.statusCode = 413
          response.setHeader('content-type', 'application/json; charset=utf8')
          response.end(message, 'utf8')
          hasError = true
        }
      })

      request.on('end', async () => {
        if (hasError) return resolve()

        /** @type {Task} */
        let task
        try {
          task = JSON.parse(body)
        } catch (error) {
          const message = JSON.stringify({ message: 'payload could not be parsed into a valid object from json string' })
          response.statusCode = 400
          response.setHeader('content-type', 'application/json; charset=utf8')
          response.end(message, 'utf8')
          return resolve()
        }

        if (!task.host || typeof task.host !== 'string' || task.host.trim().length < 3) {
          const message = JSON.stringify({ message: '"host" must be defined and a string of minimal 3 chars' })
          response.statusCode = 400
          response.setHeader('content-type', 'application/json; charset=utf8')
          response.end(message, 'utf8')
          return resolve()
        }

        if ((!task.callback || typeof task.callback !== 'string' || task.callback.trim().length < 10) &&
          (!task.webhook || typeof task.webhook !== 'string' || task.webhook.trim().length < 10)) {
          const message = JSON.stringify({ message: 'both, "callback" and "webhook" are not defined. so this would be not returning the result to anyone.' })
          response.statusCode = 400
          response.setHeader('content-type', 'application/json; charset=utf8')
          response.end(message, 'utf8')
          return resolve()
        }

        task.id = uuidv4()
        const message = JSON.stringify({ message: 'OK', id: task.id })
        response.statusCode = 200
        response.setHeader('content-type', 'application/json; charset=utf8')
        response.end(message, 'utf8')
        tasks.push(task)
        console.log('got new task')
        console.dir(task)
        return resolve()
      })
    } else {
      const message = JSON.stringify({ message: 'not found' })
      response.statusCode = 404
      response.setHeader('content-type', 'application/json; charset=utf8')
      response.end(message, 'utf8')
    }
  })
}

(async () => {
  slack.setWebhook(config.slackWebHookUri)
  overrideOptionsFromCommandLineArguments()

  setInterval(async () => {
    if (taskRunning) return
    taskRunning = true
    const task = tasks.shift()
    for (const t of tasksToEnqueue) {
      tasks.push(t)
    }
    tasksToEnqueue = []
    if (!task) { taskRunning = false; return }
    console.log('running task:')
    console.dir(task)
    messagesToSend = []
    taskResult = null
    await processDomain(task)
    await sendReport(task)
    messagesToSend = []
    taskResult = null
    console.log(`${tasks.length} number of tasks remaining`)
    taskRunning = false
  }, 100)

  if (config.startHttpServer) {
    http.createServer(handleApiRequest).listen(config.httpServerPort)
    console.log(`http server started: http://${os.hostname()}:${config.httpServerPort}/`)
    console.log(`# curl -v -H 'content-type: text/json; charset=utf8' --data '{"host":"mozilla-old.badssl.com","callback":"https://your-server.local/tls-tester-result"}' http://${os.hostname()}:${config.httpServerPort}/api/enqueue`)
  } else {
    while (tasks.length > 0 || taskRunning) {
      await sleep(200)
    }
    process.exit(0)
  }
})()
