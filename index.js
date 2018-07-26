'use-strict'

const http = require('http')
const https = require('https')
const url = require('url')
const { URL: Url } = url
const os = require('os')
const { execSync } = require('child_process')

const fs = require('fs-extra')
const moment = require('moment')
const Slack = require('slack-node')
const punycode = require('./node_modules/punycode')
const argv = require('minimist')(process.argv.slice(2))
const uuidv4 = require('uuid/v4')

const { TlsServiceAuditResult, HostAddressSpecificCertificateResult, Certificate } = require('tlsinfo')
const Config = require('./Config.js')

if (!fs.existsSync('./Config.js')) {
  fs.copySync('./Config.example.js', './Config.js')
}

let config = Config.Config
let slack = new Slack()
let messagesToSend = []
/** @type {Config.TaskResult} */
let taskResult = null
let isFirstMessageOfItem = true
let isFirstOveralMessage = true
let taskRunning = false
/** @type {Config.Task[]} */
let tasks = []
/** @type {Config.Task[]} */
let tasksToEnqueue = []
const contentTypeJson = 'application/json; charset=utf8'

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
        port: config.defaultPort || 443,
        callback: '',
        webhook: '',
        id: '',
        ignore: []
      })
    }
  }
}

/**
 * @param {string} warning
 */
function isReportingViaConfigEnabled (warning) {
  const containsReportingPredicate = /** @param {string} x */ x => x === warning
  const isIgnoredOnAllDomains = config.ignore.some(containsReportingPredicate)
  return !isIgnoredOnAllDomains
}

/**
 * @param {string} uri
 */
async function sendReportWebook (uri) {
  if (!uri) return
  slack.setWebhook(uri)

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
 * @param {Config.Task} task
 */
async function sendReportCallback (task) {
  const callback = new Url(task.callback)
  let requestOptions = {
    timeout: (config.connectionTimeoutSeconds || 60) * 1000,
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

    req.setTimeout((config.connectionTimeoutSeconds || 60) * 1000)
    setTimeout(() => {
      req.emit('close')
    }, (config.connectionTimeoutSeconds || 60) * 1000 + 100)
    const resultText = JSON.stringify(taskResult, null, 4)
    req.setHeader('content-type', contentTypeJson)
    req.end(`${resultText}\n`, 'utf8')
    req.on('close', () => {
      resolve()
    })
    req.on('error', (e) => {
      resolve()
    })
  })
}

/**
 * @param {Config.Task} task
 */
async function sendReport (task) {
  if (task && task.callback) await sendReportCallback(task)
  if ((config.enableSlack && config.slackWebHookUri) || task.webhook) await sendReportWebook(task && task.webhook ? task.webhook : config.slackWebHookUri)
}

/**
 * @param {string} message
 * @param {string} host
 * @param {number} port
 * @param {Config.Task} task
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
        items: [message],
        error: ''
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
 * @param {string} host
 * @param {number} port
 * @param {Config.Task} task
 */
function checkWeakCipherUsage (ciphers, host, port, task) {
  if (ciphers.findIndex(x => x.indexOf('NULL') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherNULL')) {
    addMessage(`Weak cipher usage of NULL`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('RC') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherRC')) {
    addMessage(`Weak cipher usage of RC2/4/5`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('IDEA') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherIDEA')) {
    addMessage(`Weak cipher usage of IDEA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('DSS') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherDSS')) {
    addMessage(`Weak cipher usage of DSS`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('ADH') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherADH')) {
    addMessage(`Weak cipher usage of ADH`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('CAMELLIA') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherCAMELLIA')) {
    addMessage(`Weak cipher usage of CAMELLIA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('SEED') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherSEED')) {
    addMessage(`Weak cipher usage of SEED`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('AECDH') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherAECDH')) {
    addMessage(`Weak cipher usage of AECDH`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('MD5') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherMD5')) {
    addMessage(`Weak cipher usage of MD5`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('SRP') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherSRP')) {
    addMessage(`Weak cipher usage of SRP`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('DES') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherDES')) {
    addMessage(`Weak cipher usage of DES`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('3DES') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherDES')) {
    addMessage(`Weak cipher usage of 3DES`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('ARIA') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherARIA')) {
    addMessage(`Weak cipher usage of ARIA`, host, port, task)
  }
  if (ciphers.findIndex(x => x.indexOf('PSK') >= 0) >= 0 && isReportingViaConfigEnabled('HasCipherPSK')) {
    addMessage(`Weak cipher usage of PSK`, host, port, task)
  }
  if (ciphers.includes('AES128-SHA') && isReportingViaConfigEnabled('AES128-SHA')) {
    addMessage(`Weak cipher usage of AES128-SHA`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-SHA') && isReportingViaConfigEnabled('AES256-SHA')) {
    addMessage(`Weak cipher usage of AES256-SHA`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES128-SHA256') && isReportingViaConfigEnabled('AES128-SHA256')) {
    addMessage(`Weak cipher usage of AES128-SHA256`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-SHA256') && isReportingViaConfigEnabled('AES256-SHA256')) {
    addMessage(`Weak cipher usage of AES256-SHA256`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES256-GCM-SHA384') && isReportingViaConfigEnabled('AES256-GCM-SHA384')) {
    addMessage(`Weak cipher usage of AES256-GCM-SHA384`, host, port, task, 'warn')
  }
  if (ciphers.includes('AES128-GCM-SHA256') && isReportingViaConfigEnabled('AES128-GCM-SHA256')) {
    addMessage(`Weak cipher usage of AES128-GCM-SHA256`, host, port, task, 'warn')
  }
}

/**
 * @param {HostAddressSpecificCertificateResult} hostSpecificCert
 * @param {Config.Task} hostSpecificCert
 */
function validateCertificateResult (hostSpecificCert, task) {
  const cert = hostSpecificCert.certificateResult
  const servername = cert.servername
  const asciiHostname = punycode.toASCII(servername)
  const chain = cert.chain
  const thresholdDate = moment(chain.cert.notAfter).subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = Math.abs(moment(chain.cert.notAfter).diff(moment(), 'days'))

  if (validUntilDaysVolaited && isReportingViaConfigEnabled('Expire')) {
    addMessage(`Is valid until "${chain.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays}. days difference to expiration date: ${daysDifference} days`, servername, cert.port, task)
  }

  if (moment(chain.cert.notBefore) > moment() && isReportingViaConfigEnabled('NotYetValid')) {
    addMessage(`Is not yet valid; notBefore ${chain.cert.notBefore}`, servername, cert.port, task)
  }

  if ((!chain.cert.altNames || chain.cert.altNames.length === 0) && isReportingViaConfigEnabled('NoAltName')) {
    addMessage(`Does not have any altName`, servername, cert.port, task)
  }

  if (chain.cert.altNames.indexOf(asciiHostname) === -1) {
    const message = `Does not match ${servername}. We got "${chain.cert.altNames}"`
    if ((!chain.cert.altNames.some(x => x.indexOf('*') >= 0)) && isReportingViaConfigEnabled('CommonNameInvalid')) {
      addMessage(message, servername, cert.port, task)
    } else {
      let matchesAnyWildcard = false
      if (chain.cert.altNames.some(x => x.indexOf('*') >= 0)) {
        for (let index = 0; index < chain.cert.altNames.length; index++) {
          const element = chain.cert.altNames[index]
          if (matchesWildcardExpression(asciiHostname, element)) matchesAnyWildcard = true
        }
      }

      if (!matchesAnyWildcard && isReportingViaConfigEnabled('CommonNameInvalid')) addMessage(message, servername, cert.port, task)
    }
  }

  if (chain.cert.publicKey.bitSize < 4096 && isReportingViaConfigEnabled('PubKeySize')) {
    addMessage(`Public key size of ${chain.cert.publicKey.bitSize} is < 4096`, servername, cert.port, task, 'warn')
  }

  if (chain.cert.signatureAlgorithm.startsWith('md') && isReportingViaConfigEnabled('HasSomeMessageDigestAlgorithm')) {
    addMessage(`Weak signature algorithm (md): ${chain.cert.signatureAlgorithm}`, servername, cert.port, task)
  }

  if (chain.cert.signatureAlgorithm.startsWith('sha1') && isReportingViaConfigEnabled('SHA1')) {
    addMessage(`Weak signature algorithm (sha1): ${chain.cert.signatureAlgorithm}`, servername, cert.port, task)
  }

  if (chain.issuer) {
    if (chain.issuer.cert.signatureAlgorithm.startsWith('md') && isReportingViaConfigEnabled('HasSomeMessageDigestAlgorithmOnCA')) {
      addMessage(`Weak signature algorithm of CA (md): ${chain.issuer.cert.signatureAlgorithm} ${chain.issuer.cert.subject.commonName}`, servername, cert.port, task)
    }

    if (chain.issuer.cert.signatureAlgorithm.startsWith('sha1') && isReportingViaConfigEnabled('SHA1OnCA')) {
      addMessage(`Weak signature algorithm of CA (sha1): ${chain.issuer.cert.signatureAlgorithm} ${chain.issuer.cert.subject.commonName}`, servername, cert.port, task)
    }

    if (chain.issuer.cert.publicKey.bitSize < 2048 && isReportingViaConfigEnabled('PubKeySizeOnCA')) {
      addMessage(`Public key size of ${chain.cert.publicKey.bitSize} is < 2048 from CA ${chain.issuer.cert.subject.commonName}`, servername, cert.port, task)
    }
  }
}

/**
 * @param {TlsServiceAuditResult} result
 * @param {Config.Task} task
 */
function validateTlsServiceAuditResult (result, task) {
  for (const cert of result.certificates) {
    validateCertificateResult(cert, task)
  }

  if (chain.cert.ciphers.SSLv3_method && isReportingViaConfigEnabled('SSLv3')) {
    addMessage(`Weak / Outdated protocol supported: SSLv3`, servername, cert.port, task)
  }

  if (chain.cert.ciphers.SSLv2_method && isReportingViaConfigEnabled('SSLv2')) {
    addMessage(`Weak / Outdated protocol supported: SSLv2`, servername, cert.port, task)
  }

  if (!chain.cert.ciphers.TLSv1_2_method && isReportingViaConfigEnabled('NoTLSv1.2')) {
    addMessage(`Modern protocol NOT supported: TLS 1.2`, servername, cert.port, task)
  }

  if (!chain.cert.extensions.cTPrecertificateSCTs && isReportingViaConfigEnabled('NoCertificateTransparency')) {
    addMessage(`No Certificate Transparency`, servername, cert.port, task, 'warn')
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

  checkWeakCipherUsage(ciphers, result.host, result.port, task)
}

/**
 * @param {Config.Task} task
 */
async function processDomain (task) {
  if (!task.host) {
    addMessage(`host not defined for ${Config.task}`, task.host, task.port, task)
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
      const result = await tlsinfo.getServerResults({
        host: task.host,
        servername: task.host,
        port: task.port,
        minDHSize: 1,
        timeOutMs: (config.connectionTimeoutSeconds || 60) * 1000
      })
      result.ignoreReports = task.ignore || []
      validateTlsServiceAuditResult(result, task)
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
 * @param {string} url
 * @param {http.IncomingMessage} request
 * @returns {boolean}
 */
function validateCallback (url = '', request) {
  if (!url) return false
  if (!(request instanceof http.IncomingMessage) || !request.socket.remoteAddress) return false
  if (url.trim().length < 10) return false
  if (config.httpsCallbacksOnly && !url.startsWith('https://')) {
    if (!url.startsWith('http://')) return false
    if (config.httpCallbacksAllowedFrom.includes(request.socket.remoteAddress)) return true // Is OK
    for (const allowedTo of config.httpCallbacksAllowedTo) {
      if (typeof allowedTo === 'string' && url.indexOf(allowedTo) >= 0) return true // Is OK
      if (allowedTo instanceof RegExp && allowedTo.test(url)) return true // Is OK
    }
    return false
  }
  if (!url.startsWith('https://')) return false
  return true // Is OK
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
        response.setHeader('content-type', contentTypeJson)
        response.end(`${message}\n`, 'utf8')
        return resolve()
      }

      let isImplemented = request.headers['content-type'] && request.headers['content-type'].toLocaleLowerCase().indexOf('json') >= 0

      if (!isImplemented) {
        const message = JSON.stringify({ message: 'any other content-type than json is not implemented' })
        response.statusCode = 501
        response.setHeader('content-type', contentTypeJson)
        response.end(`${message}\n`, 'utf8')
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
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          hasError = true
        }
      })

      request.on('end', async () => {
        if (hasError) return resolve()

        /** @type {Config.Task} */
        let task
        try {
          task = JSON.parse(body)
        } catch (error) {
          const message = JSON.stringify({ message: 'payload could not be parsed into a valid object from json string' })
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          return resolve()
        }

        if (!task.host || typeof task.host !== 'string' || task.host.trim().length < 3) {
          const message = JSON.stringify({ message: '"host" must be defined and a string of minimal 3 chars' })
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          return resolve()
        }

        if ((!task.callback || typeof task.callback !== 'string' || task.callback.trim().length < 10) &&
              (!task.webhook || typeof task.webhook !== 'string' || task.webhook.trim().length < 10)) {
          const message = JSON.stringify({ message: 'both, "callback" and "webhook" are not defined. so this would be not returning the result to anyone.' })
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          return resolve()
        }

        if (validateCallback(task.callback, request) && validateCallback(task.webhook, request)) {
          const message = JSON.stringify({ message: '"callback" or "webhook" are not HTTPS. This is administratively prohibited.' })
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          return resolve()
        }

        task.id = uuidv4()
        const message = JSON.stringify({ message: 'OK', id: task.id })
        response.statusCode = 200
        response.setHeader('content-type', contentTypeJson)
        response.end(`${message}\n`, 'utf8')
        tasks.push(task)
        const clientAddress = request.headers['x-forwarded-for'] ? request.headers['x-forwarded-for'] : request.connection.remoteAddress
        const logCallbackUrl = task.callback ? ` with callback ${task.callback}` : ''
        const logWebookUrl = task.webhook ? ` with webook ${task.webhook}` : ''
        if (config.enableConsoleLog) console.log(`got new task for: ${task.host} from ${clientAddress}${logCallbackUrl}${logWebookUrl}`)
        return resolve()
      })
    } else {
      const message = JSON.stringify({ message: 'not found' })
      response.statusCode = 404
      response.setHeader('content-type', contentTypeJson)
      response.end(`${message}\n`, 'utf8')
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
    if (config.startHttpServer || config.enableConsoleLog) console.log(`running task for ${Config.task.host}`)
    messagesToSend = []
    taskResult = null
    await processDomain(task)
    await sendReport(task)
    messagesToSend = []
    taskResult = null
    if (config.enableConsoleLog) console.log(`number of tasks remaining: ${Config.tasks.length}`)
    taskRunning = false
  }, 100)

  if (config.startHttpServer) {
    http.createServer(handleApiRequest).listen(config.httpServerPort)
    let fqdn = ''
    if (os.platform() === 'linux') fqdn = execSync('hostname -f').toLocaleString().trim()
    fqdn = fqdn.length > 0 ? fqdn : os.hostname()
    console.log(`http server started: http://${fqdn}:${config.httpServerPort}/`)
    if (config.enableConsoleLog) console.log(`# curl -v -H 'content-type: ${contentTypeJson}' --data '{"host":"mozilla-old.badssl.com","callback":"https://your-server.local/tls-tester-result"}' http://${fqdn}:${config.httpServerPort}/api/enqueue`)
  } else if (config.enableConsoleLog || (config.enableSlack && config.slackWebHookUri)) {
    for (const task of config.domains) {
      if (config.enableSlack && config.slackWebHookUri && !task.webhook) task.webhook = config.slackWebHookUri
      tasksToEnqueue.push(task)
    }

    while (tasks.length > 0 || tasksToEnqueue.length > 0) {
      await sleep(10)
    }
    process.exit(0)
  }
})()
