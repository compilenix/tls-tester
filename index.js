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

const {
  TlsServiceAudit,
  TlsServiceAuditResult, // eslint-disable-line
  HostAddressSpecificCertificateResult, // eslint-disable-line
  ProtocolVersionResult, // eslint-disable-line
  ProtocolVersion,
  HostAddressResult, // eslint-disable-line
  Cipher,
  CipherResult // eslint-disable-line
} = require('tlsinfo')

if (!fs.existsSync('./Config.js')) {
  fs.copySync('./Config.example.js', './Config.js')
}

const Config = require('./Config.js')

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
const possibleToIgnoreList = [
  'Expire',
  'NotYetValid',
  'PubKeySize',
  'PubKeySizeOnCA',
  'NoCertificateTransparency',
  'NoAltName',
  'CommonNameInvalid',
  'SHA1',
  'SHA1OnCA',
  'SSLv3',
  'SSLv2',
  'TLSv1',
  'TLSv1_1',
  'NoTLSv1_2',
  'HasSomeMessageDigestAlgorithm',
  'HasSomeMessageDigestAlgorithmOnCA',
  'AES128-SHA',
  'AES256-SHA',
  'AES128-SHA256',
  'AES256-SHA256',
  'AES256-GCM-SHA384',
  'AES128-GCM-SHA256',
  'HasCipherNULL',
  'HasCipherRC',
  'HasCipherIDEA',
  'HasCipherDSS',
  'HasCipherADH',
  'HasCipherCAMELLIA',
  'HasCipherSEED',
  'HasCipherAECDH',
  'HasCipherMD5',
  'HasCipherSRP',
  'HasCipherDES',
  'HasCipherDES',
  'HasCipherARIA',
  'HasCipherPSK'
]
const LOGLEVEL = {
  Error: 'err',
  Warning: 'warn'
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
        ignore: [],
        callbackRawResultEnabled: config.callbackRawResultEnabled
      })
    }
  }
}

/**
 * @param {string} warning
 * @param {string[]} ignore
 */
function isReportingViaConfigEnabled (warning, ignore) {
  const containsReportingPredicate = /** @param {string} x */ x => x === warning
  const isIgnoredOnAllDomains = config.ignore.some(containsReportingPredicate)
  const isIgnoredOnThisHost = ignore && ignore.length && ignore.length > 0 && ignore.some(containsReportingPredicate)
  return !isIgnoredOnAllDomains && !isIgnoredOnThisHost
}

/**
 * @param {string} uri
 */
async function sendReportWebook (uri) {
  if (!uri) return
  slack.setWebhook(uri)

  let payloads = []
  let attachments = []
  messagesToSend = messagesToSend.sort((one, two) => {
    if (one.message < two.message) return -1
    if (one.message > two.message) return 1
    return 0
  })

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
    try {
      slack.webhook(payload, (err, response) => {
        if (err) console.log(err, response)
      })
    } catch (error) {
      // ignore
    }
    await sleep(1000)
  }

  slack.setWebhook('')
}

/**
 * @param {Config.Task} task
 * @param {TlsServiceAuditResult} result
 */
async function sendReportCallback (task, result) {
  const callback = new Url(task.callback)
  let requestOptions = {
    timeout: config.httpCallbackTimeout,
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

    let prettyFormat = true
    if (task.callbackRawResultEnabled) {
      taskResult.callbackRawResult = result
      prettyFormat = false
    }

    taskResult.items = taskResult.items.sort()

    req.setTimeout(config.httpCallbackTimeout)
    setTimeout(() => {
      req.emit('close')
    }, config.httpCallbackTimeout)
    let resultText = ''
    prettyFormat ? resultText = JSON.stringify(taskResult, null, 4) : resultText = JSON.stringify(taskResult)
    req.setHeader('content-type', contentTypeJson)
    req.end(`${resultText}\n`, 'utf8')
    req.once('close', () => {
      resolve()
    })
    req.once('error', e => {
      resolve()
    })
  })
}

/**
 * @param {Config.Task} task
 * @param {TlsServiceAuditResult} result
 */
async function sendReport (task, result) {
  if (task && config.enableSlack && task.webhook) await sendReportWebook(task.webhook)
  if (task && task.callback) await sendReportCallback(task, result)
}

/**
 * @param {string} message
 * @param {Config.Task} task
 * @param {HostAddressResult} hostResult
 * @param {string} level
 * @see {LOGLEVEL}
 */
function addMessage (message, task, hostResult = null, level = LOGLEVEL.Error) {
  if (config.enableConsoleLog) {
    if (isFirstMessageOfItem) {
      let newLine = '\n'
      if (isFirstOveralMessage) newLine = ''
      console.log(`${newLine}${task.host}:${task.port}`)
    }

    console.log(`[${new Date().toUTCString()}] ${hostResult === null ? `` : `${hostResult} -> `}${message}`)
    isFirstMessageOfItem = false
  }

  let messageItem = `${hostResult === null ? `` : `${hostResult} -> `}${message}`
  if (task && task.callback) {
    if (taskResult === null) {
      taskResult = {
        host: hostResult.host,
        port: task.port,
        id: task.id,
        items: [messageItem],
        error: '',
        callbackRawResult: null
      }
    } else {
      taskResult.items.push(messageItem)
    }
  }

  if (!config.enableSlack && !task.webhook) {
    return
  }

  messageItem = `${task.host}:${task.port} ${hostResult === null ? `` : `(${hostResult}) -> `}${message}`
  let color = '#d50200' // error
  switch (level) {
    case LOGLEVEL.Warning:
      color = '#de9e31'
      break
  }
  messagesToSend.push({
    message: `${messageItem}\n`,
    ts: Date.now() / 1000,
    color: color
  })
}

/**
 * @param {HostAddressSpecificCertificateResult} hostSpecificCert
 * @param {Config.Task} task
 */
function validateCertificateResult (hostSpecificCert, task) {
  if (typeof task.host !== 'string') return

  const cert = hostSpecificCert.certificateResult
  const asciiHostname = punycode.toASCII(task.host)
  const chain = cert.chain
  const thresholdDate = moment(chain.cert.notAfter).subtract(config.validUntilDays, 'days')
  const validUntilDaysVolaited = thresholdDate <= moment()
  const daysDifference = Math.abs(moment(chain.cert.notAfter).diff(moment(), 'days'))

  if (validUntilDaysVolaited && isReportingViaConfigEnabled('Expire', task.ignore)) {
    addMessage(`Is valid until "${chain.cert.notAfter}" and therefore volates the threshold of ${config.validUntilDays}. days difference to expiration date: ${daysDifference} days`, task, hostSpecificCert.address)
  }

  if (moment(chain.cert.notBefore) > moment() && isReportingViaConfigEnabled('NotYetValid', task.ignore)) {
    addMessage(`Is not yet valid; notBefore ${chain.cert.notBefore}`, task, hostSpecificCert.address)
  }

  if ((!chain.cert.altNames || chain.cert.altNames.length === 0) && isReportingViaConfigEnabled('NoAltName', task.ignore)) {
    addMessage(`Does not have any altName`, task, hostSpecificCert.address)
  }

  if (chain.cert.altNames.indexOf(asciiHostname) === -1) {
    const message = `Does not match ${task.host}. We got "${chain.cert.altNames}"`
    if ((!chain.cert.altNames.some(x => x.indexOf('*') >= 0)) && isReportingViaConfigEnabled('CommonNameInvalid', task.ignore)) {
      addMessage(message, task, hostSpecificCert.address)
    } else {
      let matchesAnyWildcard = false
      if (chain.cert.altNames.some(x => x.indexOf('*') >= 0)) {
        for (let index = 0; index < chain.cert.altNames.length; index++) {
          const element = chain.cert.altNames[index]
          if (matchesWildcardExpression(asciiHostname, element)) matchesAnyWildcard = true
        }
      }

      if (!matchesAnyWildcard && isReportingViaConfigEnabled('CommonNameInvalid', task.ignore)) addMessage(message, task, hostSpecificCert.address)
    }
  }

  if (chain.cert.publicKey.bitSize < 4096 && isReportingViaConfigEnabled('PubKeySize', task.ignore)) {
    addMessage(`Public key size of ${chain.cert.publicKey.bitSize} is < 4096`, task, hostSpecificCert.address, LOGLEVEL.Warning)
  }

  if (chain.cert.signatureAlgorithm.startsWith('md') && isReportingViaConfigEnabled('HasSomeMessageDigestAlgorithm', task.ignore)) {
    addMessage(`Weak signature algorithm (md): ${chain.cert.signatureAlgorithm}`, task, hostSpecificCert.address)
  }

  if (chain.cert.signatureAlgorithm.startsWith('sha1') && isReportingViaConfigEnabled('SHA1', task.ignore)) {
    addMessage(`Weak signature algorithm (sha1): ${chain.cert.signatureAlgorithm}`, task, hostSpecificCert.address)
  }

  if (!chain.cert.extensions.cTPrecertificateSCTs && isReportingViaConfigEnabled('NoCertificateTransparency', task.ignore)) {
    addMessage(`No Certificate Transparency`, task, hostSpecificCert.address, LOGLEVEL.Warning)
  }

  if (chain.issuer) {
    if (chain.issuer.cert.signatureAlgorithm.startsWith('md') && isReportingViaConfigEnabled('HasSomeMessageDigestAlgorithmOnCA', task.ignore)) {
      addMessage(`Weak signature algorithm of CA (md): ${chain.issuer.cert.signatureAlgorithm} ${chain.issuer.cert.subject.commonName}`, task, hostSpecificCert.address)
    }

    if (chain.issuer.cert.signatureAlgorithm.startsWith('sha1') && isReportingViaConfigEnabled('SHA1OnCA', task.ignore)) {
      addMessage(`Weak signature algorithm of CA (sha1): ${chain.issuer.cert.signatureAlgorithm} ${chain.issuer.cert.subject.commonName}`, task, hostSpecificCert.address)
    }

    if (chain.issuer.cert.publicKey.bitSize < 2048 && isReportingViaConfigEnabled('PubKeySizeOnCA', task.ignore)) {
      addMessage(`Public key size of ${chain.cert.publicKey.bitSize} is < 2048 from CA ${chain.issuer.cert.subject.commonName}`, task, hostSpecificCert.address)
    }
  }
}

/**
 * @param {ProtocolVersionResult} protoResult
 * @param {Config.Task} task
 */
function validateTlsServiceProtocolVersionResult (protoResult, task) {
  const protocol = protoResult.protocol
  const protocols = ProtocolVersion.protocolName
  const messageTemplate = `Weak / Outdated protocol supported: ${protocol}`

  for (const hostAddress of protoResult.enabled) {
    switch (protocol) {
      case protocols.SSLv2:
        if (isReportingViaConfigEnabled('SSLv2', task.ignore)) addMessage(messageTemplate, task, hostAddress)
        continue
      case protocols.SSLv3:
        if (isReportingViaConfigEnabled('SSLv3', task.ignore)) addMessage(messageTemplate, task, hostAddress)
        continue
      case protocols.TLSv1:
        if (isReportingViaConfigEnabled('TLSv1', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
        continue
      case protocols.TLSv1_1:
        if (isReportingViaConfigEnabled('TLSv1_1', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
        continue
    }
  }

  for (const hostAddress of protoResult.disabled) {
    switch (protocol) {
      case protocols.TLSv1_2:
        if (isReportingViaConfigEnabled('NoTLSv1_2', task.ignore)) addMessage(`Modern protocol NOT supported: ${protocol}`, task, hostAddress)
        continue
      case protocols.TLSv1_3:
        if (isReportingViaConfigEnabled('NoTLSv1_3', task.ignore)) addMessage(`Modern protocol NOT supported: ${protocol}`, task, hostAddress)
        continue
    }
  }
}

/**
 * @param {CipherResult} cipherResult
 * @param {Config.Task} task
 */
function validateTlsServiceCipherResult (cipherResult, task) {
  const cipher = cipherResult.cipher

  for (const protocol of cipherResult.protocolSpecificResults) {
    for (const hostAddress of protocol.enabled) {
      const messageTemplate = `Weak cipher usage of ${protocol.protocol} -> ${cipher}`

      if (cipher.indexOf('NULL') >= 0 && isReportingViaConfigEnabled('HasCipherNULL', task.ignore)) addMessage(`${messageTemplate} (contains 'NULL')`, task, hostAddress)
      if (cipher.indexOf('RC') >= 0 && isReportingViaConfigEnabled('HasCipherRC', task.ignore)) addMessage(`${messageTemplate} (contains 'RC')`, task, hostAddress)
      if (cipher.indexOf('IDEA') >= 0 && isReportingViaConfigEnabled('HasCipherIDEA', task.ignore)) addMessage(`${messageTemplate} (contains 'IDEA')`, task, hostAddress)
      if (cipher.indexOf('DSS') >= 0 && isReportingViaConfigEnabled('HasCipherDSS', task.ignore)) addMessage(`${messageTemplate} (contains 'DSS')`, task, hostAddress)
      if (cipher.indexOf('ADH') >= 0 && isReportingViaConfigEnabled('HasCipherADH', task.ignore)) addMessage(`${messageTemplate} (contains 'ADH')`, task, hostAddress)
      if (cipher.indexOf('CAMELLIA') >= 0 && isReportingViaConfigEnabled('HasCipherCAMELLIA', task.ignore)) addMessage(`${messageTemplate} (contains 'CAMELLIA')`, task, hostAddress)
      if (cipher.indexOf('SEED') >= 0 && isReportingViaConfigEnabled('HasCipherSEED', task.ignore)) addMessage(`${messageTemplate} (contains 'SEED')`, task, hostAddress)
      if (cipher.indexOf('AECDH') >= 0 && isReportingViaConfigEnabled('HasCipherAECDH', task.ignore)) addMessage(`${messageTemplate} (contains 'AECDH')`, task, hostAddress)
      if (cipher.indexOf('MD5') >= 0 && isReportingViaConfigEnabled('HasCipherMD5', task.ignore)) addMessage(`${messageTemplate} (contains 'MD5')`, task, hostAddress)
      if (cipher.indexOf('SRP') >= 0 && isReportingViaConfigEnabled('HasCipherSRP', task.ignore)) addMessage(`${messageTemplate} (contains 'SRP')`, task, hostAddress)
      if (cipher.indexOf('DES') >= 0 && isReportingViaConfigEnabled('HasCipherDES', task.ignore)) addMessage(`${messageTemplate} (contains 'DES')`, task, hostAddress)
      if (cipher.indexOf('3DES') >= 0 && isReportingViaConfigEnabled('HasCipherDES', task.ignore)) addMessage(`${messageTemplate} (contains '3DES)`, task, hostAddress)
      if (cipher.indexOf('ARIA') >= 0 && isReportingViaConfigEnabled('HasCipherARIA', task.ignore)) addMessage(`${messageTemplate} (contains 'ARIA')`, task, hostAddress)
      if (cipher.indexOf('PSK') >= 0 && isReportingViaConfigEnabled('HasCipherPSK', task.ignore)) addMessage(`${messageTemplate} (contains 'PSK')`, task, hostAddress)

      if (cipher === 'AES128-SHA' && isReportingViaConfigEnabled('AES128-SHA', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
      if (cipher === 'AES256-SHA' && isReportingViaConfigEnabled('AES256-SHA', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
      if (cipher === 'AES128-SHA256' && isReportingViaConfigEnabled('AES128-SHA256', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
      if (cipher === 'AES256-SHA256' && isReportingViaConfigEnabled('AES256-SHA256', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
      if (cipher === 'AES256-GCM-SHA384' && isReportingViaConfigEnabled('AES256-GCM-SHA384', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
      if (cipher === 'AES128-GCM-SHA256' && isReportingViaConfigEnabled('AES128-GCM-SHA256', task.ignore)) addMessage(messageTemplate, task, hostAddress, LOGLEVEL.Warning)
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

  for (const protocol of result.protocols) {
    validateTlsServiceProtocolVersionResult(protocol, task)
  }

  for (const cipher of Cipher.filterEnabled(result.ciphers)) {
    validateTlsServiceCipherResult(cipher, task)
  }
}

/**
 * @param {Config.Task} task
 * @returns {Promise<TlsServiceAuditResult>}
 */
async function processDomain (task) {
  if (!task || !task.host || typeof task.host !== 'string') {
    addMessage(`host not defined for ${task}`, task)
    return
  }
  if (!task.port) {
    task.port = config.defaultPort || 443
  }

  isFirstMessageOfItem = true

  return new Promise(async (resolve, reject) => {
    /** @type {TlsServiceAuditResult} */
    let result = null

    try {
      if (typeof task.host !== 'string') throw new Error(`"host" is not typeof string => ${typeof task.host}`)
      const tlsServiceAudit = new TlsServiceAudit({
        host: task.host,
        port: task.port
      })
      result = await tlsServiceAudit.run()
      validateTlsServiceAuditResult(result, task)
    } catch (e) {
      let error = e
      if (error.error && error.error.code) error = error.error
      switch (error.code) {
        case 'ECONNRESET':
          addMessage(`Connection reset`, task)
          break
        case 'ECONNREFUSED':
          addMessage(`Connection refused (ip: ${error.address || error.message || undefined})`, task)
          break
        case 'ETIMEDOUT':
          addMessage(`Connection timed-out`, task)
          break
        case 'ENOTFOUND':
          addMessage(`Host can't be resolved / found -> ENOTFOUND`, task)
          break
        case 'EAI_AGAIN':
          addMessage(`Host can't be resolved -> EAI_AGAIN`, task)
          break
        default:
          addMessage(`\n\`\`\`${JSON.stringify(error, null, 4)}\`\`\``, task)
          break
      }
    }

    isFirstOveralMessage = false
    resolve(result)
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
  if (!config.httpsCallbacksOnly && url.startsWith('https://')) return true
  if (!url.startsWith('http://')) return false
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
        const message = JSON.stringify({ message: 'Method not allowed.' })
        response.statusCode = 405
        response.setHeader('content-type', contentTypeJson)
        response.end(`${message}\n`, 'utf8')
        return resolve()
      }

      let isImplemented = request.headers['content-type'] && request.headers['content-type'].toLocaleLowerCase().indexOf('json') >= 0

      if (!isImplemented) {
        const message = JSON.stringify({ message: 'any other content-type than json is not implemented.' })
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
          const message = JSON.stringify({ message: 'Payload lager than 10e6 (~ 10MB).' })
          response.statusCode = 413
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          hasError = true
        }
      })

      request.once('end', async () => {
        if (hasError) return resolve()

        /** @type {Config.Task} */
        let task = new Config.Task()
        try {
          task = Object.assign(task, JSON.parse(body))
        } catch (error) {
          const message = JSON.stringify([{ message: 'payload could not be parsed into a valid object from json string.' }])
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${message}\n`, 'utf8')
          return resolve()
        }
        const errorMessages = []

        if ((!task.callback || typeof task.callback !== 'string' || task.callback.trim().length < 10) &&
              (!task.webhook || typeof task.webhook !== 'string' || task.webhook.trim().length < 10)) {
          errorMessages.push({ message: 'both, "callback" and "webhook" are not defined. so this would be not returning the result to anyone.' })
        }

        if ((task.callback && !validateCallback(task.callback, request)) || (task.webhook && !validateCallback(task.webhook, request))) {
          errorMessages.push({ message: '"callback" and / or "webhook" are not HTTPS. This is administratively prohibited.' })
        }

        if (task.ignore &&
          (
            typeof task.ignore !== 'object' ||
            typeof task.ignore.length !== 'number'
          )
        ) {
          errorMessages.push({ message: '"ignore" is defined but not a list.', possible_warnings_to_ignore: possibleToIgnoreList })
        }

        if (task.ignore && task.ignore.length && typeof task.ignore.length === 'number') {
          let unknowns = []
          for (const ignores of task.ignore) {
            if (!possibleToIgnoreList.includes(ignores)) unknowns.push(ignores)
          }

          if (unknowns.length > 0) errorMessages.push({ message: '"ignore" does include values which are not known', unknown_ignore_values: unknowns, possible_warnings_to_ignore: possibleToIgnoreList })
        }

        // i now what i'm doing, it's OK. Trust me... not.
        // @ts-ignore
        if (task.callbackRawResultEnabled == 'true') task.callbackRawResultEnabled = true // eslint-disable-line
        // @ts-ignore
        if (task.callbackRawResultEnabled == 'false') task.callbackRawResultEnabled = false // eslint-disable-line
        if (typeof task.callbackRawResultEnabled === 'string') {
          errorMessages.push({ message: '"callbackRawResultEnabled" has to be of type boolean.' })
        }

        const isValidSingleHost = task.host && typeof task.host === 'string' && task.host.trim().length >= 3
        const isValidMultiHost = task.host instanceof Array && task.host.length > 0 && task.host.every(value => typeof value === 'string' && value.trim().length >= 3)

        if (!isValidSingleHost && !isValidMultiHost) {
          errorMessages.push({ message: '"host" must be defined and a string of minimal 3 chars. OR a string array, larger than 0 and containing only strings with a minimal length on 3 chars.' })
        }

        if (errorMessages.length > 0) {
          response.statusCode = 400
          response.setHeader('content-type', contentTypeJson)
          response.end(`${JSON.stringify(errorMessages, null, 2)}\n`, 'utf8')
          return resolve()
        }

        let message = ''
        if (isValidMultiHost) {
          let multiTaskInstances = []
          for (const host of task.host) {
            multiTaskInstances.push({
              id: uuidv4(),
              host: host,
              port: task.port || config.defaultPort || 443,
              callback: task.callback,
              webhook: task.webhook,
              ignore: task.ignore,
              callbackRawResultEnabled: task.callbackRawResultEnabled
            })
          }

          message = JSON.stringify([{ message: 'OK', task: multiTaskInstances }])
          for (const multiTaskInstance of multiTaskInstances) {
            tasks.push(multiTaskInstance)
          }
        } else { // isValidSingleHost
          task.id !== '' ? task.id = task.id : task.id = uuidv4()
          message = JSON.stringify([{ message: 'OK', task: task }])
          tasks.push(task)
        }

        response.statusCode = 200
        response.setHeader('content-type', contentTypeJson)
        response.end(`${message}\n`, 'utf8')

        const clientAddress = request.headers['x-forwarded-for'] ? request.headers['x-forwarded-for'] : request.connection.remoteAddress
        const logCallbackUrl = task.callback ? ` with callback ${task.callback}` : ''
        const logWebookUrl = task.webhook ? ` with webook ${task.webhook}` : ''
        if (config.enableConsoleLog) console.log(`got new task for: ${task.host} from ${clientAddress}${logCallbackUrl}${logWebookUrl}`)
        return resolve()
      })
    } else {
      const message = JSON.stringify([{ message: 'not found' }])
      response.statusCode = 404
      response.setHeader('content-type', contentTypeJson)
      response.end(`${message}\n`, 'utf8')
    }
  })
}

/**
 * @param {http.IncomingMessage} request
 * @param {http.ServerResponse} response
 */
function handleApiRequestNextTick (request, response) {
  process.nextTick(() => handleApiRequest(request, response))
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
    if (config.startHttpServer || config.enableConsoleLog) console.log(`running task for ${task.host}`)
    messagesToSend = []
    taskResult = null
    const result = await processDomain(task)
    await sendReport(task, result)
    messagesToSend = []
    taskResult = null
    if (config.enableConsoleLog) console.log(`number of tasks remaining: ${tasks.length}`)
    taskRunning = false
  }, 100)

  if (config.startHttpServer) {
    http.createServer(handleApiRequestNextTick).listen(config.httpServerPort)
    let fqdn = ''
    if (os.platform() === 'linux') fqdn = execSync('hostname -f').toLocaleString().trim()
    fqdn = fqdn.length > 0 ? fqdn : os.hostname()
    console.log(`http server started: http://${fqdn}:${config.httpServerPort}/`)
    if (config.enableConsoleLog) console.log(`# curl -v -H 'content-type: ${contentTypeJson}' --data '{"host":"expired.badssl.com","callback":"https://your-server.local/tls-tester-result"}' http://${fqdn}:${config.httpServerPort}/api/enqueue`)
  } else if (config.enableConsoleLog || (config.enableSlack && config.slackWebHookUri)) {
    for (const task of config.domains) {
      if (config.enableSlack && config.slackWebHookUri && !task.webhook) task.webhook = config.slackWebHookUri
      tasksToEnqueue.push(task)
    }

    while (tasks.length > 0 || tasksToEnqueue.length > 0 || taskRunning) { // eslint-disable-line no-unmodified-loop-condition
      await sleep(10)
    }
    process.exit(0)
  }
})()
