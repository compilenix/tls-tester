class Config {
  constructor () {
    this.version = 1
    this.startHttpServer = false
    this.httpServerPort = 16636
    this.httpsCallbacksOnly = true // applies to webhooks, too
    this.validUntilDays = 10
    this.connectionTimeoutSeconds = 60 // connection timeout task / domain (has to be greater than 0)
    this.defaultPort = 443
    this.ignore = [] // this warnings / errors will be ignored on all domains

    this.enableConsoleLog = true
    this.enableSlack = false
    this.slackWebHookUri = 'https://hooks.slack.com/services/xxxxxx/xxxxxx/xxxxxx'
    this.slackChannel = ''
    this.slackUsername = 'tls-tester-bot'

    this.botName = 'tls-tester-bot'
    this.botIcon = 'https://compilenix.org/cdn/Compilenix.png'

    // possible warnings / errors to ignore:
    // - Expire
    // - NotYetValid
    // - PubKeySize
    // - PubKeySizeOnCA
    // - NoCertificateTransparency
    // - NoAltName
    // - CommonNameInvalid
    // - SHA1
    // - SHA1OnCA
    // - SSLv3
    // - SSLv2
    // - NoTLSv1.2
    // - HasSomeMessageDigestAlgorithm
    // - HasSomeMessageDigestAlgorithmOnCA
    // - AES128-SHA
    // - AES256-SHA
    // - AES128-SHA256
    // - AES256-SHA256
    // - AES256-GCM-SHA384
    // - AES128-GCM-SHA256
    // - HasCipherNULL
    // - HasCipherRC
    // - HasCipherIDEA
    // - HasCipherDSS
    // - HasCipherADH
    // - HasCipherCAMELLIA
    // - HasCipherSEED
    // - HasCipherAECDH
    // - HasCipherMD5
    // - HasCipherSRP
    // - HasCipherDES
    // - HasCipherDES
    // - HasCipherARIA
    // - HasCipherPSK

    /** @type {Task[]} */
    this.domains = [
      { host: 'www.microsoft.com', ignore: ['AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES128-SHA256', 'AES256-SHA', 'AES128-SHA'] },
      { host: 'expired.badssl.com', ignore: ['AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES128-SHA256', 'AES256-SHA', 'AES128-SHA'] },
      { host: 'mozilla-old.badssl.com' }
    ]
  }
}

class Task {
  constructor () {
    this.host = ''
    this.port = 443
    /** @type {string[]} */
    this.ignore = []
    this.id = ''
    this.webhook = ''
    this.callback = ''
  }
}

class TaskResult {
  constructor () {
    this.id = ''
    this.host = ''
    this.port = 443
    /** @type {string[]} */
    this.items = []
    this.error = ''
  }
}

module.exports.Config = new Config()
module.exports.Task = Task
module.exports.TaskResult = TaskResult
