/// <reference path="typings/index.d.ts"/>

class Config {
  constructor () {
    this.version = 1
    this.validUntilDays = 10
    this.connectionTimeoutMs = 2000 // connection timeout per socket (there are possibly many connections per host)
    this.defaultPort = 443
    this.ignore = [] // this warnings will be ignored on all domains

    this.enableConsoleLog = true
    this.enableSlack = false
    this.slackWebHookUri = 'https://hooks.slack.com/services/xxxxxx/xxxxxx/xxxxxx'
    this.slackChannel = ''
    this.slackUsername = 'tls-tester-bot'

    this.botName = 'tls-tester-bot'
    this.botIcon = 'https://compilenix.org/cdn/Compilenix.png'

    // possible warnings to ignore:
    // - Expire
    // - PubKeySize
    // - NoCertificateTransparency
    // - AES128-SHA
    // - AES256-SHA
    // - AES128-SHA256
    // - AES256-SHA256
    // - AES256-GCM-SHA384
    // - AES128-GCM-SHA256

    /** @type {ConfigDomain[]} */
    this.domains = [
      { host: 'www.microsoft.com', ignore: ['AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES128-SHA256', 'AES256-SHA', 'AES128-SHA'] },
      { host: 'expired.badssl.com', ignore: ['AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA256', 'AES128-SHA256', 'AES256-SHA', 'AES128-SHA'] },
      { host: 'mozilla-old.badssl.com' }
    ]
  }
}

module.exports = new Config()
