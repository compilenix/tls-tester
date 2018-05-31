/// <reference path="typings/index.d.ts"/>

class Config {
  constructor () {
    this.version = 1
    this.validUntilDays = 10

    this.enableSlack = true
    this.slackWebHookUri = 'https://hooks.slack.com/services/xxxxxx/xxxxxx/xxxxxx'
    this.slackChannel = ''
    this.slackUsername = 'tls-tester-bot'

    this.botName = 'tls-tester-bot'
    this.botIcon = 'https://compilenix.org/cdn/Compilenix.png'

    /** @type {ConfigDomain[]} */
    this.domains = [
      { host: 'www.microsoft.com', servername: '', port: 443 },
      { host: 'expired.badssl.com', servername: '', port: 443 },
      { host: 'mozilla-old.badssl.com', servername: '', port: 443 }
    ]
  }
}

module.exports = new Config()
