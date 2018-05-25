class Config {
  constructor () {
    this.Version = '1'
    this.validUntilDays = 10

    this.domains = [
      { host: 'expired.badssl.com' },
      // 'services.plan.de'
      // 'github.com'
    ]
  }
}

module.exports = new Config()
