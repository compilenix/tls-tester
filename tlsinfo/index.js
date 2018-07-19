'use-strict'
const { ServiceAudit } = require('./lib/ServiceAudit')
const { Certificate } = require('./lib/Certificate')

// async function run () {
//   try {
//     const cert = new Certificate({
//       host: 'google.com',
//       port: 465
//     })
//     const certResult = await cert.get(2500)
//     debugger
//   } catch (error) {
//     debugger
//   }
// }

// run()

module.exports = {
  ServiceAudit: ServiceAudit,
  Certificate: Certificate
}
