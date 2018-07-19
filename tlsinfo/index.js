'use-strict'
const { ServiceAudit } = require('./lib/ServiceAudit')
const { Certificate } = require('./lib/Certificate')

// async function run () {
//   try {
//     const cert = new Certificate({
//       host: 'google.com',
//       port: 465
//     })
//     let certResult = null
//     try { certResult = await cert.get(2500) } catch (error) { }
//     debugger
//     cert.setOptions({
//       host: 'heise.de'
//     })
//     try { certResult = await cert.get() } catch (error) { }
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
