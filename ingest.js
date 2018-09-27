const http = require('http')
const url = require('url')
const { URL: Url } = url
const argv = require('minimist')(process.argv.slice(2))

const fs = require('fs-extra')

if (!fs.existsSync('./Config.js')) {
  fs.copySync('./Config.example.js', './Config.js')
}

const Config = require('./Config.js')

let config = Config.Config

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

async function run () {
  overrideOptionsFromCommandLineArguments()
  for (const domain of config.domains) {
    /** @type {Config.Task} */
    let task = {
      host: domain.host,
      callbackInvokeForced: false
    }
    if (config.slackWebHookUri) task.webhook = config.slackWebHookUri
    if (domain.port) task.port = domain.port
    if ((config.ignore && config.ignore.length > 0) || (domain.ignore && domain.ignore.length > 0)) task.ignore = []
    if (config.ignore && config.ignore.length > 0) task.ignore = config.ignore.concat(task.ignore)
    if (domain.ignore && domain.ignore.length > 0) task.ignore = domain.ignore.concat(task.ignore)

    await new Promise((resolve, reject) => {
      let url = new Url(`http://127.0.0.1:${config.httpServerPort}/api/enqueue`)
      /** @type {http.RequestOptions} */
      let options = {
        protocol: url.protocol,
        method: 'POST',
        host: url.host,
        port: url.port,
        hostname: url.hostname,
        path: url.pathname
      }
      const req = http.request(options, res => {
        if (res.statusCode === 200) return
        console.log(`Error: code ${res.statusCode} (${res.statusMessage})`)
        res.setEncoding('utf8')
        let body = ''
        res.on('data', chunk => {
          body += chunk
        })
        res.on('end', () => {
          console.dir(body)
        })
        res.on('close', () => {
          resolve()
        })
        res.on('error', () => {
          resolve()
        })
      })
      req.on('close', () => {
        resolve()
      })
      req.on('error', () => {
        resolve()
      })
      const taskString = JSON.stringify(task)
      req.setHeader('content-type', 'application/json; charset=utf8')
      req.end(taskString, 'utf8')
    })
  }
}

run()
