const assert = require('assert')

let config = {
  httpsCallbacksOnly: true,
  /** @type {string[]} */
  httpCallbacksAllowedFrom: [],
  /** @type {(string | RegExp)[]} */
  httpCallbacksAllowedTo: []
}

let request = {
  socket: {
    remoteAddress: '10.6.9.240'
  }
}

/**
 * @param {string} url
 * @returns {boolean}
 */
function validateCallback (url = '', request) {
  if (!url) return false
  // if (!(request instanceof http.IncomingMessage) || !request.socket.remoteAddress) return false
  if (!request.socket.remoteAddress) return false
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

assert.strictEqual(validateCallback('ftp://compilenix.org/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://compilenix.org/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('https://compilenix.org/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('ftp://10.6.9.240/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://10.6.9.240/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('https://10.6.9.240/ldjfksjdf', request), true)

config.httpsCallbacksOnly = false
assert.strictEqual(validateCallback('ftp://compilenix.org/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://compilenix.org/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('https://compilenix.org/ldjfksjdf', request), true)

config.httpsCallbacksOnly = true
config.httpCallbacksAllowedFrom.push('10.6.9.240')
assert.strictEqual(validateCallback('ftp://10.6.9.240/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://10.6.9.240/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('https://10.6.9.240/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('http://0.0.0.0/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('https://0.0.0.0/ldjfksjdf', request), true)

config.httpCallbacksAllowedFrom = []
config.httpCallbacksAllowedTo.push('slack.com')
assert.strictEqual(validateCallback('ftp://compilenix.slack.com/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://compilenix.slack.com/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('https://compilenix.slack.com/ldjfksjdf', request), true)

config.httpCallbacksAllowedTo.push(/.*\.?lala\.net\//i)
assert.strictEqual(validateCallback('ftp://compilenix.slack.com/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('http://compilenix.slack.com/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('http://compilenix.org/ldjfksjdf', request), false)
assert.strictEqual(validateCallback('https://compilenix.lala.net/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('http://compilenix.lala.net/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('http://lala.net/ldjfksjdf', request), true)
assert.strictEqual(validateCallback('https://lala.net/ldjfksjdf', request), true)
