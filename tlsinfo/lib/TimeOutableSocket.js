const events = require('events')
const net = require('net')

class TimeOutableSocket extends events.EventEmitter {
  /**
   * @param {net.Socket} socket
   * @param {number} timeout
   */
  constructor (socket = null, timeout = -1) {
    super()
    if (socket) this.setSocket(socket)
    this.timeout = 30000
    this.setTimeout(timeout)
  }

  destroySocket (error = null) {
    // if (this.socket && !this.socket.destroyed) this.socket.destroy(error)
  }

  /**
   * @param {net.Socket} socket
   */
  setSocket (socket) {
    if (!socket || !(socket instanceof net.Socket)) throw new Error('socket must be defined and an instance of net.Socket')
    this.socket = socket
    this.socket.setTimeout(this.timeout, () => {
      const error = 'timeout'
      this.destroySocket(error)
      this.emit('timeout', error)
    })
  }

  /**
   * set timeout in ms
   * @param {number} ms
   */
  setTimeout (ms) {
    if (typeof ms === 'number' && ms > 0) this.timeout = ms
  }
}

module.exports = TimeOutableSocket
