interface ServerResult {
  host: string
  port: number
  cert: X509
  certPEM: string
  protocols: TlsProtocol[]
  ciphers: Cipher
}
