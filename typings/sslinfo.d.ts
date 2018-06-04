interface ServerResult {
  host: string
  port: number
  cert: X509
  certPEM: string
  certCa: ?X509
  certCaPem: ?string
  protocols: TlsProtocol[]
  ciphers: Cipher,
  ignoreWarnings: ?string[]
}
