// Type definitions for tlsinfo x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
/// <reference types="node"/>

declare module 'tlsinfo' {
  import { X509, TlsProtocol, Cipher } from 'x509'
  export interface CertificateResult {
    host: string
    port: number
    cert: X509
    certPem: string
    certCa?: X509
    certCaPem: string
  }

  export interface ServiceAuditResult {
    host: string
    port: number
    cert: X509
    certPEM: string
    certCa?: X509
    certCaPem?: string
    protocols: TlsProtocol[]
    ciphers: Cipher,
    ignoreReports?: string[]
  }

  export class Certificate extends NodeJS.EventEmitter {

  }

  export class ServiceAudit extends NodeJS.EventEmitter {

  }
}
