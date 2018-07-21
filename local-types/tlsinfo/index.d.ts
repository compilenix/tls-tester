// Type definitions for tlsinfo x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
/// <reference types="node"/>

declare module 'tlsinfo' {
  import { X509, TlsProtocol, Cipher } from 'x509'
  import { ConnectionOptions, TLSSocket } from 'tls'

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

  export class TlsSocketWrapper extends NodeJS.EventEmitter {
    /**
     * Default: 30000 -> 30s
     */
    readonly timeout: number
    constructor()
    constructor(options: ConnectionOptions)
    destroySocket(): void
    destroySocket(error: any): void
    private onTimeout(): void
    private onError(error: any): void
    private onError(error: any, reject: (reason?: any) => void): void
    /**
     * default 30000ms -> 30s
     */
    setTimeout(ms: number): void
    on(event: 'timeout', listener: (...args: any[]) => void): this
    emit(event: 'timeout', ...args: any[]): boolean
    setOptions(options: ConnectionOptions): void
    resetOptions(): void
    resetOptions(options: ConnectionOptions): void
    setNoDelay(noDelay?: boolean): this;
    setKeepAlive(enable?: boolean, initialDelay?: number): this;
    connect(): Promise<TLSSocket>
    connect(timeout: number): Promise<TLSSocket>
  }
  export class Certificate extends TlsSocketWrapper {
    constructor()
    constructor(options: ConnectionOptions)
    /**
     * @param certRaw in pem format without: -----BEGIN CERTIFICATE-----
     */
    static parseRawPemCertificate(certRaw: string): X509
    /**
     * @param cert in pem format with: -----BEGIN CERTIFICATE-----
     */
    static parsePemCertificate(cert: string): X509
    fetch(): Promise<CertificateResult>
    fetch(timeout: number): Promise<CertificateResult>
  }

  export class ProtocolVersion extends TlsSocketWrapper {

  }
  export class ServiceAudit extends TlsSocketWrapper {
  }
}
