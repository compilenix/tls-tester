// Type definitions for tlsinfo x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
/// <reference types="node"/>

declare module 'tlsinfo' {
  import { X509, TlsProtocol, Cipher } from 'x509'
  import { ConnectionOptions, TLSSocket } from 'tls'
  import { Socket } from 'net'

  export class TimeOutableSocket extends NodeJS.EventEmitter {
    /**
     * Default: 30000 -> 30s
     */
    readonly timeout: number
    protected readonly socket: Socket

    constructor(socket: Socket)
    constructor(socket: Socket, timeout: number)
    destroySocket(): void
    destroySocket(error: any): void
    setSocket(socket: Socket): void
    /**
     * default 30000ms -> 30s
     */
    setTimeout(ms: number): void
    on(event: 'timeout', listener: (...args: any[]) => void): this
    emit(event: 'timeout', ...args: any[]): boolean
  }

  export class TlsSocketWrapper extends TimeOutableSocket {
    protected readonly socket: TLSSocket

    constructor()
    constructor(options: ConnectionOptions)
    private onTimeout(): void
    private onError(error: any): void
    private onError(error: any, reject: (reason?: any) => void): void
    /**
     * default 30000ms -> 30s
     */
    setOptions(options: ConnectionOptions): void
    resetOptions(): void
    resetOptions(options: ConnectionOptions): void
    setNoDelay(noDelay?: boolean): this;
    setKeepAlive(enable?: boolean, initialDelay?: number): this;
    connect(): Promise<TLSSocket>
    connect(timeout: number): Promise<TLSSocket>
  }

  export interface CertificateResult {
    host: string
    port: number
    cert: X509
    certPem: string
    certCa?: X509
    certCaPem: string
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

  export interface CipherResult {
    /**
     * @see {Cipher.suites}
     */
    enabled: string[]
    /**
     * @see {Cipher.suites}
     */
    disabled: string[]
    /**
     * @see {Cipher.suites}
     */
    unsupported: string[]
  }

  export class Cipher extends TlsSocketWrapper {
    static readonly suites: [
      'NULL-MD5',
      'NULL-SHA',
      'EXP-RC4-MD5',
      'RC4-MD5',
      'RC4-SHA',
      'EXP-RC2-CBC-MD5',
      'IDEA-CBC-SHA',
      'EXP-DES-CBC-SHA',
      'DES-CBC-SHA',
      'DES-CBC3-SHA',
      'EXP-DHE-DSS-DES-CBC-SHA',
      'DHE-DSS-CBC-SHA',
      'DHE-DSS-DES-CBC3-SHA',
      'EXP-DHE-RSA-DES-CBC-SHA',
      'DHE-RSA-DES-CBC-SHA',
      'DHE-RSA-DES-CBC3-SHA',
      'EXP-ADH-RC4-MD5',
      'ADH-RC4-MD5',
      'EXP-ADH-DES-CBC-SHA',
      'ADH-DES-CBC-SHA',
      'ADH-DES-CBC3-SHA',
      'EXP1024-DES-CBC-SHA',
      'EXP1024-RC4-SHA',
      'EXP1024-DHE-DSS-DES-CBC-SHA',
      'EXP1024-DHE-DSS-RC4-SHA',
      'DHE-DSS-RC4-SHA'
      // TODO: complete list
    ]

    constructor()
    constructor(options: ConnectionOptions)
    /**
     * Similar to setTimeout but does apply to each individual connection rather then to the whole service audit.
     *
     * Default: equal to setTimeout
     */
    setTimeoutPerConnection(ms: number): void
    test(): Promise<ProtocolVersionResult>
    test(timeout: number): Promise<ProtocolVersionResult>
    test(timeoutPerConnection: number): Promise<ProtocolVersionResult>
  }

  export interface ProtocolVersionResult {
    /**
     * @see {ProtocolVersion.protocols}
     */
    enabled: string[]
    /**
     * @see {ProtocolVersion.protocols}
     */
    disabled: string[]
    /**
     * @see {ProtocolVersion.protocols}
     */
    unsupported: string[]
  }

  export class ProtocolVersion extends TlsSocketWrapper {
    static readonly protocols: [
      'SSLv2',
      'SSLv3',
      'TLSv1',
      'TLSv1.1',
      'TLSv1.2',
      'TLSv1.3'
    ]

    constructor()
    constructor(options: ConnectionOptions)
    /**
     * @param protocol I.e.: TLSv1.2
     */
    protected static map(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3'): 'SSLv2_method' | 'SSLv3_method' | 'TLSv1_method' | 'TLSv1_1_method' | 'TLSv1_2_method' | 'TLSv1_3_method' | ''
    static getSupportedProtocols(): [] | [
      'SSLv2',
      'SSLv3',
      'TLSv1'
    ] | [
      'SSLv2',
      'SSLv3',
      'TLSv1',
      'TLSv1.1',
      'TLSv1.2'
    ] | [
      'SSLv3',
      'TLSv1',
      'TLSv1.1',
      'TLSv1.2'
    ] | [
      'SSLv3',
      'TLSv1',
      'TLSv1.1',
      'TLSv1.2',
      'TLSv1.3'
    ]
    test(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3'): Promise<ProtocolVersionResult>
    test(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3', timeout: number): Promise<ProtocolVersionResult>
    test(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3', timeoutPerConnection: number): Promise<ProtocolVersionResult>
  }

  export interface ServiceAuditResult {
    certificate: CertificateResult
  }

  export class ServiceAudit extends TimeOutableSocket {
    constructor()
    constructor(options: ConnectionOptions)
    /**
     * Similar to setTimeout but does apply to each individual connection rather then to the whole service audit.
     *
     * Default: equal to setTimeout
     */
    setTimeoutPerConnection(ms: number): void
    run(): Promise<ServiceAuditResult>
    run(timeout: number): Promise<ServiceAuditResult>
    run(timeoutPerConnection: number): Promise<ServiceAuditResult>
  }
}
