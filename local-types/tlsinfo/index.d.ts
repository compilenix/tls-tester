// Type definitions for tlsinfo x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
/// <reference types="node"/>

declare module 'tlsinfo' {
  import { X509, TlsProtocol, Cipher } from 'x509'
  import { ConnectionOptions, TLSSocket, TlsOptions } from 'tls'
  import { Socket } from 'net'
  import { LookupAddress } from 'dns'

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
    protected options: TlsOptions

    constructor()
    constructor(options: ConnectionOptions)
    private onError(error: any): void
    private onError(error: any, reject: (reason?: any) => void): void
    private onError(error: any, reject: (reason?: any) => void, selfdestruct: boolean): void
    /**
     * default 30000ms -> 30s
     */
    updateOptions(options: ConnectionOptions): void
    resetOptions(): void
    resetOptions(options: ConnectionOptions): void
    setNoDelay(noDelay?: boolean): this;
    setKeepAlive(enable?: boolean, initialDelay?: number): this;
    connect(): Promise<void>
    connect(timeout: number): Promise<void>
    connect(timeout: number, selfdestruct: boolean): Promise<void>
  }

  export class HostAddressSpecificCertificateResult {
    address: HostAddressResult
    certificateResult: CertificateResult
  }

  export class CertificateResult {
    servername: string
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
    fetch(): Promise<HostAddressSpecificCertificateResult[]>
    fetch(timeout: number): Promise<HostAddressSpecificCertificateResult[]>
  }

  export class CipherResult {
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
    test(): Promise<ProtocolVersionResult>
    test(timeout: number): Promise<ProtocolVersionResult>
    test(timeoutPerConnection: number): Promise<ProtocolVersionResult>
  }

  export class HostAddressResult {
    host: string
    address: string
    family: number
  }

  export class DnsHelper {
    static lookup(host: string): Promise<{ addresses: HostAddressResult[], warnings: string[] }>
  }

  export class HostAddressSpecificProtocolVersionResult {
    address: HostAddressResult
    protocol: string
    state: boolean
  }

  export class ProtocolVersionResult {
    host: string,
    port: number,
    ipAddress: HostAddressResult[]
    protocol: string
    /**
     * Protocols that are supported by the current Node.JS version and accepted by the Service
     * @see {ProtocolVersion.protocols}
     */
    enabled: HostAddressSpecificProtocolVersionResult[]
    /**
     * Protocols that are supported by the current Node.JS version but NOT accepted by the Service
     * @see {ProtocolVersion.protocols}
     */
    disabled: HostAddressSpecificProtocolVersionResult[]
    /**
     * Protocols that are NOT supported by the current Node.JS version
     * @see {ProtocolVersion.protocols}
     */
    unsupported: HostAddressSpecificProtocolVersionResult[]
    /**
     * Warnings; I.e. host has multiple ip addresses
     */
    warnings: string[]
  }

  export class ProtocolVersion extends TlsSocketWrapper {
    static readonly protocols: [
      'SSLv2',
      'SSLv3',
      'TLSv1',
      'TLSv1_1',
      'TLSv1_2',
      'TLSv1_3'
    ]

    constructor()
    constructor(options: ConnectionOptions)
    /**
     * @param protocol I.e.: TLSv1_2
     */
    protected static map(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3'): 'SSLv2_method' | 'SSLv3_method' | 'TLSv1_method' | 'TLSv1_1_method' | 'TLSv1_2_method' | 'TLSv1_3_method' | ''
    static getSupportedProtocols(): [] | [
      'SSLv3',
      'TLSv1'
    ] | [
      'TLSv1',
      'TLSv1_1',
      'TLSv1_2'
    ] | [
      'TLSv1',
      'TLSv1_1',
      'TLSv1_2',
      'TLSv1_3'
    ]
    /**
     * @param protocol I.e.: TLSv1_2
     */
    test(protocol: 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3'): Promise<ProtocolVersionResult>
    /**
     * @param protocol I.e.: TLSv1_2
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @see {ProtocolVersion.setTimeout}
     */
    test(protocol: 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3', timeout: number): Promise<ProtocolVersionResult>
    /**
     * @param protocol I.e.: TLSv1_2
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @see {ProtocolVersion.setTimeout}
     * @param ipVersions default is [4, 6]
     */
    test(protocol: 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3', timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<ProtocolVersionResult>
    /**
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]
     */
    testMultiple(protocols: string[]): Promise<ProtocolVersionResult[]>
    /**
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @see {ProtocolVersion.setTimeout}
     */
    testMultiple(protocols: string[], timeout: number): Promise<ProtocolVersionResult[]>
    /**
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     * @see {ProtocolVersion.setTimeout}
     */
    testMultiple(protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<ProtocolVersionResult[]>
  }

  export class ServiceAuditResult {
    certificate: CertificateResult
  }

  export class ServiceAudit extends TimeOutableSocket {
    constructor()
    constructor(options: ConnectionOptions)
    run(): Promise<ServiceAuditResult>
    run(timeout: number): Promise<ServiceAuditResult>
    run(timeoutPerConnection: number): Promise<ServiceAuditResult>
  }
}
