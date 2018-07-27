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
    setTimeout(ms: number): void
    static validateOptions(options: ConnectionOptions): ConnectionOptions
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

  export class CertificateChain {
    cert: X509
    pem: string
    issuer: CertificateChain
  }

  export class CertificateResult {
    servername: string
    port: number
    chain: CertificateChain
  }

  export class Certificate extends TlsSocketWrapper {
    constructor()
    constructor(options: ConnectionOptions)
    /**
     * @param certRaw in pem format without: -----BEGIN CERTIFICATE-----
     */
    public static parseRawPemCertificate(certRaw: string): X509
    /**
     * @param cert in pem format with: -----BEGIN CERTIFICATE-----
     */
    public static parsePemCertificate(cert: string): X509
    fetch(): Promise<HostAddressSpecificCertificateResult[]>
    fetch(timeout: number): Promise<HostAddressSpecificCertificateResult[]>
    fetch(timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<HostAddressSpecificCertificateResult[]>
    fetch(timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<HostAddressSpecificCertificateResult[]>
  }

  export class ProtocolVersionSpecificCipherResult {
    protocol: string
    enabled: HostAddressResult[]
    disabled: HostAddressResult[]
    unsupported: HostAddressResult[]
  }

  export class CipherResult {
    host: string
    port: number
    cipher: string
    ipAddress: HostAddressResult[]
    protocolSpecificResults: ProtocolVersionSpecificCipherResult[]
  }

  export class Cipher extends TlsSocketWrapper {
    public static readonly suites: [
      // SSL v3.0 cipher suites
      'NULL-MD5', // SSL_RSA_WITH_NULL_MD5
      'NULL-SHA', // SSL_RSA_WITH_NULL_SHA
      'RC4-MD5', // SSL_RSA_WITH_RC4_128_MD5
      'RC4-SHA', // SSL_RSA_WITH_RC4_128_SHA
      'IDEA-CBC-SHA', // SSL_RSA_WITH_IDEA_CBC_SHA
      'DES-CBC3-SHA', // SSL_RSA_WITH_3DES_EDE_CBC_SHA
      'DH-DSS-DES-CBC3-SHA', // SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
      'DH-RSA-DES-CBC3-SHA', // SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
      'DHE-DSS-DES-CBC3-SHA', // SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
      'DHE-RSA-DES-CBC3-SHA', // SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
      'ADH-RC4-MD5', // SSL_DH_anon_WITH_RC4_128_MD5
      'ADH-DES-CBC3-SHA', // SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
      // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_NULL_SHA
      // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
      // 'Not implemented.', // SSL_FORTEZZA_KEA_WITH_RC4_128_SHA

      // TLS v1.0 cipher suites
      'EXP-RC4-MD5', // TLS_RSA_EXPORT_WITH_RC4_40_MD5
      'EXP-RC2-CBC-MD5', // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
      'EXP-DES-CBC-SHA', // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
      'DES-CBC-SHA', // TLS_RSA_WITH_DES_CBC_SHA
      // 'Not implemented.', // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
      // 'Not implemented.', // TLS_DH_DSS_WITH_DES_CBC_SHA
      // 'Not implemented.', // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
      // 'Not implemented.', // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
      // 'Not implemented.', // TLS_DH_RSA_WITH_DES_CBC_SHA
      // 'Not implemented.', // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
      'EXP-EDH-DSS-DES-CBC-SHA', // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
      'EDH-DSS-CBC-SHA', // TLS_DHE_DSS_WITH_DES_CBC_SHA
      'EDH-DSS-DES-CBC3-SHA', // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
      'EXP-EDH-RSA-DES-CBC-SHA', // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
      'EDH-RSA-DES-CBC-SHA', // TLS_DHE_RSA_WITH_DES_CBC_SHA
      'EDH-RSA-DES-CBC3-SHA', // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
      'EXP-ADH-RC4-MD5', // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
      'EXP-ADH-DES-CBC-SHA', // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
      'ADH-DES-CBC-SHA', // TLS_DH_anon_WITH_DES_CBC_SHA

      // AES ciphersuites from RFC3268
      'AES128-SHA', // TLS_RSA_WITH_AES_128_CBC_SHA
      'AES256-SHA', // TLS_RSA_WITH_AES_256_CBC_SHA
      'DH-DSS-AES128-SHA', // TLS_DH_DSS_WITH_AES_128_CBC_SHA
      'DH-DSS-AES256-SHA', // TLS_DH_DSS_WITH_AES_256_CBC_SHA
      'DH-RSA-AES128-SHA', // TLS_DH_RSA_WITH_AES_128_CBC_SHA
      'DH-RSA-AES256-SHA', // TLS_DH_RSA_WITH_AES_256_CBC_SHA
      'DHE-DSS-AES128-SHA', // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
      'DHE-DSS-AES256-SHA', // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
      'DHE-RSA-AES128-SHA', // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
      'DHE-RSA-AES256-SHA', // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
      'ADH-AES128-SHA', // TLS_DH_anon_WITH_AES_128_CBC_SHA
      'ADH-AES256-SHA', // TLS_DH_anon_WITH_AES_256_CBC_SHA

      // Camellia ciphersuites from RFC4132
      'CAMELLIA128-SHA', // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
      'CAMELLIA256-SHA', // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
      'DH-DSS-CAMELLIA128-SHA', // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
      'DH-DSS-CAMELLIA256-SHA', // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
      'DH-RSA-CAMELLIA128-SHA', // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
      'DH-RSA-CAMELLIA256-SHA', // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
      'DHE-DSS-CAMELLIA128-SHA', // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
      'DHE-DSS-CAMELLIA256-SHA', // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
      'DHE-RSA-CAMELLIA128-SHA', // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
      'DHE-RSA-CAMELLIA256-SHA', // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
      'ADH-CAMELLIA128-SHA', // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
      'ADH-CAMELLIA256-SHA', // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA

      // SEED ciphersuites from RFC4162
      'SEED-SHA', // TLS_RSA_WITH_SEED_CBC_SHA
      'DH-DSS-SEED-SHA', // TLS_DH_DSS_WITH_SEED_CBC_SHA
      'DH-RSA-SEED-SHA', // TLS_DH_RSA_WITH_SEED_CBC_SHA
      'DHE-DSS-SEED-SHA', // TLS_DHE_DSS_WITH_SEED_CBC_SHA
      'DHE-RSA-SEED-SHA', // TLS_DHE_RSA_WITH_SEED_CBC_SHA
      'ADH-SEED-SHA', // TLS_DH_anon_WITH_SEED_CBC_SHA

      // GOST ciphersuites from draft-chudov-cryptopro-cptls
      // 'GOST94-GOST89-GOST89', // TLS_GOSTR341094_WITH_28147_CNT_IMIT
      // 'GOST2001-GOST89-GOST89', // TLS_GOSTR341001_WITH_28147_CNT_IMIT
      // 'GOST94-NULL-GOST94', // TLS_GOSTR341094_WITH_NULL_GOSTR3411
      // 'GOST2001-NULL-GOST94', // TLS_GOSTR341001_WITH_NULL_GOSTR3411

      // Additional Export 1024 and other cipher suites
      'EXP1024-DES-CBC-SHA', // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
      'EXP1024-RC4-SHA', // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
      'EXP1024-DHE-DSS-DES-CBC-SHA', // TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
      'EXP1024-DHE-DSS-RC4-SHA', // TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
      'DHE-DSS-RC4-SHA', // TLS_DHE_DSS_WITH_RC4_128_SHA

      // Elliptic curve cipher suites
      'ECDH-RSA-NULL-SHA', // TLS_ECDH_RSA_WITH_NULL_SHA
      'ECDH-RSA-RC4-SHA', // TLS_ECDH_RSA_WITH_RC4_128_SHA
      'ECDH-RSA-DES-CBC3-SHA', // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
      'ECDH-RSA-AES128-SHA', // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
      'ECDH-RSA-AES256-SHA', // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
      'ECDH-ECDSA-NULL-SHA', // TLS_ECDH_ECDSA_WITH_NULL_SHA
      'ECDH-ECDSA-RC4-SHA', // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
      'ECDH-ECDSA-DES-CBC3-SHA', // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
      'ECDH-ECDSA-AES128-SHA', // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
      'ECDH-ECDSA-AES256-SHA', // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
      'ECDHE-RSA-NULL-SHA', // TLS_ECDHE_RSA_WITH_NULL_SHA
      'ECDHE-RSA-RC4-SHA', // TLS_ECDHE_RSA_WITH_RC4_128_SHA
      'ECDHE-RSA-DES-CBC3-SHA', // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
      'ECDHE-RSA-AES128-SHA', // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
      'ECDHE-RSA-AES256-SHA', // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      'ECDHE-ECDSA-NULL-SHA', // TLS_ECDHE_ECDSA_WITH_NULL_SHA
      'ECDHE-ECDSA-RC4-SHA', // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
      'ECDHE-ECDSA-DES-CBC3-SHA', // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
      'ECDHE-ECDSA-AES128-SHA', // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
      'ECDHE-ECDSA-AES256-SHA', // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
      'AECDH-NULL-SHA', // TLS_ECDH_anon_WITH_NULL_SHA
      'AECDH-RC4-SHA', // TLS_ECDH_anon_WITH_RC4_128_SHA
      'AECDH-DES-CBC3-SHA', // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
      'AECDH-AES128-SHA', // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
      'AECDH-AES256-SHA', // TLS_ECDH_anon_WITH_AES_256_CBC_SHA

      // TLS v1.2 cipher suites
      'NULL-SHA256', // TLS_RSA_WITH_NULL_SHA256
      'AES128-SHA256', // TLS_RSA_WITH_AES_128_CBC_SHA256
      'AES256-SHA256', // TLS_RSA_WITH_AES_256_CBC_SHA256
      'AES128-GCM-SHA256', // TLS_RSA_WITH_AES_128_GCM_SHA256
      'AES256-GCM-SHA384', // TLS_RSA_WITH_AES_256_GCM_SHA384
      'DH-RSA-AES128-SHA256', // TLS_DH_RSA_WITH_AES_128_CBC_SHA256
      'DH-RSA-AES256-SHA256', // TLS_DH_RSA_WITH_AES_256_CBC_SHA256
      'DH-RSA-AES128-GCM-SHA256', // TLS_DH_RSA_WITH_AES_128_GCM_SHA256
      'DH-RSA-AES256-GCM-SHA384', // TLS_DH_RSA_WITH_AES_256_GCM_SHA384
      'DH-DSS-AES128-SHA256', // TLS_DH_DSS_WITH_AES_128_CBC_SHA256
      'DH-DSS-AES256-SHA256', // TLS_DH_DSS_WITH_AES_256_CBC_SHA256
      'DH-DSS-AES128-GCM-SHA256', // TLS_DH_DSS_WITH_AES_128_GCM_SHA256
      'DH-DSS-AES256-GCM-SHA384', // TLS_DH_DSS_WITH_AES_256_GCM_SHA384
      'DHE-RSA-AES128-SHA256', // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
      'DHE-RSA-AES256-SHA256', // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
      'DHE-RSA-AES128-GCM-SHA256', // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
      'DHE-RSA-AES256-GCM-SHA384', // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
      'DHE-DSS-AES128-SHA256', // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
      'DHE-DSS-AES256-SHA256', // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
      'DHE-DSS-AES128-GCM-SHA256', // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
      'DHE-DSS-AES256-GCM-SHA384', // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
      'ECDH-RSA-AES128-SHA256', // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
      'ECDH-RSA-AES256-SHA384', // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
      'ECDH-RSA-AES128-GCM-SHA256', // TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
      'ECDH-RSA-AES256-GCM-SHA384', // TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
      'ECDH-ECDSA-AES128-SHA256', // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
      'ECDH-ECDSA-AES256-SHA384', // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
      'ECDH-ECDSA-AES128-GCM-SHA256', // TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
      'ECDH-ECDSA-AES256-GCM-SHA384', // TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
      'ECDHE-RSA-AES128-SHA256', // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
      'ECDHE-RSA-AES256-SHA384', // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
      'ECDHE-RSA-AES128-GCM-SHA256', // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      'ECDHE-RSA-AES256-GCM-SHA384', // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      'ECDHE-ECDSA-AES128-SHA256', // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
      'ECDHE-ECDSA-AES256-SHA384', // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
      'ECDHE-ECDSA-AES128-GCM-SHA256', // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      'ECDHE-ECDSA-AES256-GCM-SHA384', // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      'ADH-AES128-SHA256', // TLS_DH_anon_WITH_AES_128_CBC_SHA256
      'ADH-AES256-SHA256', // TLS_DH_anon_WITH_AES_256_CBC_SHA256
      'ADH-AES128-GCM-SHA256', // TLS_DH_anon_WITH_AES_128_GCM_SHA256
      'ADH-AES256-GCM-SHA384', // TLS_DH_anon_WITH_AES_256_GCM_SHA384
      'AES128-CCM', // RSA_WITH_AES_128_CCM
      'AES256-CCM', // RSA_WITH_AES_256_CCM
      'DHE-RSA-AES128-CCM', // DHE_RSA_WITH_AES_128_CCM
      'DHE-RSA-AES256-CCM', // DHE_RSA_WITH_AES_256_CCM
      'AES128-CCM8', // RSA_WITH_AES_128_CCM_8
      'AES256-CCM8', // RSA_WITH_AES_256_CCM_8
      'DHE-RSA-AES128-CCM8', // DHE_RSA_WITH_AES_128_CCM_8
      'DHE-RSA-AES256-CCM8', // DHE_RSA_WITH_AES_256_CCM_8
      'ECDHE-ECDSA-AES128-CCM', // ECDHE_ECDSA_WITH_AES_128_CCM
      'ECDHE-ECDSA-AES256-CCM', // ECDHE_ECDSA_WITH_AES_256_CCM
      'ECDHE-ECDSA-AES128-CCM8', // ECDHE_ECDSA_WITH_AES_128_CCM_8
      'ECDHE-ECDSA-AES256-CCM8', // ECDHE_ECDSA_WITH_AES_256_CCM_8

      // Pre shared keying (PSK) cipheruites
      'PSK-NULL-SHA', // PSK_WITH_NULL_SHA
      'DHE-PSK-NULL-SHA', // DHE_PSK_WITH_NULL_SHA
      'RSA-PSK-NULL-SHA', // RSA_PSK_WITH_NULL_SHA
      'PSK-RC4-SHA', // PSK_WITH_RC4_128_SHA
      'PSK-3DES-EDE-CBC-SHA', // PSK_WITH_3DES_EDE_CBC_SHA
      'PSK-AES128-CBC-SHA', // PSK_WITH_AES_128_CBC_SHA
      'PSK-AES256-CBC-SHA', // PSK_WITH_AES_256_CBC_SHA
      'DHE-PSK-RC4-SHA', // DHE_PSK_WITH_RC4_128_SHA
      'DHE-PSK-3DES-EDE-CBC-SHA', // DHE_PSK_WITH_3DES_EDE_CBC_SHA
      'DHE-PSK-AES128-CBC-SHA', // DHE_PSK_WITH_AES_128_CBC_SHA
      'DHE-PSK-AES256-CBC-SHA', // DHE_PSK_WITH_AES_256_CBC_SHA
      'RSA-PSK-RC4-SHA', // RSA_PSK_WITH_RC4_128_SHA
      'RSA-PSK-3DES-EDE-CBC-SHA', // RSA_PSK_WITH_3DES_EDE_CBC_SHA
      'RSA-PSK-AES128-CBC-SHA', // RSA_PSK_WITH_AES_128_CBC_SHA
      'RSA-PSK-AES256-CBC-SHA', // RSA_PSK_WITH_AES_256_CBC_SHA
      'DHE-PSK-AES128-GCM-SHA256', // DHE_PSK_WITH_AES_128_GCM_SHA256
      'DHE-PSK-AES256-GCM-SHA384', // DHE_PSK_WITH_AES_256_GCM_SHA384
      'RSA-PSK-AES128-GCM-SHA256', // RSA_PSK_WITH_AES_128_GCM_SHA256
      'RSA-PSK-AES256-GCM-SHA384', // RSA_PSK_WITH_AES_256_GCM_SHA384
      'PSK-AES128-CBC-SHA256', // PSK_WITH_AES_128_CBC_SHA256
      'PSK-AES256-CBC-SHA384', // PSK_WITH_AES_256_CBC_SHA384
      'PSK-NULL-SHA256', // PSK_WITH_NULL_SHA256
      'PSK-NULL-SHA384', // PSK_WITH_NULL_SHA384
      'DHE-PSK-AES128-CBC-SHA256', // DHE_PSK_WITH_AES_128_CBC_SHA256
      'DHE-PSK-AES256-CBC-SHA384', // DHE_PSK_WITH_AES_256_CBC_SHA384
      'DHE-PSK-NULL-SHA256', // DHE_PSK_WITH_NULL_SHA256
      'DHE-PSK-NULL-SHA384', // DHE_PSK_WITH_NULL_SHA384
      'RSA-PSK-AES128-CBC-SHA256', // RSA_PSK_WITH_AES_128_CBC_SHA256
      'RSA-PSK-AES256-CBC-SHA384', // RSA_PSK_WITH_AES_256_CBC_SHA384
      'RSA-PSK-NULL-SHA256', // RSA_PSK_WITH_NULL_SHA256
      'RSA-PSK-NULL-SHA384', // RSA_PSK_WITH_NULL_SHA384
      'PSK-AES128-GCM-SHA256', // PSK_WITH_AES_128_GCM_SHA256
      'PSK-AES256-GCM-SHA384', // PSK_WITH_AES_256_GCM_SHA384
      'ECDHE-PSK-RC4-SHA', // ECDHE_PSK_WITH_RC4_128_SHA
      'ECDHE-PSK-3DES-EDE-CBC-SHA', // ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
      'ECDHE-PSK-AES128-CBC-SHA', // ECDHE_PSK_WITH_AES_128_CBC_SHA
      'ECDHE-PSK-AES256-CBC-SHA', // ECDHE_PSK_WITH_AES_256_CBC_SHA
      'ECDHE-PSK-AES128-CBC-SHA256', // ECDHE_PSK_WITH_AES_128_CBC_SHA256
      'ECDHE-PSK-AES256-CBC-SHA384', // ECDHE_PSK_WITH_AES_256_CBC_SHA384
      'ECDHE-PSK-NULL-SHA', // ECDHE_PSK_WITH_NULL_SHA
      'ECDHE-PSK-NULL-SHA256', // ECDHE_PSK_WITH_NULL_SHA256
      'ECDHE-PSK-NULL-SHA384', // ECDHE_PSK_WITH_NULL_SHA384
      'PSK-CAMELLIA128-SHA256', // PSK_WITH_CAMELLIA_128_CBC_SHA256
      'PSK-CAMELLIA256-SHA384', // PSK_WITH_CAMELLIA_256_CBC_SHA384
      'DHE-PSK-CAMELLIA128-SHA256', // DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
      'DHE-PSK-CAMELLIA256-SHA384', // DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
      'RSA-PSK-CAMELLIA128-SHA256', // RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
      'RSA-PSK-CAMELLIA256-SHA384', // RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
      'ECDHE-PSK-CAMELLIA128-SHA256', // ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
      'ECDHE-PSK-CAMELLIA256-SHA384', // ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
      'PSK-AES128-CCM', // PSK_WITH_AES_128_CCM
      'PSK-AES256-CCM', // PSK_WITH_AES_256_CCM
      'DHE-PSK-AES128-CCM', // DHE_PSK_WITH_AES_128_CCM
      'DHE-PSK-AES256-CCM', // DHE_PSK_WITH_AES_256_CCM
      'PSK-AES128-CCM8', // PSK_WITH_AES_128_CCM_8
      'PSK-AES256-CCM8', // PSK_WITH_AES_256_CCM_8
      'DHE-PSK-AES128-CCM8', // DHE_PSK_WITH_AES_128_CCM_8
      'DHE-PSK-AES256-CCM8', // DHE_PSK_WITH_AES_256_CCM_8

      // Camellia HMAC-Based ciphersuites from RFC6367
      'ECDHE-ECDSA-CAMELLIA128-SHA256', // TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
      'ECDHE-ECDSA-CAMELLIA256-SHA384', // TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
      'ECDHE-RSA-CAMELLIA128-SHA256', // TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
      'ECDHE-RSA-CAMELLIA256-SHA384', // TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384

      // ChaCha20-Poly1305 cipher suites
      'ECDHE-RSA-CHACHA20-POLY1305', // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      'ECDHE-ECDSA-CHACHA20-POLY1305', // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      'DHE-RSA-CHACHA20-POLY1305', // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      'PSK-CHACHA20-POLY1305', // TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
      'ECDHE-PSK-CHACHA20-POLY1305', // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
      'DHE-PSK-CHACHA20-POLY1305', // TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
      'RSA-PSK-CHACHA20-POLY1305' // TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
    ]
    private static suitesString: string

    constructor()
    constructor(options: ConnectionOptions)
    public static getCipherSuitesString(): string
    public static getCipherSuitesString(list: string[]): string
    /**
     * Test executes using all supported protocols (ProtocolVersion.getSupportedProtocols())
     * @param cipher I.e.: 'AES128-GCM-SHA256'
     */
    test(cipher: string): Promise<CipherResult>
    /**
     * @param cipher I.e.: 'AES128-GCM-SHA256'
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     */
    test(cipher: string, protocols: string[]): Promise<CipherResult>
    /**
     * @param cipher I.e.: 'AES128-GCM-SHA256'
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     */
    test(cipher: string, protocols: string[], timeout: number): Promise<CipherResult>
    /**
     * @param cipher I.e.: 'AES128-GCM-SHA256'
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     */
    test(cipher: string, protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<CipherResult>
    /**
     * @param cipher I.e.: 'AES128-GCM-SHA256'
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     */
    test(cipher: string, protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<CipherResult>
    /**
     * Test executes using all supported protocols (ProtocolVersion.getSupportedProtocols())
     * @param ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
     */
    testMultiple(ciphers: string[]): Promise<CipherResult[]>
    /**
     * @param ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     */
    testMultiple(ciphers: string[], protocols: string[]): Promise<CipherResult[]>
    /**
     * @param ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     */
    testMultiple(ciphers: string[], protocols: string[], timeout: number): Promise<CipherResult[]>
    /**
     * @param ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     */
    testMultiple(ciphers: string[], protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<CipherResult[]>
    /**
     * @param ciphers I.e.: [ 'AES128-GCM-SHA256', 'AES128-SHA']
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]. defaults to result of ProtocolVersion.getSupportedProtocols()
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     */
    testMultiple(ciphers: string[], protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<CipherResult[]>
    static filterEnabled(cipherResults: CipherResult[]): CipherResult[]
    static filterDisabled(cipherResults: CipherResult[]): CipherResult[]
    static filterUnsupported(cipherResults: CipherResult[]): CipherResult[]
  }

  export class HostAddressResult {
    host: string
    address: string
    family: number
  }

  export class DnsHelper {
    public static lookup(host: string): Promise<HostAddressResult[]>
  }

  export class ProtocolVersionResult {
    host: string
    port: number
    ipAddress: HostAddressResult[]
    /**
     * Example: TLS1_2
     */
    protocol: string
    /**
     * Protocols that are supported by the current Node.JS version and accepted by the Service
     * @see {ProtocolVersion.protocols}
     */
    enabled: HostAddressResult[]
    /**
     * Protocols that are supported by the current Node.JS version but NOT accepted by the Service
     * @see {ProtocolVersion.protocols}
     */
    disabled: HostAddressResult[]
    /**
     * Protocols that are NOT supported by the current Node.JS version
     * @see {ProtocolVersion.protocols}
     */
    unsupported: HostAddressResult[]
    /**
     * Warnings; I.e. host has multiple ip addresses
     */
    warnings: string[]
  }

  export class ProtocolVersion extends TlsSocketWrapper {
    public static readonly protocols: [
      'SSLv2',
      'SSLv3',
      'TLSv1',
      'TLSv1_1',
      'TLSv1_2',
      'TLSv1_3'
    ]
    public static readonly protocolName: {
      SSLv2: string
      SSLv3: string
      TLSv1: string
      TLSv1_1: string
      TLSv1_2: string
      TLSv1_3: string
    }

    constructor()
    constructor(options: ConnectionOptions)
    /**
     * @param protocol I.e.: TLSv1_2
     */
    protected static map(protocol: 'SSLv2' | 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3'): 'SSLv2_method' | 'SSLv3_method' | 'TLSv1_method' | 'TLSv1_1_method' | 'TLSv1_2_method' | 'TLSv1_3_method' | ''
    public static getSupportedProtocols(): string[] | [
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
     * @param protocol I.e.: TLSv1_2
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @see {ProtocolVersion.setTimeout}
     * @param ipVersions default is [4, 6]
     */
    test(protocol: 'SSLv3' | 'TLSv1' | 'TLSv1' | 'TLSv1_1' | 'TLSv1_2' | 'TLSv1_3', timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<ProtocolVersionResult>
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
    /**
     * @param protocols I.e.: [ 'TLSv1_1', 'TLSv1_2' ]
     * @param timeout -1 is default, which means: don't change the current timeout value
     * @param ipVersions default is [4, 6]
     * @see {ProtocolVersion.setTimeout}
     */
    testMultiple(protocols: string[], timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<ProtocolVersionResult[]>
  }

  export class TlsServiceAuditResult {
    certificates: HostAddressSpecificCertificateResult[]
    ciphers: CipherResult[]
    protocols: ProtocolVersionResult[]
  }

  export class TlsServiceAudit extends TimeOutableSocket {
    protected readonly options: ConnectionOptions
    constructor()
    constructor(options: ConnectionOptions)
    updateOptions(options: ConnectionOptions): void
    /**
     * @see {ProtocolVersion.protocols}
     */
    setProtocols(protocols: string[]): void
    /**
     * @see {Cipher.suites}
     */
    setCiphers(ciphers: string[]): void
    run(): Promise<TlsServiceAuditResult>
    run(timeout: number): Promise<TlsServiceAuditResult>
    run(timeout: number, ipVersions: [4] | [6] | [4, 6]): Promise<TlsServiceAuditResult>
    run(timeout: number, ipVersions: [4] | [6] | [4, 6], addresses: HostAddressResult[]): Promise<TlsServiceAuditResult>
  }
}
