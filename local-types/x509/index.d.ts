// Type definitions for x509 x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// export as namespace x509

declare module 'x509' {
  export const version: string

  /**
   * Performs basic certificate validation against a bundle of ca certificates
   *
   * It accepts an error-first callback as first argument. If the error is null, then the certificate is valid.
   *
   * The error messages are the same returned by openssl: [x509_verify_cert_error_string]{@link https://www.openssl.org/docs/man1.0.2/crypto/X509_STORE_CTX_get_error.html}
   *
   * **Note**: As now, this function only accepts absolute paths to existing files as arguments
   * @param certPath
   * @param CABundlePath
   * @param callback
   */
  export function verify(certPath: string, CABundlePath: string, callback: (error: any, result: any) => void): boolean

  /**
   * @param cert may be a filename or a raw base64 encoded PEM string in any of these methods
   */
  export function getAltNames(cert: string): string[]

  /**
   * Parse certificate with x509.parseCert and return the subject.
   * @param cert may be a filename or a raw base64 encoded PEM string in any of these methods
   */
  export function getSubject(cert: string): X509Identity

  /**
   * Parse certificate with x509.parseCert and return the issuer.
   * @param cert may be a filename or a raw base64 encoded PEM string in any of these methods
   */
  export function getIssuer(cert: string): X509Identity

  /**
   * Parse subject, issuer, valid before and after date, and alternate names from certificate.
   * @param path may be a filename or a raw base64 encoded PEM string in any of these methods
   */
  export function parseCert(path: string): X509

  export interface X509 {
    version: number
    subject: X509Identity
    issuer: X509Identity
    serial: string
    notBefore: Date
    notAfter: Date
    subjectHash: string
    signatureAlgorithm: string
    fingerPrint: string
    publicKey: X509PublicKey
    extensions: X509Extensions
    altNames: string[]
  }

  export interface Cipher {
    SSLv2_method: TlsMethod
    SSLv3_method: TlsMethod
    TLSv1_method: TlsMethod
    TLSv1_1_method: TlsMethod
    TLSv1_2_method: TlsMethod
  }

  export interface TlsMethod {
    name: string
    enabled: string[]
    disabled: string[]
    unsupported: string[]
  }

  export interface TlsProtocol {
    protocol: string
    name: string
    enabled: boolean
    error: string
  }

  export interface X509Extensions {
    authorityKeyIdentifier: string
    subjectKeyIdentifier: string
    subjectAlternativeName: string
    keyUsage: string
    extendedKeyUsage: string
    cRLDistributionPoints: string
    certificatePolicies: string
    authorityInformationAccess: string
    basicConstraints: string
    cTPrecertificateSCTs: string
  }

  export interface X509PublicKey {
    algorithm: string
    e: string
    n: string
    bitSize: number
  }

  export interface X509Identity {
    countryName: string
    postalCode: string
    stateOrProvinceName: string
    localityName: string
    streetAddress: string
    organizationName: string
    organizationalUnitName: string
    commonName: string
    businessCategory: string
    jurisdictionCountryName: string
    jurisdictionStateOrProvinceName: string
    serialNumber: string
  }
}
