interface X509 {
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

interface Cipher {
  SSLv2_method: TlsMethod
  SSLv3_method: TlsMethod
  TLSv1_method: TlsMethod
  TLSv1_1_method: TlsMethod
  TLSv1_2_method: TlsMethod
}

interface TlsMethod {
  name: string
  enabled: string[]
  disabled: string[]
  unsupported: string[]
}

interface TlsProtocol {
  protocol: string
  name: string
  enabled: boolean
  error: string
}

interface X509Extensions {
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

interface X509PublicKey {
  algorithm: string
  e: string
  n: string
  bitSize: number
}

interface X509Identity {
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
