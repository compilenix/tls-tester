const { TlsServiceAudit, TlsServiceAuditResult } = require('./lib/TlsServiceAudit')
const { Certificate, CertificateResult, HostAddressSpecificCertificateResult } = require('./lib/Certificate')
const { ProtocolVersion, ProtocolVersionResult } = require('./lib/ProtocolVersion')
const { Cipher, CipherResult, ProtocolVersionSpecificCipherResult } = require('./lib/Cipher')

module.exports = {
  TlsServiceAudit: TlsServiceAudit,
  TlsServiceAuditResult: TlsServiceAuditResult,
  Certificate: Certificate,
  CertificateResult: CertificateResult,
  HostAddressSpecificCertificateResult: HostAddressSpecificCertificateResult,
  ProtocolVersion: ProtocolVersion,
  ProtocolVersionResult: ProtocolVersionResult,
  Cipher: Cipher,
  ProtocolVersionSpecificCipherResult: ProtocolVersionSpecificCipherResult,
  CipherResult: CipherResult,
  TlsSocketWrapper: ProtocolVersion,
  TimeOutableSocket: ProtocolVersion
}
