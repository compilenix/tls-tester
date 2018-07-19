// Type definitions for tlsinfo x.x
// Project: https://github.com/baz/foo (Does not have to be to GitHub, but prefer linking to a source code repository rather than to a project website.)
// Definitions by: My Self <https://github.com/me>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
import { X509 } from 'x509'

declare module tlsinfo {
  export interface CertificateResult {
    host: string
    port: number
    cert: X509
    certPem: string
    certCa?: X509
    certCaPem: string
  }
}
