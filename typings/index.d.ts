/// <reference path="X509.d.ts" />
/// <reference path="sslinfo.d.ts" />

interface ConfigDomain {
  host: string,
  port?: number,
  ignore?: Warning[]
}
