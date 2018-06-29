/// <reference path="X509.d.ts" />
/// <reference path="sslinfo.d.ts" />

interface ConfigDomain {
  host: string,
  port?: number,
  ignore?: string[]
}

interface Task extends ConfigDomain {
  id: string,
  webhook?: string,
  callback?: string
}

interface TaskResult {
  id: string,
  host: string,
  port: number,
  items: string[]
  error?: string
}
