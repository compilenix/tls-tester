# How it looks
## Slack
![screenshot1](https://git.compilenix.org/Compilenix/tls-tester/raw/master/screenshot1.png)

## CLI
All config settings (or defaults via `config.example.js`) are overwritten by cli parameters!

```bash
node index.js --enableSlack false --domains www.microsoft.com,expired.badssl.com --ignore Expire,PubKeySize
```

![screenshot2](https://git.compilenix.org/Compilenix/tls-tester/raw/master/screenshot2.png)

# Usage
* install nvm (https://github.com/creationix/nvm)
* `cp config.example.js config.js`
* edit config.js
* run `npm start`
* profit!

## Use as a Service
* `npm start`
* `curl -v -H 'content-type: text/json' --data '{ "host": "mozilla-old.badssl.com", "callback":"http://callbackUrl" }' http://localhost:16636/api/enqueue`

# What it can test / cover
* basic connectivity (connection timeout, conn-reset, conn-refused, ...)
* certificate is about to expire or is expired
* certificate is not yet valid
* existence of subjectAltNames
* subjectAltName does include a matching hostname (also working with wildcards)
* public key size is greater or equal to 4096
* weak signature algorithm (sha1 or md*)
* weak / outdated protocols: SSLv2, SSLv3
* modern protocol not supported / enabled: TLS 1.2
* CT (Certificate Transparency)
* intermediate ca (if chain is sent by server):
  * public key size of intermediate ca (is greater or equal to 2048)
  * weak signature algorithm of intermediate ca (sha1 or md*)
* weak / outdated ciphers:
  * RC*
  * MD5
  * DES
  * Trpple DES (3DES)
  * ... for the complete List search for "checkWeakCipherUsage" in this repo

# What it won't test / cover for you
* certificates in chain not send by the server
* Extended Validation
* OCSP Must Staple
* OCSP stapling
* Certificate Revocation
* SSLv2 cipher
* SSLv3 cipher
* Forward Secrecy
* Is trusted by common trust stores (Mozilla, Apple, Android, Java, Windows)
* Client Handshake Simulation (i.e.: Java 8, Firefox, Android)
* DROWN Attack
* BEAST attack
* POODLE (SSLv3)
* POODLE (TLS)
* Downgrade attack prevention
* Weak key (Debian)
* Uses common DH primes
* SSL/TLS compression
* Heartbeat and it's vulnerability (https://community.qualys.com/blogs/securitylabs/2014/04/08/ssl-labs-test-for-the-heartbleed-attack)
* Ticketbleed (vulnerability)
* OpenSSL CCS vuln. (CVE-2014-0224)
* OpenSSL Padding Oracle vuln.
(CVE-2016-2107)
* ROBOT (vulnerability)
* TLS Session resumption (caching)
* TLS Session resumption (tickets)
* Long handshake intolerance
* TLS extension intolerance
* TLS version intolerance
* ECDH public server param reuse
* SSL 2 handshake compatibility
* ALPN (Application-Layer Protocol Negotiation)
* NPN (Next Protocol Negotiation) NOTE: ALPN replaces NPN

## What it never will test / cover for you, by design
* Strict Transport Security (HSTS)
* HSTS Preloading
* Public Key Pinning (HPKP)
* DNS CAA

These do not diectly apply to TLS or SSL and could maybe integrated in:
* https://git.compilenix.org/Compilenix/http-tester
* https://git.compilenix.org/Compilenix/dns-tester
