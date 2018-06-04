## Usage
* install nvm (https://github.com/creationix/nvm)
* `cp config.example.js config.js`
* edit config.js
* run `npm start`
* profit!

## Demo
### Slack
![screenshot1](https://git.compilenix.org/Compilenix/tls-tester/raw/master/screenshot1.png)

### CLI
All config settings (or defaults via `config.example.js`) are overwritten by cli parameters!

```bash
node index.js --enableSlack false --domains www.microsoft.com,expired.badssl.com --ignore Expire,PubKeySize
```

![screenshot2](https://git.compilenix.org/Compilenix/tls-tester/raw/master/screenshot2.png)
