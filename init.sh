#!/bin/bash
unset npm_config_prefix
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" || {
  echo "you need nvm (https://github.com/creationix/nvm)"; exit 1
}

nvm install $(cat ./.nvmrc)
nvm use $(cat ./.nvmrc)
npm install
npm rebuild
nvm use default
