#!/bin/bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm

nvm install $(cat ./.nvmrc)
nvm use $(cat ./.nvmrc)
npm install
npm rebuild
nvm use default
