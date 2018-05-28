#!/bin/bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ ! -d "./node_modules" ] && ./initDev.sh

nvm use $(cat ./.nvmrc)
nvm run $*
nvm use default
