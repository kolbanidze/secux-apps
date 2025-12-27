#!/bin/bash

rm -f security-manager.tar.gz
rm -f *.tar.zst
rm -f *.tar.zst.sig
rm -rf pkg src

tar --exclude='.git' \
    --exclude='security-manager.tar.gz' \
    --exclude='pkg' \
    --exclude='src' \
    -czvf security-manager.tar.gz security-manager/
updpkgsums

makepkg -f --sign