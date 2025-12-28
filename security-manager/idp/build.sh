#!/bin/bash

#requirements openssl, argon2, cjson

gcc idp_tpm.c -largon2 -lcjson -lsodium -o idp_tpm 
