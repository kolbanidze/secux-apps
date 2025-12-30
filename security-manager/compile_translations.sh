#!/bin/bash

DOMAIN="org.secux.securitymanager"
LOCALE_DIR="locales"

echo "Compiling translations..."
msgfmt $LOCALE_DIR/ru/LC_MESSAGES/$DOMAIN.po -o $LOCALE_DIR/ru/LC_MESSAGES/$DOMAIN.mo
msgfmt $LOCALE_DIR/en/LC_MESSAGES/$DOMAIN.po -o $LOCALE_DIR/en/LC_MESSAGES/$DOMAIN.mo