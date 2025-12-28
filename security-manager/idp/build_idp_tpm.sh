#!/bin/bash
python -m nuitka \
  --standalone \
  --onefile \
  --lto=yes \
  --plugin-enable=upx \
  --upx-binary=/usr/bin/upx \
  --output-filename=idp-tpm \
  --remove-output \
  idp-tpm.py