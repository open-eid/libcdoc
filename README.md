# libcdoc

A encryption/decryption library for CDoc container format.

## Fetures

- CDoc1 encryption by certificate (RSA/ECC)
- CDoc1 decryption (PKSC11/NCrypt private key)
- CDoc2 encryption by public key (RSA/ECC)
- CDoc2 decryption by private key (PKSC11/NCrypt)
- CDoc2 keyserver support
- CDoc2 symmetric encryption (AES)
- CDoc2 symmetrik encryption (password-based)

## Building

  cmake -S . -B build
  cmake --build build
