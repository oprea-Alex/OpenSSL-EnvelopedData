# OpenSSL-EnvelopedData
C implementation of the PKCS# 7 (CMS) format "Enveloped Data" using the OpenSSL library and the RecipientInfo structure defined in OpenSSL/pkcs7.h.

The output can be parsed using openssl.exe(1.1.1b in this example):
1. openssl.exe pkcs7 -inform der -in .\envelope.out -out .\openssl.envelope

2.openssl.exe pkcs7 -in .\openssl.envelope -print

One can use openssl.exe cms instead of pkcs7!!!
