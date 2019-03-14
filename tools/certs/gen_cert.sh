#!/bin/bash
mkdir private newcerts
touch index.txt
touch index.txt.attr

openssl genrsa -out private/rootCA.key 4096
openssl req -x509 -new -nodes -key private/rootCA.key -sha256 -days 1024 -out rootCA.crt -config ca.cnf
# openssl pkcs12 -nodes -password pass:password -in rootCA.crt -export -nokeys -out rootCA.pfx

openssl genrsa -out example.org.key 2048
openssl req -new -key example.org.key -out example.org.csr -config san.cnf
openssl ca -batch -config ca.cnf -in example.org.csr -out example.org.crt -create_serial

openssl genrsa -out revoked.org.key 2048
openssl req -new -key revoked.org.key -out revoked.org.csr -config revoked.cnf

openssl ca -batch -config ca.cnf -in revoked.org.csr -out revoked.org.crt -create_serial

openssl ca -revoke revoked.org.crt -config ca.cnf

rm *.csr
rm *.old

# Append the issuer cert to make it a valid chain for use in tests
cat rootCA.crt >> example.org.crt
cat rootCA.crt >> revoked.org.crt
