#!/bin/bash

#openssl genrsa -des3 -out CA-key.pem 2048
#openssl req -new -key CA-key.pem -x509 -days 1000 -out CA-cert.pem

#openssl genrsa -des3 -out server-key.pem 2048 
#openssl req –new –config openssl.cnf –key server-key.pem –out signingReq.csr
#openssl x509 -req -days 365 -in signingReq.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out server-cert.pem

#openssl req -x509 -newkey rsa:2048 -keyout server.key -days 365 -out server.crt -nodes


openssl genrsa -out server_local.key 2048
openssl req -new -key server_local.key -out server_local.pem \
   -subj "/C=US/ST=Massachusetts/L=Boston/O=XYZ Inc/CN=api.xyz.com/emailAddress=info@xyz.com"
openssl x509 -req -days 2000 -in server_local.pem -signkey server_local.key -out server_ca.pem
