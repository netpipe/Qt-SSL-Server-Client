#!/bin/bash
openssl genrsa -out client_local.key 2048
openssl req -new -key client_local.key -out client_local.pem \
   -subj "/C=US/ST=Massachusetts/L=Boston/O=XYZ Inc/CN=api.xyz.com/emailAddress=info@xyz.com"
openssl x509 -req -days 2000 -in client_local.pem -signkey client_local.key -out client_ca.pem
