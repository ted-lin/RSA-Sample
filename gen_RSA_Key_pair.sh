#!/bin/bash

echo "generate key-pair [ private.key & public.key ]"
echo "openssl genrsa -out private.key 1024"
openssl genrsa -out private.key 1024
echo "openssl rsa -in private.key -pubout > public.key"
openssl rsa -in private.key -pubout > public.key
echo "convert private key to der type"
openssl rsa -in private.key -outform DER -out der_private.key
echo "this operation will override origin key-pair, be careful!!"
rm private.key


