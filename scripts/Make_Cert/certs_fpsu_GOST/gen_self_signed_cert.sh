#!/bin/bash

: ${1?"Usage: $0 DOMAIN"}

cert_dir="$(pwd)/certificates"

domain=$1

pk_name="server.nopass.key"
cert_name="server.crt"

# validity
days=365
# Country code [XX]
C="RU"
# City
L="Moscow"
# Organization
O="Default Company Ltd"
# E-mail
E="support@${domain}"

# SCRIPT
mkdir -p ${cert_dir}/${domain}
cd ${cert_dir}/${domain}
echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = DNS:*.${domain}, DNS:${domain}
extendedKeyUsage = serverAuth, clientAuth" > ${domain}.ext
echo "[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
CN = *.${domain}
emailAddress = ${E}
O = ${O}
L = ${L}
C = ${C}

[ req_ext ]
subjectAltName = DNS:*.${domain}, DNS:${domain}
extendedKeyUsage = serverAuth, clientAuth
" > ${domain}.cnf

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out ca_${domain}.key

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out ${pk_name}

openssl req \
    -x509 \
    -new \
    -nodes \
    -key ca_${domain}.key \
    -sha256 \
    -days 7300 \
    -subj "/C=${C}/ST=/L=${L}/O=${O}/emailAddress=${E}" \
    -out ca.crt

openssl req \
    -new \
    -config ${domain}.cnf \
    -key ${pk_name} \
    -out ${domain}.csr

openssl x509 \
    -req \
    -days ${days} \
    -sha256 \
    -in ${domain}.csr \
    -CA ca.crt \
    -CAkey ca_${domain}.key \
    -CAcreateserial \
    -out ${cert_name} \
    -extfile ${domain}.ext

rm -f ${domain}.{ext,cnf,csr}
printf "
\033[01;33m#######################################\033[00m
\033[01;33m#######\033[00m         \033[01;31mREPORT\033[00m         \033[01;33m########\033[00m
\033[01;33m#######################################\033[00m
\033[01;32mFind certificate in:\033[00m
\033[01;34m$(pwd)\033[00m
\033[01;33m#######################################\033[00m
\033[01;32mCA:\033[00m $(openssl x509 -in ca_${domain}.crt -subject -dates -noout)
\033[01;33m#######################################\033[00m
\033[01;32mWildcard:\033[00m $(openssl x509 -in ${cert_name} -subject -dates -noout)
"
cd - > /dev/null

# Test key and certificate
openssl x509 -noout -modulus -in ${cert_dir}/${domain}/${cert_name} | openssl md5
openssl rsa -noout -modulus -in ${cert_dir}/${domain}/${pk_name} | openssl md5
