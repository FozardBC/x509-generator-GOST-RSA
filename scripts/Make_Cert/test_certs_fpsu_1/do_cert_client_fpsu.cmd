openssl genrsa -out Client2_test_ocsp.key 2048

openssl req -new -nodes -keyout Client2_test_ocsp.key -out Client2_test_ocsp.csr -days 365 -config ssl2.conf

openssl x509 -req -days 365 -in Client2_test_ocsp.csr -CA ami_ca2.pem -CAkey ami_ca2.key -out Client2_test_ocsp.crt -extensions v3_ca -extfile ssl2.conf

openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey Client2_test_ocsp.key -in Client2_test_ocsp.crt -passout pass:1234 -name "Client2_test_ocsp" -out Client2_test_ocsp.pfx
