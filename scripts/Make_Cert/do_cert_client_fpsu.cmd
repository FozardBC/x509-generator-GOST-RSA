C:\OpenSSL\bin\openssl.exe genrsa -out client3_fpsu.key 2048

C:\OpenSSL\bin\openssl.exe req -new -nodes -keyout client3_fpsu.key -out client3_fpsu.csr -days 365 -config ssl2.conf

C:\OpenSSL\bin\openssl.exe x509 -req -days 365 -in client3_fpsu.csr -CA ami_ca.crt -CAkey ami_ca.key -out client3_fpsu.crt -extensions v3_ca -extfile ssl2.conf

C:\OpenSSL\bin\openssl.exe pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey client3_fpsu.key -in client3_fpsu.crt -passout pass:1234 -name "FPSU-IP Client 3" -out client3_fpsu.pfx