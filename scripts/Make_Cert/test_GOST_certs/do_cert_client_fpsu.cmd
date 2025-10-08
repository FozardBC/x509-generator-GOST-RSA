C:\OpenSSL\bin\openssl.exe genrsa -out 1_test_client.key 2048

C:\OpenSSL\bin\openssl.exe req -new -nodes -keyout 1_test_client.key -out 1_test_client.csr -days 365 -config ssl2.conf

C:\OpenSSL\bin\openssl.exe x509 -req -days 365 -in client1_fpsu.csr -CA CA_cert.pem -CAkey CA_private_key.pem -out client1_fpsu.crt -extensions v3_ca -extfile ssl2.conf

