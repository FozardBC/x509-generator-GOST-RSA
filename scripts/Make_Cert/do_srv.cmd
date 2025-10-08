C:\OpenSSL\bin\openssl.exe genrsa -out 192.168.12.38.key 2048

C:\OpenSSL\bin\openssl.exe req -new -nodes -keyout 192.168.12.38.key -out 192.168.12.38.csr -days 3650 -config ssl1.conf

C:\OpenSSL\bin\openssl.exe x509 -req -days 3650 -in tpm-no-pin.csr -CA amicon_ca_5.crt -CAkey amicon_ca_5.key -out tpm-no-pin.crt

----------------------------


C:\OpenSSL\bin\openssl.exe genrsa -out client3_fpsu.key 2048

C:\OpenSSL\bin\openssl.exe req -new -nodes -keyout client3_fpsu.key -out client3_fpsu.csr -days 365 -config ssl2.conf

C:\OpenSSL\bin\openssl.exe x509 -req -days 365 -in client3_fpsu.csr -CA ami_ca.crt -CAkey ami_ca.key -out client3_fpsu.crt -extensions v3_ca -extfile ssl2.conf



pfx
----
C:\OpenSSL\bin\openssl.exe pkcs12 -export -out server_fpsu.pfx -inkey server_fpsu.key -in server_fpsu_2.crt
C:\OpenSSL\bin\openssl.exe pkcs12 -export -out client_fpsu.pfx -inkey client_fpsu.key -in client_FPSU_3.cer


C:\OpenSSL\bin\openssl.exe pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey server_fpsu.key -in AMICON-CA.crt -in server_fpsu_2.crt -passout pass:1234 -name "FPSU_server" -out server_fpsu.pfx

C:\OpenSSL\bin\openssl.exe pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey GDR_cert.key -in GDR_cert.cer -passout pass:1234 -name "FPSU-IP Client GDR" -out GDR_cert.pfx


Извлечь из pfx:
openssl pkcs12 -in amicon_ca_5.pfx -nocerts -nodes -out amicon_ca_5.key
openssl pkcs12 -in amicon_ca_5.pfx -clcerts -nokeys -out amicon_ca_5.crt



-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

[ v3_ca ]

authorityKeyIdentifier=keyid,issuer

basicConstraints=CA:FALSE
keyUsage         = digitalSignature
extendedKeyUsage = clientAuth, codeSigning
privateKeyUsagePeriod = ASN1:SEQUENCE:privateKeyUsagePeriod
#keyUsage         = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment 
#extendedKeyUsage = clientAuth, codeSigning, emailProtection
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

1) Делаем сертифиак ЦА (сертификат в DER):
openssl req -x509 -newkey gost2012_256 -pkeyopt paramset:C -nodes -days 7300 -keyout AMICON_CA_sign_C.key -out AMICON_CA_sign_C.crt

2) создаём ключ и запрос (срок 1 год и 3 месяца):
openssl req -newkey gost2012_256 -pkeyopt paramset:C -nodes -keyout user_for_sign.key -out user_for_sign.csr -config ssl.conf -utf8

3) по запросу делаем сертификат:
openssl x509 -req -days 5475 -in user_for_sign.csr -CA AMICON_CA_sign_C.crt -CAkey AMICON_CA_sign_C.key -out user_for_sign.crt -extensions v3_ca -extfile ssl.conf -outform DER -utf8
