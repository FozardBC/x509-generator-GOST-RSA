C:\OpenSSL\bin\openssl.exe
--------------------------------------------------------------

C:\OpenSSL\bin\openssl.exe genrsa -out server_fpsu.key 2048

C:\OpenSSL\bin\openssl.exe req -new -nodes -keyout server_fpsu_1.key -out server_fpsu_1.csr -days 3650 -config ssl1.conf

C:\OpenSSL\bin\openssl.exe x509 -req -days 3650 -in server_fpsu_1.csr -CA AMICON-CA.crt -CAkey AMICON-CA.key -out server_fpsu_1.crt -extensions v3_ca -extfile ssl1.conf

******************************************************************************************
Клиентские серт:

1) openssl genrsa -out kyzya_1.key 4096
2) openssl req -new -nodes -keyout kyzya_1.key -out kyzya_1.csr -days 365 -config ssl2.conf
3) openssl x509 -req -days 365 -in kyzya_1.csr -CA nafanya_CA2.cer -CAkey nafanya_CA2.key -out kyzya_1.cer -extensions v3_ca -extfile ssl2.conf
4) openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey ocsp_win_cli1.key -in ocsp_win_cli1.cer -passout pass:1234 -name "ocsp_win_cli1" -out ocsp_win_cli1.pfx

******************************************************************************************
SERVER sert:

1) openssl genrsa -out afonya_3.key 4096
2) openssl req -new -nodes -keyout afonya_3.key -out afonya_3.csr  -config ssl1.conf
3) openssl x509 -req -days 365 -in afonya_3.csr -CA nafanya_CA2.cer -CAkey nafanya_CA2.key -out afonya_3.cer -extensions v3_ca -extfile ssl1.conf
4) openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey afonya_3.key -in afonya_3.cer -passout pass:1234 -name "afonya_3" -out afonya_3.pfx

******************************************************************************************
OCSP sert:

1) openssl genrsa -out ocsp.key 4096
2) openssl req -new -nodes -keyout ocsp.key -out ocsp.csr -days 365 -config ssl_ocsp.conf
3) openssl x509 -req -days 365 -in ocsp.csr -CA ami_ca2.cer -CAkey ami_ca2.key -out ocsp.cer -extensions v3_ca -extfile ssl_ocsp.conf
4) openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey ocsp_client2.key -in ocsp_client2.cer -passout pass:1234 -name "ocsp_client2" -out ocsp_client2.pfx
pfx
----
C:\OpenSSL\bin\openssl.exe pkcs12 -export -out server_fpsu.pfx -inkey server_fpsu.key -in server_fpsu_2.crt
C:\OpenSSL\bin\openssl.exe pkcs12 -export -out client_fpsu.pfx -inkey client_fpsu.key -in client_FPSU_3.cer


Чтобы извлечь закрытую часть сертификата, выполните команду:
C:\OpenSSL\bin\openssl.exe pkcs12 -in fpsu.pfx -clcerts -nokeys -out fpsu1.crt
C:\OpenSSL\bin\openssl.exe pkcs12 -in fpsu.pfx -nocerts -out fpsu1.key


C:\OpenSSL\bin\openssl.exe pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey cli_OCSP_1.key -in ami_ca.pem -in Server22_FPSU.crt -passout pass:1234 -name "cli_OCSP_1" -out cli_OCSP_1.pfx

openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey Client1_test_ocsp.key -in Client1_test_ocsp.crt -passout pass:1234 -name "Client1_test_ocsp" -out Client1_test_ocsp.pfx


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Корневой и Промежуточный :


1) openssl genrsa -out nafanya_CA.key 4096
2) openssl req -x509 -new -keyout nafanya_CA.key -out nafanya_CA.cer -days 3650 -sha256 -config ca_ssl.conf -extensions v3_ca


1) openssl genrsa -out nafanya_CA3.key 4096
2) openssl req -new -key nafanya_CA3.key -out nafanya_CA3.csr
3) openssl x509 -req -days 3640 -in nafanya_CA3.csr -CA nafanya_CA.cer -CAkey nafanya_CA.key -out nafanya_CA3.cer -extensions v3_intermediate_ca -extfile ca_ssl2.conf


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

_______________________________________________________________________________________________________________________________


openssl s_client -connect 192.168.12.80:443 -cert kyzya_10.cer -key kyzya_10.key -CAfile nafanya_CA2.cer -servername server5

openssl ocsp -CAfile ami_ca2.cer -url http://192.168.12.38 -resp_text -issuer ocsp.cer -cert ocsp_client2.cer
