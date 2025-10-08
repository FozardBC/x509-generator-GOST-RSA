установить гост:
apt install libengine-gost-openssl1.1

посмотреть шифронаборы: 
openssl ciphers | tr ':' '\n' | grep GOST

-------------------------------------------------

1) Делаем сертифиак ЦА (сертификат в DER):
openssl req -x509 -newkey gost2012_256 -pkeyopt paramset:C -nodes -days 7300 -keyout AMICON_CA_sign_C.key -out AMICON_CA_sign_C.crt -outform DER -utf8


2) создаём ключ и запрос:
openssl req -newkey gost2012_256 -pkeyopt paramset:C -nodes -keyout clientGOST_1.key -out clientGOST_1.csr -config ssl1.conf -utf8


3) по запросу делаем сертификат:
openssl x509 -req -days 5475 -in user_for_sign_v3.csr -CA AMICON_CA_sign_C.crt -CAkey AMICON_CA_sign_C.key -out user_for_sign_v3.crt -extensions v3_ca -extfile ssl1.conf -outform DER -utf8


-------------------------------------------------

сертификат в der:
openssl x509 -in AMICON_CA_sign.key -out AMICON_CA_sign_DER.key -outform DER 

ключ в der:
openssl pkey -in test_sign.key -out test_sign_.key -outform DER -inform pem


--------------------------------------------------
PFX

openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey user_for_sign_v3.key -in user_for_sign_v3.crt -passout pass:1234 -name "user_for_sign_v3" -out user_for_sign_v3.pfx
