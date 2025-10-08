установить гост:
apt install libengine-gost-openssl1.1

посмотреть шифронаборы: 
openssl ciphers | tr ':' '\n' | grep GOST

-------------------------------------------------

1) Делаем сертифиак ЦА (чтобы в DER добавить   "-outform DER"):
openssl req -x509 -newkey gost2012_256 -pkeyopt paramset:C -nodes -days 7300 -keyout AMI_CA_C.key -out AMI_CA_C.crt -utf8 -config ca.conf

2) создаём ключ и запрос:
openssl req -newkey gost2012_256 -pkeyopt paramset:C -nodes -keyout clientGOST_1.key -out clientGOST_1.csr -config ssl1.conf -utf8


3) по запросу делаем сертификат:
openssl x509 -req -days 5475 -in token1.cms.req -CA AMI_CA_C.crt -CAkey AMI_CA_C.key -out tocken1.crt -extensions v3_ca -extfile ssl1.conf -utf8

-------------------------------------------------

сертификат в der:
openssl x509 -in AMICON_CA_sign.key -out AMICON_CA_sign_DER.key -outform DER 

ключ в der:
openssl pkey -in test_sign.key -out test_sign_.key -outform DER -inform pem

изменить формат запроса из cms в csr:
openssl cms -in user.cms -inform PEM -verify -noverify -out tocken1.csr -outform PEM
openssl cms -in user.cms -verify -noverify -out request.csr -outform PEM

--------------------------------------------------
PFX

openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey clientGOST_1.key -in clientGOST_1.crt -passout pass:1234 -name "clientGOST_1" -out clientGOST_1.pfx


Извлечь из pfx:

openssl pkcs12 -in amicon_ca_5.pfx -nocerts -nodes -out amicon_ca_5.key
openssl pkcs12 -in amicon_ca_5.pfx -clcerts -nokeys -out amicon_ca_5.crt
