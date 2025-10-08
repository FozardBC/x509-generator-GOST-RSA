#!/bin/bash

# Установить значения для пароля и других переменных
PFX_PASSWORD="1234"
KEY_NAME="ser2_fpsu"
CONFIG_FILE="ssl1.conf"
CA_CERT="ami_ca2.pem"
CA_KEY="ami_ca2.key"

# 1. Генерация приватного ключа
echo "Генерация приватного ключа..."
openssl genrsa -out ${KEY_NAME}.key 4096
if [ $? -ne 0 ]; then
  echo "Ошибка при генерации ключа!"
  exit 1
fi

# 2. Создание запроса на сертификат (CSR)
echo "Создание CSR..."
openssl req -new -nodes -keyout ${KEY_NAME}.key -out ${KEY_NAME}.csr -days 365 -config ${CONFIG_FILE}
if [ $? -ne 0 ]; then
  echo "Ошибка при создании CSR!"
  exit 1
fi

# 3. Подписание CSR с использованием корневого сертификата
echo "Подписание сертификата..."
openssl x509 -req -days 365 -in ${KEY_NAME}.csr -CA ${CA_CERT} -CAkey ${CA_KEY} -out ${KEY_NAME}.pem -extensions v3_ca -extfile ${CONFIG_FILE}
if [ $? -ne 0 ]; then
  echo "Ошибка при подписании сертификата!"
  exit 1
fi

# 4. Экспорт в формате PKCS#12
echo "Экспорт сертификата в PKCS#12..."
openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 -inkey ${KEY_NAME}.key -in ${KEY_NAME}.pem -passout pass:${PFX_PASSWORD} -name "${KEY_NAME}" -out ${KEY_NAME}.pfx
if [ $? -ne 0 ]; then
  echo "Ошибка при экспорте в PKCS#12!"
  exit 1
fi

echo "Все операции выполнены успешно!"

