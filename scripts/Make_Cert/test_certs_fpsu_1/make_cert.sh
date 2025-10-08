#!/bin/bash

# Укажите имена сертификатов через пробел
#CERT_NAMES=("kyzya_win1" "kyzya_win2" "kyzya_win3")
CERT_NAMES=("IT_iOS")

# Параметры CA
CA_CERT="nafanya_CA2.cer"
CA_KEY="nafanya_CA2.key"
CONFIG_TEMPLATE="ssl2.conf"
DAYS=366
PFX_PASSWORD="1234"

# Проверка наличия файла конфигурации
if [[ ! -f "$CONFIG_TEMPLATE" ]]; then
    echo "Ошибка: Файл конфигурации $CONFIG_TEMPLATE не найден!"
    exit 1
fi

for NAME in "${CERT_NAMES[@]}"; do
    echo "Generating certificate for: $NAME"

    # Создание временного конфигурационного файла
    CONFIG_FILE="ssl2_$NAME.conf"
    sed -e "s/ocsp_client2/$NAME/g" -e "s/%CERT_NAME%/$NAME/g" "$CONFIG_TEMPLATE" > "$CONFIG_FILE"

    # Генерация ключа
    openssl genrsa -out "$NAME.key" 4096

    # Создание запроса на сертификат
    openssl req -new -key "$NAME.key" -out "$NAME.csr"  -config "$CONFIG_FILE"

    # Подпись сертификата CA
    openssl x509 -req -days "$DAYS" -in "$NAME.csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -out "$NAME.cer" \
        -extensions v3_ca -extfile "$CONFIG_FILE"

    # Создание PFX
    openssl pkcs12 -export -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg SHA1 \
        -inkey "$NAME.key" -in "$NAME.cer" -passout pass:"$PFX_PASSWORD" \
        -name "$NAME" -out "$NAME.pfx"

    # Удаление временного конфигурационного файла
    rm "$CONFIG_FILE"
done

echo "All certificates generated successfully!"
