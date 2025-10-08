#!/bin/bash

# Параметры подключения
HOST="192.168.12.80"
PORT="443"
CLIENT_CERT="ocsp_client2.cer"
CLIENT_KEY="ocsp_client2.key"
CA_FILE="ami_ca2.cer"
SERVER_NAME="server5"

# Лог-файл (по желанию)
LOG_FILE="openssl_connection.log"

# Проверка наличия файлов
if [[ ! -f "$CLIENT_CERT" || ! -f "$CLIENT_KEY" || ! -f "$CA_FILE" ]]; then
    echo "Ошибка: отсутствуют необходимые файлы сертификатов/ключей!"
    exit 1
fi

# Функция для проверки соединения
test_openssl_connection() {
    echo "Попытка подключения к ${HOST}:${PORT}..."

    # Команда openssl с перенаправлением вводов/выводов
    openssl s_client \
        -connect "${HOST}:${PORT}" \
        -cert "$CLIENT_CERT" \
        -key "$CLIENT_KEY" \
        -CAfile "$CA_FILE" \
        -servername "$SERVER_NAME" \
        -showcerts \
        -status \
        <<< "Q" 2>&1 | tee "$LOG_FILE"

    # Проверка кода возврата openssl
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        echo "✅ Успешное подключение! Лог сохранён в $LOG_FILE"

        # Дополнительная проверка OCSP Stapling (если нужно)
        if grep -q "OCSP Response Status: successful" "$LOG_FILE"; then
            echo "🔐 Сервер поддерживает OCSP Stapling."
        else
            echo "⚠️ OCSP Stapling не поддерживается или не настроен."
        fi

    else
        echo "❌ Ошибка подключения! Проверьте параметры и логи."
        exit 1
    fi
}

# Вызов функции
test_openssl_connection

# Закрытие скрипта
exit 0
