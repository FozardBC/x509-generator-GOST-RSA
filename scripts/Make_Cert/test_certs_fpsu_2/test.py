import subprocess
import os

site = "my-site.ru"
openssl = 'C:/OpenSSL_3.1.2/bin/openssl.exe'
pfx_file = "CA.pfx"
pfx_password = "1"
ssl_conf_file = "ssl.conf"

def runcommand(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении команды: {e}")
        raise


# Проверка наличия исполняемого файла OpenSSL
if not os.path.exists(openssl):
    print("Ошибка: Файл OpenSSL не найден.")
    exit(1)
    
# Генерация ключа
keycommand = openssl, 'genrsa', '-out', f'{site}.key', '2048'
runcommand(keycommand)


# Проверка существования ключа перед созданием запроса
key_path = f'{site}.key'
if os.path.exists(key_path):
    # Создание запроса на сертификат
    csr_command = [
        openssl, 'req',
        '-new', '-key', key_path,
        '-out', f'{site}.csr',
        '-config', ssl_conf_file
    ]
    runcommand(csr_command)

    # Проверка существования запроса перед созданием сертификата
    csr_path = f'{site}.csr'
    if os.path.exists(csr_path):
        # Создание сертификата на основе запроса
        cert_command = [
            openssl, 'x509',
            '-req', '-in', csr_path,
            '-CA', pfx_file,
            '-passin', f'pass:{pfx_password}',
            '-out', f'{site}.crt',
            '-days', '365', '-sha256'
        ]
        runcommand(cert_command)
    else:
        print(f"Файл {csr_path} не найден.")
else:
    print(f"Файл {key_path} не найден.")
