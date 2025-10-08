'''
import subprocess
import os

site = "33333.ru"
pfx_file = "ami_ca.pfx"
pfx_password = "1"
ca = "ami_CA"

# Извлечение ключа и сертификата из PFX-файла
extract_key_command = [
    'C:/OpenSSL_3.1.2/bin/openssl.exe',
    'pkcs12',
    '-in', pfx_file,
    '-nocerts', '-out', '{}.key'.format(ca),
    '-nodes',
    '-password', 'pass:{}'.format(pfx_password)
]
subprocess.run(extract_key_command)

extract_cert_command = [
    'C:/OpenSSL_3.1.2/bin/openssl.exe',
    'pkcs12',
    '-in', pfx_file,
    '-clcerts', '-nokeys', '-out', '{}.crt'.format(site),
    '-nodes',
    '-password', 'pass:{}'.format(pfx_password)
]
subprocess.run(extract_cert_command)

# Создание сертификата на основе ключа и сертификата
cert_command = [
    'C:/OpenSSL_3.1.2/bin/openssl. exe',
    'req',
    '-new',
    '-key', '{}.key'.format(site),
    '-out', '{}.csr'.format(site),
    '-config', 'ssl.conf'
]
subprocess.run(cert_command)

sign_command = [
    'C:/OpenSSL_3.1.2/bin/openssl.exe',
    'x509',
    '-req', '-in', '{}.csr'.format(site),
    '-CA', '{}.crt'.format(site),
    '-CAkey', '{}.key'.format(site),
    '-CAcreateserial',
    '-CAserial', 'sites.srl',
    '-out', '{}.crt'.format(site),
    '-days', '365',
    '-sha256'
]
subprocess.run(sign_command)

# Удаление временных файлов
for file_to_remove in ['{}.csr'.format(site)]:
    os.remove(file_to_remove)


-----------------------------------------------------------------------
'''

import subprocess
import os

site = "my-site.ru"
openssl_path = 'C:/OpenSSL3.1.2/bin/openssl.exe'
pfx_file = "CA.pfx"
pfx_password = "pass"
ssl_conf_file = "ssl.conf"

def run_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при выполнении команды: {e}")

# Генерация ключа
key_command = [openssl_path, 'genrsa', '-out', f'{site}.key', '2048']
run_command(key_command)

# Проверка существования ключа перед созданием запроса
key_path = f'{site}.key'
if os.path.exists(key_path):
    # Создание запроса на сертификат
    csr_command = [
        openssl_path, 'req',
        '-new', '-key', key_path,
        '-out', f'{site}.csr',
        '-config', ssl_conf_file
    ]
    run_command(csr_command)

    # Проверка существования запроса перед созданием сертификата
    csr_path = f'{site}.csr'
    if os.path.exists(csr_path):
        # Создание сертификата на основе запроса
        cert_command = [
            openssl_path, 'x509',
            '-req', '-in', csr_path,
            '-CA', pfx_file,
            '-passin', f'pass:{pfx_password}',
            '-out', f'{site}.crt',
            '-days', '365', '-sha256'
        ]
        run_command(cert_command)
    else:
        print(f"Файл {csr_path} не найден.")
else:
    print(f"Файл {key_path} не найден.")
