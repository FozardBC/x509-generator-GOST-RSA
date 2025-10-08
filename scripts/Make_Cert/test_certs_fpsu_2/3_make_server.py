from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from datetime import datetime, timedelta, timezone

def create_server_certificate(server_name, days_valid, ca_cert_path, ca_key_path, password):
    # Генерация закрытого ключа сервера
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Генерация CSR (запрос на сертификат) для сервера
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Msk"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Msk"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AMICON"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"{server_name} department"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"support@{server_name}.ru"),
        x509.NameAttribute(NameOID.COMMON_NAME, server_name),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(server_name)]),
        critical=False,
    ).sign(server_key, hashes.SHA256())

    # Загрузка сертификата и ключа ЦА
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Подписание серверного сертификата ЦА
    now = datetime.now(timezone.utc)
    server_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + timedelta(days=days_valid)
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, 
                      content_commitment=False, data_encipherment=False,
                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                      encipher_only=False, decipher_only=False),  # Добавлены недостающие параметры
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(server_name)]),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    # Сохранение серверного ключа
    key_filename = f"{server_name}.key"
    with open(key_filename, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Сохранение серверного сертификата
    cert_filename = f"{server_name}.crt"
    with open(cert_filename, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    # Упаковка в PFX (PKCS12)
    pfx_filename = f"{server_name}.pfx"
    pfx_data = serialize_key_and_certificates(
        name=server_name.encode("utf-8"),
        key=server_key,
        cert=server_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )

    with open(pfx_filename, "wb") as f:
        f.write(pfx_data)

    print(f"Server certificate and key have been saved as {cert_filename} and {key_filename}.")
    print(f"PFX file has been saved as {pfx_filename}.")

# Параметры сертификата
server_name = "Server22_FPSU"
days_valid = 365  # Срок действия в днях
ca_cert_path = "CA_cert.pem"
ca_key_path = "CA_private_key.pem"
password = "1234"  # Пароль для PFX

# Создание серверного сертификата
create_server_certificate(server_name, days_valid, ca_cert_path, ca_key_path, password)
