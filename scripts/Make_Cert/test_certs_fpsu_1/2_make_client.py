from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from datetime import datetime, timedelta, timezone

def create_client_certificate(client_name, days_valid, ca_cert_path, ca_key_path, password):
    # Генерация закрытого ключа клиента
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Генерация CSR (запрос на сертификат) для клиента
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Msk"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Msk"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AMICON"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"{client_name} department"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"support@{client_name}.ru"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(client_name)]),
        critical=False,
    ).sign(client_key, hashes.SHA256())

    # Загрузка сертификата и ключа ЦА
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Подписание клиентского сертификата ЦА
    now = datetime.now(timezone.utc)
    client_cert = x509.CertificateBuilder().subject_name(
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
                      encipher_only=False, decipher_only=False),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        critical=False
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(client_name)]),
        critical=False
    ).sign(ca_key, hashes.SHA256())

    # Сохранение клиентского ключа
    key_filename = f"{client_name}.key"
    with open(key_filename, "wb") as f:
        f.write(
            client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Сохранение клиентского сертификата
    cert_filename = f"{client_name}.crt"
    with open(cert_filename, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    # Упаковка в PFX (PKCS12)
    pfx_filename = f"{client_name}.pfx"
    pfx_data = serialize_key_and_certificates(
        name=client_name.encode("utf-8"),
        key=client_key,
        cert=client_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )

    with open(pfx_filename, "wb") as f:
        f.write(pfx_data)

    print(f"Client certificate and key have been saved as {cert_filename} and {key_filename}.")
    print(f"PFX file has been saved as {pfx_filename}.")

# Параметры сертификата
client_name = "Client6_FPSU"
days_valid = 365  # Срок действия в днях
ca_cert_path = "CA_cert.pem"
ca_key_path = "CA_private_key.pem"
password = "1234"  # Пароль для PFX

# Создание клиентского сертификата
create_client_certificate(client_name, days_valid, ca_cert_path, ca_key_path, password)