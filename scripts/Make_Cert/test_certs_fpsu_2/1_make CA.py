from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone

# Генерация закрытого ключа RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Параметры для сертификата CA
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Moscow"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Moscow"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ami_test_CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "ami_test_CA"),
])

# Текущая дата и время с указанием UTC
now = datetime.now(timezone.utc)

# Создание сертификата
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)  # Для самоподписанного сертификата субъект = эмитент
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=3650))  # Действителен 10 лет
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    .sign(private_key, hashes.SHA256())
)

# Сохранение ключа и сертификата в файлы
with open("CA_private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open("CA_cert.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

print("CA certificate and private key generated successfully!")
