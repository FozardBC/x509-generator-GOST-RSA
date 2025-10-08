package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		cn       = flag.String("cn", "", "Common Name (обязательно)")
		org      = flag.String("org", "Default Org", "Organization")
		country  = flag.String("country", "RU", "Country (2-letter code)")
		days     = flag.Int("days", 365, "Срок действия (дней)")
		keyType  = flag.String("key-type", "rsa2048", "Тип ключа: rsa2048 или rsa4096")
		certType = flag.String("cert-type", "server", "Тип сертификата: server или client")
		caName   = flag.String("ca", "", "Имя УЦ (файлы: <ca>.cer и <ca>.key)")
	)
	flag.Parse()

	if *cn == "" {
		flag.Usage()
		log.Fatal("--cn обязателен")
	}
	if *caName == "" {
		flag.Usage()
		log.Fatal("--ca обязателен (указывает имя файлов УЦ: <ca>.cer и <ca>.key)")
	}
	if *certType != "server" && *certType != "client" {
		log.Fatal("--cert-type должен быть 'server' или 'client'")
	}
	if *keyType != "rsa2048" && *keyType != "rsa4096" {
		log.Fatal("--key-type должен быть 'rsa2048' или 'rsa4096'")
	}

	caCertFile := *caName + ".cer"
	caKeyFile := *caName + ".key"

	// === 1. Загрузка сертификата УЦ из <ca>.cer ===
	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Не удалось прочитать %s: %v", caCertFile, err)
	}

	var caCert *x509.Certificate
	block, _ := pem.Decode(caCertData)
	if block != nil {
		// PEM
		caCert, err = x509.ParseCertificate(block.Bytes)
	} else {
		// Предполагаем DER
		caCert, err = x509.ParseCertificate(caCertData)
	}
	if err != nil {
		log.Fatalf("Ошибка разбора сертификата УЦ из %s: %v", caCertFile, err)
	}

	// === 2. Загрузка ключа УЦ из <ca>.key ===
	caKeyData, err := os.ReadFile(caKeyFile)
	if err != nil {
		log.Fatalf("Не удалось прочитать %s: %v", caKeyFile, err)
	}

	block, _ = pem.Decode(caKeyData)
	if block == nil {
		log.Fatalf("Файл %s должен быть в PEM-формате", caKeyFile)
	}

	var caPrivateKey interface{}
	caPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		caPrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Ошибка разбора ключа УЦ из %s (поддерживаются только RSA в PKCS#1/PKCS#8): %v", caKeyFile, err)
		}
	}

	rsaCAKey, ok := caPrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("Поддерживаются только RSA-ключи УЦ. Получен тип: %T", caPrivateKey)
	}

	fmt.Printf("✅ Загружен УЦ: %s\n", caCert.Subject.CommonName)

	// === 3. Генерация нового ключа ===
	keySize := 2048
	if *keyType == "rsa4096" {
		keySize = 4096
	}

	fmt.Printf("Генерация %s ключа...\n", *keyType)
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// === 4. Создание шаблона сертификата ===
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(1<<62))
	if err != nil {
		log.Fatalf("Ошибка генерации серийного номера: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, *days)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   *cn,
			Organization: []string{*org},
			Country:      []string{*country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if *certType == "server" {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if !strings.Contains(*cn, "@") && net.ParseIP(*cn) == nil {
			template.DNSNames = []string{*cn}
		}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// === 5. Подпись сертификата УЦ ===
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &newPrivateKey.PublicKey, rsaCAKey)
	if err != nil {
		log.Fatalf("Ошибка подписания сертификата: %v", err)
	}

	// === 6. Сохранение результата ===
	keyFile := *cn + ".key"
	certFile := *cn + ".crt"

	if err := savePEMKey(keyFile, newPrivateKey); err != nil {
		log.Fatalf("Ошибка записи ключа: %v", err)
	}
	if err := savePEMCert(certFile, derBytes); err != nil {
		log.Fatalf("Ошибка записи сертификата: %v", err)
	}

	fmt.Printf("✅ Сертификат подписан УЦ '%s' и сохранён:\n  Ключ: %s\n  Сертификат: %s\n", *caName, keyFile, certFile)
}

func savePEMKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func savePEMCert(filename string, derBytes []byte) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}
