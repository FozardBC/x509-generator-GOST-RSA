package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidOCSP                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidCAIssuers           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

	OutputFolder string = "./certs/generated"
	CAfolder     string = "./certs/CA"
)

type CertificateRequest struct {
	CommonName            string // например: "server.example.com" или "user@example.com"
	Organization          string // например: "My Company"
	Country               string // 2 буквы, например: "RU"
	Time                  string
	UTC                   int
	KeyType               string // "rsa2048" или "rsa4096"
	CertType              string // "server" или "client"
	CAName                string // имя УЦ → файлы: <CAName>.cer и <CAName>.key
	AuthorityInfoAccess   string
	CrlDistributionPoints string
	Serial                int
}

type RSACertificateGenerator struct {
	log *slog.Logger
	CR  *CertificateRequest
}

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

type authorityInfoAccess []accessDescription

func New(log *slog.Logger) *RSACertificateGenerator {
	return &RSACertificateGenerator{
		log: log,
		CR:  &CertificateRequest{},
	}
}

// GenerateCertificate генерирует и подписывает сертификат на основе запроса
func (gen *RSACertificateGenerator) GenCertAndTrustCA(
	commonName string,
	organization string,
	country string,
	timeLive string,
	UTC int,
	keyType string,
	certType string,
	caName string,
	requestid string,
	crlDistributionPoints string,
	authorityInfoAccess string,
	serial int,
) error {

	var RequestFolder string = filepath.Join(OutputFolder, requestid)

	_, err := os.Stat(RequestFolder)

	if errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(RequestFolder, 0777)
		if err != nil {
			return fmt.Errorf("failed to mkdir for reqeustID:%w", err)
		}

	}

	gen.CR = &CertificateRequest{
		CommonName:            commonName,
		Organization:          organization,
		Country:               country,
		Time:                  timeLive,
		UTC:                   UTC,
		KeyType:               keyType,
		CertType:              certType,
		CAName:                caName,
		CrlDistributionPoints: crlDistributionPoints,
		AuthorityInfoAccess:   authorityInfoAccess,
		Serial:                serial,
	}

	filepath.Join()

	caCertFile := filepath.Join(CAfolder, gen.CR.CAName, gen.CR.CAName) + ".cer"
	caKeyFile := filepath.Join(CAfolder, gen.CR.CAName, gen.CR.CAName) + ".key"

	// === 1. Загрузка сертификата УЦ ===
	caCertData, err := os.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать %s: %w", caCertFile, err)
	}

	var caCert *x509.Certificate
	if block, rest := pem.Decode(caCertData); block != nil && len(rest) == 0 {
		caCert, err = x509.ParseCertificate(block.Bytes)
	} else {
		// Предполагаем DER
		caCert, err = x509.ParseCertificate(caCertData)
	}
	if err != nil {
		return fmt.Errorf("ошибка разбора сертификата УЦ из %s: %w", caCertFile, err)
	}

	// === 2. Загрузка приватного ключа УЦ ===
	caKeyData, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("не удалось прочитать %s: %w", caKeyFile, err)
	}

	block, _ := pem.Decode(caKeyData)
	if block == nil {
		return fmt.Errorf("файл %s должен быть в PEM-формате", caKeyFile)
	}

	var caPrivateKey interface{}
	caPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		caPrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("ошибка разбора ключа УЦ из %s (поддерживаются только RSA в PKCS#1/PKCS#8): %w", caKeyFile, err)
		}
	}

	rsaCAKey, ok := caPrivateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("поддерживаются только RSA-ключи УЦ, получен тип: %T", caPrivateKey)
	}

	// === 3. Генерация нового ключа ===
	keySize := 2048
	if gen.CR.KeyType == "rsa4096" {
		keySize = 4096
	}

	newPrivateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %w", err)
	}

	notBefore := time.Now()
	var notAfter time.Time

	switch gen.CR.Time {
	case "1year":
		notAfter = time.Now().AddDate(1, 0, 0)
	case "1day":
		notAfter = notBefore.AddDate(0, 0, 1)
	case "future1m":
		notBefore = time.Now().AddDate(0, 1, 0)
		notAfter = time.Now().AddDate(1, 0, 0)
	case "future1d":
		notBefore = time.Now().AddDate(0, 0, 1)
		notAfter = time.Now().AddDate(1, 0, 0)
	case "future1h":
		notBefore = time.Now().Add(1 * time.Hour)
		notAfter = time.Now().AddDate(1, 0, 0)
	case "overdue":
		notBefore = time.Now()
		notAfter = time.Now()
	}

	if gen.CR.UTC == 0 {
		notBefore = notBefore.Add(3 * time.Hour)
		notAfter = notAfter.Add(3 * time.Hour)
	}

	var SERIALID *big.Int

	// === 4. Создание шаблона сертификата ===
	if gen.CR.Serial != 0 {
		bigInt := new(big.Int)
		SERIALID = bigInt.SetInt64(int64(serial))
	} else {
		SERIALID, err = rand.Int(rand.Reader, new(big.Int).SetInt64(1<<62))
		if err != nil {
			return fmt.Errorf("ошибка генерации серийного номера: %w", err)
		}
	}

	template := x509.Certificate{
		SerialNumber: SERIALID,
		Subject: pkix.Name{
			CommonName:   gen.CR.CommonName,
			Organization: []string{gen.CR.Organization},
			Country:      []string{strings.ToUpper(gen.CR.Country)},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	CertType := strings.Split(gen.CR.CertType, ",")

	for _, val := range CertType {
		switch val {
		case "server":
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			if !strings.Contains(gen.CR.CommonName, "@") && net.ParseIP(gen.CR.CommonName) == nil {
				template.DNSNames = []string{gen.CR.CommonName}
			}
		case "client":
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "empty":
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageAny)
		case "email":
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		}
	}

	if crlDistributionPoints != " " {
		CrlDistPoints := strings.Split(gen.CR.CrlDistributionPoints, ",")

		template.CRLDistributionPoints = append(template.CRLDistributionPoints, CrlDistPoints...)
	}

	if gen.CR.AuthorityInfoAccess != " " {
		aiaInfo, err := buildAuthorityInfoAccess(gen.CR.AuthorityInfoAccess)
		if err != nil {
			gen.log.Warn("failed to add AuthAccessInfo", "err", err.Error())
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       oidAuthorityInfoAccess,
			Critical: false,
			Value:    aiaInfo,
		})

	}

	// === 5. Подпись сертификата ===
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &newPrivateKey.PublicKey, rsaCAKey)
	if err != nil {
		return fmt.Errorf("ошибка подписания сертификата: %w", err)
	}

	// === 6. Сохранение файлов ===
	keyFile := filepath.Join(RequestFolder, gen.CR.CommonName) + ".key"
	certFile := filepath.Join(RequestFolder, gen.CR.CommonName) + ".crt"

	// keyFile = uniqueFilePath(OutputFolder, keyFile)
	// certFile = uniqueFilePath(OutputFolder, certFile)

	if err := savePEMKey(keyFile, newPrivateKey); err != nil {
		return fmt.Errorf("ошибка записи ключа в %s: %w", keyFile, err)
	}
	if err := savePEMCert(certFile, derBytes); err != nil {
		return fmt.Errorf("ошибка записи сертификата в %s: %w", certFile, err)
	}

	return nil
}

func UniqueFilePath(dir, filename string) string {
	base := filepath.Join(dir, filename) + ".crt"
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return filename // файл не существует — можно использовать как есть
	}

	// Разделяем имя файла на имя и расширение
	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)

	counter := 1
	for {
		newName := fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, ext)
		newPath := filepath.Join(dir, newName) + ".crt"
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newName // нашли свободное имя
		}
		counter++
	}

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

func buildAuthorityInfoAccess(parameter string) ([]byte, error) {
	var aia authorityInfoAccess

	parts := strings.Split(parameter, ",")
	for _, part := range parts {
		parts := strings.SplitN(part, ";", 2)
		if len(parts) != 2 {
			continue
		}
		method, uri := parts[0], parts[1]
		_, err := url.Parse(uri)
		if err != nil {
			continue // или верните ошибку
		}

		switch strings.ToLower(method) {
		case "ocsp":
			rawURI := asn1.RawValue{
				Tag:        6, // IA5String tag in GeneralName for URI
				Class:      2, // Context-specific
				IsCompound: false,
				Bytes:      []byte(uri),
			}
			aia = append(aia, accessDescription{
				Method:   oidOCSP,
				Location: rawURI,
			})
		case "caissuers":
			rawURI := asn1.RawValue{
				Tag:        6,
				Class:      2,
				IsCompound: false,
				Bytes:      []byte(uri),
			}
			aia = append(aia, accessDescription{
				Method:   oidCAIssuers,
				Location: rawURI,
			})
		}
	}

	return asn1.Marshal(aia)
}
