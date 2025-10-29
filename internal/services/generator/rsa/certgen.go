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
	"html-cer-gen/internal/models"
	"html-cer-gen/internal/services/generator"
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

type RSACertificateGenerator struct {
	log *slog.Logger
	CR  *models.CertRequest
}

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

type authorityInfoAccess []accessDescription

func New(log *slog.Logger) *RSACertificateGenerator {
	return &RSACertificateGenerator{
		log: log,
		CR:  &models.CertRequest{},
	}
}

// GenerateCertificate генерирует и подписывает сертификат на основе запроса
func (gen *RSACertificateGenerator) GenCertAndTrustCA(CertRequest *models.CertRequest, requestid string) error {

	var RequestFolder string = filepath.Join(OutputFolder, requestid)

	_, err := os.Stat(RequestFolder)

	if errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(RequestFolder, 0777)
		if err != nil {
			return fmt.Errorf("failed to mkdir for reqeustID:%w", err)
		}

	}

	gen.CR = CertRequest

	filepath.Join()

	caCertFile := filepath.Join(CAfolder, gen.CR.CAName, gen.CR.CAName) + generator.CertExt
	caKeyFile := filepath.Join(CAfolder, gen.CR.CAName, gen.CR.CAName) + generator.KeyExt

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
		SERIALID = bigInt.SetInt64(int64(gen.CR.Serial))
	} else {
		SERIALID, err = rand.Int(rand.Reader, new(big.Int).SetInt64(1<<62))
		if err != nil {
			return fmt.Errorf("ошибка генерации серийного номера: %w", err)
		}
	}

	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	template := x509.Certificate{
		SerialNumber: SERIALID,
		Subject: pkix.Name{
			CommonName: gen.CR.CommonName,
			Country:    []string{strings.ToUpper(gen.CR.Country)},
			Province:   []string{gen.CR.Province}, //
			Locality:   []string{gen.CR.Locality},

			Organization:       []string{gen.CR.Organization},
			OrganizationalUnit: []string{gen.CR.OrganizationUnit}, //

			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type: oidEmailAddress,
					Value: asn1.RawValue{
						Tag:   asn1.TagIA5String,
						Bytes: []byte(gen.CR.Email),
					},
				},
			},
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

	if gen.CR.CrlDistributionPoints != " " {
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

	if gen.CR.UPN != " " {
		ex, err := createUPNExtension(gen.CR.UPN)
		if err != nil {
			return fmt.Errorf("ошибка при добавлении поля User Principal Name:%w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ex)
	}

	// === 5. Подпись сертификата ===
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &newPrivateKey.PublicKey, rsaCAKey)
	if err != nil {
		return fmt.Errorf("ошибка подписания сертификата: %w", err)
	}

	// === 6. Сохранение файлов ===
	keyFile := filepath.Join(RequestFolder, gen.CR.CommonName) + generator.KeyExt
	certFile := filepath.Join(RequestFolder, gen.CR.CommonName) + generator.CertExt

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
	base := filepath.Join(dir, filename) + generator.CertExt
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return filename // файл не существует — можно использовать как есть
	}

	// Разделяем имя файла на имя и расширение
	ext := filepath.Ext(filename)
	nameWithoutExt := strings.TrimSuffix(filename, ext)

	counter := 1
	for {
		newName := fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, ext)
		newPath := filepath.Join(dir, newName) + generator.CertExt
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

func createUPNExtension(upn string) (pkix.Extension, error) {
	type UPN struct {
		A string `asn1:"utf8"`
	}
	type OtherName struct {
		OID   asn1.ObjectIdentifier
		Value interface{} `asn1:"tag:0"`
	}
	type GeneralNames struct {
		OtherName OtherName `asn1:"tag:0"`
	}

	upnExt, err := asn1.Marshal(GeneralNames{
		OtherName: OtherName{
			// init our ASN.1 object identifier
			OID: asn1.ObjectIdentifier{
				1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
			// This is the email address of the person we
			// are generating the certificate for.
			Value: UPN{
				A: upn,
			},
		},
	})

	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ошибка кодирования otherName: %w", err)
	}

	extSubjectAltName := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
		Critical: false,
		Value:    upnExt,
	}

	return extSubjectAltName, nil

}
