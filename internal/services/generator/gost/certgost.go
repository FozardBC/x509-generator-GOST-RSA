package gost

import (
	"fmt"
	"html-cer-gen/internal/models"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type GostCertificateGenerator struct {
	log *slog.Logger
	CR  *models.CertRequest
}

func New(log *slog.Logger) *GostCertificateGenerator {
	return &GostCertificateGenerator{
		log: log,
		CR:  &models.CertRequest{},
	}
}

var CAfolder string = "./certs/CA"
var OutputFolder string = "./certs/generated"

// GenGostCertAndTrustCA генерирует и подписывает сертификат по ГОСТ с использованием OpenSSL
func (gen *GostCertificateGenerator) GenCertAndTrustCA(CertRequest *models.CertRequest, requestid string) error {

	requestFolder := filepath.Join(OutputFolder, requestid)
	if err := os.MkdirAll(requestFolder, 0755); err != nil {
		return fmt.Errorf("failed to mkdir for requestID: %w", err)
	}

	gen.CR = CertRequest

	// Пути к файлам
	keyFile := filepath.Join(requestFolder, gen.CR.CommonName+".key")
	csrFile := filepath.Join(requestFolder, gen.CR.CommonName+".csr")
	certFile := filepath.Join(requestFolder, gen.CR.CommonName+".cer")

	caDir := filepath.Join(CAfolder, gen.CR.CAName)
	caCertFile := filepath.Join(caDir, gen.CR.CAName+".cer")
	caKeyFile := filepath.Join(caDir, gen.CR.CAName+".key")

	key := "gost2012_256"
	switch gen.CR.KeyType {
	case "GOST2012512":
		key = "gost2012_512"
	}

	// 1. Генерация ГОСТ-ключа
	cmd1 := exec.Command("openssl", "genpkey",
		"-engine", "gost",
		"-algorithm", key,
		"-pkeyopt", "paramset:A",
		"-out", keyFile)
	cmd1.Env = append(os.Environ(), "OPENSSL_CONF=/etc/ssl/openssl.cnf")
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("ошибка генерации ГОСТ-ключа: %w", err)
	}

	// 2. Создание CSR
	subj := fmt.Sprintf("/C=%s/O=%s/CN=%s", strings.ToUpper(gen.CR.Country), gen.CR.Organization, gen.CR.CommonName)
	cmd2 := exec.Command("openssl", "req", "-new",
		"-key", keyFile,
		"-out", csrFile,
		"-subj", subj,
		"-utf8")
	if err := cmd2.Run(); err != nil {
		return fmt.Errorf("ошибка создания CSR: %w", err)
	}

	// Подготовка времени
	days := "365"

	switch gen.CR.Time {
	case "1year":
		days = "365"
	case "1day":
		days = "1"
	case "1month":
		days = "30"
	case "future1d":
		days = "365"
	case "future1m":

	case "overdue":
		days = "-1"
	default:
		days = "365"
	}

	// Формат для OpenSSL: YYMMDDHHMMSSZ

	// 3. Подготовка расширений

	extFile := filepath.Join(requestFolder, "v3.ext")
	extContent := `basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
`
	if gen.CR.CertType == "server" {
		extContent += fmt.Sprintf("extendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n", gen.CR.CommonName)
	} else if gen.CR.CertType == "client" {
		extContent += "extendedKeyUsage=clientAuth\n"
	} else if gen.CR.CertType == "email" {
		extContent += "extendedKeyUsage=emailProtection\n"
	}

	if gen.CR.CrlDistributionPoints != "" && gen.CR.CrlDistributionPoints != " " {
		uris := strings.Split(gen.CR.CrlDistributionPoints, ",")
		var crlLines []string
		for _, uri := range uris {
			crlLines = append(crlLines, fmt.Sprintf("URI:%s", strings.TrimSpace(uri)))
		}
		extContent += fmt.Sprintf("crlDistributionPoints=%s\n", strings.Join(crlLines, ","))
	}

	if gen.CR.AuthorityInfoAccess != "" {
		var aiaEntries []string
		uris := strings.Split(gen.CR.AuthorityInfoAccess, ",")
		for _, part := range uris {
			parts := strings.SplitN(part, ";", 2)
			if len(parts) != 2 {
				continue
			}
			method, uri := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			parsedURI, err := url.Parse(uri)
			if err != nil || parsedURI.Scheme == "" {
				continue
			}

			switch strings.ToLower(method) {
			case "ocsp":
				aiaEntries = append(aiaEntries, "OCSP;URI:"+uri)
			case "caissuers":
				aiaEntries = append(aiaEntries, "caIssuers;URI:"+uri)
			}
		}

		if len(aiaEntries) > 0 {
			extContent += "authorityInfoAccess = " + strings.Join(aiaEntries, ", ") + "\n"
		}
	}

	// AuthorityInfoAccess пока не поддерживается напрямую в OpenSSL через extfile — пропускаем или обрабатываем отдельно

	if err := os.WriteFile(extFile, []byte(extContent), 0644); err != nil {
		return fmt.Errorf("ошибка записи расширений: %w", err)
	}

	var SERIALID string

	if gen.CR.Serial != 0 {
		SERIALID = strconv.Itoa(gen.CR.Serial)

		cmd3 := exec.Command("openssl", "x509", "-req",
			"-in", csrFile,
			"-CA", caCertFile,
			"-CAkey", caKeyFile,

			"-out", certFile,
			"-days", days,
			"-extfile", extFile,
			"-set_serial", SERIALID,
		)
		cmd3.Env = append(os.Environ(), "OPENSSL_CONF=/etc/ssl/openssl.cnf")

		if output, err := cmd3.CombinedOutput(); err != nil {
			return fmt.Errorf("ошибка подписи сертификата УЦ: %w\nOutput: %s", err, string(output))
		}

		// 5. (Опционально) Удалить временные файлы
		_ = os.Remove(csrFile)
		_ = os.Remove(extFile)
		// .srl файл (сериальный номер) можно оставить или удалить — OpenSSL сам управляет

		return nil
	}

	// 4. Подпись сертификата УЦ
	cmd3 := exec.Command("openssl", "x509", "-req",
		"-in", csrFile,
		"-CA", caCertFile,
		"-CAkey", caKeyFile,
		"-CAcreateserial",
		"-out", certFile,
		"-days", days,
		"-extfile", extFile,
	)
	// Убрали -engine из команды, но оставили в env
	cmd3.Env = append(os.Environ(), "OPENSSL_CONF=/etc/ssl/openssl.cnf")

	if output, err := cmd3.CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка подписи сертификата УЦ: %w\nOutput: %s", err, string(output))
	}

	// 5. (Опционально) Удалить временные файлы
	_ = os.Remove(csrFile)
	_ = os.Remove(extFile)
	// .srl файл (сериальный номер) можно оставить или удалить — OpenSSL сам управляет

	return nil
}
