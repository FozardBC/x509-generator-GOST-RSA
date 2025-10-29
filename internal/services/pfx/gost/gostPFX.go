package gostPFX

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

type Creator struct {
	log *slog.Logger
}

func New(log *slog.Logger) *Creator {
	return &Creator{
		log: log,
	}
}

func (c *Creator) Create(certPath, keyPath, password string) ([]byte, error) {
	outFile := certPath + ".pfx"

	cmd := exec.Command(
		"openssl", "pkcs12", "-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-out", outFile,
		"-password", "pass:"+password,
		"-engine", "gost",
		"-keypbe", "gost89",
		"-certpbe", "gost89",
		"-macalg", "md_gost12_512",
	)

	// Используем CombinedOutput или запускаем и читаем файл после
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("openssl error: %s", string(exitErr.Stderr))
		}
		return nil, err
	}

	// Читаем результат из файла
	pfxData, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read .pfx file: %w", err)
	}

	// Опционально: удаляем временный .pfx файл здесь или в вызывающем коде
	return pfxData, nil
}
