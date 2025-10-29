package rsaPFX

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

	outPath := certPath + ".pfx"

	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-password", "pass:"+password,
		"-out", outPath,
		"-macalg", "sha1",
		"-nodes", // не шифровать закрытый ключ дополнительно
		"-keypbe", "pbeWithSHA1And3-KeyTripleDES-CBC",
		"-certpbe", "pbeWithSHA1And3-KeyTripleDES-CBC",
	)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("openssl error: %s", string(exitErr.Stderr))
		}
		return nil, err
	}

	pfxData, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read .pfx file: %w", err)
	}

	return pfxData, nil
}
