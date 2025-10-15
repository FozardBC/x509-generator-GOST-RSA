package gostPFX

import (
	"fmt"
	"log/slog"
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
	cmd := exec.Command(
		"openssl", "pkcs12", "-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-out", "container",
		"-certfile", certPath,

		"-password", "pass:"+password,
		"-nodes",
		"-engine", "gost",
		"-keypbe", "gost89",
		"-certpbe", "gost89",
		"-macalg", "md_gost12_512",
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("openssl error: %s", string(exitErr.Stderr))
		}
		return nil, err
	}
	return output, nil
}
