package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	certgen "html-cer-gen/internal/services/generator/rsa"
	"io"
	"os"
	"path/filepath"
)

// ZipFolderToBytes принимает название папки (например, "my_certs")
// и возвращает её содержимое в виде ZIP-архива ([]byte).
// Папка должна находиться в текущей рабочей директории.
func ZipFolderToBytes(folderName string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	folderPath := filepath.Join(certgen.OutputFolder, folderName)

	// Проверим, что папка существует
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("папка не найдена: %s", folderPath)
	}

	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(folderPath, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		zipPath := filepath.ToSlash(relPath)

		if info.IsDir() {
			_, err = zw.Create(zipPath + "/")
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		fw, err := zw.Create(zipPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(fw, file)
		return err
	})

	if err != nil {
		zw.Close() // закрываем даже при ошибке (на всякий)
		return nil, err
	}

	// 🔥 ОБЯЗАТЕЛЬНО закрываем ДО чтения buf.Bytes()
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("ошибка финализации ZIP: %w", err)
	}

	return buf.Bytes(), nil
}
