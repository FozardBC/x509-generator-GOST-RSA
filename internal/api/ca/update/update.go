package update

import (
	"html-cer-gen/internal/api/middlewares/requestid"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

var CAfolder string = "./certs/CA"

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		logHandler := log.With("requestid", requestid.Get(c))

		entries, err := os.ReadDir(CAfolder)
		if err != nil {
			logHandler.Error("Не удалось прочитать директорию с сертификатами", "err", err.Error())
			c.JSON(500, gin.H{"error": "Не удалось прочитать директорию с сертификатами"})
			return
		}

		var availableCAs []string

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			dirName := entry.Name()
			dirPath := filepath.Join(CAfolder, dirName)

			// Проверяем наличие .cer и .key файлов с именем директории
			cerPath := filepath.Join(dirPath, dirName+".cer")
			keyPath := filepath.Join(dirPath, dirName+".key")

			if fileExists(cerPath) && fileExists(keyPath) {
				availableCAs = append(availableCAs, dirName)
			}
		}

		c.JSON(200, gin.H{
			"certificates": availableCAs,
		})
	}
}

// Вспомогательная функция для проверки существования файла
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
