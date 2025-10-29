package ca

import (
	"fmt"
	"html-cer-gen/internal/lib/api/response"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

var CAfolder string = "./certs/CA"

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		log.Debug("INFO", "body", c.Request.Body)

		name := c.Param("caName")
		if name == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "параметр cn обязателен"})
			return
		}

		namePath := filepath.Join(name, name) + ".cer"

		logHandler := log.With("requestid", namePath)

		// Полный путь к файлу
		filePath := filepath.Join(CAfolder, namePath)

		// Проверяем существование файла
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logHandler.Error("file not found", "path", filePath, "err", err.Error())
			c.JSON(http.StatusNotFound, response.Error("файл не найден"))
			return
		}

		// Читаем файл
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			logHandler.Error("failed to read file", "path", filePath, "err", err.Error())
			c.JSON(http.StatusInternalServerError, response.Error("ошибка чтения файла"))
			return
		}

		// Определяем Content-Type в зависимости от расширения файла

		// Устанавливаем заголовки для скачивания
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.cer\"", name))
		c.Header("Content-Length", fmt.Sprintf("%d", len(fileData)))

		c.Data(http.StatusOK, "application/x-pem-file", fileData)
	}

}
