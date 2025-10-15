package pfx

import (
	"fmt"
	"html-cer-gen/internal/api/middlewares/requestid"
	"html-cer-gen/internal/services/pfx"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func New(log *slog.Logger, RsaCreator pfx.Creator, GostCreator pfx.Creator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Парсим multipart форму
		reqID := requestid.Get(c)

		certFile, certErr := c.FormFile("certFile")
		keyFile, keyErr := c.FormFile("keyFile")
		password := c.PostForm("password")
		keyType := c.PostForm("keyTypePFX")

		var creator pfx.Creator

		switch keyType {
		case "RSA":
			creator = RsaCreator
		case "GOST":
			creator = GostCreator
		default:
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Неверный тип ключа"})
			return
		}

		// 2. Валидация полей
		if certErr != nil || keyErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Требуются файлы сертификата и ключа"})
			return
		}

		if password == "" || len(password) < 4 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Пароль обязателен и должен быть не короче 4 символов"})
			return
		}

		// 3. Проверка расширений
		certExt := filepath.Ext(certFile.Filename)
		keyExt := filepath.Ext(keyFile.Filename)

		if certExt != ".cer" && certExt != ".crt" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Сертификат должен быть .cer или .crt"})
			return
		}
		if keyExt != ".key" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Ключ должен быть .key"})
			return
		}

		// 4. Сохраняем временные файлы (или читаем в память)
		tmpDir := fmt.Sprintf("./certs/pfx/%s", reqID)
		certPath := filepath.Join(tmpDir, certFile.Filename)
		keyPath := filepath.Join(tmpDir, keyFile.Filename)

		if err := c.SaveUploadedFile(certFile, certPath); err != nil {
			log.Error("Не удалось сохранить сертификат", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения сертификата"})
			return
		}
		defer os.Remove(certPath)

		if err := c.SaveUploadedFile(keyFile, keyPath); err != nil {
			log.Error("Не удалось сохранить ключ", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения ключа"})
			return
		}
		defer os.Remove(keyPath)

		// 5. Генерация .pfx (пример через OpenSSL CLI — замени на свою реализацию)
		pfxData, err := creator.Create(certPath, keyPath, password)
		if err != nil {
			log.Error("Ошибка создания PFX", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать .pfx контейнер"})
			return
		}

		// 6. Отправка файла
		c.Header("Content-Type", "application/x-pkcs12")
		c.Header("Content-Disposition", `attachment; filename="certificate.pfx"`)
		c.Data(http.StatusOK, "application/x-pkcs12", pfxData)
	}
}
