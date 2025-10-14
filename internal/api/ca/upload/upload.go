package upload

import (
	"fmt"
	"html-cer-gen/internal/api/middlewares/requestid"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		caDir := "./certs/CA"

		c.Request.ParseMultipartForm(5 << 20)

		logHadnler := log.With("requestid", requestid.Get(c))

		// Получаем файлы из формы
		certFile, certHeader, err := c.Request.FormFile("certFile")
		if err != nil {
			logHadnler.Error(err.Error())

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Не удалось получить файл сертификата",
				"Details": err.Error(),
			})
			return
		}
		defer certFile.Close()

		keyFile, keyHeader, err := c.Request.FormFile("keyFile")
		if err != nil {
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Не удалось получить файл ключа",
				"Details": err.Error(),
			})
			return
		}
		defer keyFile.Close()

		// Получаем имя УЦ
		caName := c.Request.FormValue("caName")
		if caName == "" {

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Имя УЦ не может быть пустым",
				"Details": "",
			})
			return
		}

		// Проверяем расширения файлов
		certExt := strings.ToLower(filepath.Ext(certHeader.Filename))
		if certExt != ".cer" && certExt != ".crt" {

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Файл сертификата должен иметь расширение .cer или .crt",
				"Details": "",
			})
			return
		}

		keyExt := strings.ToLower(filepath.Ext(keyHeader.Filename))
		if keyExt != ".key" {

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Файл ключа должен иметь расширение .key",
				"Details": "",
			})
			return
		}

		// Создаем директорию для УЦ если не существует
		caDir = filepath.Join(caDir, caName)
		if err := os.MkdirAll(caDir, 0755); err != nil {

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Не удалось создать директорию для УЦ",
				"Details": err.Error(),
			})
			return
		}

		// Сохраняем сертификат
		certPath := filepath.Join(caDir, fmt.Sprintf("%s.cer", caName))
		certDst, err := os.Create(certPath)
		if err != nil {

			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Не удалось сохранить сертификат",
				"Details": err.Error(),
			})
			return
		}
		defer certDst.Close()

		if _, err := io.Copy(certDst, certFile); err != nil {

			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Не удалось сохранить сертификат",
				"Details": err.Error(),
			})
			return
		}

		// Сохраняем ключ
		keyPath := filepath.Join(caDir, fmt.Sprintf("%s.key", caName))
		keyDst, err := os.Create(keyPath)
		if err != nil {

			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Не удалось сохранить ключ",
				"Details": err.Error(),
			})
			return
		}
		defer keyDst.Close()

		if _, err := io.Copy(keyDst, keyFile); err != nil {

			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Не удалось сохранить ключ",
				"Details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Удостоверяющий центр успешно загружен",
			"caName":  caName,
		})
	}

}

func ListCAHandler(c *gin.Context) {
	caDir := "./ca"

	files, err := os.ReadDir(caDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Не удалось прочитать директорию УЦ: " + err.Error(),
		})
		return
	}

	var caList []map[string]string
	for _, file := range files {
		if file.IsDir() {
			caList = append(caList, map[string]string{
				"name": file.Name(),
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"cas":     caList,
	})
}
