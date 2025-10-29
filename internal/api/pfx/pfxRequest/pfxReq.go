package pfxrequest

import (
	"fmt"
	"html-cer-gen/internal/services/pfx"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func New(log *slog.Logger, RsaCreator pfx.Creator, GostCreator pfx.Creator) gin.HandlerFunc {
	return func(c *gin.Context) {

		//reqID := requestid.Get(c)

		reqPfxID := c.Param("reqid")
		if reqPfxID == "" {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Неверно передан параметр ReqID",
			})
			return
		}

		commonName := c.Query("commonName")
		if reqPfxID == "" {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Неверно передан параметр commonName",
			})
			return
		}

		keyType := c.Query("keyType")
		if reqPfxID == "" {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Неверно передан параметр keyType",
			})
			return
		}

		password := c.Query("password")
		if reqPfxID == "" {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Неверно передан параметр password",
			})
			return
		}

		folderPath := fmt.Sprintf("./certs/generated/%s", reqPfxID)

		certName := commonName + ".cer"
		keyName := commonName + ".key"

		certPath := filepath.Join(folderPath, certName)
		keyPath := filepath.Join(folderPath, keyName)

		var creator pfx.Creator

		switch keyType {
		case "rsa2048", "rsa4096":
			creator = RsaCreator
		case "GOST2012256", "GOST2012512":
			creator = GostCreator
		default:
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Неверно передан параметр keyType",
			})
			return
		}

		pfxData, err := creator.Create(certPath, keyPath, password)
		if err != nil {
			log.Error("Ошибка создания PFX", "error", err)
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Ошибка создания контейнера .pfx",
				"Details": err.Error(),
			})
			return
		}

		// 6. Отправка файла
		c.Header("Content-Type", "application/x-pkcs12")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pfx"`, commonName))
		c.Data(http.StatusOK, "application/x-pkcs12", pfxData)

	}
}
