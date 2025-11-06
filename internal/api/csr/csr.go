package csr

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

var htmlFile = "csr.html"

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		c.HTML(http.StatusOK, htmlFile, nil)

		// reqID := requestid.Get(c)

		// logHandler := log.With(
		// 	slog.String("requestID", requestid.Get(c)),
		// )

		// selectedCa := c.Query("caName")
		// if selectedCa == "" {
		// 	selectedCa = "_"
		// }

		// certFile, certFileHeader, err := c.Request.FormFile("csrFile")
		// if err != nil {
		// 	logHandler.Error(err.Error())

		// 	c.JSON(http.StatusBadRequest, gin.H{
		// 		"error": "Не удалось получить файл сертификата." + err.Error(),
		// 	})
		// 	return
		// }
		// defer certFile.Close()

		// принимаем файл csr
		// принимаем Выбранный УЦ
		// отдаем .key .cer
	}
}
