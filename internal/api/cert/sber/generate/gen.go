package sber

import (
	"fmt"
	"html-cer-gen/internal/api/middlewares/requestid"
	"html-cer-gen/internal/lib/api/response"
	"html-cer-gen/internal/models"
	sbergen "html-cer-gen/internal/services/sberGen"
	"html-cer-gen/internal/services/sberGen/generate/rsa"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// add  GostGenerator *gost.GostCertificateGenerator
func New(log *slog.Logger, RsaGenerator *rsa.SberRSACertificateGenerator) gin.HandlerFunc {
	return func(c *gin.Context) {

		reqID := requestid.Get(c)

		logHandler := log.With(
			slog.String("requestID", requestid.Get(c)),
		)

		log.Debug("INFO", "body", c.Request.Body)

		var Req *models.SberCertRequest

		if err := c.ShouldBind(&Req); err != nil {
			logHandler.Error("Ошибка при преобразовании JSON", "Ошибка", err.Error())
			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Ошибка при преобразовании JSON",
				"Details": err.Error(),
			})
			return
		}

		if err := validator.New().Struct(Req); err != nil {
			validatorErr := err.(validator.ValidationErrors)

			logHandler.Error("invalid request", "err", err.Error())

			c.HTML(http.StatusBadRequest, "error.html", gin.H{
				"Message": "Ошибка при преобразовании JSON",
				"Details": response.ValidationError(validatorErr),
			})

			return
		}

		logHandler.Debug("REQ", "Body", Req)

		if Req.Count == 0 {
			Req.Count = 1
		}

		var generator sbergen.SberGenerator

		switch Req.KeyType {
		case "rsa2048":
			generator = RsaGenerator
		case "rsa4096":
			generator = RsaGenerator
			// default:
			// 	generator = GostGenerator
			// }
		}
		if Req.Count > 1 {
			for i := range Req.Count {

				name := fmt.Sprintf("%s_%d", Req.CommonName, i+1)

				temp := Req.CommonName
				Req.CommonName = name

				if err := generator.GenCertAndTrustCA(Req, reqID); err != nil {
					logHandler.Error("failed to generate cert and trust CA", "err", err.Error(), "Data", Req)

					c.HTML(http.StatusInternalServerError, "error.html", gin.H{
						"Message": "Ошибка при генерации сертификатов",
						"Details": err.Error(),
					})

					return
				}

				Req.CommonName = temp

				_ = i
			}
		}

		if err := generator.GenCertAndTrustCA(Req, reqID); err != nil {
			logHandler.Error("failed to generate cert and trust CA", "err", err.Error(), "Data", Req)

			c.HTML(http.StatusInternalServerError, "error.html", gin.H{
				"Message": "Ошибка при генерации сертификатов",
				"Details": err.Error(),
			})

			return
		}

		c.HTML(http.StatusOK, "download.html", gin.H{
			"CommonName": Req.CommonName,
			"Count":      Req.Count,
			"ReqID":      reqID,
			"SelectedCA": Req.CAName,
		})
	}
}
