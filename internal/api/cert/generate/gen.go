package generate

import (
	"fmt"
	"html-cer-gen/internal/api/middlewares/requestid"
	"html-cer-gen/internal/lib/api/response"
	"html-cer-gen/internal/models"
	"html-cer-gen/internal/services/generator"
	"html-cer-gen/internal/services/generator/gost"
	rsa "html-cer-gen/internal/services/generator/rsa"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func New(log *slog.Logger, RsaGenerator *rsa.RSACertificateGenerator, GostGenerator *gost.GostCertificateGenerator) gin.HandlerFunc {
	return func(c *gin.Context) {

		reqID := requestid.Get(c)

		logHandler := log.With(
			slog.String("requestID", requestid.Get(c)),
		)

		log.Debug("INFO", "body", c.Request.Body)

		var Req *models.CertRequest

		if err := c.ShouldBind(&Req); err != nil {
			logHandler.Error("Ошибка при преобразовании JSON", "Ошибка", err.Error())
			c.HTML(http.StatusBadRequest, "form.html", gin.H{
				"Error": fmt.Sprintf("Ошибка валидации: %v", err),
			})
			return
		}

		if err := validator.New().Struct(Req); err != nil {
			validatorErr := err.(validator.ValidationErrors)

			logHandler.Error("invalid request", "err", err.Error())

			c.JSON(http.StatusBadRequest, response.ValidationError(validatorErr))

			return
		}

		logHandler.Debug("REQ", "Body", Req)

		if Req.Count == 0 {
			Req.Count = 1
		}

		var generator generator.Generator

		switch Req.KeyType {
		case "rsa2048":
			generator = RsaGenerator
		case "rsa4096":
			generator = RsaGenerator
		default:
			generator = GostGenerator
		}

		for i := range Req.Count {

			name := fmt.Sprintf("%s_%d", Req.CommonName, i+1)

			if err := generator.GenCertAndTrustCA(Req, reqID); err != nil {
				logHandler.Error("failed to generate cert and trust CA", "err", err.Error(), "Data", Req)

				c.JSON(http.StatusInternalServerError, err.Error())

				return
			}
			_ = i
		}

		if Req.Count > 1 {

		}

		c.HTML(http.StatusOK, "download.html", gin.H{
			"CommonName": Req.CommonName,
			"Count":      Req.Count,
			"ReqID":      reqID,
			"SelectedCA": Req.CAName,
		})
	}
}
