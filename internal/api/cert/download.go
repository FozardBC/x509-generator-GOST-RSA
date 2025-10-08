package cert

import (
	"fmt"
	"html-cer-gen/internal/lib/api/response"
	"html-cer-gen/internal/services/archive"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		log.Debug("INFO", "body", c.Request.Body)

		ReqID := c.Param("reqid")
		if ReqID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "параметр cn обязателен"})
			return
		}

		selectedCa := c.Query("caName")
		if selectedCa == "" {
			selectedCa = "_"
		}

		commonName := c.Query("commonName")
		if commonName == "" {
			commonName = "certs"
		}

		logHandler := log.With("requestid", ReqID)

		zipData, err := archive.ZipFolderToBytes(ReqID)
		if err != nil {
			logHandler.Error("failed to get zip", "err", err.Error())

			c.JSON(http.StatusInternalServerError, response.Error("failed to get zip"))
			return
		}

		c.Header("Content-Type", "application/zip")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s(CA:%s).zip\"", commonName, selectedCa))

		c.Data(http.StatusOK, "application/zip", zipData)
	}

}
