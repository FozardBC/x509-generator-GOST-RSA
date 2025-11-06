package reqlog

import (
	"html-cer-gen/internal/api/middlewares/requestid"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func RequestIdMidlleware(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		reqID := requestid.Get(c)

		c.Next()

		log.Info("Request", "RequestID", reqID, "Path", c.Request.URL.Path, "Status", c.Writer.Status(), "IP", c.ClientIP())
	}
}
