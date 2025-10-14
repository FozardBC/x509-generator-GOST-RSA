package pfx

import (
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

	}
}
