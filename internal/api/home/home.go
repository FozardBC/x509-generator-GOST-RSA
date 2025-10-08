package home

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

var htmlFile = "index.html"

func New(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {

		c.HTML(http.StatusOK, htmlFile, nil)

	}
}
