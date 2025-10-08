package requestid

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type contextKey string
type headerKey string

const ContextKeyRequestID contextKey = "requestID"
const HeaderKeyRequestID headerKey = "X-Request-ID"

func RequestIdMidlleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestid := uuid.New().String()

		c.Header(string(HeaderKeyRequestID), requestid)

		c.Set(string(ContextKeyRequestID), requestid)

		ctx := context.WithValue(c.Request.Context(), ContextKeyRequestID, requestid)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

func Get(c *gin.Context) string {
	if id, exists := c.Get(string(ContextKeyRequestID)); exists {
		return id.(string)
	}
	return ""
}
