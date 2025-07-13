package handlers

import (
	"medods/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")
		if header == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
				Error: "Unauthorized",
			})
			return
		}

		claims, ok := h.validateToken(header)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
				Error: "Unautorized",
			})
			return
		}

		token, ok := h.database.GetToken(claims.TokenID)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
				Error: "Unautorized",
			})
			return
		}

		ctx.Set("token", token)
		ctx.Next()
	}
}
