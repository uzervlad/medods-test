package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"

	"medods/database"
	"medods/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Handlers struct {
	database *database.Database
	webhook  string
}

func CreateHandlers(database *database.Database) Handlers {
	return Handlers{
		database: database,
		webhook:  os.Getenv("WEBHOOK_URL"),
	}
}

// GetTokens
//
//	@Summary	Get token for user
//	@Router		/tokens [get]
//	@Produce	json
//	@Param		guid	query		string					true	"User GUID"
//	@Success	200		{object}	models.TokenResponse	"`refresh_token` is a base64-encoded string, and should be decoded when used"
//	@Failure	400		{object}	models.ErrorResponse
//	@Failure	500		{object}	models.ErrorResponse
func (h *Handlers) GetTokens(ctx *gin.Context) {
	guid := ctx.Query("guid")
	if guid == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{
			Error: "No guid provided",
		})
		return
	}

	useragent := ctx.Request.UserAgent()
	ip := ctx.ClientIP()

	token_id, refresh_token, ok := h.generateRefreshToken(guid, useragent, ip)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unable to generate a token",
		})
		return
	}

	access_token, ok := h.generateAccessToken(guid, token_id)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unable to generate a token",
		})
		return
	}

	response := models.TokenResponse{
		AccessToken:  access_token,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(refresh_token)),
	}

	ctx.JSON(http.StatusOK, response)
}

// GetUUID
//
//	@Summary	Get UUID
//	@Router		/uuid [post]
//	@Accept		json
//	@Produce	json
//	@Success	200	{object}	models.GetUserResponse
//	@Failure	401	{object}	models.ErrorResponse
//	@Security	ApiKeyAuth
func (h *Handlers) GetUUID(ctx *gin.Context) {
	token := ctx.MustGet("token").(models.DatabaseToken)

	ctx.JSON(http.StatusOK, models.GetUserResponse{
		GUID: token.GUID,
	})
}

// RefreshToken
//
//	@Summary	Refresh tokens
//	@Router		/refresh [post]
//	@Accept		json
//	@Produce	json
//	@Param		tokens	body		models.RefreshBody	true	"Token pair"
//	@Success	200		{object}	models.TokenResponse
//	@Failure	400		{object}	models.ErrorResponse
//	@Failure	401		{object}	models.ErrorResponse
//	@Failure	403		{object}	models.ErrorResponse
//	@Failure	422		{object}	models.ErrorResponse
//	@Failure	500		{object}	models.ErrorResponse
func (h *Handlers) RefreshToken(ctx *gin.Context) {
	var body models.RefreshBody
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnprocessableEntity, models.ErrorResponse{
			Error: "Malformed body",
		})
		return
	}

	claims, ok := h.validateToken(body.AccessToken)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unauthorized",
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

	refresh_bytes, err := hex.DecodeString(body.RefreshToken)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, models.ErrorResponse{
			Error: "Invalid token",
		})
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(token.HashedRefreshToken), refresh_bytes); err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unauthorized",
		})
		return
	}

	useragent := ctx.Request.UserAgent()
	ip := ctx.ClientIP()

	if useragent != token.UserAgent {
		h.invalidateToken(claims.TokenID)
		ctx.AbortWithStatusJSON(http.StatusForbidden, models.ErrorResponse{
			Error: "Forbidden",
		})
		return
	}

	if ip != token.IP.String() {
		h.webhookPost(claims.GUID, token.IP.String(), ip)
	}

	token_id, refresh_token, ok := h.generateRefreshToken(claims.GUID, useragent, ip)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unable to generate a token",
		})
		return
	}

	access_token, ok := h.generateAccessToken(claims.GUID, token_id)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, models.ErrorResponse{
			Error: "Unable to generate a token",
		})
		return
	}

	response := models.TokenResponse{
		AccessToken:  access_token,
		RefreshToken: base64.StdEncoding.EncodeToString([]byte(refresh_token)),
	}

	ctx.JSON(http.StatusOK, response)
}

// Logout
//
//	@Summary	Logout
//	@Router		/logout [post]
//	@Produce	json
//	@Success	200	{object}	models.LogoutResponse
//	@Failure	401	{object}	models.ErrorResponse
//	@Failure	500	{object}	models.ErrorResponse
//	@Security	ApiKeyAuth
func (h *Handlers) Logout(ctx *gin.Context) {
	token := ctx.MustGet("token").(models.DatabaseToken)

	if !h.invalidateToken(token.ID) {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, models.ErrorResponse{
			Error: "Unexpected database error??",
		})
		return
	}

	ctx.JSON(http.StatusOK, models.LogoutResponse{
		OK: true,
	})
}
