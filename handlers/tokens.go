package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"medods/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const jwtSecret = "medods"

func (h *Handlers) generateRefreshToken(guid, useragent, ip string) (int, string, bool) {
	refresh_bytes := make([]byte, 64)
	rand.Read(refresh_bytes)
	refresh_token := hex.EncodeToString(refresh_bytes)

	refresh_token_bcrypt, err := bcrypt.GenerateFromPassword(refresh_bytes, bcrypt.DefaultCost)
	if err != nil {
		return 0, "", false
	}

	token_id, ok := h.database.CreateToken(guid, string(refresh_token_bcrypt), useragent, ip)
	if !ok {
		return 0, "", false
	}

	return token_id, refresh_token, true
}

func (h *Handlers) generateAccessToken(guid string, token_id int) (string, bool) {
	access_token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, models.Claims{
		GUID:    guid,
		TokenID: token_id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{
				Time: time.Now().Add(time.Hour * 24),
			},
		},
	}).SignedString([]byte(jwtSecret))
	if err != nil {
		//     :\
		h.invalidateToken(token_id)
		// h.pool.Exec(context.Background(), "delete from tokens where id = $1", token_id)
		return "", false
	}

	return access_token, true
}

func (h *Handlers) invalidateToken(token_id int) bool {
	return h.database.DeleteToken(token_id)
}

func (h *Handlers) validateToken(t string) (*models.Claims, bool) {
	token, err := jwt.ParseWithClaims(t, &models.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte("medods"), nil
	})
	if err != nil {
		return &models.Claims{}, false
	}
	claims, ok := token.Claims.(*models.Claims)
	if !ok {
		return &models.Claims{}, false
	}
	return claims, true
}
