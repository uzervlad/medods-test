package models

import (
	"net/netip"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	GUID    string `json:"guid"`
	TokenID int    `json:"token"`
	jwt.RegisteredClaims
}

type DatabaseToken struct {
	ID                 int
	GUID               string
	HashedRefreshToken string
	UserAgent          string
	IP                 netip.Addr
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type GetUserBody struct {
	AccessToken string `json:"access_token"`
}

type GetUserResponse struct {
	GUID string `json:"guid"`
}

type RefreshBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LogoutResponse struct {
	OK bool `json:"ok"`
}
