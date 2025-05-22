package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtRS struct {
	Method     jwt.SigningMethod
	PrivateKey string
	PublicKey  string
	Opt        SubOptions
}

func NewJwtRS(opt JwtOptions) *JwtRS {
	return &JwtRS{
		Method:     opt.Alg,
		PrivateKey: opt.PrivateKey,
		PublicKey:  opt.PublicKey,
		Opt: SubOptions{
			Exp:       opt.Exp,
			IgnoreExp: opt.IgnoreExp,
		},
	}
}

func (rs *JwtRS) Generate(payload jwt.MapClaims) (string, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(rs.Opt.Exp).Unix()

	claims := jwt.NewWithClaims(rs.Method, payload)

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(rs.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("could not decode key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("could not parse key: %w", err)
	}

	token, err := claims.SignedString(key)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (rs *JwtRS) Verify(token string) (jwt.MapClaims, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(rs.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	if !rs.Opt.IgnoreExp && time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

func (rs *JwtRS) Decode(token string) (jwt.MapClaims, error) {
	// Create an empty claims object or your own custom claims type
	claims := jwt.MapClaims{}

	// Parse the token without verifying the signature
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
