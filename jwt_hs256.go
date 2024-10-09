package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SubOptions struct {
	Exp       time.Duration
	IgnoreExp bool
}
type JwtHS256 struct {
	Secret string
	Opt    SubOptions
}

func NewJwtHS256(opt JwtOptions) *JwtHS256 {
	return &JwtHS256{
		Secret: opt.Secret,
		Opt: SubOptions{
			Exp:       opt.Exp,
			IgnoreExp: opt.IgnoreExp,
		},
	}
}

func (hs256 *JwtHS256) Generate(payload jwt.MapClaims) (string, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(hs256.Opt.Exp).Unix()

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	token, err := claims.SignedString([]byte(hs256.Secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (hs256 *JwtHS256) Verify(token string) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(hs256.Secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	if !hs256.Opt.IgnoreExp && time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}
