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
type JwtHS struct {
	Method jwt.SigningMethod
	Secret string
	Opt    SubOptions
}

func NewJwtHS(opt JwtOptions) *JwtHS {
	return &JwtHS{
		Method: opt.Alg,
		Secret: opt.Secret,
		Opt: SubOptions{
			Exp:       opt.Exp,
			IgnoreExp: opt.IgnoreExp,
		},
	}
}

func (hs *JwtHS) Generate(payload jwt.MapClaims) (string, error) {
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(hs.Opt.Exp).Unix()

	claims := jwt.NewWithClaims(hs.Method, payload)

	token, err := claims.SignedString([]byte(hs.Secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (hs *JwtHS) Verify(token string) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(hs.Secret), nil
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

	if !hs.Opt.IgnoreExp && time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}
