package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

type Jwt interface {
	Generate(payload jwt.MapClaims) (string, error)
	Verify(token string) (jwt.MapClaims, error)
}

type JwtOptions struct {
	Alg        jwt.SigningMethod
	Secret     string
	PrivateKey string
	PublicKey  string
	Exp        time.Duration
	IgnoreExp  bool
	Factory    func(module core.Module) JwtOptions
}

func NewJwt(opt JwtOptions) Jwt {
	if opt.Alg == jwt.SigningMethodRS256 {
		return NewJwtRS256(opt)
	} else {
		return NewJwtHS256(opt)
	}
}
