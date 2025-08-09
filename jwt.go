package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type GenOptions struct {
	Exp        time.Duration
	Secret     string
	PrivateKey string
}

type VerifyOptions struct {
	Secret    string
	PublicKey string
}

type Jwt interface {
	Generate(payload jwt.MapClaims, opts ...GenOptions) (string, error)
	Decode(token string) (jwt.MapClaims, error)
	Verify(token string, opts ...VerifyOptions) (jwt.MapClaims, error)
}

type JwtOptions struct {
	Alg           jwt.SigningMethod
	Secret        string
	PrivateKey    string
	PublicKey     string
	Exp           time.Duration
	SkipValidaton bool
}

func NewJwt(opt JwtOptions) Jwt {
	switch opt.Alg {
	case jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodHS512:
		return NewJwtHS(opt)
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512:
		return NewJwtRS(opt)
	}
	panic(fmt.Sprintf("not support alg %s\n", opt.Alg))
}
