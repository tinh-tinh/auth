package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinh-tinh/tinhtinh/v2/common"
)

type SubOptions struct {
	Exp           time.Duration
	SkipValidaton bool
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
			Exp:           opt.Exp,
			SkipValidaton: opt.SkipValidaton,
		},
	}
}

func (hs *JwtHS) Generate(payload jwt.MapClaims, opts ...GenOptions) (string, error) {
	var exp time.Duration
	if len(opts) > 0 {
		options := common.MergeStruct(opts...)
		exp = options.Exp
	} else {
		exp = hs.Opt.Exp
	}

	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(exp).Unix()

	claims := jwt.NewWithClaims(hs.Method, payload)

	token, err := claims.SignedString([]byte(hs.Secret))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (hs *JwtHS) Verify(token string) (jwt.MapClaims, error) {
	parseOptions := []jwt.ParserOption{}
	if hs.Opt.SkipValidaton {
		parseOptions = append(parseOptions, jwt.WithoutClaimsValidation())
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(hs.Secret), nil
	}, parseOptions...)
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (hs *JwtHS) Decode(token string) (jwt.MapClaims, error) {
	// Create an empty claims object or your own custom claims type
	claims := jwt.MapClaims{}

	// Parse the token without verifying the signature
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
