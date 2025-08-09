package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinh-tinh/tinhtinh/v2/common"
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
			Exp:           opt.Exp,
			SkipValidaton: opt.SkipValidaton,
		},
	}
}

func (rs *JwtRS) Generate(payload jwt.MapClaims, opts ...GenOptions) (string, error) {
	opt := GenOptions{
		Exp:        rs.Opt.Exp,
		PrivateKey: rs.PrivateKey,
	}

	if len(opts) > 0 {
		temp := append(opts, opt)
		opt = common.MergeStruct(temp...)
	}

	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(opt.Exp).Unix()

	claims := jwt.NewWithClaims(rs.Method, payload)

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(opt.PrivateKey)
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

func (rs *JwtRS) Verify(token string, opts ...VerifyOptions) (jwt.MapClaims, error) {
	opt := VerifyOptions{
		PublicKey: rs.PublicKey,
	}

	if len(opts) > 0 {
		temp := append(opts, opt)
		opt = common.MergeStruct(temp...)
	}

	decodedPublicKey, err := base64.StdEncoding.DecodeString(opt.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("validate: parse key: %w", err)
	}

	parseOptions := []jwt.ParserOption{}
	if rs.Opt.SkipValidaton {
		parseOptions = append(parseOptions, jwt.WithoutClaimsValidation())
	}

	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return key, nil
	}, parseOptions...)
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("validate: invalid token")
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
