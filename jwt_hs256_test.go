package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2"
)

func Test_HS256(t *testing.T) {
	jwtService := auth.NewJwtHS(auth.JwtOptions{
		Alg:    jwt.SigningMethodHS256,
		Secret: "secret",
		Exp:    time.Hour,
	})

	token, err := jwtService.Generate(jwt.MapClaims{
		"foo": "bar",
	})
	require.Nil(t, err)

	payload, err := jwtService.Verify(token)
	require.Nil(t, err)
	require.Equal(t, "bar", payload["foo"])

	// Case wrong token
	_, err = jwtService.Verify("Abc")
	require.Error(t, err)

	jwtService2 := auth.NewJwtHS(auth.JwtOptions{
		Alg:    jwt.SigningMethodHS256,
		Secret: "abc",
		Exp:    time.Second,
	})
	token, err = jwtService2.Generate(jwt.MapClaims{
		"foo": "bar",
	})
	require.Nil(t, err)

	// Case wrong secret
	_, err = jwtService.Verify(token)
	require.NotNil(t, err)

	// Case expired
	time.Sleep(3 * time.Second)
	_, err = jwtService2.Verify(token)
	require.NotNil(t, err)
}

func Test_HS256_Exp(t *testing.T) {
	jwtService := auth.NewJwtHS(auth.JwtOptions{
		Alg:    jwt.SigningMethodHS256,
		Secret: "secret",
		Exp:    time.Hour,
	})

	token, err := jwtService.Generate(jwt.MapClaims{
		"foo": "bar",
	}, auth.GenOptions{Exp: 1 * time.Millisecond})
	require.Nil(t, err)
	time.Sleep(10 * time.Millisecond)

	_, err = jwtService.Verify(token)
	require.NotNil(t, err)
}
