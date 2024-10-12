package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func Test_HS256(t *testing.T) {
	jwtService := NewJwtHS256(JwtOptions{
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

	jwtService2 := NewJwtHS256(JwtOptions{
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
	require.Error(t, err)

	// Case expired
	time.Sleep(3 * time.Second)
	_, err = jwtService2.Verify(token)
	require.Error(t, err)
}
