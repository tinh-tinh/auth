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
	require.NoError(t, err)

	payload, err := jwtService.Verify(token)
	require.NoError(t, err)
	require.Equal(t, "bar", payload["foo"])
}
