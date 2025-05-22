package auth_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2"
)

func Test_Panic(t *testing.T) {
	require.Panics(t, func() {
		_ = auth.NewJwt(auth.JwtOptions{
			Alg: jwt.SigningMethodES256,
		})
	})
}
