package csrf_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2/csrf"
)

func Test_Csrf(t *testing.T) {
	csrfToken := &csrf.Config{
		GetSecret: func() string {
			return "secret"
		},
		GetSessionIdentifier: func(r *http.Request) string {
			return r.Header.Get("x-identifier")
		},
		IgnoreMethod: []string{http.MethodPost},
		Size:         100,
		CookieOptions: http.Cookie{
			Name:   "csrf_token",
			MaxAge: 3600,
			Domain: "localhost",
			Path:   "/",
		},
	}

	df, err := csrf.DefaultConfig(csrfToken)
	require.Nil(t, err)
	require.Equal(t, []string{http.MethodPost}, df.IgnoreMethod)
	require.Equal(t, 100, df.Size)
	require.Equal(t, "secret", df.GetSecret())

	cookie := csrfToken.GetCookie("csrf_token")
	require.Equal(t, "localhost", cookie.Domain)
	require.Equal(t, "csrf_token", cookie.Name)

	_, err = csrf.DefaultConfig(&csrf.Config{})
	require.NotNil(t, err)

	_, err = csrf.DefaultConfig(&csrf.Config{
		GetSecret: func() string {
			return ""
		},
	})

	require.NotNil(t, err)
}
