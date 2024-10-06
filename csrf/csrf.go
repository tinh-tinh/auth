package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"
)

type Config struct {
	GetSecret            func() string
	GetSessionIdentifier func(r *http.Request) string
	CookieOptions        http.Cookie
	Size                 int
	IgnoreMethod         []string
	GetTokenFromRequest  func(*http.Request) string
}

func (c *Config) Generate(r *http.Request) string {
	// Gether the values
	secret := c.GetSecret()
	sessionID := c.GetSessionIdentifier(r)
	random := CryptoRandom(c.Size)

	// Create the CSRF Token
	message := sessionID + "!" + random
	hmac := hmac.New(sha256.New, []byte(secret))

	_, err := hmac.Write([]byte(message))
	if err != nil {
		panic(err)
	}

	token := base32.StdEncoding.EncodeToString(hmac.Sum(nil)) + "." + message
	return token
}

func (c *Config) Verify(token string) bool {
	comps := strings.Split(token, ".")
	message := comps[1]

	secret := c.GetSecret()
	hmac := hmac.New(sha256.New, []byte(secret))

	_, err := hmac.Write([]byte(message))
	if err != nil {
		panic(err)
	}
	verify := hmac.Sum(nil)

	return strings.Compare(comps[0], base32.StdEncoding.EncodeToString(verify)) == 0
}

func (c *Config) GetCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     c.CookieOptions.Name,
		Value:    token,
		Path:     c.CookieOptions.Path,
		Domain:   c.CookieOptions.Domain,
		MaxAge:   c.CookieOptions.MaxAge,
		Secure:   c.CookieOptions.Secure,
		HttpOnly: c.CookieOptions.HttpOnly,
		SameSite: c.CookieOptions.SameSite,
	}
}

func DefaultConfig(config *Config) (*Config, error) {
	defaultConfig := &Config{
		CookieOptions: http.Cookie{
			Name:     "csrf_token",
			Path:     "/",
			MaxAge:   3600,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		},
		Size:         32,
		IgnoreMethod: []string{""},
	}

	if config.GetSecret != nil {
		defaultConfig.GetSecret = config.GetSecret
	} else {
		return nil, errors.New("csrf: GetSecret is required")
	}

	if config.GetSessionIdentifier != nil {
		defaultConfig.GetSessionIdentifier = config.GetSessionIdentifier
	} else {
		return nil, errors.New("csrf: GetSessionIdentifier is required")
	}

	if config.GetTokenFromRequest != nil {
		defaultConfig.GetTokenFromRequest = config.GetTokenFromRequest
	}

	if config.IgnoreMethod != nil {
		defaultConfig.IgnoreMethod = config.IgnoreMethod
	}

	if config.Size != 0 {
		defaultConfig.Size = config.Size
	}

	if config.CookieOptions.Name != "" {
		defaultConfig.CookieOptions.Name = config.CookieOptions.Name
	}

	if config.CookieOptions.MaxAge != 0 {
		defaultConfig.CookieOptions.MaxAge = config.CookieOptions.MaxAge
	}

	if !config.CookieOptions.Secure {
		defaultConfig.CookieOptions.Secure = config.CookieOptions.Secure
	}

	if !config.CookieOptions.HttpOnly {
		defaultConfig.CookieOptions.HttpOnly = config.CookieOptions.HttpOnly
	}

	if config.CookieOptions.SameSite != http.SameSiteStrictMode {
		defaultConfig.CookieOptions.SameSite = config.CookieOptions.SameSite
	}

	if config.CookieOptions.Domain != "" {
		defaultConfig.CookieOptions.Domain = config.CookieOptions.Domain
	}

	if config.CookieOptions.Path != "" {
		defaultConfig.CookieOptions.Path = config.CookieOptions.Path
	}

	if config.CookieOptions.MaxAge != 0 {
		defaultConfig.CookieOptions.MaxAge = config.CookieOptions.MaxAge
	}

	return defaultConfig, nil
}

func CryptoRandom(length int) string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}
