package twofa_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2/twofa"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func TestModule(t *testing.T) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")
		totpCode := twofa.Inject(module)

		ctrl.Post("", func(ctx core.Ctx) error {
			data, err := totpCode.Generate(totp.GenerateOpts{
				Issuer:      "Snake Oil",
				AccountName: "alice@example.com",
			})
			if err != nil {
				return err
			}
			return ctx.JSON(core.Map{
				"data": data.Secret(),
			})
		})

		ctrl.Get("", func(ctx core.Ctx) error {
			secret := ctx.Query("secret")
			code := ctx.Query("code")
			valid := totpCode.Validate(code, secret)
			return ctx.JSON(core.Map{
				"data": valid,
			})
		})

		return ctrl
	}

	authModule := func(module core.Module) core.Module {
		mod := module.New(core.NewModuleOptions{
			Controllers: []core.Controllers{authController},
		})

		return mod
	}

	appModule := func() core.Module {
		appMod := core.NewModule(core.NewModuleOptions{
			Imports: []core.Modules{
				twofa.Register(),
				authModule,
			},
		})

		return appMod
	}

	app := core.CreateFactory(appModule)
	app.SetGlobalPrefix("api")

	testServer := httptest.NewServer(app.PrepareBeforeListen())
	defer testServer.Close()

	testClient := testServer.Client()

	resp, err := testClient.Post(testServer.URL+"/api/test", "application/json", nil)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	type Response struct {
		Data interface{} `json:"data"`
	}

	var res Response
	require.Nil(t, json.Unmarshal(data, &res))

	resp, err = testClient.Get(testServer.URL + "/api/test?secret=" + res.Data.(string) + "&code=123456")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	data, err = io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Nil(t, json.Unmarshal(data, &res))
	require.False(t, res.Data.(bool), "Expected code validation to fail with incorrect code")
}
