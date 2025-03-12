package csrf_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2/csrf"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Test_Module(t *testing.T) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")
		csrfToken := csrf.Inject(module)

		ctrl.Get("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
				"data": csrfToken.Generate(ctx.Req()),
			})
		})

		ctrl.Guard(csrf.Guard).Post("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
				"data": "ok",
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
				csrf.Register(&csrf.Config{
					GetSecret: func() string {
						return "my-secret-string"
					},
					GetSessionIdentifier: func(r *http.Request) string {
						return r.Header.Get("X-Session-Id")
					},
					GetTokenFromRequest: func(r *http.Request) string {
						return r.Header.Get("X-CSRF-Token")
					},
				}),
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

	req, err := http.NewRequest("GET", testServer.URL+"/api/test", nil)
	req.Header.Set("X-Session-Id", "123")
	require.Nil(t, err)

	resp, err := testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	data, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	type Response struct {
		Data interface{} `json:"data"`
	}

	var res Response
	require.Nil(t, json.Unmarshal(data, &res))

	req, err = http.NewRequest("POST", testServer.URL+"/api/test", nil)
	require.Nil(t, err)

	req.Header.Set("X-Session-Id", "123")
	req.Header.Set("X-CSRF-Token", res.Data.(string))

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = testClient.Post(testServer.URL+"/api/test", "application/json", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
