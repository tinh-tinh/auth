package csrf

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/tinhtinh/core"
)

func Test_Module(t *testing.T) {
	authController := func(module *core.DynamicModule) *core.DynamicController {
		ctrl := module.NewController("test")
		csrf := InjectCSRF(module)

		ctrl.Get("", func(ctx core.Ctx) {
			ctx.JSON(core.Map{
				"data": csrf.Generate(ctx.Req()),
			})
		})

		ctrl.Guard(Guard).Post("", func(ctx core.Ctx) {
			ctx.JSON(core.Map{
				"data": "ok",
			})
		})

		return ctrl
	}

	authModule := func(module *core.DynamicModule) *core.DynamicModule {
		mod := module.New(core.NewModuleOptions{
			Controllers: []core.Controller{authController},
		})

		return mod
	}

	appModule := func() *core.DynamicModule {
		appMod := core.NewModule(core.NewModuleOptions{
			Imports: []core.Module{
				Register(&Config{
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
}
