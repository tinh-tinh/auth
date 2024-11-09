package throttler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/throttler"
	"github.com/tinh-tinh/tinhtinh/core"
)

func Test_Throttler(t *testing.T) {
	authController := func(module *core.DynamicModule) *core.DynamicController {
		ctrl := module.NewController("test")

		ctrl.Guard(throttler.Guard).Get("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
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
				throttler.ForRoot(&throttler.Config{Limit: 5, Ttl: 1 * time.Second}),
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
	resp, err := testClient.Get(testServer.URL + "/api/test")
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	req, err := http.NewRequest("GET", testServer.URL+"/api/test", nil)
	require.Nil(t, err)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	for i := 0; i < 10; i++ {
		resp, err = testClient.Do(req)
		require.Nil(t, err)
		if i < 5 {
			require.Equal(t, http.StatusOK, resp.StatusCode)
		} else {
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
		}
	}
}
