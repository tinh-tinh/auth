package throttler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2/throttler"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Test_Throttler(t *testing.T) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")

		ctrl.Guard(throttler.Guard).Get("", func(ctx core.Ctx) error {
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

func Test_ThrottlerFactory(t *testing.T) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")

		ctrl.Guard(throttler.Guard).Get("", func(ctx core.Ctx) error {
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
				throttler.ForRootFactory(func(ref core.RefProvider) *throttler.Config {
					return &throttler.Config{Limit: 5, Ttl: 1 * time.Second}
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

func BenchmarkXxx(b *testing.B) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")

		ctrl.Guard(throttler.Guard).Get("", func(ctx core.Ctx) error {
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
				throttler.ForRoot(&throttler.Config{Limit: 100, Ttl: 10 * time.Second}),
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
	require.Nil(b, err)
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := testClient.Do(req)
			require.Nil(b, err)
			fmt.Println(resp.StatusCode)
		}
	})
}
