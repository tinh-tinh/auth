package auth_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/tinh-tinh/auth/v2"
	"github.com/tinh-tinh/tinhtinh/v2/common"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Test_Role(t *testing.T) {
	authController := func(module core.Module) core.Controller {
		ctrl := module.NewController("test")
		jwtService := auth.InjectJwt(module)

		ctrl.Get("", func(ctx core.Ctx) error {
			data, err := jwtService.Generate(jwt.MapClaims{
				"roles": []string{"admin", "user"},
			})

			if err != nil {
				return common.BadRequestException(ctx.Res(), err.Error())
			}
			return ctx.JSON(core.Map{
				"data": data,
			})
		})

		ctrl.Metadata(auth.Roles("admin")).Guard(auth.Guard, auth.RoleGuard).Post("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
				"data": "ok",
			})
		})

		ctrl.Guard(auth.RoleGuard).Put("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
				"data": "ok",
			})
		})

		ctrl.Metadata(auth.Roles("admin")).Guard(auth.RoleGuard).Patch("", func(ctx core.Ctx) error {
			return ctx.JSON(core.Map{
				"data": "ok",
			})
		})

		ctrl.Get("failed-roles-type", func(ctx core.Ctx) error {
			data, err := jwtService.Generate(jwt.MapClaims{
				"roles": []int{1, 2, 3},
			})

			if err != nil {
				return common.BadRequestException(ctx.Res(), err.Error())
			}
			return ctx.JSON(core.Map{
				"data": data,
			})
		})

		ctrl.Get("failed-roles-format", func(ctx core.Ctx) error {
			data, err := jwtService.Generate(jwt.MapClaims{
				"roles": "haha",
			})

			if err != nil {
				return common.BadRequestException(ctx.Res(), err.Error())
			}
			return ctx.JSON(core.Map{
				"data": data,
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
				auth.Register(auth.JwtOptions{
					Alg:    jwt.SigningMethodHS256,
					Secret: "secret",
					Exp:    time.Hour,
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", res.Data))

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = testClient.Post(testServer.URL+"/api/test", "application/json", nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest("PUT", testServer.URL+"/api/test", nil)
	require.Nil(t, err)

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	req, err = http.NewRequest("PATCH", testServer.URL+"/api/test", nil)
	require.Nil(t, err)

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest("GET", testServer.URL+"/api/test/failed-roles-type", nil)
	require.Nil(t, err)

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	data, err = io.ReadAll(resp.Body)
	require.Nil(t, err)

	require.Nil(t, json.Unmarshal(data, &res))
	req, err = http.NewRequest("POST", testServer.URL+"/api/test", nil)
	require.Nil(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", res.Data))

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	req, err = http.NewRequest("GET", testServer.URL+"/api/test/failed-roles-format", nil)
	require.Nil(t, err)

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, resp.StatusCode)

	data, err = io.ReadAll(resp.Body)
	require.Nil(t, err)

	require.Nil(t, json.Unmarshal(data, &res))
	req, err = http.NewRequest("POST", testServer.URL+"/api/test", nil)
	require.Nil(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", res.Data))

	resp, err = testClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
