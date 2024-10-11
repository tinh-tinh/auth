package auth

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
	"github.com/tinh-tinh/tinhtinh/common"
	"github.com/tinh-tinh/tinhtinh/core"
)

func Test_Role(t *testing.T) {
	authController := func(module *core.DynamicModule) *core.DynamicController {
		ctrl := module.NewController("test")
		jwtService := InjectJwt(module)

		ctrl.Get("", func(ctx core.Ctx) {
			data, err := jwtService.Generate(jwt.MapClaims{
				"roles": []string{"admin", "user"},
			})

			if err != nil {
				common.BadRequestException(ctx.Res(), err.Error())
			}
			ctx.JSON(core.Map{
				"data": data,
			})
		})

		ctrl.Metadata(Roles("admin")).Guard(RoleGuard, Guard).Post("", func(ctx core.Ctx) {
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
				Register(JwtOptions{
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
}
