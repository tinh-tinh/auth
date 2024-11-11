package oauth2

import (
	"net/http"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/tinh-tinh/tinhtinh/common"
	"github.com/tinh-tinh/tinhtinh/core"
)

type Config struct {
	OverrideRoutes bool
	RedirectURL    string
	Provider       goth.Provider
}

const OAUTH core.Provide = "OAUTH"

func Register(config *Config) core.Module {
	return func(module *core.DynamicModule) *core.DynamicModule {
		goth.UseProviders(config.Provider)
		options := core.NewModuleOptions{
			Providers: []core.Provider{func(module *core.DynamicModule) *core.DynamicProvider {
				prd := module.NewProvider(core.ProviderOptions{
					Name:  OAUTH,
					Value: config,
				})
				return prd
			}},
		}

		if !config.OverrideRoutes {
			options.Controllers = []core.Controller{controller}
		}
		oauth2Module := module.New(options)
		oauth2Module.Export(OAUTH)

		return oauth2Module
	}
}

func Inject(module *core.DynamicModule) *Config {
	val, ok := module.Ref(OAUTH).(*Config)
	if !ok {
		return nil
	}
	return val
}

func controller(module *core.DynamicModule) *core.DynamicController {
	ctrl := module.NewController("oauth2")
	config := module.Ref(OAUTH).(*Config)

	ctrl.Get("{provider}", config.SignInWithProvider())
	ctrl.Get("{provider}/callback", config.CallbackHandler())

	return ctrl
}

func (c *Config) SignInWithProvider() core.Handler {
	return func(ctx core.Ctx) error {
		provider := ctx.Param("provider")
		q := ctx.Req().URL.Query()
		q.Add("provider", provider)
		ctx.Req().URL.RawQuery = q.Encode()
		gothic.BeginAuthHandler(ctx.Res(), ctx.Req())
		return nil
	}
}

func (c *Config) CallbackHandler() core.Handler {
	return func(ctx core.Ctx) error {
		providers := ctx.Param("provider")
		q := ctx.Req().URL.Query()
		q.Add("provider", providers)
		ctx.Req().URL.RawQuery = q.Encode()

		_, err := gothic.CompleteUserAuth(ctx.Res(), ctx.Req())
		if err != nil {
			return common.UnauthorizedException(ctx.Res(), err.Error())
		}

		http.Redirect(ctx.Res(), ctx.Req(), c.RedirectURL, http.StatusTemporaryRedirect)
		return nil
	}
}
