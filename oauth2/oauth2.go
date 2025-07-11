package oauth2

import (
	"net/http"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/tinh-tinh/tinhtinh/v2/common"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

type Config struct {
	OverrideRoutes bool
	RedirectURL    string
	Provider       goth.Provider
}

const OAUTH core.Provide = "OAUTH"

func Register(config *Config) core.Modules {
	return func(module core.Module) core.Module {
		goth.UseProviders(config.Provider)
		options := core.NewModuleOptions{
			Providers: []core.Providers{func(module core.Module) core.Provider {
				prd := module.NewProvider(core.ProviderOptions{
					Name:  OAUTH,
					Value: config,
				})
				return prd
			}},
		}

		if !config.OverrideRoutes {
			options.Controllers = []core.Controllers{controller}
		}
		oauth2Module := module.New(options)
		oauth2Module.Export(OAUTH)

		return oauth2Module
	}
}

func Inject(module core.RefProvider) *Config {
	val, ok := module.Ref(OAUTH).(*Config)
	if !ok {
		return nil
	}
	return val
}

func controller(module core.Module) core.Controller {
	ctrl := module.NewController("oauth2")
	config := module.Ref(OAUTH).(*Config)

	ctrl.Get("{provider}", config.SignInWithProvider())
	ctrl.Get("{provider}/callback", config.CallbackHandler())

	return ctrl
}

func (c *Config) SignInWithProvider() core.Handler {
	return func(ctx core.Ctx) error {
		provider := ctx.Path("provider")
		q := ctx.Req().URL.Query()
		q.Add("provider", provider)
		ctx.Req().URL.RawQuery = q.Encode()
		gothic.BeginAuthHandler(ctx.Res(), ctx.Req())
		return nil
	}
}

func (c *Config) CallbackHandler() core.Handler {
	return func(ctx core.Ctx) error {
		providers := ctx.Path("provider")
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
