package auth

import "github.com/tinh-tinh/tinhtinh/core"

const JWT_TOKEN core.Provide = "JWT_TOKEN"

func Register(opt JwtOptions) core.Module {
	return func(module *core.DynamicModule) *core.DynamicModule {
		tokenModule := module.New(core.NewModuleOptions{})
		tokenModule.NewProvider(core.ProviderOptions{
			Name:  JWT_TOKEN,
			Value: NewJwt(opt),
		})
		tokenModule.Export(JWT_TOKEN)

		return tokenModule
	}
}
