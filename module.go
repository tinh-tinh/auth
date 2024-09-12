package auth

import "github.com/tinh-tinh/tinhtinh/core"

const JWT_TOKEN core.Provide = "JWT_TOKEN"

func Register(opt Options) core.Module {
	return func(module *core.DynamicModule) *core.DynamicModule {
		tokenModule := module.New(core.NewModuleOptions{})
		tokenModule.NewProvider(NewJwt(opt), JWT_TOKEN)
		tokenModule.Export(JWT_TOKEN)

		return tokenModule
	}
}
