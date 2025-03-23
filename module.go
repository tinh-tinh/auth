package auth

import "github.com/tinh-tinh/tinhtinh/v2/core"

const JWT_TOKEN core.Provide = "JWT_TOKEN"

func Register(opt JwtOptions) core.Modules {
	return func(module core.Module) core.Module {
		tokenModule := module.New(core.NewModuleOptions{})
		tokenModule.NewProvider(core.ProviderOptions{
			Name:  JWT_TOKEN,
			Value: NewJwt(opt),
		})
		tokenModule.Export(JWT_TOKEN)

		return tokenModule
	}
}

func InjectJwt(module core.RefProvider) Jwt {
	jwtService, ok := module.Ref(JWT_TOKEN).(Jwt)
	if !ok {
		return nil
	}
	return jwtService
}
