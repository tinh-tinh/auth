package csrf

import "github.com/tinh-tinh/tinhtinh/core"

const CSRF_NAME core.Provide = "CSRF"

func Register(opt *Config) core.Module {
	csrf, err := DefaultConfig(opt)
	if err != nil {
		panic(err)
	}
	return func(module *core.DynamicModule) *core.DynamicModule {
		csrfModule := module.New(core.NewModuleOptions{})
		csrfModule.NewProvider(core.ProviderOptions{
			Name:  CSRF_NAME,
			Value: csrf,
		})
		csrfModule.Export(CSRF_NAME)
		return csrfModule
	}
}

func Inject(module *core.DynamicModule) *Config {
	csrf, ok := module.Ref(CSRF_NAME).(*Config)
	if !ok {
		return nil
	}
	return csrf
}
