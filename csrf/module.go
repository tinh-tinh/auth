package csrf

import "github.com/tinh-tinh/tinhtinh/v2/core"

const CSRF_NAME core.Provide = "CSRF"

func Register(opt *Config) core.Modules {
	csrf, err := DefaultConfig(opt)
	if err != nil {
		panic(err)
	}
	return func(module core.Module) core.Module {
		csrfModule := module.New(core.NewModuleOptions{})
		csrfModule.NewProvider(core.ProviderOptions{
			Name:  CSRF_NAME,
			Value: csrf,
		})
		csrfModule.Export(CSRF_NAME)
		return csrfModule
	}
}

func Inject(module core.RefProvider) *Config {
	csrf, ok := module.Ref(CSRF_NAME).(*Config)
	if !ok {
		return nil
	}
	return csrf
}
