package authz

import (
	"github.com/casbin/casbin/v2"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

const CASBIN core.Provide = "AUTHZ_CASBIN"

func Register(params ...interface{}) core.Modules {
	return func(module core.Module) core.Module {
		enforce, err := casbin.NewEnforcer(params...)
		if err != nil {
			panic(err)
		}

		casbinModule := module.New(core.NewModuleOptions{})
		casbinModule.NewProvider(core.ProviderOptions{
			Name:  CASBIN,
			Value: enforce,
		})
		casbinModule.Export(CASBIN)

		return casbinModule
	}
}

func Inject(module core.RefProvider) *casbin.Enforcer {
	provider, ok := module.Ref(CASBIN).(*casbin.Enforcer)
	if provider == nil || !ok {
		return nil
	}

	return provider
}
