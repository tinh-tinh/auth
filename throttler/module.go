package throttler

import (
	"time"

	"github.com/tinh-tinh/tinhtinh/common/memory"
	"github.com/tinh-tinh/tinhtinh/core"
)

type Config struct {
	Ttl   time.Duration
	Limit int
}

type Throttler struct {
	Limit int
	Store *memory.Store
}

func New(config *Config) *Throttler {
	return &Throttler{
		Limit: config.Limit,
		Store: memory.New(memory.Options{
			Ttl: config.Ttl,
			Max: 500,
		}),
	}
}

const THROTTLER core.Provide = "THROTTLER"

func ForRoot(config *Config) core.Module {
	throttler := New(config)
	return func(module *core.DynamicModule) *core.DynamicModule {
		throttlerModule := module.New(core.NewModuleOptions{})

		throttlerModule.NewProvider(core.ProviderOptions{
			Name:  THROTTLER,
			Value: throttler,
		})
		throttlerModule.Export(THROTTLER)

		return throttlerModule
	}
}

func Guard(ctrl core.RefProvider, ctx *core.Ctx) bool {
	ip := ctx.Headers("X-Forwarded-For")
	if ip == "" {
		ip = ctx.Req().RemoteAddr
	}

	throttler, ok := ctrl.Ref(THROTTLER).(*Throttler)
	if !ok {
		return true
	}

	if ip != "" {
		val := throttler.Store.Get(ip)

		if val != nil {
			intVal, ok := val.(int)
			if !ok {
				return false
			}
			if intVal >= throttler.Limit {
				return false
			}

			throttler.Store.Set(ip, intVal+1)
		} else {
			throttler.Store.Set(ip, 1)
		}
	}

	return true
}
