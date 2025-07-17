package throttler

import (
	"time"

	"github.com/tinh-tinh/tinhtinh/v2/common/memory"
	"github.com/tinh-tinh/tinhtinh/v2/core"
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

func ForRoot(config *Config) core.Modules {
	throttler := New(config)
	return func(module core.Module) core.Module {
		throttlerModule := module.New(core.NewModuleOptions{})

		throttlerModule.NewProvider(core.ProviderOptions{
			Name:  THROTTLER,
			Value: throttler,
		})
		throttlerModule.Export(THROTTLER)

		return throttlerModule
	}
}

type ConfigFactory func(ref core.RefProvider) *Config

func ForRootFactory(factory ConfigFactory) core.Modules {
	return func(module core.Module) core.Module {
		config := factory(module)
		throttlerModule := module.New(core.NewModuleOptions{})

		throttlerModule.NewProvider(core.ProviderOptions{
			Name:  THROTTLER,
			Value: New(config),
		})
		throttlerModule.Export(THROTTLER)

		return throttlerModule
	}
}

func Guard(ctx core.Ctx) bool {
	ip := ctx.Headers("X-Forwarded-For")
	if ip == "" {
		ip = ctx.Req().RemoteAddr
	}

	throttler, ok := ctx.Ref(THROTTLER).(*Throttler)
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
