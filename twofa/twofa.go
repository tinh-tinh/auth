package twofa

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/tinh-tinh/tinhtinh/core"
)

type Totp struct{}

func (tp *Totp) GenerateCode(secret string, t time.Time) (string, error) {
	return totp.GenerateCode(secret, t)
}

func (tp *Totp) GenerateCodeCustom(secret string, t time.Time, opts totp.ValidateOpts) (string, error) {
	return totp.GenerateCodeCustom(secret, t, opts)
}

func (tp *Totp) ValidateCustom(passcode string, secret string, t time.Time, opts totp.ValidateOpts) (bool, error) {
	return totp.ValidateCustom(passcode, secret, t, opts)
}

func (tp *Totp) Validate(passcode string, secret string) bool {
	return totp.Validate(passcode, secret)
}

func (tp *Totp) Generate(opts totp.GenerateOpts) (*otp.Key, error) {
	return totp.Generate(opts)
}

const TOTP core.Provide = "TOTP"

func Register() core.Module {
	return func(module *core.DynamicModule) *core.DynamicModule {
		twoFAModule := module.New(core.NewModuleOptions{})

		twoFAModule.NewProvider(core.ProviderOptions{
			Name:  TOTP,
			Value: &Totp{},
		})
		twoFAModule.Export(TOTP)
		return twoFAModule
	}
}

func Inject(module *core.DynamicModule) *Totp {
	val, ok := module.Ref(TOTP).(*Totp)
	if !ok {
		return nil
	}
	return val
}
