package csrf

import (
	"github.com/tinh-tinh/tinhtinh/v2/common"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Guard(ctrl core.RefProvider, ctx core.Ctx) bool {
	csrf, ok := ctrl.Ref(CSRF_NAME).(*Config)
	if !ok {
		common.InternalServerException(ctx.Res(), "csrf not registered")
		return false
	}

	token := csrf.GetTokenFromRequest(ctx.Req())
	if token != "" {
		return csrf.Verify(token)
	}

	return false
}
