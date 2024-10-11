package csrf

import (
	"github.com/tinh-tinh/tinhtinh/common"
	"github.com/tinh-tinh/tinhtinh/core"
)

func Guard(ctrl *core.DynamicController, ctx *core.Ctx) bool {
	csrf, ok := ctrl.Inject(CSRF_NAME).(*Config)
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
