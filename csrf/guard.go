package csrf

import (
	"fmt"

	"github.com/tinh-tinh/tinhtinh/v2/common"
	"github.com/tinh-tinh/tinhtinh/v2/core"
)

func Guard(ctx core.Ctx) bool {
	csrf, ok := ctx.Ref(CSRF_NAME).(*Config)
	if !ok {
		if err := common.InternalServerException(ctx.Res(), "csrf not registered"); err != nil {
			fmt.Println(err)
		}
		return false
	}

	token := csrf.GetTokenFromRequest(ctx.Req())
	if token != "" {
		return csrf.Verify(token)
	}

	return false
}
