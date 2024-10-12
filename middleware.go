package auth

import (
	"strings"

	"github.com/tinh-tinh/tinhtinh/core"
)

const USER core.CtxKey = "USER"

func Guard(ctrl *core.DynamicController, ctx *core.Ctx) bool {
	tokenService := ctrl.Inject(JWT_TOKEN).(Jwt)
	header := ctx.Headers("Authorization")
	if header == "" {
		return false
	}
	authorization := strings.Split(header, " ")
	var token string
	if len(authorization) > 1 {
		token = authorization[1]
	} else {
		return false
	}

	payload, err := tokenService.Verify(token)
	if err != nil {
		return false
	}

	ctx.Set(USER, payload)
	return true
}
