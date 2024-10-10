package auth

import (
	"fmt"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinh-tinh/tinhtinh/core"
)

const ROLES = "ROLES"

func Roles(roles ...string) *core.Metadata {
	return core.SetMetadata(ROLES, roles)
}

func RoleGuard(ctrl *core.DynamicController, ctx core.Ctx) bool {
	roles, ok := ctrl.GetMetadata(ROLES).([]string)
	if !ok {
		return true
	}

	user, ok := ctx.Get(USER).(jwt.MapClaims)
	if !ok {
		fmt.Println(ctx.Get(USER))
		return false
	}
	userRoles, ok := user["roles"].([]string)
	if !ok {
		return false
	}

	fmt.Println(roles)
	fmt.Println(userRoles)

	roleIdx := slices.IndexFunc(roles, func(r string) bool {
		userRoleIdx := slices.IndexFunc(userRoles, func(u string) bool {
			return u == r
		})
		return userRoleIdx != -1
	})

	return roleIdx != -1
}
