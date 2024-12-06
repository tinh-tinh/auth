package auth

import (
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinh-tinh/tinhtinh/core"
)

const ROLES = "ROLES"

func Roles(roles ...string) *core.Metadata {
	return core.SetMetadata(ROLES, roles)
}

func RoleGuard(ctrl core.RefProvider, ctx *core.Ctx) bool {
	roles, ok := ctx.GetMetadata(ROLES).([]string)
	if !ok {
		return true
	}

	user, ok := ctx.Get(USER).(jwt.MapClaims)
	if !ok {
		return false
	}

	userRoles, ok := user["roles"].([]interface{})
	if !ok {
		return false
	}

	roleIdx := slices.IndexFunc(roles, func(r string) bool {
		userRoleIdx := slices.IndexFunc(userRoles, func(u interface{}) bool {
			uStr, ok := u.(string)
			if !ok {
				return false
			}
			return uStr == r
		})
		return userRoleIdx != -1
	})

	return roleIdx != -1
}
