package echo

import (
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
	"github.com/labstack/echo/v4"
)

// Annotation annotation structure | 注解结构体
type Annotation struct {
	CheckLogin      bool     `json:"checkLogin"`
	CheckRole       []string `json:"checkRole"`
	CheckPermission []string `json:"checkPermission"`
	CheckDisable    bool     `json:"checkDisable"`
	Ignore          bool     `json:"ignore"`
}

// GetHandler gets handler with annotations | 获取带注解的处理器
func GetHandler(handler echo.HandlerFunc, annotations ...*Annotation) echo.HandlerFunc {
	return func(c echo.Context) error {
		if len(annotations) > 0 && annotations[0].Ignore {
			if handler != nil {
				return handler(c)
			}
			return nil
		}

		ctx := NewEchoContext(c)
		saCtx := core.NewContext(ctx, stputil.GetManager())
		token := saCtx.GetTokenValue()

		if token == "" {
			return writeErrorResponse(c, core.NewNotLoginError())
		}

		if !stputil.IsLogin(token) {
			return writeErrorResponse(c, core.NewNotLoginError())
		}

		loginID, err := stputil.GetLoginID(token)
		if err != nil {
			return writeErrorResponse(c, err)
		}

		// Check if account is disabled | 检查是否被封禁
		if len(annotations) > 0 && annotations[0].CheckDisable {
			if stputil.IsDisable(loginID) {
				return writeErrorResponse(c, core.NewAccountDisabledError(loginID))
			}
		}

		// Check permission | 检查权限
		if len(annotations) > 0 && len(annotations[0].CheckPermission) > 0 {
			hasPermission := false
			for _, perm := range annotations[0].CheckPermission {
				if stputil.HasPermission(loginID, strings.TrimSpace(perm)) {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				return writeErrorResponse(c, core.NewPermissionDeniedError(strings.Join(annotations[0].CheckPermission, ",")))
			}
		}

		// Check role | 检查角色
		if len(annotations) > 0 && len(annotations[0].CheckRole) > 0 {
			hasRole := false
			for _, role := range annotations[0].CheckRole {
				if stputil.HasRole(loginID, strings.TrimSpace(role)) {
					hasRole = true
					break
				}
			}
			if !hasRole {
				return writeErrorResponse(c, core.NewRoleDeniedError(strings.Join(annotations[0].CheckRole, ",")))
			}
		}

		// All checks passed, execute original handler | 所有检查通过，执行原函数
		if handler != nil {
			return handler(c)
		}
		return nil
	}
}

// CheckLoginMiddleware decorator for login checking | 检查登录装饰器
func CheckLoginMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return GetHandler(next, &Annotation{CheckLogin: true})
	}
}

// CheckRoleMiddleware decorator for role checking | 检查角色装饰器
func CheckRoleMiddleware(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return GetHandler(next, &Annotation{CheckRole: roles})
	}
}

// CheckPermissionMiddleware decorator for permission checking | 检查权限装饰器
func CheckPermissionMiddleware(perms ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return GetHandler(next, &Annotation{CheckPermission: perms})
	}
}

// CheckDisableMiddleware decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisableMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return GetHandler(next, &Annotation{CheckDisable: true})
	}
}

// IgnoreMiddleware decorator to ignore authentication | 忽略认证装饰器
func IgnoreMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return GetHandler(next, &Annotation{Ignore: true})
	}
}
