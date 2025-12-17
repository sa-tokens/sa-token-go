package chi

import (
	"net/http"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
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
func GetHandler(handler http.Handler, annotations ...*Annotation) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(annotations) > 0 && annotations[0].Ignore {
			if handler != nil {
				handler.ServeHTTP(w, r)
			}
			return
		}

		ctx := NewChiContext(w, r)
		saCtx := core.NewContext(ctx, stputil.GetManager())
		token := saCtx.GetTokenValue()

		if token == "" {
			writeErrorResponse(w, core.NewNotLoginError())
			return
		}

		if !stputil.IsLogin(token) {
			writeErrorResponse(w, core.NewNotLoginError())
			return
		}

		loginID, err := stputil.GetLoginID(token)
		if err != nil {
			writeErrorResponse(w, err)
			return
		}

		// Check if account is disabled | 检查是否被封禁
		if len(annotations) > 0 && annotations[0].CheckDisable {
			if stputil.IsDisable(loginID) {
				writeErrorResponse(w, core.NewAccountDisabledError(loginID))
				return
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
				writeErrorResponse(w, core.NewPermissionDeniedError(strings.Join(annotations[0].CheckPermission, ",")))
				return
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
				writeErrorResponse(w, core.NewRoleDeniedError(strings.Join(annotations[0].CheckRole, ",")))
				return
			}
		}

		// All checks passed, execute original handler | 所有检查通过，执行原函数
		if handler != nil {
			handler.ServeHTTP(w, r)
		}
	})
}

// CheckLoginMiddleware decorator for login checking | 检查登录装饰器
func CheckLoginMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return GetHandler(next, &Annotation{CheckLogin: true})
	}
}

// CheckRoleMiddleware decorator for role checking | 检查角色装饰器
func CheckRoleMiddleware(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return GetHandler(next, &Annotation{CheckRole: roles})
	}
}

// CheckPermissionMiddleware decorator for permission checking | 检查权限装饰器
func CheckPermissionMiddleware(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return GetHandler(next, &Annotation{CheckPermission: perms})
	}
}

// CheckDisableMiddleware decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisableMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return GetHandler(next, &Annotation{CheckDisable: true})
	}
}

// IgnoreMiddleware decorator to ignore authentication | 忽略认证装饰器
func IgnoreMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return GetHandler(next, &Annotation{Ignore: true})
	}
}
