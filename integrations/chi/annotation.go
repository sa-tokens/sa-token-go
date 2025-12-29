// @Author daixk 2025/12/28
package chi

import (
	"context"
	"net/http"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
)

// Annotation annotation structure | 注解结构体
type Annotation struct {
	AuthType        string    `json:"authType"`        // Optional: specify auth type | 可选:指定认证类型
	CheckLogin      bool      `json:"checkLogin"`      // Check login | 检查登录
	CheckRole       []string  `json:"checkRole"`       // Check roles | 检查角色
	CheckPermission []string  `json:"checkPermission"` // Check permissions | 检查权限
	CheckDisable    bool      `json:"checkDisable"`    // Check disable status | 检查封禁状态
	Ignore          bool      `json:"ignore"`          // Ignore authentication | 忽略认证
	LogicType       LogicType `json:"logicType"`       // OR or AND logic (default: OR) | OR 或 AND 逻辑（默认: OR）
}

// GetHandler gets handler with annotations | 获取带注解的处理器
func GetHandler(handler http.HandlerFunc, annotations ...*Annotation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Ignore authentication | 忽略认证直接放行
		if len(annotations) > 0 && annotations[0].Ignore {
			if handler != nil {
				handler(w, r)
			}
			return
		}

		// Check if any authentication is needed | 检查是否需要任何认证
		ann := &Annotation{}
		if len(annotations) > 0 {
			ann = annotations[0]
		}

		// No authentication required | 无需任何认证
		needAuth := ann.CheckLogin || ann.CheckDisable || len(ann.CheckPermission) > 0 || len(ann.CheckRole) > 0
		if !needAuth {
			if handler != nil {
				handler(w, r)
			}
			return
		}

		ctx := r.Context()

		// Get manager | 获取 Manager
		mgr, err := stputil.GetManager(ann.AuthType)
		if err != nil {
			writeErrorResponse(w, err)
			return
		}

		// Get SaTokenContext (reuse cached context) | 获取 SaTokenContext（复用缓存上下文）
		chiCtx := NewChiContext(w, r)
		saCtx := getSaContext(chiCtx.(*ChiContext), r, mgr)
		token := saCtx.GetTokenValue()

		if token == "" {
			writeErrorResponse(w, core.NewNotLoginError())
			return
		}

		// Check login | 检查登录
		if err := mgr.CheckLogin(ctx, token); err != nil {
			writeErrorResponse(w, err)
			return
		}

		// Get loginID for further checks | 获取 loginID 用于后续检查
		var loginID string
		if ann.CheckDisable || len(ann.CheckPermission) > 0 || len(ann.CheckRole) > 0 {
			loginID, err = mgr.GetLoginIDNotCheck(ctx, token)
			if err != nil {
				writeErrorResponse(w, err)
				return
			}
		}

		// Check if account is disabled | 检查是否被封禁
		if ann.CheckDisable {
			if mgr.IsDisable(ctx, loginID) {
				writeErrorResponse(w, core.NewAccountDisabledError(loginID))
				return
			}
		}

		// Check permission | 检查权限
		if len(ann.CheckPermission) > 0 {
			var ok bool
			if ann.LogicType == LogicAnd {
				ok = mgr.HasPermissionsAnd(ctx, loginID, ann.CheckPermission)
			} else {
				ok = mgr.HasPermissionsOr(ctx, loginID, ann.CheckPermission)
			}
			if !ok {
				writeErrorResponse(w, core.NewPermissionDeniedError(strings.Join(ann.CheckPermission, ",")))
				return
			}
		}

		// Check role | 检查角色
		if len(ann.CheckRole) > 0 {
			var ok bool
			if ann.LogicType == LogicAnd {
				ok = mgr.HasRolesAnd(ctx, loginID, ann.CheckRole)
			} else {
				ok = mgr.HasRolesOr(ctx, loginID, ann.CheckRole)
			}
			if !ok {
				writeErrorResponse(w, core.NewRoleDeniedError(strings.Join(ann.CheckRole, ",")))
				return
			}
		}

		// All checks passed, execute original handler | 所有检查通过，执行原函数
		if handler != nil {
			handler(w, r)
		}
	}
}

// CheckLoginHandler decorator for login checking | 检查登录装饰器
func CheckLoginHandler(authType ...string) http.HandlerFunc {
	ann := &Annotation{CheckLogin: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(nil, ann)
}

// CheckRoleHandler decorator for role checking | 检查角色装饰器
func CheckRoleHandler(roles ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckRole: roles})
}

// CheckRoleHandlerWithAuthType decorator for role checking with auth type | 检查角色装饰器（带认证类型）
func CheckRoleHandlerWithAuthType(authType string, roles ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckRole: roles, AuthType: authType})
}

// CheckPermissionHandler decorator for permission checking | 检查权限装饰器
func CheckPermissionHandler(perms ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckPermission: perms})
}

// CheckPermissionHandlerWithAuthType decorator for permission checking with auth type | 检查权限装饰器（带认证类型）
func CheckPermissionHandlerWithAuthType(authType string, perms ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckPermission: perms, AuthType: authType})
}

// CheckDisableHandler decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisableHandler(authType ...string) http.HandlerFunc {
	ann := &Annotation{CheckDisable: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(nil, ann)
}

// IgnoreHandler decorator to ignore authentication | 忽略认证装饰器
func IgnoreHandler() http.HandlerFunc {
	return GetHandler(nil, &Annotation{Ignore: true})
}

// ============ Combined Handler | 组合处理器 ============

// CheckLoginAndRoleHandler checks login and role | 检查登录和角色
func CheckLoginAndRoleHandler(roles ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckLogin: true, CheckRole: roles})
}

// CheckLoginAndPermissionHandler checks login and permission | 检查登录和权限
func CheckLoginAndPermissionHandler(perms ...string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{CheckLogin: true, CheckPermission: perms})
}

// CheckAllHandler checks login, role, permission and disable status | 全面检查
func CheckAllHandler(roles []string, perms []string) http.HandlerFunc {
	return GetHandler(nil, &Annotation{
		CheckLogin:      true,
		CheckRole:       roles,
		CheckPermission: perms,
		CheckDisable:    true,
	})
}

// ============ Context Helper | 上下文辅助函数 ============

// GetLoginIDFromRequest gets login ID from request context | 从请求上下文获取登录 ID
func GetLoginIDFromRequest(w http.ResponseWriter, r *http.Request, authType ...string) (string, error) {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return "", err
	}

	chiCtx := NewChiContext(w, r)
	saCtx := getSaContext(chiCtx.(*ChiContext), r, mgr)
	token := saCtx.GetTokenValue()
	if token == "" {
		return "", core.ErrNotLogin
	}
	return mgr.GetLoginID(r.Context(), token)
}

// IsLoginFromRequest checks if user is logged in from request | 从请求检查用户是否已登录
func IsLoginFromRequest(w http.ResponseWriter, r *http.Request, authType ...string) bool {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return false
	}

	chiCtx := NewChiContext(w, r)
	saCtx := getSaContext(chiCtx.(*ChiContext), r, mgr)
	token := saCtx.GetTokenValue()
	if token == "" {
		return false
	}
	return mgr.IsLogin(r.Context(), token)
}

// GetTokenFromRequest gets token from request (exported) | 从请求获取 Token（导出）
func GetTokenFromRequest(w http.ResponseWriter, r *http.Request, authType ...string) string {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return ""
	}

	chiCtx := NewChiContext(w, r)
	saCtx := getSaContext(chiCtx.(*ChiContext), r, mgr)
	return saCtx.GetTokenValue()
}

// WithContext creates a new context with sa-token context | 创建带 sa-token 上下文的新上下文
func WithContext(r *http.Request, authType ...string) context.Context {
	return r.Context()
}
