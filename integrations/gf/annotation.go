// @Author daixk 2025/12/28 1:27:00
package gf

import (
	"context"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
	"github.com/gogf/gf/v2/net/ghttp"
)

// Annotation annotation structure | 注解结构体
type Annotation struct {
	AuthType        string    `json:"authType"`        // Optional: specify auth type | 可选：指定认证类型
	CheckLogin      bool      `json:"checkLogin"`      // Check login | 检查登录
	CheckRole       []string  `json:"checkRole"`       // Check roles | 检查角色
	CheckPermission []string  `json:"checkPermission"` // Check permissions | 检查权限
	CheckDisable    bool      `json:"checkDisable"`    // Check disable status | 检查封禁状态
	Ignore          bool      `json:"ignore"`          // Ignore authentication | 忽略认证
	LogicType       LogicType `json:"logicType"`       // OR or AND logic (default: OR) | OR 或 AND 逻辑（默认: OR）
}

// GetHandler gets handler with annotations | 获取带注解的处理器
func GetHandler(ctx context.Context, handler ghttp.HandlerFunc, failFunc func(r *ghttp.Request, err error), annotations ...*Annotation) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		// Ignore authentication | 忽略认证直接放行
		if len(annotations) > 0 && annotations[0].Ignore {
			if handler != nil {
				handler(r)
			} else {
				r.Middleware.Next()
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
				handler(r)
			} else {
				r.Middleware.Next()
			}
			return
		}

		// Get manager-example | 获取 Manager
		mgr, err := stputil.GetManager(ann.AuthType)
		if err != nil {
			if failFunc != nil {
				failFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// Get SaTokenContext (reuse cached context) | 获取 SaTokenContext（复用缓存上下文）
		saCtx := getSaContext(r, mgr)
		token := saCtx.GetTokenValue()

		// Check login | 检查登录
		isLogin, err := mgr.IsLogin(ctx, token)
		if err != nil {
			if failFunc != nil {
				failFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}
		if !isLogin {
			if failFunc != nil {
				failFunc(r, core.NewNotLoginError())
			} else {
				writeErrorResponse(r, core.NewNotLoginError())
			}
			return
		}

		// Get loginID for further checks | 获取 loginID 用于后续检查
		var loginID string
		if ann.CheckDisable || len(ann.CheckPermission) > 0 || len(ann.CheckRole) > 0 {
			loginID, err = mgr.GetLoginIDNotCheck(ctx, token)
			if err != nil {
				if failFunc != nil {
					failFunc(r, err)
				} else {
					writeErrorResponse(r, err)
				}
				return
			}
		}

		// Check if account is disabled | 检查是否被封禁
		if ann.CheckDisable {
			if mgr.IsDisable(ctx, loginID) {
				if failFunc != nil {
					failFunc(r, core.NewAccountDisabledError(loginID))
				} else {
					writeErrorResponse(r, core.NewAccountDisabledError(loginID))
				}
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
				if failFunc != nil {
					failFunc(r, core.NewPermissionDeniedError(strings.Join(ann.CheckPermission, ",")))
				} else {
					writeErrorResponse(r, core.NewPermissionDeniedError(strings.Join(ann.CheckPermission, ",")))
				}
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
				if failFunc != nil {
					failFunc(r, core.NewRoleDeniedError(strings.Join(ann.CheckRole, ",")))
				} else {
					writeErrorResponse(r, core.NewRoleDeniedError(strings.Join(ann.CheckRole, ",")))
				}
				return
			}
		}

		// All checks passed, execute original handler | 所有检查通过，执行原函数
		if handler != nil {
			handler(r)
		} else {
			r.Middleware.Next()
		}
	}
}

// CheckLoginMiddleware decorator for login checking | 检查登录装饰器
func CheckLoginMiddleware(
	ctx context.Context,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckLogin: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// CheckRoleMiddleware decorator for role checking | 检查角色装饰器
func CheckRoleMiddleware(
	ctx context.Context,
	roles []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckRole: roles}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// CheckPermissionMiddleware decorator for permission checking | 检查权限装饰器
func CheckPermissionMiddleware(
	ctx context.Context,
	perms []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckPermission: perms}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// CheckDisableMiddleware decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisableMiddleware(
	ctx context.Context,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckDisable: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// IgnoreMiddleware decorator to ignore authentication | 忽略认证装饰器
func IgnoreMiddleware(
	ctx context.Context,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
) ghttp.HandlerFunc {
	ann := &Annotation{Ignore: true}
	return GetHandler(ctx, handler, failFunc, ann)
}

// ============ Combined Middleware | 组合中间件 ============

// CheckLoginAndRoleMiddleware checks login and role | 检查登录和角色
func CheckLoginAndRoleMiddleware(
	ctx context.Context,
	roles []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckLogin: true, CheckRole: roles}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// CheckLoginAndPermissionMiddleware checks login and permission | 检查登录和权限
func CheckLoginAndPermissionMiddleware(
	ctx context.Context,
	perms []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckLogin: true, CheckPermission: perms}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// CheckAllMiddleware checks login, role, permission and disable status | 全面检查
func CheckAllMiddleware(
	ctx context.Context,
	roles []string,
	perms []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) ghttp.HandlerFunc {
	ann := &Annotation{CheckLogin: true, CheckRole: roles, CheckPermission: perms}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(ctx, handler, failFunc, ann)
}

// ============ Route Group Helper | 路由组辅助函数 ============

// AuthGroup creates a route group with authentication | 创建带认证的路由组
func AuthGroup(
	ctx context.Context,
	group *ghttp.RouterGroup,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) *ghttp.RouterGroup {
	group.Middleware(CheckLoginMiddleware(ctx, handler, failFunc, authType...))
	return group
}

// RoleGroup creates a route group with role checking | 创建带角色检查的路由组
func RoleGroup(
	ctx context.Context,
	group *ghttp.RouterGroup,
	roles []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) *ghttp.RouterGroup {
	group.Middleware(CheckLoginAndRoleMiddleware(ctx, roles, handler, failFunc, authType...))
	return group
}

// PermissionGroup creates a route group with permission checking | 创建带权限检查的路由组
func PermissionGroup(
	ctx context.Context,
	group *ghttp.RouterGroup,
	perms []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) *ghttp.RouterGroup {
	group.Middleware(CheckLoginAndPermissionMiddleware(ctx, perms, handler, failFunc, authType...))
	return group
}

// RoleAndPermissionGroup creates a route group with role and permission checking | 创建带角色和权限检查的路由组
func RoleAndPermissionGroup(
	ctx context.Context,
	group *ghttp.RouterGroup,
	roles []string,
	perms []string,
	handler ghttp.HandlerFunc,
	failFunc func(r *ghttp.Request, err error),
	authType ...string,
) *ghttp.RouterGroup {
	group.Middleware(CheckAllMiddleware(ctx, roles, perms, handler, failFunc, authType...))
	return group
}
