// @Author daixk 2025/12/28
package fiber

import (
	"context"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
	"github.com/gofiber/fiber/v2"
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
func GetHandler(handler fiber.Handler, annotations ...*Annotation) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Ignore authentication | 忽略认证直接放行
		if len(annotations) > 0 && annotations[0].Ignore {
			if handler != nil {
				return handler(c)
			}
			return c.Next()
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
				return handler(c)
			}
			return c.Next()
		}

		ctx := c.UserContext()

		// Get manager-example | 获取 Manager
		mgr, err := stputil.GetManager(ann.AuthType)
		if err != nil {
			return writeErrorResponse(c, err)
		}

		// Get SaTokenContext (reuse cached context) | 获取 SaTokenContext（复用缓存上下文）
		saCtx := getSaContext(c, mgr)
		token := saCtx.GetTokenValue()

		if token == "" {
			return writeErrorResponse(c, core.NewNotLoginError())
		}

		// Check login | 检查登录
		if err := mgr.CheckLogin(ctx, token); err != nil {
			return writeErrorResponse(c, err)
		}

		// Get loginID for further checks | 获取 loginID 用于后续检查
		var loginID string
		if ann.CheckDisable || len(ann.CheckPermission) > 0 || len(ann.CheckRole) > 0 {
			loginID, err = mgr.GetLoginIDNotCheck(ctx, token)
			if err != nil {
				return writeErrorResponse(c, err)
			}
		}

		// Check if account is disabled | 检查是否被封禁
		if ann.CheckDisable {
			if mgr.IsDisable(ctx, loginID) {
				return writeErrorResponse(c, core.NewAccountDisabledError(loginID))
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
				return writeErrorResponse(c, core.NewPermissionDeniedError(strings.Join(ann.CheckPermission, ",")))
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
				return writeErrorResponse(c, core.NewRoleDeniedError(strings.Join(ann.CheckRole, ",")))
			}
		}

		// All checks passed, execute original handler | 所有检查通过，执行原函数
		if handler != nil {
			return handler(c)
		}
		return c.Next()
	}
}

// CheckLoginMiddleware decorator for login checking | 检查登录装饰器
func CheckLoginMiddleware(authType ...string) fiber.Handler {
	ann := &Annotation{CheckLogin: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(nil, ann)
}

// CheckRoleMiddleware decorator for role checking | 检查角色装饰器
func CheckRoleMiddleware(roles ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckRole: roles})
}

// CheckRoleMiddlewareWithAuthType decorator for role checking with auth type | 检查角色装饰器（带认证类型）
func CheckRoleMiddlewareWithAuthType(authType string, roles ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckRole: roles, AuthType: authType})
}

// CheckPermissionMiddleware decorator for permission checking | 检查权限装饰器
func CheckPermissionMiddleware(perms ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckPermission: perms})
}

// CheckPermissionMiddlewareWithAuthType decorator for permission checking with auth type | 检查权限装饰器（带认证类型）
func CheckPermissionMiddlewareWithAuthType(authType string, perms ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckPermission: perms, AuthType: authType})
}

// CheckDisableMiddleware decorator for checking if account is disabled | 检查是否被封禁装饰器
func CheckDisableMiddleware(authType ...string) fiber.Handler {
	ann := &Annotation{CheckDisable: true}
	if len(authType) > 0 {
		ann.AuthType = authType[0]
	}
	return GetHandler(nil, ann)
}

// IgnoreMiddleware decorator to ignore authentication | 忽略认证装饰器
func IgnoreMiddleware() fiber.Handler {
	return GetHandler(nil, &Annotation{Ignore: true})
}

// ============ Combined Middleware | 组合中间件 ============

// CheckLoginAndRoleMiddleware checks login and role | 检查登录和角色
func CheckLoginAndRoleMiddleware(roles ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckLogin: true, CheckRole: roles})
}

// CheckLoginAndPermissionMiddleware checks login and permission | 检查登录和权限
func CheckLoginAndPermissionMiddleware(perms ...string) fiber.Handler {
	return GetHandler(nil, &Annotation{CheckLogin: true, CheckPermission: perms})
}

// CheckAllMiddleware checks login, role, permission and disable status | 全面检查
func CheckAllMiddleware(roles []string, perms []string) fiber.Handler {
	return GetHandler(nil, &Annotation{
		CheckLogin:      true,
		CheckRole:       roles,
		CheckPermission: perms,
		CheckDisable:    true,
	})
}

// ============ Route Group Helper | 路由组辅助函数 ============

// AuthGroup creates a route group with authentication | 创建带认证的路由组
func AuthGroup(group fiber.Router, authType ...string) fiber.Router {
	group.Use(CheckLoginMiddleware(authType...))
	return group
}

// RoleGroup creates a route group with role checking | 创建带角色检查的路由组
func RoleGroup(group fiber.Router, roles ...string) fiber.Router {
	group.Use(CheckLoginAndRoleMiddleware(roles...))
	return group
}

// PermissionGroup creates a route group with permission checking | 创建带权限检查的路由组
func PermissionGroup(group fiber.Router, perms ...string) fiber.Router {
	group.Use(CheckLoginAndPermissionMiddleware(perms...))
	return group
}

// ============ Context Helper | 上下文辅助函数 ============

// GetLoginIDFromRequest gets login ID from request context | 从请求上下文获取登录 ID
func GetLoginIDFromRequest(c *fiber.Ctx, authType ...string) (string, error) {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return "", err
	}

	saCtx := getSaContext(c, mgr)
	token := saCtx.GetTokenValue()
	if token == "" {
		return "", core.ErrNotLogin
	}
	return mgr.GetLoginID(c.UserContext(), token)
}

// IsLoginFromRequest checks if user is logged in from request | 从请求检查用户是否已登录
func IsLoginFromRequest(c *fiber.Ctx, authType ...string) bool {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return false
	}

	saCtx := getSaContext(c, mgr)
	token := saCtx.GetTokenValue()
	if token == "" {
		return false
	}
	return mgr.IsLogin(c.UserContext(), token)
}

// GetTokenFromRequest gets token from request (exported) | 从请求获取 Token（导出）
func GetTokenFromRequest(c *fiber.Ctx, authType ...string) string {
	var at string
	if len(authType) > 0 {
		at = authType[0]
	}

	mgr, err := stputil.GetManager(at)
	if err != nil {
		return ""
	}

	saCtx := getSaContext(c, mgr)
	return saCtx.GetTokenValue()
}

// WithContext creates a new context with sa-token context | 创建带 sa-token 上下文的新上下文
func WithContext(c *fiber.Ctx, authType ...string) context.Context {
	return c.UserContext()
}
