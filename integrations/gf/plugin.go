package gf

import (
	"errors"
	"net/http"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

type MiddlewareType string

var (
	MiddlewareTypeOr  MiddlewareType = "MiddlewareTypeOr"  // Logical OR permission mode | “或” 逻辑权限模式
	MiddlewareTypeAnd MiddlewareType = "MiddlewareTypeAnd" // Logical AND permission mode | “与” 逻辑权限模式
)

// Plugin GoFrame plugin for Sa-Token | GoFrame插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates an GoFrame plugin | 创建GoFrame插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)
		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(r, err)
			return
		}
		// Store Sa-Token context in GoFrame context | 将Sa-Token上下文存储到GoFrame上下文
		r.SetCtxVar("satoken", saCtx)

		r.Middleware.Next()
	}

}

// PathAuthMiddleware path-based authentication middleware | 基于路径的鉴权中间件
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		path := r.Request.URL.Path
		token := r.Header.Get(p.manager.GetConfig().TokenName)
		if token == "" {
			token = r.Cookie.Get(p.manager.GetConfig().TokenName).String()
		}

		result := core.ProcessAuth(path, token, config, p.manager)

		if result.ShouldReject() {
			writeErrorResponse(r, core.NewPathAuthRequiredError(path))
			return
		}

		if result.IsValid && result.TokenInfo != nil {
			ctx := NewGFContext(r)
			saCtx := core.NewContext(ctx, p.manager)
			r.SetCtxVar("satoken", saCtx)
			r.SetCtxVar("loginID", result.LoginID())
		}

		r.Middleware.Next()
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)

		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(r, err)
			return
		}
		if !saCtx.HasPermission(permission) {
			writeErrorResponse(r, core.NewPermissionDeniedError(permission))
			return
		}
		r.SetCtxVar("satoken", saCtx)
		r.Middleware.Next()
	}

}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)

		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(r, err)
			return
		}

		if !saCtx.HasRole(role) {
			writeErrorResponse(r, core.NewRoleDeniedError(role))
			return
		}

		r.SetCtxVar("satoken", saCtx)
		r.Middleware.Next()
	}
}

// HandlerAuthMiddleware — Authentication check middleware | 认证校验中间件
func (p *Plugin) HandlerAuthMiddleware(authFailedFunc ...func(r *ghttp.Request)) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)
		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			if len(authFailedFunc) > 0 && authFailedFunc[0] != nil {
				authFailedFunc[0](r)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		// Store Sa-Token context in GoFrame context | 将Sa-Token上下文存储到GoFrame上下文
		r.SetCtxVar("satoken", saCtx)

		r.Middleware.Next()
	}
}

// HandlerPermissionRequiredMiddleware — Permission check middleware | 权限校验中间件
func (p *Plugin) HandlerPermissionRequiredMiddleware(middlewareType MiddlewareType, permissions []string, permFailedFunc ...func(r *ghttp.Request)) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		if len(permissions) == 0 { // Skip if no permission required | 无需权限则跳过
			r.Middleware.Next()
			return
		}

		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)
		loginID, err := saCtx.GetLoginID()
		if err != nil {
			if len(permFailedFunc) > 0 && permFailedFunc[0] != nil {
				permFailedFunc[0](r)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		var hasPerm bool
		switch middlewareType {
		case MiddlewareTypeOr:
			hasPerm = saCtx.GetManager().HasPermissionsOr(loginID, permissions) // OR check | 任一权限满足即可
		case MiddlewareTypeAnd:
			hasPerm = saCtx.GetManager().HasPermissionsAnd(loginID, permissions) // AND check | 所有权限都需满足
		default:
			hasPerm = false
		}

		if !hasPerm { // No permission | 权限不足
			if len(permFailedFunc) > 0 && permFailedFunc[0] != nil {
				permFailedFunc[0](r)
				return
			}
			writeErrorResponse(r, core.NewPermissionDeniedError(strings.Join(permissions, ",")))
			return
		}

		r.Middleware.Next() // Continue | 继续执行
	}
}

// HandlerRoleRequiredMiddleware — Role check middleware | 角色校验中间件
func (p *Plugin) HandlerRoleRequiredMiddleware(middlewareType MiddlewareType, roles []string, roleFailedFunc ...func(r *ghttp.Request)) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		if len(roles) == 0 { // Skip if no role required | 无需角色则跳过
			r.Middleware.Next()
			return
		}

		ctx := NewGFContext(r)
		saCtx := core.NewContext(ctx, p.manager)
		loginID, err := saCtx.GetLoginID()
		if err != nil {
			if len(roleFailedFunc) > 0 && roleFailedFunc[0] != nil {
				roleFailedFunc[0](r)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		var hasRole bool
		switch middlewareType {
		case MiddlewareTypeOr:
			hasRole = saCtx.GetManager().HasRolesOr(loginID, roles) // OR mode | 任一角色满足即可
		case MiddlewareTypeAnd:
			hasRole = saCtx.GetManager().HasRolesAnd(loginID, roles) // AND mode | 所有角色都需满足
		default:
			hasRole = false
		}

		if !hasRole { // No required role | 无权限角色
			if len(roleFailedFunc) > 0 && roleFailedFunc[0] != nil {
				roleFailedFunc[0](r)
				return
			}
			writeErrorResponse(r, core.NewRoleDeniedError(strings.Join(roles, ",")))
			return
		}

		r.Middleware.Next() // Continue | 继续执行
	}
}

// LoginHandler 登录处理器
func (p *Plugin) LoginHandler(r *ghttp.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}

	if err := r.Parse(&req); err != nil {
		writeErrorResponse(r, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}

	device := req.Device
	if device == "" {
		device = "default"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(r, core.NewError(core.CodeServerError, "login failed", err))
		return
	}

	writeSuccessResponse(r, g.Map{
		"token": token,
	})
}

// UserInfoHandler user info handler example | 获取用户信息处理器示例
func (p *Plugin) UserInfoHandler(r *ghttp.Request) {
	ctx := NewGFContext(r)
	saCtx := core.NewContext(ctx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(r, err)
		return
	}

	// Get user permissions and roles | 获取用户权限和角色
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)

	writeSuccessResponse(r, g.Map{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetSaToken 从GoFrame上下文获取Sa-Token上下文
func GetSaToken(r *ghttp.Request) (*core.SaTokenContext, bool) {
	satoken := r.GetCtx().Value("satoken")
	if satoken == nil {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(r *ghttp.Request, err error) {
	var saErr *core.SaTokenError
	var code int
	var message string
	var httpStatus int

	// Check if it's a SaTokenError | 检查是否为SaTokenError
	if errors.As(err, &saErr) {
		code = saErr.Code
		message = saErr.Message
		httpStatus = getHTTPStatusFromCode(code)
	} else {
		// Handle standard errors | 处理标准错误
		code = core.CodeServerError
		message = err.Error()
		httpStatus = http.StatusInternalServerError
	}

	r.Response.WriteStatusExit(httpStatus, g.Map{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(r *ghttp.Request, data interface{}) {
	r.Response.WriteStatusExit(http.StatusOK, g.Map{
		"code":    core.CodeSuccess,
		"message": "success",
		"data":    data,
	})
}

// getHTTPStatusFromCode converts Sa-Token error code to HTTP status | 将Sa-Token错误码转换为HTTP状态码
func getHTTPStatusFromCode(code int) int {
	switch code {
	case core.CodeNotLogin:
		return http.StatusUnauthorized
	case core.CodePermissionDenied:
		return http.StatusForbidden
	case core.CodeBadRequest:
		return http.StatusBadRequest
	case core.CodeNotFound:
		return http.StatusNotFound
	case core.CodeServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
