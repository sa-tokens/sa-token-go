package hertz

import (
	"context"
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/gin-gonic/gin"
)

// Plugin Hertz plugin for Sa-Token | Hertz插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Hertz plugin | 创建Hertz插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hCtx := NewHertzContext(c)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Store Sa-Token context in Hertz context | 将Sa-Token上下文存储到Hertz上下文
		c.Set("satoken", saCtx)
		c.Next(ctx)
	}
}

// PathAuthMiddleware path-based authentication middleware | 基于路径的鉴权中间件
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		path := string(ctx.Path())
		token := string(ctx.GetHeader(p.manager.GetConfig().TokenName))
		if token == "" {
			token = string(ctx.Cookie(p.manager.GetConfig().TokenName))
		}

		result := core.ProcessAuth(path, token, config, p.manager)

		if result.ShouldReject() {
			writeErrorResponse(ctx, core.NewPathAuthRequiredError(path))
			ctx.Abort()
			return
		}

		if result.IsValid && result.TokenInfo != nil {
			hCtx := NewHertzContext(ctx)
			saCtx := core.NewContext(hCtx, p.manager)
			ctx.Set("satoken", saCtx)
			ctx.Set("loginID", result.LoginID())
		}

		ctx.Next(c)
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		hCtx := NewHertzContext(ctx)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(ctx, err)
			ctx.Abort()
			return
		}

		// Check permission | 检查权限
		if !saCtx.HasPermission(permission) {
			writeErrorResponse(ctx, core.NewPermissionDeniedError(permission))
			ctx.Abort()
			return
		}

		ctx.Set("satoken", saCtx)
		ctx.Next(c)
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		hCtx := NewHertzContext(ctx)
		saCtx := core.NewContext(hCtx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(ctx, err)
			ctx.Abort()
			return
		}

		// Check role | 检查角色
		if !saCtx.HasRole(role) {
			writeErrorResponse(ctx, core.NewRoleDeniedError(role))
			ctx.Abort()
			return
		}

		ctx.Set("satoken", saCtx)
		ctx.Next(c)
	}
}

// LoginHandler login handler example | 登录处理器示例
func (p *Plugin) LoginHandler(c *app.RequestContext) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Device   string `json:"device"`
	}

	if err := c.BindJSON(&req); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}

	// TODO: Validate username and password (should call your user service) | 验证用户名密码（这里应该调用你的用户服务）
	// if !validateUser(req.Username, req.Password) { ... }

	// Login | 登录
	device := req.Device
	if device == "" {
		device = "default"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "login failed", err))
		return
	}

	// Set cookie (optional) | 设置Cookie（可选）
	cfg := p.manager.GetConfig()
	if cfg.IsReadCookie {
		maxAge := int(cfg.Timeout)
		if maxAge < 0 {
			maxAge = 0
		}
		var sameSite protocol.CookieSameSite
		switch cfg.CookieConfig.SameSite {
		case "Strict":
			sameSite = protocol.CookieSameSiteStrictMode
		case "Lax":
			sameSite = protocol.CookieSameSiteLaxMode
		case "None":
			sameSite = protocol.CookieSameSiteNoneMode
		}
		c.SetCookie(
			cfg.TokenName,
			token,
			maxAge,
			cfg.CookieConfig.Path,
			cfg.CookieConfig.Domain,
			sameSite,
			cfg.CookieConfig.Secure,
			cfg.CookieConfig.HttpOnly,
		)
	}

	writeSuccessResponse(c, utils.H{
		"token": token,
	})
}

// LogoutHandler logout handler | 登出处理器
func (p *Plugin) LogoutHandler(c *app.RequestContext) {
	hCtx := NewHertzContext(c)
	saCtx := core.NewContext(hCtx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}

	if err := p.manager.Logout(loginID); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "logout failed", err))
		return
	}

	writeSuccessResponse(c, gin.H{
		"message": "logout successful",
	})
}

// UserInfoHandler user info handler example | 获取用户信息处理器示例
func (p *Plugin) UserInfoHandler(c *app.RequestContext) {
	hCtx := NewHertzContext(c)
	saCtx := core.NewContext(hCtx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}

	// Get user permissions and roles | 获取用户权限和角色
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)

	writeSuccessResponse(c, utils.H{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetSaToken gets Sa-Token context from Gin context | 从Gin上下文获取Sa-Token上下文
func GetSaToken(c *app.RequestContext) (*core.SaTokenContext, bool) {
	satoken, exists := c.Get("satoken")
	if !exists {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(c *app.RequestContext, err error) {
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

	c.JSON(httpStatus, utils.H{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(c *app.RequestContext, data interface{}) {
	c.JSON(http.StatusOK, utils.H{
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
