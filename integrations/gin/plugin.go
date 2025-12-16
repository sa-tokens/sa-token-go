package gin

import (
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/gin-gonic/gin"
)

// Plugin Gin plugin for Sa-Token | Gin插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Gin plugin | 创建Gin插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Store Sa-Token context in Gin context | 将Sa-Token上下文存储到Gin上下文
		c.Set("satoken", saCtx)
		c.Next()
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Check permission | 检查权限
		if !saCtx.HasPermission(permission) {
			writeErrorResponse(c, core.NewPermissionDeniedError(permission))
			c.Abort()
			return
		}

		c.Set("satoken", saCtx)
		c.Next()
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := NewGinContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		// Check login | 检查登录
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.Abort()
			return
		}

		// Check role | 检查角色
		if !saCtx.HasRole(role) {
			writeErrorResponse(c, core.NewRoleDeniedError(role))
			c.Abort()
			return
		}

		c.Set("satoken", saCtx)
		c.Next()
	}
}

// LoginHandler login handler example | 登录处理器示例
func (p *Plugin) LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Device   string `json:"device"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}

	// TODO: Validate username and password (should call your user service) | 验证用户名密码（这里应该调用你的用户服务）
	// if !validateUser(req.Username, req.Password) { ... }

	// Login | 登录
	device := req.Device
	if device == "" {
		device = "log"
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
		c.SetCookie(
			cfg.TokenName,
			token,
			maxAge,
			cfg.CookieConfig.Path,
			cfg.CookieConfig.Domain,
			cfg.CookieConfig.Secure,
			cfg.CookieConfig.HttpOnly,
		)
	}

	writeSuccessResponse(c, gin.H{
		"token": token,
	})
}

// LogoutHandler logout handler | 登出处理器
func (p *Plugin) LogoutHandler(c *gin.Context) {
	ctx := NewGinContext(c)
	saCtx := core.NewContext(ctx, p.manager)

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
func (p *Plugin) UserInfoHandler(c *gin.Context) {
	ctx := NewGinContext(c)
	saCtx := core.NewContext(ctx, p.manager)

	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}

	// Get user permissions and roles | 获取用户权限和角色
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)

	writeSuccessResponse(c, gin.H{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetSaToken gets Sa-Token context from Gin context | 从Gin上下文获取Sa-Token上下文
func GetSaToken(c *gin.Context) (*core.SaTokenContext, bool) {
	satoken, exists := c.Get("satoken")
	if !exists {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(c *gin.Context, err error) {
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

	c.JSON(httpStatus, gin.H{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
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
