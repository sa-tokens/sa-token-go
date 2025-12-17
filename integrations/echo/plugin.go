package echo

import (
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/labstack/echo/v4"
)

// Plugin Echo plugin for Sa-Token | Echo插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates an Echo plugin | 创建Echo插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := NewEchoContext(c)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				return writeErrorResponse(c, err)
			}

			c.Set("satoken", saCtx)
			return next(c)
		}
	}
}

// PathAuthMiddleware path-based authentication middleware | 基于路径的鉴权中间件
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			path := c.Request().URL.Path
			token := c.Request().Header.Get(p.manager.GetConfig().TokenName)
			if token == "" {
				cookie, _ := c.Cookie(p.manager.GetConfig().TokenName)
				if cookie != nil {
					token = cookie.Value
				}
			}

			result := core.ProcessAuth(path, token, config, p.manager)

			if result.ShouldReject() {
				return writeErrorResponse(c, core.NewPathAuthRequiredError(path))
			}

			if result.IsValid && result.TokenInfo != nil {
				ctx := NewEchoContext(c)
				saCtx := core.NewContext(ctx, p.manager)
				c.Set("satoken", saCtx)
				c.Set("loginID", result.LoginID())
			}

			return next(c)
		}
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := NewEchoContext(c)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				return writeErrorResponse(c, err)
			}

			if !saCtx.HasPermission(permission) {
				return writeErrorResponse(c, core.NewPermissionDeniedError(permission))
			}

			c.Set("satoken", saCtx)
			return next(c)
		}
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := NewEchoContext(c)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				return writeErrorResponse(c, err)
			}

			if !saCtx.HasRole(role) {
				return writeErrorResponse(c, core.NewRoleDeniedError(role))
			}

			c.Set("satoken", saCtx)
			return next(c)
		}
	}
}

// LoginHandler 登录处理器
func (p *Plugin) LoginHandler(c echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}

	if err := c.Bind(&req); err != nil {
		return writeErrorResponse(c, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
	}

	device := req.Device
	if device == "" {
		device = "default"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		return writeErrorResponse(c, core.NewError(core.CodeServerError, "login failed", err))
	}

	return writeSuccessResponse(c, map[string]interface{}{
		"token": token,
	})
}

// GetSaToken 从Echo上下文获取Sa-Token上下文
func GetSaToken(c echo.Context) (*core.SaTokenContext, bool) {
	satoken := c.Get("satoken")
	if satoken == nil {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(c echo.Context, err error) error {
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

	return c.JSON(httpStatus, map[string]interface{}{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
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
