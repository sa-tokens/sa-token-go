package fiber

import (
	"errors"

	"github.com/click33/sa-token-go/core"
	"github.com/gofiber/fiber/v2"
)

// Plugin Fiber plugin for Sa-Token | Fiber插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Fiber plugin | 创建Fiber插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		if err := saCtx.CheckLogin(); err != nil {
			return writeErrorResponse(c, err)
		}

		c.Locals("satoken", saCtx)
		return c.Next()
	}
}

// PathAuthMiddleware path-based authentication middleware | 基于路径的鉴权中间件
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		path := c.Path()
		token := c.Get(p.manager.GetConfig().TokenName)
		if token == "" {
			token = c.Cookies(p.manager.GetConfig().TokenName)
		}

		result := core.ProcessAuth(path, token, config, p.manager)

		if result.ShouldReject() {
			return writeErrorResponse(c, core.NewPathAuthRequiredError(path))
		}

		if result.IsValid && result.TokenInfo != nil {
			ctx := NewFiberContext(c)
			saCtx := core.NewContext(ctx, p.manager)
			c.Locals("satoken", saCtx)
			c.Locals("loginID", result.LoginID())
		}

		return c.Next()
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		if err := saCtx.CheckLogin(); err != nil {
			return writeErrorResponse(c, err)
		}

		if !saCtx.HasPermission(permission) {
			return writeErrorResponse(c, core.NewPermissionDeniedError(permission))
		}

		c.Locals("satoken", saCtx)
		return c.Next()
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := NewFiberContext(c)
		saCtx := core.NewContext(ctx, p.manager)

		if err := saCtx.CheckLogin(); err != nil {
			return writeErrorResponse(c, err)
		}

		if !saCtx.HasRole(role) {
			return writeErrorResponse(c, core.NewRoleDeniedError(role))
		}

		c.Locals("satoken", saCtx)
		return c.Next()
	}
}

// LoginHandler 登录处理器
func (p *Plugin) LoginHandler(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}

	if err := c.BodyParser(&req); err != nil {
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

	return writeSuccessResponse(c, fiber.Map{
		"token": token,
	})
}

// GetSaToken 从Fiber上下文获取Sa-Token上下文
func GetSaToken(c *fiber.Ctx) (*core.SaTokenContext, bool) {
	satoken := c.Locals("satoken")
	if satoken == nil {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(c *fiber.Ctx, err error) error {
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
		httpStatus = fiber.StatusInternalServerError
	}

	return c.Status(httpStatus).JSON(fiber.Map{
		"code":    code,
		"message": message,
		"error":   err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(c *fiber.Ctx, data interface{}) error {
	return c.JSON(fiber.Map{
		"code":    core.CodeSuccess,
		"message": "success",
		"data":    data,
	})
}

// getHTTPStatusFromCode converts Sa-Token error code to HTTP status | 将Sa-Token错误码转换为HTTP状态码
func getHTTPStatusFromCode(code int) int {
	switch code {
	case core.CodeNotLogin:
		return fiber.StatusUnauthorized
	case core.CodePermissionDenied:
		return fiber.StatusForbidden
	case core.CodeBadRequest:
		return fiber.StatusBadRequest
	case core.CodeNotFound:
		return fiber.StatusNotFound
	case core.CodeServerError:
		return fiber.StatusInternalServerError
	default:
		return fiber.StatusInternalServerError
	}
}
