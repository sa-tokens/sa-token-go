package fiber

import (
	"errors"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/manager"

	saContext "github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/stputil"
	"github.com/gofiber/fiber/v2"
)

// LogicType permission/role logic type | 权限/角色判断逻辑
type LogicType string

const (
	SaTokenCtxKey = "saCtx"

	LogicOr  LogicType = "OR"  // Logical OR | 任一满足
	LogicAnd LogicType = "AND" // Logical AND | 全部满足
)

type AuthOption func(*AuthOptions)

type AuthOptions struct {
	AuthType     string
	LogicType    LogicType
	AuthFailFunc func(c *fiber.Ctx, err error) error
}

func defaultAuthOptions() *AuthOptions {
	return &AuthOptions{LogicType: LogicAnd} // 默认 AND
}

// WithAuthType sets auth type | 设置认证类型
func WithAuthType(authType string) AuthOption {
	return func(o *AuthOptions) {
		o.AuthType = authType
	}
}

// WithLogicType sets LogicType option | 设置逻辑类型
func WithLogicType(logicType LogicType) AuthOption {
	return func(o *AuthOptions) {
		o.LogicType = logicType
	}
}

// WithAuthFailFunc sets auth failure callback | 设置认证失败回调
func WithAuthFailFunc(fn func(c *fiber.Ctx, err error) error) AuthOption {
	return func(o *AuthOptions) {
		o.AuthFailFunc = fn
	}
}

// ========== Middlewares ==========

// AuthMiddleware authentication middleware | 认证中间件
func AuthMiddleware(opts ...AuthOption) fiber.Handler {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *fiber.Ctx) error {
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		// 获取 token | Get token
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录 | Check login
		err = mgr.CheckLogin(c.UserContext(), tokenValue)
		if err != nil {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		return c.Next()
	}
}

// AuthWithStateMiddleware with state authentication middleware | 带状态返回的认证中间件
func AuthWithStateMiddleware(opts ...AuthOption) fiber.Handler {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *fiber.Ctx) error {
		// 获取 Manager | Get Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录并返回状态 | Check login with state
		_, err = mgr.CheckLoginWithState(c.UserContext(), tokenValue)

		if err != nil {
			// 用户自定义回调优先
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		return c.Next()
	}
}

// PermissionMiddleware permission check middleware | 权限校验中间件
func PermissionMiddleware(
	permissions []string,
	opts ...AuthOption,
) fiber.Handler {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *fiber.Ctx) error {
		// No permission required | 无需权限直接放行
		if len(permissions) == 0 {
			return c.Next()
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := c.UserContext()

		// Permission check | 权限校验
		var ok bool
		if options.LogicType == LogicAnd {
			ok = mgr.HasPermissionsAndByToken(ctx, tokenValue, permissions)
		} else {
			ok = mgr.HasPermissionsOrByToken(ctx, tokenValue, permissions)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, core.ErrPermissionDenied)
			}
			return writeErrorResponse(c, core.ErrPermissionDenied)
		}

		return c.Next()
	}
}

// RoleMiddleware role check middleware | 角色校验中间件
func RoleMiddleware(
	roles []string,
	opts ...AuthOption,
) fiber.Handler {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *fiber.Ctx) error {
		// No role required | 无需角色直接放行
		if len(roles) == 0 {
			return c.Next()
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, err)
			}
			return writeErrorResponse(c, err)
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := c.UserContext()

		// Role check | 角色校验
		var ok bool
		if options.LogicType == LogicAnd {
			ok = mgr.HasRolesAndByToken(ctx, tokenValue, roles)
		} else {
			ok = mgr.HasRolesOrByToken(ctx, tokenValue, roles)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				return options.AuthFailFunc(c, core.ErrRoleDenied)
			}
			return writeErrorResponse(c, core.ErrRoleDenied)
		}

		return c.Next()
	}
}

// GetSaTokenContext gets Sa-Token context from Fiber context | 获取 Sa-Token 上下文
func GetSaTokenContext(c *fiber.Ctx) (*saContext.SaTokenContext, bool) {
	v := c.Locals(SaTokenCtxKey)
	if v == nil {
		return nil, false
	}

	ctx, ok := v.(*saContext.SaTokenContext)
	return ctx, ok
}

func getSaContext(c *fiber.Ctx, mgr *manager.Manager) *saContext.SaTokenContext {
	// Try get from context | 尝试从 ctx 取值
	if v := c.Locals(SaTokenCtxKey); v != nil {
		if saCtx, ok := v.(*saContext.SaTokenContext); ok {
			return saCtx
		}
	}

	// Create new context | 创建并缓存 SaTokenContext
	saCtx := saContext.NewContext(NewFiberContext(c), mgr)
	c.Locals(SaTokenCtxKey, saCtx)

	return saCtx
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
		"data":    err.Error(),
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
