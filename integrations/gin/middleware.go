package gin

import (
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/manager"

	saContext "github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/stputil"
	"github.com/gin-gonic/gin"
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
	AuthFailFunc func(c *gin.Context, err error)
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
func WithAuthFailFunc(fn func(c *gin.Context, err error)) AuthOption {
	return func(o *AuthOptions) {
		o.AuthFailFunc = fn
	}
}

// ========== Middlewares ==========

// AuthMiddleware authentication middleware | 认证中间件
func AuthMiddleware(opts ...AuthOption) gin.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}
			c.Abort()
			return
		}

		// 获取 token | Get token
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录 | Check login
		err = mgr.CheckLogin(c.Request.Context(), tokenValue)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthWithStateMiddleware with state authentication middleware | 带状态返回的认证中间件
func AuthWithStateMiddleware(opts ...AuthOption) gin.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// 获取 Manager | Get Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}
			c.Abort()
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录并返回状态 | Check login with state
		_, err = mgr.CheckLoginWithState(c.Request.Context(), tokenValue)

		if err != nil {
			// 用户自定义回调优先
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}

			c.Abort()
			return
		}

		c.Next()
	}
}

// PermissionMiddleware permission check middleware | 权限校验中间件
func PermissionMiddleware(
	permissions []string,
	opts ...AuthOption,
) gin.HandlerFunc {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// No permission required | 无需权限直接放行
		if len(permissions) == 0 {
			c.Next()
			return
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}
			c.Abort()
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := c.Request.Context()

		// Permission check | 权限校验
		var ok bool
		switch {
		// Single permission | 单权限判断
		case len(permissions) == 1:
			ok = mgr.HasPermissionByToken(ctx, tokenValue, permissions[0])

		// AND logic | AND 逻辑
		case options.LogicType == LogicAnd:
			ok = mgr.HasPermissionsAndByToken(ctx, tokenValue, permissions)

		// OR logic (default) | OR 逻辑（默认）
		default:
			ok = mgr.HasPermissionsOrByToken(ctx, tokenValue, permissions)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, core.ErrPermissionDenied)
			} else {
				writeErrorResponse(c, core.ErrPermissionDenied)
			}
			c.Abort()
			return
		}

		c.Next()
	}
}

// RoleMiddleware role check middleware | 角色校验中间件
func RoleMiddleware(
	roles []string,
	opts ...AuthOption,
) gin.HandlerFunc {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// No role required | 无需角色直接放行
		if len(roles) == 0 {
			c.Next()
			return
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err)
			} else {
				writeErrorResponse(c, err)
			}
			c.Abort()
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := c.Request.Context()

		// Role check | 角色校验
		var ok bool

		switch {
		// Single role | 单角色判断
		case len(roles) == 1:
			ok = mgr.HasRoleByToken(ctx, tokenValue, roles[0])

		// AND logic | AND 逻辑
		case options.LogicType == LogicAnd:
			ok = mgr.HasRolesAndByToken(ctx, tokenValue, roles)

		// OR logic (default) | OR 逻辑（默认）
		default:
			ok = mgr.HasRolesOrByToken(ctx, tokenValue, roles)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, core.ErrRoleDenied)
			} else {
				writeErrorResponse(c, core.ErrRoleDenied)
			}
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetSaTokenContext gets Sa-Token context from Gin context | 获取 Sa-Token 上下文
func GetSaTokenContext(c *gin.Context) (*saContext.SaTokenContext, bool) {
	v, exists := c.Get(SaTokenCtxKey)
	if !exists {
		return nil, false
	}

	ctx, ok := v.(*saContext.SaTokenContext)
	return ctx, ok
}

func getSaContext(c *gin.Context, mgr *manager.Manager) *saContext.SaTokenContext {
	// Try get from context | 尝试从 ctx 取值
	if v, exists := c.Get(SaTokenCtxKey); exists {
		if saCtx, ok := v.(*saContext.SaTokenContext); ok {
			return saCtx
		}
	}

	// Create new context | 创建并缓存 SaTokenContext
	saCtx := saContext.NewContext(NewGinContext(c), mgr)
	c.Set(SaTokenCtxKey, saCtx)

	return saCtx
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
		"data":    err.Error(),
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
