package gin

import (
	"context"
	"errors"
	saContext "github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/stputil"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/config"
	"github.com/gin-gonic/gin"
)

// LogicType permission/role logic type | 权限/角色判断逻辑
type LogicType string

const (
	SaTokenCtxKey = "satoken"

	LogicOr  LogicType = "OR"  // 任一满足
	LogicAnd LogicType = "AND" // 全部满足
)

// AuthOption defines optional parameters for middleware | 中间件可选参数
type AuthOption func(*AuthOptions)

// AuthOptions stores optional parameters | 中间件可选参数结构体
type AuthOptions struct {
	AuthType     string
	LogicType    LogicType
	AuthFailFunc func(c *gin.Context, err error)
}

// defaultAuthOptions returns default options | 默认中间件选项
func defaultAuthOptions() *AuthOptions {
	return &AuthOptions{LogicType: LogicAnd} // 默认 AND
}

// WithAuthType sets AuthType option | 设置认证类型
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

// WithAuthFailFunc sets custom fail function | 设置自定义失败函数
func WithAuthFailFunc(fn func(c *gin.Context, err error)) AuthOption {
	return func(o *AuthOptions) {
		o.AuthFailFunc = fn
	}
}

// ========== Middlewares ==========

// AuthMiddleware checks login | 登录状态校验中间件
func AuthMiddleware(opts ...AuthOption) gin.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		// 获取 Manager | Get Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, err) // 自定义失败处理 | custom fail handler
			} else {
				writeErrorResponse(c, err) // 默认失败响应 | default error response
			}
			c.Abort()
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(c, mgr)
		err = mgr.CheckLogin(
			context.WithValue(c.Request.Context(), config.CtxTokenValue, saCtx.GetTokenValue()),
		)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(c, core.ErrNotLogin)
			} else {
				writeErrorResponse(c, core.ErrNotLogin)
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

		saCtx := getSaContext(c, mgr)

		_, err = mgr.CheckLoginWithState(context.WithValue(c.Request.Context(), config.CtxTokenValue, saCtx.GetTokenValue()))
		if err != nil {

			switch {
			case errors.Is(err, manager.ErrTokenKickout):
				err = core.ErrTokenKickout
			case errors.Is(err, manager.ErrTokenReplaced):
				err = core.ErrTokenReplaced
			default:
				err = core.ErrNotLogin
			}

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

// PermissionMiddleware checks permissions | 权限校验中间件
func PermissionMiddleware(permissions []string, opts ...AuthOption) gin.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		if len(permissions) == 0 {
			c.Next()
			return
		}

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
		ctx := context.WithValue(c.Request.Context(), config.CtxTokenValue, saCtx.GetTokenValue())

		// 判断权限 | Check permissions
		var ok bool
		switch {
		case len(permissions) == 1:
			ok = mgr.HasPermissionByToken(ctx, permissions[0])
		case options.LogicType == LogicAnd:
			ok = mgr.HasPermissionsAndByToken(ctx, permissions)
		default:
			ok = mgr.HasPermissionsOrByToken(ctx, permissions)
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

// RoleMiddleware checks roles | 角色校验中间件
func RoleMiddleware(roles []string, opts ...AuthOption) gin.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(c *gin.Context) {
		if len(roles) == 0 {
			c.Next()
			return
		}

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
		ctx := context.WithValue(c.Request.Context(), config.CtxTokenValue, saCtx.GetTokenValue())

		// 判断角色 | Check roles
		var ok bool
		switch {
		case len(roles) == 1:
			ok = mgr.HasRoleByToken(ctx, roles[0])
		case options.LogicType == LogicAnd:
			ok = mgr.HasRolesAndByToken(ctx, roles)
		default:
			ok = mgr.HasRolesOrByToken(ctx, roles)
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
	if v, exists := c.Get(SaTokenCtxKey); exists {
		if saCtx, ok := v.(*saContext.SaTokenContext); ok {
			return saCtx, true
		}
	}
	return nil, false
}

func getSaContext(c *gin.Context, mgr *manager.Manager) *saContext.SaTokenContext {
	if v, exists := c.Get(SaTokenCtxKey); exists {
		if saCtx, ok := v.(*saContext.SaTokenContext); ok {
			return saCtx
		}
	}

	saCtx := saContext.NewContext(NewGinContext(c), mgr)
	c.Set(SaTokenCtxKey, saCtx)
	return saCtx
}

// ========== Error/Success Responses ==========

func writeErrorResponse(c *gin.Context, err error) {
	var saErr *core.SaTokenError
	var code int
	var message string
	var httpStatus int

	if errors.As(err, &saErr) {
		code = saErr.Code
		message = saErr.Message
		httpStatus = getHTTPStatusFromCode(code)
	} else {
		code = core.CodeServerError
		message = err.Error()
		httpStatus = http.StatusInternalServerError
	}

	c.JSON(httpStatus, gin.H{
		"code":    code,
		"message": message,
		"data":    []interface{}{},
	})
}

func writeSuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code":    core.CodeSuccess,
		"message": "success",
		"data":    data,
	})
}

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
