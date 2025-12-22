package gf

import (
	"context"
	"errors"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/manager"
	"net/http"

	"github.com/click33/sa-token-go/core/config"
	saContext "github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/stputil"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
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
	AuthFailFunc func(r *ghttp.Request, err error)
}

func defaultAuthOptions() *AuthOptions {
	return &AuthOptions{}
}

// WithAuthType sets auth type | 设置认证类型
func WithAuthType(authType string) AuthOption {
	return func(o *AuthOptions) {
		o.AuthType = authType
	}
}

func WithLogicType(logicType LogicType) AuthOption {
	return func(o *AuthOptions) {
		o.LogicType = logicType
	}
}

// WithAuthFailFunc sets auth failure callback | 设置认证失败回调
func WithAuthFailFunc(fn func(r *ghttp.Request, err error)) AuthOption {
	return func(o *AuthOptions) {
		o.AuthFailFunc = fn
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func AuthMiddleware(opts ...AuthOption) ghttp.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		saCtx := saContext.NewContext(r.Context(), NewGFContext(r), mgr)
		err = mgr.CheckLogin(
			context.WithValue(
				r.Context(),
				config.CtxTokenValue,
				saCtx.GetTokenValue(),
			),
		)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		r.SetCtxVar(SaTokenCtxKey, saCtx)
		r.Middleware.Next()
	}
}

// AuthWithStateMiddleware authentication middleware | 认证中间件
func AuthWithStateMiddleware(opts ...AuthOption) ghttp.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		saCtx := saContext.NewContext(r.Context(), NewGFContext(r), mgr)
		_, err = mgr.CheckLoginWithState(context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()))
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}

			switch err {
			case manager.ErrTokenKickout:
				writeErrorResponse(r, core.ErrTokenKickout)
			case manager.ErrTokenReplaced:
				writeErrorResponse(r, core.ErrTokenReplaced)
			default:
				writeErrorResponse(r, core.ErrNotLogin)
			}

			return
		}

		r.SetCtxVar(SaTokenCtxKey, saCtx)
		r.Middleware.Next()
	}
}

// PermissionMiddleware permission check middleware | 权限校验中间件
func PermissionMiddleware(
	permissions []string,
	opts ...AuthOption,
) ghttp.HandlerFunc {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		// No permission required | 无需权限直接放行
		if len(permissions) == 0 {
			r.Middleware.Next()
			return
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		// Build Sa-Token context | 构建 Sa-Token 上下文
		saCtx := saContext.NewContext(
			r.Context(),
			NewGFContext(r),
			mgr,
		)

		// Permission check | 权限校验
		var ok bool

		switch {
		// Single permission | 单权限判断
		case len(permissions) == 1:
			ok = mgr.HasPermissionByToken(
				context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()),
				permissions[0],
			)

		// AND logic | AND 逻辑
		case options.LogicType == LogicAnd:
			ok = mgr.HasPermissionsAndByToken(
				context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()),
				permissions,
			)

		// OR logic (default) | OR 逻辑（默认）
		default:
			ok = mgr.HasPermissionsOrByToken(
				context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()),
				permissions,
			)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, core.ErrPermissionDenied)
				return
			}
			writeErrorResponse(r, core.ErrPermissionDenied)
			return
		}

		// Store Sa-Token context | 保存 Sa-Token 上下文
		r.SetCtxVar(SaTokenCtxKey, saCtx)

		r.Middleware.Next()
	}
}

// RoleMiddleware role check middleware | 角色校验中间件
func RoleMiddleware(
	roles []string,
	opts ...AuthOption,
) ghttp.HandlerFunc {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		// No role required | 无需角色直接放行
		if len(roles) == 0 {
			r.Middleware.Next()
			return
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, err)
				return
			}
			writeErrorResponse(r, err)
			return
		}

		// Build Sa-Token context | 构建 Sa-Token 上下文
		saCtx := saContext.NewContext(
			r.Context(),
			NewGFContext(r),
			mgr,
		)

		// Role check | 角色校验
		var ok bool

		switch {
		// Single role | 单角色判断
		case len(roles) == 1:
			ok = mgr.HasRoleByToken(context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()), roles[0])

		// AND logic | AND 逻辑
		case options.LogicType == LogicAnd:
			ok = mgr.HasRolesAndByToken(context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()), roles)

		// OR logic (default) | OR 逻辑（默认）
		default:
			ok = mgr.HasRolesOrByToken(context.WithValue(r.Context(), config.CtxTokenValue, saCtx.GetTokenValue()), roles)
		}

		if !ok {
			if options.AuthFailFunc != nil {
				options.AuthFailFunc(r, core.ErrRoleDenied)
				return
			}
			writeErrorResponse(r, core.ErrRoleDenied)
			return
		}

		// Store Sa-Token context | 保存 Sa-Token 上下文
		r.SetCtxVar(SaTokenCtxKey, saCtx)

		r.Middleware.Next()
	}
}

// GetSaTokenContext gets Sa-Token context from GoFrame context | 获取 Sa-Token 上下文
func GetSaTokenContext(r *ghttp.Request) (*saContext.SaTokenContext, bool) {
	v := r.GetCtxVar(SaTokenCtxKey)
	if v == nil {
		return nil, false
	}

	ctx, ok := v.Val().(*saContext.SaTokenContext)
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
