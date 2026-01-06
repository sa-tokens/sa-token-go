package gf

import (
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/manager"

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
	AuthType  string
	LogicType LogicType
	FailFunc  func(r *ghttp.Request, err error)
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

func WithLogicType(logicType LogicType) AuthOption {
	return func(o *AuthOptions) {
		o.LogicType = logicType
	}
}

// WithFailFunc sets auth failure callback | 设置认证失败回调
func WithFailFunc(fn func(r *ghttp.Request, err error)) AuthOption {
	return func(o *AuthOptions) {
		o.FailFunc = fn
	}
}

// ========== Middlewares ==========

// AuthMiddleware authentication middleware | 认证中间件
func AuthMiddleware(opts ...AuthOption) ghttp.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// 获取 token | Get token
		saCtx := getSaContext(r, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录 | Check login
		_, err = mgr.CheckLoginWithState(r.Context(), tokenValue)
		if err != nil {
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		r.Middleware.Next()
	}
}

// AuthWithStateMiddleware with state authentication middleware | 带状态返回的认证中间件
func AuthWithStateMiddleware(opts ...AuthOption) ghttp.HandlerFunc {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		// 获取 Manager | Get Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(r, mgr)
		tokenValue := saCtx.GetTokenValue()

		// 检查登录并返回状态 | Check login with state
		_, err = mgr.CheckLoginWithState(r.Context(), tokenValue)

		if err != nil {
			// 用户自定义回调优先
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}

			return
		}

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
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(r, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := r.Context()

		// Permission check | 权限校验
		var ok bool
		if options.LogicType == LogicAnd {
			ok = mgr.HasPermissionsAndByToken(ctx, tokenValue, permissions)
		} else {
			ok = mgr.HasPermissionsOrByToken(ctx, tokenValue, permissions)
		}

		if !ok {
			if options.FailFunc != nil {
				options.FailFunc(r, core.ErrPermissionDenied)
			} else {
				writeErrorResponse(r, core.ErrPermissionDenied)
			}
			return
		}

		r.Middleware.Next()
	}
}

// PermissionPathMiddleware permission check middleware | 基于路径的权限校验中间件
func PermissionPathMiddleware(
	permissions []string,
	opts ...AuthOption,
) ghttp.HandlerFunc {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(r *ghttp.Request) {
		// Create a per-request copy of permissions and append current path | 每次请求创建权限副本并追加当前路径
		reqPermissions := append([]string{}, permissions...)
		reqPermissions = append(reqPermissions, r.URL.Path)

		if len(reqPermissions) == 0 {
			r.Middleware.Next()
			return
		}

		// Get Manager | 获取 Manager
		mgr, err := stputil.GetManager(options.AuthType)
		if err != nil {
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(r, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := r.Context()

		// Permission check | 权限校验
		var ok bool
		if options.LogicType == LogicAnd {
			ok = mgr.HasPermissionsAndByToken(ctx, tokenValue, reqPermissions)
		} else {
			ok = mgr.HasPermissionsOrByToken(ctx, tokenValue, reqPermissions)
		}

		if !ok {
			if options.FailFunc != nil {
				options.FailFunc(r, core.ErrPermissionDenied)
			} else {
				writeErrorResponse(r, core.ErrPermissionDenied)
			}
			return
		}

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
			if options.FailFunc != nil {
				options.FailFunc(r, err)
			} else {
				writeErrorResponse(r, err)
			}
			return
		}

		// 构建 Sa-Token 上下文 | Build Sa-Token context
		saCtx := getSaContext(r, mgr)
		tokenValue := saCtx.GetTokenValue()
		ctx := r.Context()

		// Role check | 角色校验
		var ok bool
		if options.LogicType == LogicAnd {
			ok = mgr.HasRolesAndByToken(ctx, tokenValue, roles)
		} else {
			ok = mgr.HasRolesOrByToken(ctx, tokenValue, roles)
		}

		if !ok {
			if options.FailFunc != nil {
				options.FailFunc(r, core.ErrRoleDenied)
			} else {
				writeErrorResponse(r, core.ErrRoleDenied)
			}
			return
		}

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

func getSaContext(r *ghttp.Request, mgr *manager.Manager) *saContext.SaTokenContext {
	// Try get from context | 尝试从 ctx 取值
	if v := r.GetCtxVar(SaTokenCtxKey); v != nil {
		// gvar.Var -> interface{} -> *SaTokenContext
		if saCtx, ok := v.Val().(*saContext.SaTokenContext); ok {
			return saCtx
		}
	}

	// Create new context | 创建并缓存 SaTokenContext
	saCtx := saContext.NewContext(NewGFContext(r), mgr)
	r.SetCtxVar(SaTokenCtxKey, saCtx)

	return saCtx
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
		"data":    err.Error(),
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
