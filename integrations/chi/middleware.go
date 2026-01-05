package chi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/manager"

	saContext "github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/stputil"
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
	FailFunc  func(w http.ResponseWriter, r *http.Request, err error)
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

// WithFailFunc sets auth failure callback | 设置认证失败回调
func WithFailFunc(fn func(w http.ResponseWriter, r *http.Request, err error)) AuthOption {
	return func(o *AuthOptions) {
		o.FailFunc = fn
	}
}

// ========== Middlewares ==========

// AuthMiddleware authentication middleware | 认证中间件
func AuthMiddleware(opts ...AuthOption) func(http.Handler) http.Handler {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mgr, err := stputil.GetManager(options.AuthType)
			if err != nil {
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}
				return
			}

			// 获取 token | Get token
			ctx := NewChiContext(w, r)
			saCtx := getSaContext(ctx.(*ChiContext), r, mgr)
			tokenValue := saCtx.GetTokenValue()

			// 检查登录 | Check login
			err = mgr.CheckLogin(r.Context(), tokenValue)
			if err != nil {
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthWithStateMiddleware with state authentication middleware | 带状态返回的认证中间件
func AuthWithStateMiddleware(opts ...AuthOption) func(http.Handler) http.Handler {
	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 获取 Manager | Get Manager
			mgr, err := stputil.GetManager(options.AuthType)
			if err != nil {
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}
				return
			}

			// 构建 Sa-Token 上下文 | Build Sa-Token context
			ctx := NewChiContext(w, r)
			saCtx := getSaContext(ctx.(*ChiContext), r, mgr)
			tokenValue := saCtx.GetTokenValue()

			// 检查登录并返回状态 | Check login with state
			_, err = mgr.CheckLoginWithState(r.Context(), tokenValue)

			if err != nil {
				// 用户自定义回调优先
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PermissionMiddleware permission check middleware | 权限校验中间件
func PermissionMiddleware(
	permissions []string,
	opts ...AuthOption,
) func(http.Handler) http.Handler {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No permission required | 无需权限直接放行
			if len(permissions) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Get Manager | 获取 Manager
			mgr, err := stputil.GetManager(options.AuthType)
			if err != nil {
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}
				return
			}

			// 构建 Sa-Token 上下文 | Build Sa-Token context
			ctx := NewChiContext(w, r)
			saCtx := getSaContext(ctx.(*ChiContext), r, mgr)
			tokenValue := saCtx.GetTokenValue()
			reqCtx := r.Context()

			// Permission check | 权限校验
			var ok bool
			if options.LogicType == LogicAnd {
				ok = mgr.HasPermissionsAndByToken(reqCtx, tokenValue, permissions)
			} else {
				ok = mgr.HasPermissionsOrByToken(reqCtx, tokenValue, permissions)
			}

			if !ok {
				if options.FailFunc != nil {
					options.FailFunc(w, r, core.ErrPermissionDenied)
				} else {
					writeErrorResponse(w, core.ErrPermissionDenied)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RoleMiddleware role check middleware | 角色校验中间件
func RoleMiddleware(
	roles []string,
	opts ...AuthOption,
) func(http.Handler) http.Handler {

	options := defaultAuthOptions()
	for _, opt := range opts {
		opt(options)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No role required | 无需角色直接放行
			if len(roles) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Get Manager | 获取 Manager
			mgr, err := stputil.GetManager(options.AuthType)
			if err != nil {
				if options.FailFunc != nil {
					options.FailFunc(w, r, err)
				} else {
					writeErrorResponse(w, err)
				}
				return
			}

			// 构建 Sa-Token 上下文 | Build Sa-Token context
			ctx := NewChiContext(w, r)
			saCtx := getSaContext(ctx.(*ChiContext), r, mgr)
			tokenValue := saCtx.GetTokenValue()
			reqCtx := r.Context()

			// Role check | 角色校验
			var ok bool
			if options.LogicType == LogicAnd {
				ok = mgr.HasRolesAndByToken(reqCtx, tokenValue, roles)
			} else {
				ok = mgr.HasRolesOrByToken(reqCtx, tokenValue, roles)
			}

			if !ok {
				if options.FailFunc != nil {
					options.FailFunc(w, r, core.ErrRoleDenied)
				} else {
					writeErrorResponse(w, core.ErrRoleDenied)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetSaTokenContext gets Sa-Token context from request | 获取 Sa-Token 上下文
func GetSaTokenContext(r *http.Request) (*saContext.SaTokenContext, bool) {
	v := r.Context().Value(SaTokenCtxKey)
	if v == nil {
		return nil, false
	}

	ctx, ok := v.(*saContext.SaTokenContext)
	return ctx, ok
}

func getSaContext(chiCtx *ChiContext, r *http.Request, mgr *manager.Manager) *saContext.SaTokenContext {
	// Try get from context | 尝试从 ctx 取值
	if v := r.Context().Value(SaTokenCtxKey); v != nil {
		if saCtx, ok := v.(*saContext.SaTokenContext); ok {
			return saCtx
		}
	}

	// Create new context | 创建并缓存 SaTokenContext
	saCtx := saContext.NewContext(chiCtx, mgr)
	chiCtx.Set(SaTokenCtxKey, saCtx)

	return saCtx
}

// ============ Error Handling Helpers | 错误处理辅助函数 ============

// writeErrorResponse writes a standardized error response | 写入标准化的错误响应
func writeErrorResponse(w http.ResponseWriter, err error) {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    code,
		"message": message,
		"data":    err.Error(),
	})
}

// writeSuccessResponse writes a standardized success response | 写入标准化的成功响应
func writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
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
