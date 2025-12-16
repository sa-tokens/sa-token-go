package chi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/click33/sa-token-go/core"
)

// Plugin Chi plugin for Sa-Token | Chi插件
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Chi plugin | 创建Chi插件
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{
		manager: manager,
	}
}

// AuthMiddleware authentication middleware | 认证中间件
func (p *Plugin) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := NewChiContext(w, r)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				writeErrorResponse(w, err)
				return
			}

			// Store Sa-Token context | 存储Sa-Token上下文
			ctx.Set("satoken", saCtx)
			next.ServeHTTP(w, r)
		})
	}
}

// PermissionRequired permission validation middleware | 权限验证中间件
func (p *Plugin) PermissionRequired(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := NewChiContext(w, r)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				writeErrorResponse(w, err)
				return
			}

			if !saCtx.HasPermission(permission) {
				writeErrorResponse(w, core.NewPermissionDeniedError(permission))
				return
			}

			ctx.Set("satoken", saCtx)
			next.ServeHTTP(w, r)
		})
	}
}

// RoleRequired role validation middleware | 角色验证中间件
func (p *Plugin) RoleRequired(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := NewChiContext(w, r)
			saCtx := core.NewContext(ctx, p.manager)

			if err := saCtx.CheckLogin(); err != nil {
				writeErrorResponse(w, err)
				return
			}

			if !saCtx.HasRole(role) {
				writeErrorResponse(w, core.NewRoleDeniedError(role))
				return
			}

			ctx.Set("satoken", saCtx)
			next.ServeHTTP(w, r)
		})
	}
}

// LoginHandler 登录处理器
func (p *Plugin) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}

	device := req.Device
	if device == "" {
		device = "log"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(w, core.NewError(core.CodeServerError, "login failed", err))
		return
	}

	writeSuccessResponse(w, map[string]interface{}{
		"token": token,
	})
}

// GetSaToken 从请求上下文获取Sa-Token上下文
func GetSaToken(r *http.Request) (*core.SaTokenContext, bool) {
	satoken := r.Context().Value("satoken")
	if satoken == nil {
		return nil, false
	}
	ctx, ok := satoken.(*core.SaTokenContext)
	return ctx, ok
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
		"error":   err.Error(),
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
