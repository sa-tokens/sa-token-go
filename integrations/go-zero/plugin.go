package gozero

import (
	"encoding/json"
	"net/http"

	"github.com/sa-tokens/sa-token-go/core"
	"github.com/zeromicro/go-zero/rest"
)

// Plugin provides Sa-Token middleware and handlers for go-zero rest server.
// Plugin 为 go-zero rest 服务提供 Sa-Token 中间件与处理器。
type Plugin struct {
	manager *core.Manager
}

// NewPlugin creates a Plugin with the given Manager.
// NewPlugin 使用指定 Manager 创建 Plugin。
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{manager: manager}
}

// TokenInterceptor parses token and stores it on request context (no login check).
// TokenInterceptor 解析 token 并写入 context，不做登录校验。
func (p *Plugin) TokenInterceptor() rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rc := NewGoZeroContext(w, r)
			tok := core.ReadTokenFromRequest(rc, p.manager)
			next(w, attachTokenToRequest(r, tok))
		}
	}
}

// AuthMiddleware requires a valid login session.
// AuthMiddleware 要求有效登录会话。
func (p *Plugin) AuthMiddleware() rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rc := NewGoZeroContext(w, r)
			saCtx := core.NewContext(rc, p.manager)
			// Check login | 检查登录
			// Try to get token from context first | 优先使用拦截器已解析的 token
			var err error
			if token := GetTokenFromCtx(r); token != "" {
				err = p.manager.CheckLogin(token)
			} else {
				err = saCtx.CheckLogin()
			}
			if err != nil {
				writeErrorResponse(w, err)
				return
			}
			next(w, attachSaTokenToRequest(w, r, saCtx, ""))
		}
	}
}

// PathAuthMiddleware applies path-based auth rules from config.
// PathAuthMiddleware 按 PathAuthConfig 做路径级鉴权。
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			rc := NewGoZeroContext(w, r)
			token := core.ReadTokenFromRequest(rc, p.manager)
			result := core.ProcessAuth(path, token, config, p.manager)

			if result.ShouldReject() {
				writeErrorResponse(w, core.NewPathAuthRequiredError(path))
				return
			}

			if result.IsValid && result.TokenInfo != nil {
				rc2 := NewGoZeroContext(w, r)
				saCtx := core.NewContext(rc2, p.manager)
				r = attachSaTokenToRequest(w, r, saCtx, result.LoginID())
			}
			next(w, r)
		}
	}
}

// PermissionRequired middleware checks login and a single permission.
// PermissionRequired 中间件校验登录与单项权限。
func (p *Plugin) PermissionRequired(permission string) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rc := NewGoZeroContext(w, r)
			saCtx := core.NewContext(rc, p.manager)
			if err := saCtx.CheckLogin(); err != nil {
				writeErrorResponse(w, err)
				return
			}
			if !saCtx.HasPermission(permission) {
				writeErrorResponse(w, core.NewPermissionDeniedError(permission))
				return
			}
			next(w, attachSaTokenToRequest(w, r, saCtx, ""))
		}
	}
}

// RoleRequired middleware checks login and a single role.
// RoleRequired 中间件校验登录与单项角色。
func (p *Plugin) RoleRequired(role string) rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			rc := NewGoZeroContext(w, r)
			saCtx := core.NewContext(rc, p.manager)
			if err := saCtx.CheckLogin(); err != nil {
				writeErrorResponse(w, err)
				return
			}
			if !saCtx.HasRole(role) {
				writeErrorResponse(w, core.NewRoleDeniedError(role))
				return
			}
			next(w, attachSaTokenToRequest(w, r, saCtx, ""))
		}
	}
}

// LoginHandler is an example login endpoint; validate password in your user service before production.
// LoginHandler 为示例登录接口；生产环境须在用户服务校验密码。
func (p *Plugin) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Device   string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, core.NewError(core.CodeBadRequest, core.ErrInvalidConfig.Error(), err))
		return
	}
	if req.Username == "" {
		writeErrorResponse(w, core.NewError(core.CodeInvalidParameter, core.ErrInvalidLoginID.Error(), core.ErrInvalidLoginID))
		return
	}
	// TODO: validate username/password via user service | TODO: 调用用户服务校验账号密码

	device := req.Device
	if device == "" {
		device = "default"
	}
	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(w, err)
		return
	}

	cfg := p.manager.GetConfig()
	if cfg.IsReadCookie {
		maxAge := int(cfg.Timeout)
		if maxAge < 0 {
			maxAge = 0
		}
		rc := NewGoZeroContext(w, r)
		rc.SetCookie(cfg.TokenName, token, maxAge,
			cfg.CookieConfig.Path, cfg.CookieConfig.Domain,
			cfg.CookieConfig.Secure, cfg.CookieConfig.HttpOnly)
	}
	writeSuccessResponse(w, map[string]interface{}{"token": token})
}

// LogoutHandler logs out by loginID (aligned with Gin integration).
// LogoutHandler 按 loginID 登出（与 Gin 集成语义一致）。
func (p *Plugin) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	rc := NewGoZeroContext(w, r)
	saCtx := core.NewContext(rc, p.manager)
	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(w, err)
		return
	}
	if err := p.manager.Logout(loginID); err != nil {
		writeErrorResponse(w, core.NewError(core.CodeServerError, core.ErrStorageUnavailable.Error(), err))
		return
	}
	writeSuccessResponse(w, map[string]interface{}{"message": "logout successful"})
}

// LogoutByTokenHandler logs out by token string.
// LogoutByTokenHandler 按 token 字符串登出。
func (p *Plugin) LogoutByTokenHandler(w http.ResponseWriter, r *http.Request) {
	rc := NewGoZeroContext(w, r)
	token := core.ReadTokenFromRequest(rc, p.manager)
	if token == "" {
		writeErrorResponse(w, core.NewNotLoginError())
		return
	}
	if err := p.manager.LogoutByToken(token); err != nil {
		writeErrorResponse(w, err)
		return
	}
	writeSuccessResponse(w, map[string]interface{}{"message": "logout successful"})
}

// UserInfoHandler returns loginId, roles and permissions for current session.
// UserInfoHandler 返回当前会话的 loginId、角色与权限。
func (p *Plugin) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	rc := NewGoZeroContext(w, r)
	saCtx := core.NewContext(rc, p.manager)
	if err := saCtx.CheckLogin(); err != nil {
		writeErrorResponse(w, err)
		return
	}
	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(w, err)
		return
	}
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)
	writeSuccessResponse(w, map[string]interface{}{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetTokenFromCtx returns token stored by TokenInterceptor.
// GetTokenFromCtx 返回 TokenInterceptor 写入的 token。
func GetTokenFromCtx(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Context().Value(ctxKeyToken); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetSaToken returns SaTokenContext from request context.
// GetSaToken 从 request context 获取 SaTokenContext。
func GetSaToken(r *http.Request) (*core.SaTokenContext, bool) {
	if r == nil {
		return nil, false
	}
	if v := r.Context().Value(ctxKeySaToken); v != nil {
		if sa, ok := v.(*core.SaTokenContext); ok {
			return sa, true
		}
	}
	return nil, false
}

// GetLoginIDFromCtx returns loginID from PathAuthMiddleware.
// GetLoginIDFromCtx 返回 PathAuthMiddleware 写入的 loginID。
func GetLoginIDFromCtx(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	if v := r.Context().Value(ctxKeyLoginID); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}
