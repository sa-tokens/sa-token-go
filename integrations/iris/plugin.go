package iris

import (
	"errors"
	"net/http"

	irisfw "github.com/kataras/iris/v12"
	"github.com/sa-tokens/sa-token-go/core"
)

// Plugin wraps a sa-token Manager and exposes middlewares / example handlers to Iris.
// Plugin 封装 sa-token Manager，向 Iris 暴露中间件与示例 Handler。
type Plugin struct {
	manager *core.Manager
}

// NewPlugin constructs a Plugin. The manager must be non-nil and is owned by the caller.
// NewPlugin 构造 Plugin；manager 必须非空，其生命周期由调用方负责。
func NewPlugin(manager *core.Manager) *Plugin {
	return &Plugin{manager: manager}
}

// satokenTokenCtxKey is the key under which TokenInterceptor stores the parsed token.
// satokenTokenCtxKey TokenInterceptor 写入 iris.Context 的 token 键名。
const satokenTokenCtxKey = "satoken_token"

// satokenCtxKey is the key under which auth middlewares store the *SaTokenContext.
// satokenCtxKey 鉴权中间件写入的 *SaTokenContext 键名。
const satokenCtxKey = "satoken"

// satokenLoginIDKey is the key under which PathAuthMiddleware writes back the loginID.
// satokenLoginIDKey PathAuthMiddleware 在鉴权通过时回写的 loginID 键名。
const satokenLoginIDKey = "loginID"

// TokenInterceptor parses the token from the request and stores it on the context.
// It does NOT enforce login; use AuthMiddleware for that.
// Usage: app.Use(p.TokenInterceptor()), then read via GetTokenFromCtx(c).
// TokenInterceptor 仅解析 token 写入上下文，不做登录校验。
// 用法：app.Use(p.TokenInterceptor()) 之后通过 GetTokenFromCtx(c) 读取。
func (p *Plugin) TokenInterceptor() irisfw.Handler {
	return func(c irisfw.Context) {
		tok := core.ReadTokenFromRequest(NewIrisContext(c), p.manager)
		c.Values().Set(satokenTokenCtxKey, tok)
		c.Next()
	}
}

// AuthMiddleware enforces login: on failure it writes a standard error response and stops.
// AuthMiddleware 强制登录校验：未登录直接终止并返回标准错误响应。
func (p *Plugin) AuthMiddleware() irisfw.Handler {
	return func(c irisfw.Context) {
		saCtx := core.NewContext(NewIrisContext(c), p.manager)
		// Check login | 检查登录
		// Try to get token from context first | 优先使用拦截器已解析的 token
		var err error
		if token := GetTokenFromCtx(c); token != "" {
			err = p.manager.CheckLogin(token)
		} else {
			err = saCtx.CheckLogin()
		}
		if err != nil {
			writeErrorResponse(c, err)
			c.StopExecution()
			return
		}
		c.Values().Set(satokenCtxKey, saCtx)
		c.Next()
	}
}

// PathAuthMiddleware authorizes by path rules from core.PathAuthConfig.
// Path is taken from c.Request().URL.Path to avoid Iris Path() ambiguity under Party /
// path rewriting, matching the gin integration's behavior.
// PathAuthMiddleware 按路径规则鉴权，规则由 core.PathAuthConfig 提供。
// 路径取自 c.Request().URL.Path，避免 Iris Path() 在 Party / 路径重写下的歧义，
// 行为与 gin 集成保持一致。
func (p *Plugin) PathAuthMiddleware(config *core.PathAuthConfig) irisfw.Handler {
	return func(c irisfw.Context) {
		ctx := NewIrisContext(c)
		path := c.Request().URL.Path
		token := core.ReadTokenFromRequest(ctx, p.manager)

		result := core.ProcessAuth(path, token, config, p.manager)
		if result.ShouldReject() {
			writeErrorResponse(c, core.NewPathAuthRequiredError(path))
			c.StopExecution()
			return
		}

		if result.IsValid && result.TokenInfo != nil {
			saCtx := core.NewContext(NewIrisContext(c), p.manager)
			c.Values().Set(satokenCtxKey, saCtx)
			c.Values().Set(satokenLoginIDKey, result.LoginID())
		}
		c.Next()
	}
}

// PermissionRequired requires both login AND the given permission.
// PermissionRequired 在登录基础上额外要求指定权限。
func (p *Plugin) PermissionRequired(permission string) irisfw.Handler {
	return func(c irisfw.Context) {
		saCtx := core.NewContext(NewIrisContext(c), p.manager)
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.StopExecution()
			return
		}
		if !saCtx.HasPermission(permission) {
			writeErrorResponse(c, core.NewPermissionDeniedError(permission))
			c.StopExecution()
			return
		}
		c.Values().Set(satokenCtxKey, saCtx)
		c.Next()
	}
}

// RoleRequired requires both login AND the given role.
// RoleRequired 在登录基础上额外要求指定角色。
func (p *Plugin) RoleRequired(role string) irisfw.Handler {
	return func(c irisfw.Context) {
		saCtx := core.NewContext(NewIrisContext(c), p.manager)
		if err := saCtx.CheckLogin(); err != nil {
			writeErrorResponse(c, err)
			c.StopExecution()
			return
		}
		if !saCtx.HasRole(role) {
			writeErrorResponse(c, core.NewRoleDeniedError(role))
			c.StopExecution()
			return
		}
		c.Values().Set(satokenCtxKey, saCtx)
		c.Next()
	}
}

// LoginHandler is a DEMO-ONLY login endpoint.
// WARNING: this handler does NOT validate password. In production you MUST implement
// real username/password verification, otherwise it is equivalent to passwordless login.
// LoginHandler 仅作为演示用的登录端点。
// 警告：此 Handler 不做密码校验，生产环境必须自行实现用户名/密码验证，
// 否则等同于「无密码登录」，文档与示例必须强调这一点。
func (p *Plugin) LoginHandler(c irisfw.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"` // declared only; not used in any verification | 仅做形参声明，未参与任何校验
		Device   string `json:"device"`
	}
	if err := c.ReadJSON(&req); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeBadRequest, "invalid request parameters", err))
		return
	}
	if req.Username == "" {
		writeErrorResponse(c, core.NewError(core.CodeBadRequest, "username is required", nil))
		return
	}

	device := req.Device
	if device == "" {
		device = "default"
	}

	token, err := p.manager.Login(req.Username, device)
	if err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "login failed", err))
		return
	}

	cfg := p.manager.GetConfig()
	if cfg.IsReadCookie {
		maxAge := int(cfg.Timeout)
		if maxAge < 0 {
			maxAge = 0
		}
		// Reuse buildCookie from context.go to keep SameSite policy in one place.
		// 复用 context.go 中的 buildCookie，统一 SameSite 策略。
		c.SetCookie(buildCookie(
			cfg.TokenName, token, maxAge,
			cfg.CookieConfig.Path, cfg.CookieConfig.Domain,
			cfg.CookieConfig.Secure, cfg.CookieConfig.HttpOnly,
			http.SameSiteLaxMode,
		))
	}

	writeSuccessResponse(c, map[string]interface{}{"token": token})
}

// LogoutHandler logs out the login session associated with the current token.
// LogoutHandler 登出当前 token 对应的登录态。
func (p *Plugin) LogoutHandler(c irisfw.Context) {
	saCtx := core.NewContext(NewIrisContext(c), p.manager)
	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}
	if err := p.manager.Logout(loginID); err != nil {
		writeErrorResponse(c, core.NewError(core.CodeServerError, "logout failed", err))
		return
	}
	writeSuccessResponse(c, map[string]interface{}{"message": "logout successful"})
}

// UserInfoHandler returns loginID, permissions and roles for the logged-in user (demo).
// UserInfoHandler 返回登录用户的 loginID、权限与角色列表（示例用途）。
func (p *Plugin) UserInfoHandler(c irisfw.Context) {
	saCtx := core.NewContext(NewIrisContext(c), p.manager)
	loginID, err := saCtx.GetLoginID()
	if err != nil {
		writeErrorResponse(c, err)
		return
	}
	permissions, _ := p.manager.GetPermissions(loginID)
	roles, _ := p.manager.GetRoles(loginID)
	writeSuccessResponse(c, map[string]interface{}{
		"loginId":     loginID,
		"permissions": permissions,
		"roles":       roles,
	})
}

// GetTokenFromCtx returns the token saved by TokenInterceptor, or "" when absent.
// GetTokenFromCtx 读取 TokenInterceptor 写入的 token；未挂拦截器时返回空串。
func GetTokenFromCtx(c irisfw.Context) string {
	if v := c.Values().Get(satokenTokenCtxKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetSaToken fetches the SaTokenContext stashed by an auth middleware.
// GetSaToken 从 iris.Context 取出鉴权中间件存放的 SaTokenContext。
func GetSaToken(c irisfw.Context) (*core.SaTokenContext, bool) {
	v := c.Values().Get(satokenCtxKey)
	if v == nil {
		return nil, false
	}
	ctx, ok := v.(*core.SaTokenContext)
	return ctx, ok
}

// ============ Standardized response helpers | 标准化响应辅助函数 ============

// writeErrorResponse writes a unified error JSON:
//   - SaTokenError: returns its business code + message + mapped HTTP status;
//   - core sentinel errors (e.g. ErrNotLogin from manager.CheckLogin): mapped via
//     resolveErrorFromSentinel without exposing wrapped internals;
//   - other errors: returns CodeServerError + "internal error".
//
// writeErrorResponse 输出统一错误 JSON：
//   - SaTokenError：返回业务码 + 业务消息 + 业务 HTTP 状态；
//   - core 哨兵错误（如 manager.CheckLogin 返回的 ErrNotLogin）：经 resolveErrorFromSentinel 映射；
//   - 其他 error：返回 CodeServerError + "internal error"，不暴露原始 err.Error()。
func writeErrorResponse(c irisfw.Context, err error) {
	code, httpStatus, message := resolveErrorResponse(err)
	c.StatusCode(httpStatus)
	_ = c.JSON(map[string]interface{}{
		"code":    code,
		"message": message,
	})
}

// resolveErrorResponse maps any error to business code, HTTP status and user-facing message.
// resolveErrorResponse 将任意 error 映射为业务码、HTTP 状态与用户可见消息。
func resolveErrorResponse(err error) (code int, httpStatus int, message string) {
	var saErr *core.SaTokenError
	if errors.As(err, &saErr) {
		return saErr.Code, getHTTPStatusFromCode(saErr.Code), saErr.Message
	}
	if code, httpStatus, message, ok := resolveErrorFromSentinel(err); ok {
		return code, httpStatus, message
	}
	return core.CodeServerError, http.StatusInternalServerError, "internal error"
}

// resolveErrorFromSentinel maps core sentinel errors to API responses.
// Order matters: more specific sentinels should appear before broader ones.
// resolveErrorFromSentinel 将 core 哨兵错误映射为 API 响应；顺序敏感，更具体的哨兵应靠前。
func resolveErrorFromSentinel(err error) (code int, httpStatus int, message string, ok bool) {
	type sentinelMatch struct {
		sentinel   error
		code       int
		httpStatus int
	}
	matches := []sentinelMatch{
		{core.ErrNotLogin, core.CodeNotLogin, http.StatusUnauthorized},
		{core.ErrTokenInvalid, core.CodeTokenInvalid, http.StatusUnauthorized},
		{core.ErrTokenExpired, core.CodeTokenExpired, http.StatusUnauthorized},
		{core.ErrKickedOut, core.CodeKickedOut, http.StatusUnauthorized},
		{core.ErrPermissionDenied, core.CodePermissionDenied, http.StatusForbidden},
		{core.ErrRoleDenied, core.CodePermissionDenied, http.StatusForbidden},
		{core.ErrAccountDisabled, core.CodeAccountDisabled, http.StatusForbidden},
		{core.ErrPathAuthRequired, core.CodePathAuthRequired, http.StatusUnauthorized},
		{core.ErrPathNotAllowed, core.CodePathNotAllowed, http.StatusForbidden},
	}
	for _, m := range matches {
		if errors.Is(err, m.sentinel) {
			return m.code, m.httpStatus, m.sentinel.Error(), true
		}
	}
	return 0, 0, "", false
}

// writeSuccessResponse writes a unified success JSON. | writeSuccessResponse 输出统一成功 JSON。
func writeSuccessResponse(c irisfw.Context, data interface{}) {
	c.StatusCode(http.StatusOK)
	_ = c.JSON(map[string]interface{}{
		"code":    core.CodeSuccess,
		"message": "success",
		"data":    data,
	})
}

// getHTTPStatusFromCode maps a sa-token business code to an HTTP status code.
// The mapping mirrors integrations/go-zero/error_response.go so that behavior is
// consistent across integrations.
// getHTTPStatusFromCode 将 sa-token 业务码映射为 HTTP 状态码，
// 映射表对齐 integrations/go-zero/error_response.go，确保跨集成行为一致。
func getHTTPStatusFromCode(code int) int {
	switch code {
	case core.CodeNotLogin,
		core.CodeTokenInvalid, core.CodeTokenExpired,
		core.CodeActiveTimeout, core.CodeKickedOut, core.CodeSessionError:
		return http.StatusUnauthorized
	case core.CodePermissionDenied,
		core.CodeAccountDisabled, core.CodeMaxLoginCount:
		return http.StatusForbidden
	case core.CodeBadRequest, core.CodeInvalidParameter:
		return http.StatusBadRequest
	case core.CodeNotFound:
		return http.StatusNotFound
	case core.CodeServerError, core.CodeStorageError:
		return http.StatusInternalServerError
	default:
		// Codes in 10001-19999 are treated as permission/state errors -> 403.
		// 10001-19999 段视为权限/状态类错误，回落 403；其余 500。
		if code >= 10001 && code < 20000 {
			return http.StatusForbidden
		}
		return http.StatusInternalServerError
	}
}
