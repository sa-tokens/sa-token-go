package hertz

import (
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

// HertzContext Hertz request context adapter | Gin请求上下文适配器
type HertzContext struct {
	c       *app.RequestContext
	aborted bool
}

// NewHertzContext creates a Hertz context adapter | 创建Hertz上下文适配器
func NewHertzContext(c *app.RequestContext) adapter.RequestContext {
	return &HertzContext{c: c}
}

// GetHeader gets request header | 获取请求头
func (h *HertzContext) GetHeader(key string) string {
	return string(h.c.GetHeader(key))
}

// GetQuery gets query parameter | 获取查询参数
func (h *HertzContext) GetQuery(key string) string {
	return h.c.Query(key)
}

// GetCookie gets cookie | 获取Cookie
func (h *HertzContext) GetCookie(key string) string {
	cookie := h.c.Cookie(key)
	return string(cookie)
}

// SetHeader sets response header | 设置响应头
func (h *HertzContext) SetHeader(key, value string) {
	h.c.Header(key, value)
}

// SetCookie sets cookie | 设置Cookie
func (h *HertzContext) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	h.c.SetCookie(name, value, maxAge, path, domain, protocol.CookieSameSiteLaxMode, secure, httpOnly)
}

// GetClientIP gets client IP address | 获取客户端IP地址
func (h *HertzContext) GetClientIP() string {
	return h.c.ClientIP()
}

// GetMethod gets request method | 获取请求方法
func (h *HertzContext) GetMethod() string {
	return string(h.c.Method())
}

// GetPath gets request path | 获取请求路径
func (h *HertzContext) GetPath() string {
	return string(h.c.Path())
}

// Set sets context value | 设置上下文值
func (h *HertzContext) Set(key string, value interface{}) {
	h.c.Set(key, value)
}

// Get gets context value | 获取上下文值
func (h *HertzContext) Get(key string) (interface{}, bool) {
	return h.c.Get(key)
}

// ============ Additional Required Methods | 额外必需的方法 ============

// GetHeaders implements adapter.RequestContext.
func (h *HertzContext) GetHeaders() map[string][]string {
	headers := make(map[string][]string)
	h.c.Request.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = []string{string(value)}
	})
	return headers
}

// GetQueryAll implements adapter.RequestContext.
func (h *HertzContext) GetQueryAll() map[string][]string {
	params := make(map[string][]string)
	h.c.QueryArgs().VisitAll(func(key, value []byte) {
		params[string(key)] = []string{string(value)}
	})
	return params
}

// GetPostForm implements adapter.RequestContext.
func (h *HertzContext) GetPostForm(key string) string {
	return h.c.PostForm(key)
}

// GetBody implements adapter.RequestContext.
func (h *HertzContext) GetBody() ([]byte, error) {
	return h.c.GetRawData(), nil
}

// GetURL implements adapter.RequestContext.
func (h *HertzContext) GetURL() string {
	return string(h.c.Request.URI().RequestURI())
}

// GetUserAgent implements adapter.RequestContext.
func (h *HertzContext) GetUserAgent() string {
	return string(h.c.UserAgent())
}

// SetCookieWithOptions implements adapter.RequestContext.
func (h *HertzContext) SetCookieWithOptions(options *adapter.CookieOptions) {
	// Set SameSite attribute
	var sameSite protocol.CookieSameSite
	switch options.SameSite {
	case "Strict":
		sameSite = protocol.CookieSameSiteStrictMode
	case "Lax":
		sameSite = protocol.CookieSameSiteLaxMode
	case "None":
		sameSite = protocol.CookieSameSiteNoneMode
	}
	h.c.SetCookie(
		options.Name,
		options.Value,
		options.MaxAge,
		options.Path,
		options.Domain,
		sameSite,
		options.Secure,
		options.HttpOnly,
	)
}

// GetString implements adapter.RequestContext.
func (h *HertzContext) GetString(key string) string {
	value, exists := h.c.Get(key)
	if !exists {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

// MustGet implements adapter.RequestContext.
func (h *HertzContext) MustGet(key string) any {
	value, exists := h.c.Get(key)
	if !exists {
		panic("key not found: " + key)
	}
	return value
}

// Abort implements adapter.RequestContext.
func (h *HertzContext) Abort() {
	h.aborted = true
	h.c.Abort()
}

// IsAborted implements adapter.RequestContext.
func (h *HertzContext) IsAborted() bool {
	return h.aborted
}
