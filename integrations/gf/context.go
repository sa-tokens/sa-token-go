package gf

import (
	"net/http"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/gogf/gf/v2/net/ghttp"
)

type GFContext struct {
	c       *ghttp.Request
	aborted bool
}

// NewGFContext creates a GF context adapter | 创建GF上下文适配器
func NewGFContext(c *ghttp.Request) adapter.RequestContext {
	return &GFContext{
		c: c,
	}
}

// Get implements adapter.RequestContext.
func (g *GFContext) Get(key string) (interface{}, bool) {
	v := g.c.Get(key)
	return v, v.IsNil()
}

// GetClientIP implements adapter.RequestContext.
func (g *GFContext) GetClientIP() string {
	return g.c.GetClientIp()
}

// GetCookie implements adapter.RequestContext.
func (g *GFContext) GetCookie(key string) string {
	return g.c.Cookie.Get(key).String()
}

// GetHeader implements adapter.RequestContext.
func (g *GFContext) GetHeader(key string) string {
	return g.c.Header.Get(key)
}

// GetMethod implements adapter.RequestContext.
func (g *GFContext) GetMethod() string {
	return g.c.Method
}

// GetPath implements adapter.RequestContext.
func (g *GFContext) GetPath() string {
	return g.c.Request.URL.Path
}

// GetQuery implements adapter.RequestContext.
func (g *GFContext) GetQuery(key string) string {
	return g.c.Request.URL.Query().Get(key)
}

// Set implements adapter.RequestContext.
func (g *GFContext) Set(key string, value interface{}) {
	g.c.SetCtxVar(key, value)
}

// SetCookie implements adapter.RequestContext.
func (g *GFContext) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool) {
	g.c.Cookie.SetHttpCookie(&http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// SetHeader implements adapter.RequestContext.
func (g *GFContext) SetHeader(key string, value string) {
	g.c.Header.Set(key, value)
}

// ============ Additional Required Methods | 额外必需的方法 ============

// GetHeaders implements adapter.RequestContext.
func (g *GFContext) GetHeaders() map[string][]string {
	return g.c.Header
}

// GetQueryAll implements adapter.RequestContext.
func (g *GFContext) GetQueryAll() map[string][]string {
	return g.c.Request.URL.Query()
}

// GetPostForm implements adapter.RequestContext.
func (g *GFContext) GetPostForm(key string) string {
	return g.c.GetForm(key).String()
}

// GetBody implements adapter.RequestContext.
func (g *GFContext) GetBody() ([]byte, error) {
	body := g.c.GetBody()
	return body, nil
}

// GetURL implements adapter.RequestContext.
func (g *GFContext) GetURL() string {
	return g.c.Request.URL.String()
}

// GetUserAgent implements adapter.RequestContext.
func (g *GFContext) GetUserAgent() string {
	return g.c.Header.Get("User-Agent")
}

// SetCookieWithOptions implements adapter.RequestContext.
func (g *GFContext) SetCookieWithOptions(options *adapter.CookieOptions) {
	cookie := &http.Cookie{
		Name:     options.Name,
		Value:    options.Value,
		MaxAge:   options.MaxAge,
		Path:     options.Path,
		Domain:   options.Domain,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: http.SameSite(0), // Default to SameSiteNone
	}

	// Set SameSite attribute
	switch options.SameSite {
	case "Strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "Lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "None":
		cookie.SameSite = http.SameSiteNoneMode
	}

	g.c.Cookie.SetHttpCookie(cookie)
}

// GetString implements adapter.RequestContext.
func (g *GFContext) GetString(key string) string {
	v := g.c.Get(key)
	return v.String()
}

// MustGet implements adapter.RequestContext.
func (g *GFContext) MustGet(key string) any {
	v := g.c.Get(key)
	if v.IsNil() {
		panic("key not found: " + key)
	}
	return v
}

// Abort implements adapter.RequestContext.
func (g *GFContext) Abort() {
	g.aborted = true
}

// IsAborted implements adapter.RequestContext.
func (g *GFContext) IsAborted() bool {
	return g.aborted
}
