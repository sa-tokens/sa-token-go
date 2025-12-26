package gin

import (
	"net/http"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/gin-gonic/gin"
)

type GinContext struct {
	c       *gin.Context
	aborted bool
}

// NewGinContext creates a Gin context adapter | 创建Gin上下文适配器
func NewGinContext(c *gin.Context) adapter.RequestContext {
	return &GinContext{
		c: c,
	}
}

// Get implements adapter.RequestContext.
func (g *GinContext) Get(key string) (interface{}, bool) {
	return g.c.Get(key)
}

// GetClientIP implements adapter.RequestContext.
func (g *GinContext) GetClientIP() string {
	return g.c.ClientIP()
}

// GetCookie implements adapter.RequestContext.
func (g *GinContext) GetCookie(key string) string {
	cookie, _ := g.c.Cookie(key)
	return cookie
}

// GetHeader implements adapter.RequestContext.
func (g *GinContext) GetHeader(key string) string {
	return g.c.GetHeader(key)
}

// GetMethod implements adapter.RequestContext.
func (g *GinContext) GetMethod() string {
	return g.c.Request.Method
}

// GetPath implements adapter.RequestContext.
func (g *GinContext) GetPath() string {
	return g.c.Request.URL.Path
}

// GetQuery implements adapter.RequestContext.
func (g *GinContext) GetQuery(key string) string {
	return g.c.Query(key)
}

// Set implements adapter.RequestContext.
func (g *GinContext) Set(key string, value interface{}) {
	g.c.Set(key, value)
}

// SetCookie implements adapter.RequestContext.
func (g *GinContext) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool) {
	g.c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
	g.c.SetSameSite(http.SameSiteLaxMode)
}

// SetHeader implements adapter.RequestContext.
func (g *GinContext) SetHeader(key string, value string) {
	g.c.Header(key, value)
}

// ============ Additional Required Methods | 额外必需的方法 ============

// GetHeaders implements adapter.RequestContext.
func (g *GinContext) GetHeaders() map[string][]string {
	return g.c.Request.Header
}

// GetQueryAll implements adapter.RequestContext.
func (g *GinContext) GetQueryAll() map[string][]string {
	return g.c.Request.URL.Query()
}

// GetPostForm implements adapter.RequestContext.
func (g *GinContext) GetPostForm(key string) string {
	return g.c.PostForm(key)
}

// GetBody implements adapter.RequestContext.
func (g *GinContext) GetBody() ([]byte, error) {
	return g.c.GetRawData()
}

// GetURL implements adapter.RequestContext.
func (g *GinContext) GetURL() string {
	return g.c.Request.URL.String()
}

// GetUserAgent implements adapter.RequestContext.
func (g *GinContext) GetUserAgent() string {
	return g.c.GetHeader("User-Agent")
}

// SetCookieWithOptions implements adapter.RequestContext.
func (g *GinContext) SetCookieWithOptions(options *adapter.CookieOptions) {
	g.c.SetCookie(
		options.Name,
		options.Value,
		options.MaxAge,
		options.Path,
		options.Domain,
		options.Secure,
		options.HttpOnly,
	)

	// Set SameSite attribute
	switch options.SameSite {
	case "Strict":
		g.c.SetSameSite(http.SameSiteStrictMode)
	case "Lax":
		g.c.SetSameSite(http.SameSiteLaxMode)
	case "None":
		g.c.SetSameSite(http.SameSiteNoneMode)
	}
}

// GetString implements adapter.RequestContext.
func (g *GinContext) GetString(key string) string {
	v := g.c.GetString(key)
	return v
}

// MustGet implements adapter.RequestContext.
func (g *GinContext) MustGet(key string) any {
	v, exists := g.c.Get(key)
	if !exists {
		panic("key not found: " + key)
	}
	return v
}

// Abort implements adapter.RequestContext.
func (g *GinContext) Abort() {
	g.aborted = true
	g.c.Abort()
}

// IsAborted implements adapter.RequestContext.
func (g *GinContext) IsAborted() bool {
	return g.aborted
}
