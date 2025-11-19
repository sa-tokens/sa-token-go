package kratos

import (
	"context"
	"io"
	"net/http"
	"sync"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/go-kratos/kratos/v2/transport"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

type KratosContext struct {
	ctx     context.Context
	values  map[string]interface{}
	mu      sync.RWMutex
	aborted bool
}

// NewKratosContext creates a Kratos context adapter | 创建Kratos上下文适配器
// This constructor accepts any request/response objects that implement the KratosRequest/KratosResponse interfaces
func NewKratosContext(ctx context.Context) adapter.RequestContext {
	return &KratosContext{
		ctx: ctx,
	}
}

// GetHeader gets request header | 获取请求头
func (k *KratosContext) GetHeader(key string) string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		return tr.RequestHeader().Get(key)
	}
	return ""
}

// GetQuery gets query parameter | 获取查询参数
func (k *KratosContext) GetQuery(key string) string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			return request.URL.Query().Get(key)
		}
	}
	return ""
}

// GetCookie gets cookie | 获取Cookie
func (k *KratosContext) GetCookie(key string) string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			cookie, err := request.Cookie(key)
			if err != nil {
				return ""
			}
			return cookie.Value
		}
	}
	return ""
}

// SetHeader sets response header | 设置响应头
func (k *KratosContext) SetHeader(key, value string) {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		tr.ReplyHeader().Set(key, value)
	}
}

// SetCookie sets cookie | 设置Cookie
func (k *KratosContext) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Domain:   domain,
	}
	khttp.SetCookie(k.ctx, cookie)
}

// GetClientIP gets client IP address | 获取客户端IP地址
func (k *KratosContext) GetClientIP() string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		// 尝试从X-Forwarded-AutoMatcher获取，如果获取不到，再从X-Forwarded-For获取
		var xff string
		if xff = tr.RequestHeader().Get("X-Forwarded-AutoMatcher"); xff == "" {
			xff = tr.RequestHeader().Get("X-Forwarded-For")
		}
		if xff != "" {
			// X-Forwarded-For可能包含多个IP，取第一个
			if idx := indexOf(xff, ","); idx > 0 {
				return trimSpace(xff[:idx])
			}
			return trimSpace(xff)
		}

		// 尝试从X-Real-IP获取
		if xri := tr.RequestHeader().Get("X-Real-IP"); xri != "" {
			return trimSpace(xri)
		}

		// 如果是HTTP transport，尝试从Request获取
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			if request.RemoteAddr != "" {
				// RemoteAddr格式: "IP:Port"，需要去掉端口
				if idx := lastIndexOf(request.RemoteAddr, ":"); idx > 0 {
					return request.RemoteAddr[:idx]
				}
				return request.RemoteAddr
			}
		}
	}
	return ""
}

// GetMethod gets request method | 获取请求方法
func (k *KratosContext) GetMethod() string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			return request.Method
		}
	}
	return ""
}

// GetPath gets request path | 获取请求路径
func (k *KratosContext) GetPath() string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		return tr.Operation()
	}
	return ""
}

// Set sets context value | 设置上下文值
func (k *KratosContext) Set(key string, value interface{}) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.values == nil {
		k.values = make(map[string]interface{})
	}

	k.values[key] = value
}

// Get gets context value | 获取上下文值
func (k *KratosContext) Get(key string) (interface{}, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	value, exists := k.values[key]
	return value, exists
}

func (k *KratosContext) GetHeaders() map[string][]string {
	headers := make(map[string][]string)
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		header := tr.RequestHeader()
		// Kratos的RequestHeader返回的是transport.Header类型，遍历所有键获取值
		for _, key := range header.Keys() {
			headers[key] = header.Values(key)
		}
	}
	return headers
}

func (k *KratosContext) GetQueryAll() map[string][]string {
	params := make(map[string][]string)
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			query := htr.Request().URL.Query()
			for key, values := range query {
				params[key] = values
			}
		}
	}
	return params
}

func (k *KratosContext) GetPostForm(key string) string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			if err := request.ParseForm(); err != nil {
				return ""
			}
			return request.PostFormValue(key)
		}
	}
	return ""
}

func (k *KratosContext) GetBody() ([]byte, error) {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			if request.Body == nil {
				return nil, nil
			}
			defer request.Body.Close()
			return io.ReadAll(request.Body)
		}
	}
	return nil, nil
}

func (k *KratosContext) GetURL() string {
	if tr, ok := transport.FromServerContext(k.ctx); ok {
		if htr, ok := tr.(*khttp.Transport); ok {
			request := htr.Request()
			return request.URL.String()
		}
	}
	return ""
}

func (k *KratosContext) GetUserAgent() string {
	return k.GetHeader("User-Agent")
}

func (k *KratosContext) SetCookieWithOptions(options *adapter.CookieOptions) {
	cookie := &http.Cookie{
		Name:     options.Name,
		Value:    options.Value,
		Path:     options.Path,
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: options.HttpOnly,
		SameSite: http.SameSiteLaxMode, // Default to Lax
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

	khttp.SetCookie(k.ctx, cookie)
}

func (k *KratosContext) GetString(key string) string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.values == nil {
		return ""
	}
	value, exists := k.values[key]
	if !exists {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func (k *KratosContext) MustGet(key string) any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.values == nil {
		panic("key not found: " + key)
	}
	value, exists := k.values[key]
	if !exists {
		panic("key not found: " + key)
	}
	return value
}

func (k *KratosContext) Abort() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.aborted = true
}

func (k *KratosContext) IsAborted() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.aborted
}
