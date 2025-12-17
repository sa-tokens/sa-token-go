package router

import (
	"strings"
	"github.com/click33/sa-token-go/core/manager"
)

// MatchPath matches a path against a pattern (Ant-style wildcard) | 匹配路径与模式（Ant风格通配符）
// Supported patterns:
//   - "/**": Match all paths | 匹配所有路径
//   - "/api/**": Match all paths starting with "/api/" | 匹配所有以"/api/"开头的路径
//   - "/api/*": Match single-level paths under "/api/" | 匹配"/api/"下的单级路径
//   - "*.html": Match paths ending with ".html" | 匹配以".html"结尾的路径
//   - "/exact": Exact match | 精确匹配
func MatchPath(path, pattern string) bool {
	if pattern == "/**" {
		return true
	}

	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(path, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(path, suffix)
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2]
		if strings.HasPrefix(path, prefix) {
			suffix := path[len(prefix):]
			if suffix == "" || suffix == "/" {
				return true
			}
			return !strings.Contains(suffix[1:], "/")
		}
		return false
	}

	return path == pattern
}

// MatchAny checks if path matches any pattern in the list | 检查路径是否匹配列表中的任意模式
func MatchAny(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchPath(path, pattern) {
			return true
		}
	}
	return false
}

// NeedAuth determines if authentication is needed for a path | 判断路径是否需要鉴权
// Returns true if path matches include patterns but not exclude patterns | 如果路径匹配包含模式但不匹配排除模式，返回true
func NeedAuth(path string, include, exclude []string) bool {
	return MatchAny(path, include) && !MatchAny(path, exclude)
}

// PathAuthConfig path-based authentication configuration | 基于路径的鉴权配置
// Configure which paths require authentication and which are excluded | 配置哪些路径需要鉴权，哪些路径被排除
type PathAuthConfig struct {
	// Include paths that require authentication (include patterns) | 需要鉴权的路径（包含模式）
	Include   []string
	// Exclude paths excluded from authentication (exclude patterns) | 排除鉴权的路径（排除模式）
	Exclude   []string
	// Validator optional login ID validator function | 可选的登录ID验证函数
	Validator func(loginID string) bool
}

// NewPathAuthConfig creates a new path authentication configuration | 创建新的路径鉴权配置
func NewPathAuthConfig() *PathAuthConfig {
	return &PathAuthConfig{
		Include:   []string{},
		Exclude:   []string{},
		Validator: nil,
	}
}

// SetInclude sets paths that require authentication | 设置需要鉴权的路径
func (c *PathAuthConfig) SetInclude(patterns []string) *PathAuthConfig {
	c.Include = patterns
	return c
}

// SetExclude sets paths excluded from authentication | 设置排除鉴权的路径
func (c *PathAuthConfig) SetExclude(patterns []string) *PathAuthConfig {
	c.Exclude = patterns
	return c
}

// SetValidator sets a custom login ID validator function | 设置自定义的登录ID验证函数
func (c *PathAuthConfig) SetValidator(validator func(loginID string) bool) *PathAuthConfig {
	c.Validator = validator
	return c
}

// Check checks if a path requires authentication | 检查路径是否需要鉴权
func (c *PathAuthConfig) Check(path string) bool {
	return NeedAuth(path, c.Include, c.Exclude)
}

// ValidateLoginID validates a login ID using the configured validator | 使用配置的验证器验证登录ID
func (c *PathAuthConfig) ValidateLoginID(loginID string) bool {
	if c.Validator == nil {
		return true
	}
	return c.Validator(loginID)
}

// AuthResult authentication result after processing | 处理后的鉴权结果
type AuthResult struct {
	// NeedAuth whether authentication is required for this path | 此路径是否需要鉴权
	NeedAuth  bool
	// Token extracted token value | 提取的token值
	Token     string
	// TokenInfo token information if valid | 如果有效则包含token信息
	TokenInfo *manager.TokenInfo
	// IsValid whether the token is valid | token是否有效
	IsValid   bool
}

// ShouldReject checks if the request should be rejected | 检查请求是否应该被拒绝
func (r *AuthResult) ShouldReject() bool {
	return r.NeedAuth && (!r.IsValid || r.Token == "")
}

// LoginID gets the login ID from token info | 从token信息中获取登录ID
func (r *AuthResult) LoginID() string {
	if r.TokenInfo != nil {
		return r.TokenInfo.LoginID
	}
	return ""
}

// ProcessAuth processes authentication for a request path | 处理请求路径的鉴权
// This function checks if the path requires authentication, validates the token,
// and returns an AuthResult with all relevant information | 此函数检查路径是否需要鉴权，验证token，并返回包含所有相关信息的AuthResult
func ProcessAuth(path, tokenStr string, config *PathAuthConfig, mgr *manager.Manager) *AuthResult {
	needAuth := config.Check(path)
	
	token := tokenStr
	isValid := false
	var tokenInfo *manager.TokenInfo

	if token != "" {
		isValid = mgr.IsLogin(token)
		if isValid {
			info, err := mgr.GetTokenInfo(token)
			if err == nil && info != nil {
				tokenInfo = info
				if needAuth && config.Validator != nil {
					isValid = config.ValidateLoginID(tokenInfo.LoginID)
				}
			}
		}
	}

	return &AuthResult{
		NeedAuth:  needAuth,
		Token:     token,
		TokenInfo: tokenInfo,
		IsValid:   isValid,
	}
}

// PathAuthHandler interface for path authentication handlers | 路径鉴权处理器接口
type PathAuthHandler interface {
	GetPath() string
	GetToken() string
	GetManager() *manager.Manager
	GetPathAuthConfig() *PathAuthConfig
}

// CheckPathAuth checks path authentication using the handler interface | 使用处理器接口检查路径鉴权
// Returns true if authentication is required and should be rejected | 如果需要鉴权且应该被拒绝，返回true
func CheckPathAuth(handler PathAuthHandler) bool {
	path := handler.GetPath()
	token := handler.GetToken()
	manager := handler.GetManager()
	config := handler.GetPathAuthConfig()
	
	if config == nil {
		config = NewPathAuthConfig().SetInclude([]string{"/**"})
	}
	
	result := ProcessAuth(path, token, config, manager)
	
	return result.ShouldReject()
}

