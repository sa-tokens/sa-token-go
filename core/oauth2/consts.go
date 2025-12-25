// @Author daixk 2025/12/5 9:42:00
package oauth2

import (
	"time"
)

// Constants for OAuth2 | OAuth2常量
const (
	DefaultCodeExpiration  = 10 * time.Minute    // Authorization code expiration | 授权码过期时间
	DefaultTokenExpiration = 2 * time.Hour       // Access token expiration | 访问令牌过期时间
	DefaultRefreshTTL      = 30 * 24 * time.Hour // Refresh token expiration | 刷新令牌过期时间

	CodeLength         = 32 // Authorization code byte length | 授权码字节长度
	AccessTokenLength  = 32 // Access token byte length | 访问令牌字节长度
	RefreshTokenLength = 32 // Refresh token byte length | 刷新令牌字节长度

	CodeKeySuffix    = "oauth2:code:"    // Code key suffix after prefix | 授权码键后缀
	TokenKeySuffix   = "oauth2:token:"   // Token key suffix after prefix | 令牌键后缀
	RefreshKeySuffix = "oauth2:refresh:" // Refresh key suffix after prefix | 刷新令牌键后缀

	TokenTypeBearer = "Bearer" // Token type | 令牌类型
)

// GrantType OAuth2 grant type | OAuth2授权类型
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code" // Authorization code flow | 授权码模式
	GrantTypeRefreshToken      GrantType = "refresh_token"      // Refresh token flow | 刷新令牌模式
	GrantTypeClientCredentials GrantType = "client_credentials" // Client credentials flow | 客户端凭证模式
	GrantTypePassword          GrantType = "password"           // Password flow | 密码模式
)
