package core

import (
	"time"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/context"
	"github.com/click33/sa-token-go/core/listener"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
	"github.com/click33/sa-token-go/core/utils"
)

// Version Sa-Token-Go version | Sa-Token-Go版本
const Version = "0.1.3"

// ============ Exported Types | 导出的类型 ============
// Export main types and functions for external use | 导出主要类型和函数，方便外部使用

// Configuration related types | 配置相关类型
type (
	Config          = config.Config
	CookieConfig    = config.CookieConfig
	LoggerConfig    = config.LoggerConfig
	RenewPoolConfig = config.RenewPoolConfig

	TokenStyle   = config.TokenStyle
	SameSiteMode = config.SameSiteMode
	LogLevel     = config.LogLevel
)

// Token style constants | Token风格常量
const (
	TokenStyleUUID      = config.TokenStyleUUID
	TokenStyleSimple    = config.TokenStyleSimple
	TokenStyleRandom32  = config.TokenStyleRandom32
	TokenStyleRandom64  = config.TokenStyleRandom64
	TokenStyleRandom128 = config.TokenStyleRandom128
	TokenStyleJWT       = config.TokenStyleJWT
	TokenStyleHash      = config.TokenStyleHash
	TokenStyleTimestamp = config.TokenStyleTimestamp
	TokenStyleTik       = config.TokenStyleTik
)

// Adapter interfaces | 适配器接口
type (
	Codec          = adapter.Codec
	Generator      = adapter.Generator
	Log            = adapter.Log
	Pool           = adapter.Pool
	Storage        = adapter.Storage
	RequestContext = adapter.RequestContext
)

// Core types | 核心类型
type (
	Builder = builder.Builder

	Manager   = manager.Manager
	TokenInfo = manager.TokenInfo

	Session = session.Session

	SaTokenContext = context.SaTokenContext

	NonceManager = security.NonceManager

	AccessTokenInfo     = security.AccessTokenInfo
	RefreshTokenInfo    = security.RefreshTokenInfo
	RefreshTokenManager = security.RefreshTokenManager

	OAuth2Client      = oauth2.Client
	OAuth2Server      = oauth2.OAuth2Server
	OAuth2AccessToken = oauth2.AccessToken
	OAuth2GrantType   = oauth2.GrantType
)

// Event related types | 事件相关类型
type (
	EventListener  = listener.Listener
	EventManager   = listener.Manager
	EventData      = listener.EventData
	Event          = listener.Event
	ListenerFunc   = listener.ListenerFunc
	ListenerConfig = listener.ListenerConfig
)

// Event constants | 事件常量
const (
	EventLogin           = listener.EventLogin
	EventLogout          = listener.EventLogout
	EventKickout         = listener.EventKickout
	EventDisable         = listener.EventDisable
	EventUntie           = listener.EventUntie
	EventRenew           = listener.EventRenew
	EventCreateSession   = listener.EventCreateSession
	EventDestroySession  = listener.EventDestroySession
	EventPermissionCheck = listener.EventPermissionCheck
	EventRoleCheck       = listener.EventRoleCheck
	EventAll             = listener.EventAll
)

const (
	GrantTypeAuthorizationCode = oauth2.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = oauth2.GrantTypeRefreshToken
	GrantTypeClientCredentials = oauth2.GrantTypeClientCredentials
	GrantTypePassword          = oauth2.GrantTypePassword
)

// ============ Utility Functions | 工具函数 ============

var (
	// String utilities | 字符串工具
	RandomString        = utils.RandomString
	RandomNumericString = utils.RandomNumericString
	RandomAlphanumeric  = utils.RandomAlphanumeric
	IsEmpty             = utils.IsEmpty
	IsNotEmpty          = utils.IsNotEmpty
	DefaultString       = utils.DefaultString

	// Slice utilities | 切片工具
	ContainsString = utils.ContainsString
	RemoveString   = utils.RemoveString
	UniqueStrings  = utils.UniqueStrings
	MergeStrings   = utils.MergeStrings
	FilterStrings  = utils.FilterStrings
	MapStrings     = utils.MapStrings

	// Pattern matching | 模式匹配
	MatchPattern = utils.MatchPattern

	// Duration utilities | 时长工具
	FormatDuration = utils.FormatDuration
	ParseDuration  = utils.ParseDuration

	// Hash & Encoding | 哈希和编码
	SHA256Hash   = utils.SHA256Hash
	Base64Encode = utils.Base64Encode
	Base64Decode = utils.Base64Decode
)

// ============ Factory Functions | 工厂函数 ============

// DefaultConfig Returns log configuration | 返回默认配置
func DefaultConfig() *Config {
	return config.DefaultConfig()
}

func DefaultLoggerConfig() *LoggerConfig {
	return config.DefaultLoggerConfig()
}

// NewManager Creates a new authentication manager | 创建新的认证管理器
func NewManager(cfg *Config, generator adapter.Generator, storage adapter.Storage, serializer adapter.Codec, logger adapter.Log, pool adapter.Pool) *Manager {
	return manager.NewManager(cfg, generator, storage, serializer, logger, pool)
}

// NewContext Creates a new Sa-Token context | 创建新的Sa-Token上下文
func NewContext(ctx RequestContext, mgr *Manager) *SaTokenContext {
	return context.NewContext(ctx, mgr)
}

// NewSession Creates a new session | 创建新的Session
func NewSession(id string, storage Storage, prefix string) *Session {
	return session.NewSession(id, storage, prefix)
}

// LoadSession Loads an existing session | 加载已存在的Session
func LoadSession(id string, storage Storage, prefix string) (*Session, error) {
	return session.Load(id, storage, prefix)
}

// NewTokenGenerator Creates a new token generator | 创建新的Token生成器
func NewTokenGenerator(cfg *Config) *TokenGenerator {
	return token.NewGenerator(cfg)
}

// NewEventManager Creates a new event manager | 创建新的事件管理器
func NewEventManager() *EventManager {
	return listener.NewManager()
}

// NewBuilder Creates a new builder for fluent configuration | 创建新的Builder构建器（用于流式配置）
func NewBuilder() *Builder {
	return builder.NewBuilder()
}

// NewNonceManager Creates a new nonce manager | 创建新的Nonce管理器
func NewNonceManager(storage Storage, prefix string, ttl ...int64) *NonceManager {
	var duration time.Duration
	if len(ttl) > 0 && ttl[0] > 0 {
		duration = time.Duration(ttl[0]) * time.Second
	}
	return security.NewNonceManager(storage, prefix, duration)
}

// NewRefreshTokenManager Creates a new refresh token manager | 创建新的刷新令牌管理器
func NewRefreshTokenManager(storage Storage, prefix string, cfg *Config) *RefreshTokenManager {
	return security.NewRefreshTokenManager(storage, prefix, manager.TokenKeyPrefix, cfg)
}

// NewOAuth2Server Creates a new OAuth2 server | 创建新的OAuth2服务器
func NewOAuth2Server(storage Storage, prefix string) *OAuth2Server {
	return oauth2.NewOAuth2Server(storage, prefix)
}
