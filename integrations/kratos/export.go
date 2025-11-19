package kratos

import (
	"time"

	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/stputil"
)

// ============ Re-export core types | 重新导出核心类型 ============

// Configuration related types | 配置相关类型
type (
	Config       = core.Config
	CookieConfig = core.CookieConfig
	TokenStyle   = core.TokenStyle
)

// Token style constants | Token风格常量
const (
	TokenStyleUUID      = core.TokenStyleUUID
	TokenStyleSimple    = core.TokenStyleSimple
	TokenStyleRandom32  = core.TokenStyleRandom32
	TokenStyleRandom64  = core.TokenStyleRandom64
	TokenStyleRandom128 = core.TokenStyleRandom128
	TokenStyleJWT       = core.TokenStyleJWT
	TokenStyleHash      = core.TokenStyleHash
	TokenStyleTimestamp = core.TokenStyleTimestamp
	TokenStyleTik       = core.TokenStyleTik
)

// Core types | 核心类型
type (
	Manager             = core.Manager
	TokenInfo           = core.TokenInfo
	Session             = core.Session
	TokenGenerator      = core.TokenGenerator
	SaTokenContext      = core.SaTokenContext
	Builder             = core.Builder
	NonceManager        = core.NonceManager
	RefreshTokenInfo    = core.RefreshTokenInfo
	RefreshTokenManager = core.RefreshTokenManager
	OAuth2Server        = core.OAuth2Server
	OAuth2Client        = core.OAuth2Client
	OAuth2AccessToken   = core.OAuth2AccessToken
	OAuth2GrantType     = core.OAuth2GrantType
)

// Adapter interfaces | 适配器接口
type (
	Storage        = core.Storage
	RequestContext = core.RequestContext
)

// Event related types | 事件相关类型
type (
	EventListener  = core.EventListener
	EventManager   = core.EventManager
	EventData      = core.EventData
	Event          = core.Event
	ListenerFunc   = core.ListenerFunc
	ListenerConfig = core.ListenerConfig
)

// Event constants | 事件常量
const (
	EventLogin           = core.EventLogin
	EventLogout          = core.EventLogout
	EventKickout         = core.EventKickout
	EventDisable         = core.EventDisable
	EventUntie           = core.EventUntie
	EventRenew           = core.EventRenew
	EventCreateSession   = core.EventCreateSession
	EventDestroySession  = core.EventDestroySession
	EventPermissionCheck = core.EventPermissionCheck
	EventRoleCheck       = core.EventRoleCheck
	EventAll             = core.EventAll
)

// OAuth2 grant type constants | OAuth2授权类型常量
const (
	GrantTypeAuthorizationCode = core.GrantTypeAuthorizationCode
	GrantTypeRefreshToken      = core.GrantTypeRefreshToken
	GrantTypeClientCredentials = core.GrantTypeClientCredentials
	GrantTypePassword          = core.GrantTypePassword
)

// Utility functions | 工具函数
var (
	RandomString   = core.RandomString
	IsEmpty        = core.IsEmpty
	IsNotEmpty     = core.IsNotEmpty
	DefaultString  = core.DefaultString
	ContainsString = core.ContainsString
	RemoveString   = core.RemoveString
	UniqueStrings  = core.UniqueStrings
	MergeStrings   = core.MergeStrings
	MatchPattern   = core.MatchPattern
)

// ============ Core constructor functions | 核心构造函数 ============

// DefaultConfig returns default configuration | 返回默认配置
func DefaultConfig() *Config {
	return core.DefaultConfig()
}

// NewManager creates a new authentication manager | 创建新的认证管理器
func NewManager(storage Storage, cfg *Config) *Manager {
	return core.NewManager(storage, cfg)
}

// NewContext creates a new Sa-Token context | 创建新的Sa-Token上下文
func NewContext(ctx RequestContext, mgr *Manager) *SaTokenContext {
	return core.NewContext(ctx, mgr)
}

// NewSession creates a new session | 创建新的Session
func NewSession(id string, storage Storage, prefix string) *Session {
	return core.NewSession(id, storage, prefix)
}

// LoadSession loads an existing session | 加载已存在的Session
func LoadSession(id string, storage Storage, prefix string) (*Session, error) {
	return core.LoadSession(id, storage, prefix)
}

// NewTokenGenerator creates a new token generator | 创建新的Token生成器
func NewTokenGenerator(cfg *Config) *TokenGenerator {
	return core.NewTokenGenerator(cfg)
}

// NewEventManager creates a new event manager | 创建新的事件管理器
func NewEventManager() *EventManager {
	return core.NewEventManager()
}

// NewBuilder creates a new builder for fluent configuration | 创建新的Builder构建器（用于流式配置）
func NewBuilder() *Builder {
	return core.NewBuilder()
}

// NewNonceManager creates a new nonce manager | 创建新的Nonce管理器
func NewNonceManager(storage Storage, prefix string, ttl ...int64) *NonceManager {
	return core.NewNonceManager(storage, prefix, ttl...)
}

// NewRefreshTokenManager creates a new refresh token manager | 创建新的刷新令牌管理器
func NewRefreshTokenManager(storage Storage, prefix string, cfg *Config) *RefreshTokenManager {
	return core.NewRefreshTokenManager(storage, prefix, cfg)
}

// NewOAuth2Server creates a new OAuth2 server | 创建新的OAuth2服务器
func NewOAuth2Server(storage Storage, prefix string) *OAuth2Server {
	return core.NewOAuth2Server(storage, prefix)
}

// ============ Global StpUtil functions | 全局StpUtil函数 ============

// SetManager sets the global Manager (must be called first) | 设置全局Manager（必须先调用此方法）
func SetManager(mgr *Manager) {
	stputil.SetManager(mgr)
}

// GetManager gets the global Manager | 获取全局Manager
func GetManager() *Manager {
	return stputil.GetManager()
}

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func Login(loginID interface{}, device ...string) (string, error) {
	return stputil.Login(loginID, device...)
}

// LoginByToken performs login with specified token | 使用指定Token登录
func LoginByToken(loginID interface{}, tokenValue string, device ...string) error {
	return stputil.LoginByToken(loginID, tokenValue, device...)
}

// Logout performs user logout | 用户登出
func Logout(loginID interface{}, device ...string) error {
	return stputil.Logout(loginID, device...)
}

// LogoutByToken performs logout by token | 根据Token登出
func LogoutByToken(tokenValue string) error {
	return stputil.LogoutByToken(tokenValue)
}

// IsLogin checks if the user is logged in | 检查用户是否已登录
func IsLogin(tokenValue string) bool {
	return stputil.IsLogin(tokenValue)
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func CheckLogin(tokenValue string) error {
	return stputil.CheckLogin(tokenValue)
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func GetLoginID(tokenValue string) (string, error) {
	return stputil.GetLoginID(tokenValue)
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查）
func GetLoginIDNotCheck(tokenValue string) (string, error) {
	return stputil.GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func GetTokenValue(loginID interface{}, device ...string) (string, error) {
	return stputil.GetTokenValue(loginID, device...)
}

// GetTokenInfo gets token information | 获取Token信息
func GetTokenInfo(tokenValue string) (*TokenInfo, error) {
	return stputil.GetTokenInfo(tokenValue)
}

// ============ Kickout | 踢人下线 ============

// Kickout kicks out a user session | 踢人下线
func Kickout(loginID interface{}, device ...string) error {
	return stputil.Kickout(loginID, device...)
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func Disable(loginID interface{}, duration time.Duration) error {
	return stputil.Disable(loginID, duration)
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func IsDisable(loginID interface{}) bool {
	return stputil.IsDisable(loginID)
}

// CheckDisable checks if account is disabled (throws error if disabled) | 检查账号是否被封禁（被封禁则抛出错误）
func CheckDisableByToken(tokenValue string) error {
	return stputil.CheckDisable(tokenValue)
}

// GetDisableTime gets remaining disabled time | 获取账号剩余封禁时间
func GetDisableTime(loginID interface{}) (int64, error) {
	return stputil.GetDisableTime(loginID)
}

// Untie unties/unlocks an account | 解除账号封禁
func Untie(loginID interface{}) error {
	return stputil.Untie(loginID)
}

// ============ Permission Check | 权限验证 ============

// CheckPermission checks if the account has specified permission | 检查账号是否拥有指定权限
func CheckPermissionByToken(tokenValue string, permission string) error {
	return stputil.CheckPermission(tokenValue, permission)
}

// HasPermission checks if the account has specified permission (returns bool) | 检查账号是否拥有指定权限（返回布尔值）
func HasPermission(loginID interface{}, permission string) bool {
	return stputil.HasPermission(loginID, permission)
}

// CheckPermissionAnd checks if the account has all specified permissions (AND logic) | 检查账号是否拥有所有指定权限（AND逻辑）
func CheckPermissionAndByToken(tokenValue string, permissions []string) error {
	return stputil.CheckPermissionAnd(tokenValue, permissions)
}

// CheckPermissionOr checks if the account has any of the specified permissions (OR logic) | 检查账号是否拥有指定权限中的任意一个（OR逻辑）
func CheckPermissionOrByToken(tokenValue string, permissions []string) error {
	return stputil.CheckPermissionOr(tokenValue, permissions)
}

// GetPermissionList gets the permission list for an account | 获取账号的权限列表
func GetPermissionListByToken(tokenValue string) ([]string, error) {
	return stputil.GetPermissionList(tokenValue)
}

// ============ Role Check | 角色验证 ============

// CheckRole checks if the account has specified role | 检查账号是否拥有指定角色
func CheckRoleByToken(tokenValue string, role string) error {
	return stputil.CheckRole(tokenValue, role)
}

// HasRole checks if the account has specified role (returns bool) | 检查账号是否拥有指定角色（返回布尔值）
func HasRole(loginID interface{}, role string) bool {
	return stputil.HasRole(loginID, role)
}

// CheckRoleAnd checks if the account has all specified roles (AND logic) | 检查账号是否拥有所有指定角色（AND逻辑）
func CheckRoleAndByToken(tokenValue string, roles []string) error {
	return stputil.CheckRoleAnd(tokenValue, roles)
}

// CheckRoleOr checks if the account has any of the specified roles (OR logic) | 检查账号是否拥有指定角色中的任意一个（OR逻辑）
func CheckRoleOrByToken(tokenValue string, roles []string) error {
	return stputil.CheckRoleOr(tokenValue, roles)
}

// GetRoleList gets the role list for an account | 获取账号的角色列表
func GetRoleListByToken(tokenValue string) ([]string, error) {
	return stputil.GetRoleList(tokenValue)
}

// ============ Session Management | Session管理 ============

// GetSession gets the session for a login ID | 获取登录ID的Session
func GetSession(loginID interface{}) (*Session, error) {
	return stputil.GetSession(loginID)
}

// GetSessionByToken gets the session by token | 根据Token获取Session
func GetSessionByToken(tokenValue string) (*Session, error) {
	return stputil.GetSessionByToken(tokenValue)
}

// GetTokenSession gets the token session | 获取Token的Session
func GetTokenSession(tokenValue string) (*Session, error) {
	return stputil.GetTokenSession(tokenValue)
}

// ============ Token Renewal | Token续期 ============

// RenewTimeout renews token timeout | 续期Token超时时间

// ============ Security Features | 安全特性 ============

// GenerateNonce generates a new nonce token | 生成新的Nonce令牌
func GenerateNonce() (string, error) {
	return stputil.GenerateNonce()
}

// VerifyNonce verifies a nonce token | 验证Nonce令牌
func VerifyNonce(nonce string) bool {
	return stputil.VerifyNonce(nonce)
}

// LoginWithRefreshToken performs login and returns both access token and refresh token | 登录并返回访问令牌和刷新令牌
func LoginWithRefreshToken(loginID interface{}, device ...string) (*RefreshTokenInfo, error) {
	return stputil.LoginWithRefreshToken(loginID, device...)
}

// RefreshAccessToken refreshes the access token using a refresh token | 使用刷新令牌刷新访问令牌
func RefreshAccessToken(refreshToken string) (*RefreshTokenInfo, error) {
	return stputil.RefreshAccessToken(refreshToken)
}

// RevokeRefreshToken revokes a refresh token | 撤销刷新令牌
func RevokeRefreshToken(refreshToken string) error {
	return stputil.RevokeRefreshToken(refreshToken)
}

// GetOAuth2Server gets the OAuth2 server instance | 获取OAuth2服务器实例
func GetOAuth2Server() *OAuth2Server {
	return stputil.GetOAuth2Server()
}

// Version Sa-Token-Go version | Sa-Token-Go版本
const Version = core.Version
