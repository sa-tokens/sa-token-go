package gin

import (
	"context"
	"time"

	"github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/codec/msgpack"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/listener"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
	"github.com/click33/sa-token-go/generator/sgenerator"
	"github.com/click33/sa-token-go/log/nop"
	"github.com/click33/sa-token-go/log/slog"
	"github.com/click33/sa-token-go/pool/ants"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/storage/redis"
	"github.com/click33/sa-token-go/stputil"
)

// ============ Type Aliases | 类型别名 ============

type (
	// Config 配置
	Config = config.Config
	// Manager 管理器
	Manager = manager.Manager
	// Session 会话
	Session = session.Session
	// TokenInfo Token信息
	TokenInfo = manager.TokenInfo
	// DisableInfo 封禁信息
	DisableInfo = manager.DisableInfo
	// Builder 构建器
	Builder = builder.Builder
	// SaTokenError 错误类型
	SaTokenError = core.SaTokenError
	// Event 事件类型
	Event = listener.Event
	// EventData 事件数据
	EventData = listener.EventData
	// Listener 事件监听器
	Listener = listener.Listener
	// ListenerConfig 监听器配置
	ListenerConfig = listener.ListenerConfig
	// RefreshTokenInfo 刷新令牌信息
	RefreshTokenInfo = security.RefreshTokenInfo
	// AccessTokenInfo 访问令牌信息
	AccessTokenInfo = security.AccessTokenInfo
	// OAuth2Client OAuth2客户端
	OAuth2Client = oauth2.Client
	// OAuth2AccessToken OAuth2访问令牌
	OAuth2AccessToken = oauth2.AccessToken
	// AuthorizationCode 授权码
	AuthorizationCode = oauth2.AuthorizationCode
	// OAuth2TokenRequest OAuth2令牌请求
	OAuth2TokenRequest = oauth2.TokenRequest
	// OAuth2GrantType OAuth2授权类型
	OAuth2GrantType = oauth2.GrantType
	// OAuth2UserValidator OAuth2用户验证器
	OAuth2UserValidator = oauth2.UserValidator
	// Storage 存储接口
	Storage = adapter.Storage
	// Codec 编解码接口
	Codec = adapter.Codec
	// Log 日志接口
	Log = adapter.Log
	// Pool 协程池接口
	Pool = adapter.Pool
	// Generator 生成器接口
	Generator = adapter.Generator

	// ============ Codec Types | 编解码器类型 ============

	// JSONSerializer JSON编解码器
	JSONSerializer = json.JSONSerializer
	// MsgPackSerializer MsgPack编解码器
	MsgPackSerializer = msgpack.MsgPackSerializer

	// ============ Storage Types | 存储类型 ============

	// MemoryStorage 内存存储
	MemoryStorage = memory.Storage
	// RedisStorage Redis存储
	RedisStorage = redis.Storage
	// RedisConfig Redis配置
	RedisConfig = redis.Config
	// RedisBuilder Redis构建器
	RedisBuilder = redis.Builder

	// ============ Logger Types | 日志类型 ============

	// SlogLogger 标准日志实现
	SlogLogger = slog.Logger
	// SlogLoggerConfig 标准日志配置
	SlogLoggerConfig = slog.LoggerConfig
	// SlogLogLevel 日志级别
	SlogLogLevel = slog.LogLevel
	// NopLogger 空日志实现
	NopLogger = nop.NopLogger

	// ============ Generator Types | 生成器类型 ============

	// TokenGenerator Token生成器
	TokenGenerator = sgenerator.Generator
	// TokenStyle Token风格
	TokenStyle = adapter.TokenStyle

	// ============ Pool Types | 协程池类型 ============

	// RenewPoolManager 续期池管理器
	RenewPoolManager = ants.RenewPoolManager
	// RenewPoolConfig 续期池配置
	RenewPoolConfig = ants.RenewPoolConfig
)

// ============ Error Codes | 错误码 ============

const (
	CodeSuccess          = core.CodeSuccess
	CodeBadRequest       = core.CodeBadRequest
	CodeNotLogin         = core.CodeNotLogin
	CodePermissionDenied = core.CodePermissionDenied
	CodeNotFound         = core.CodeNotFound
	CodeServerError      = core.CodeServerError
	CodeTokenInvalid     = core.CodeTokenInvalid
	CodeTokenExpired     = core.CodeTokenExpired
	CodeAccountDisabled  = core.CodeAccountDisabled
	CodeKickedOut        = core.CodeKickedOut
	CodeActiveTimeout    = core.CodeActiveTimeout
	CodeMaxLoginCount    = core.CodeMaxLoginCount
	CodeStorageError     = core.CodeStorageError
	CodeInvalidParameter = core.CodeInvalidParameter
	CodeSessionError     = core.CodeSessionError
)

// ============ Errors | 错误变量 ============

var (
	// Authentication Errors | 认证错误
	ErrNotLogin       = core.ErrNotLogin
	ErrTokenInvalid   = core.ErrTokenInvalid
	ErrTokenExpired   = core.ErrTokenExpired
	ErrTokenKickout   = core.ErrTokenKickout
	ErrTokenReplaced  = core.ErrTokenReplaced
	ErrInvalidLoginID = core.ErrInvalidLoginID
	ErrInvalidDevice  = core.ErrInvalidDevice
	ErrTokenNotFound  = core.ErrTokenNotFound

	// Authorization Errors | 授权错误
	ErrPermissionDenied = core.ErrPermissionDenied
	ErrRoleDenied       = core.ErrRoleDenied

	// Account Errors | 账号错误
	ErrAccountDisabled    = core.ErrAccountDisabled
	ErrAccountNotFound    = core.ErrAccountNotFound
	ErrLoginLimitExceeded = core.ErrLoginLimitExceeded

	// Session Errors | 会话错误
	ErrSessionNotFound       = core.ErrSessionNotFound
	ErrActiveTimeout         = core.ErrActiveTimeout
	ErrSessionInvalidDataKey = core.ErrSessionInvalidDataKey
	ErrSessionIDEmpty        = core.ErrSessionIDEmpty

	// Security Errors | 安全错误
	ErrInvalidNonce             = core.ErrInvalidNonce
	ErrRefreshTokenExpired      = core.ErrRefreshTokenExpired
	ErrNonceInvalidRefreshToken = core.ErrNonceInvalidRefreshToken
	ErrInvalidLoginIDEmpty      = core.ErrInvalidLoginIDEmpty

	// OAuth2 Errors | OAuth2错误
	ErrClientOrClientIDEmpty    = core.ErrClientOrClientIDEmpty
	ErrClientNotFound           = core.ErrClientNotFound
	ErrUserIDEmpty              = core.ErrUserIDEmpty
	ErrInvalidRedirectURI       = core.ErrInvalidRedirectURI
	ErrInvalidClientCredentials = core.ErrInvalidClientCredentials
	ErrInvalidAuthCode          = core.ErrInvalidAuthCode
	ErrAuthCodeUsed             = core.ErrAuthCodeUsed
	ErrAuthCodeExpired          = core.ErrAuthCodeExpired
	ErrClientMismatch           = core.ErrClientMismatch
	ErrRedirectURIMismatch      = core.ErrRedirectURIMismatch
	ErrInvalidAccessToken       = core.ErrInvalidAccessToken
	ErrInvalidRefreshToken      = core.ErrInvalidRefreshToken
	ErrInvalidScope             = core.ErrInvalidScope

	// System Errors | 系统错误
	ErrStorageUnavailable = core.ErrStorageUnavailable
	ErrSerializeFailed    = core.ErrSerializeFailed
	ErrDeserializeFailed  = core.ErrDeserializeFailed
	ErrTypeConvert        = core.ErrTypeConvert
)

// ============ Error Constructors | 错误构造函数 ============

var (
	NewError                 = core.NewError
	NewErrorWithContext      = core.NewErrorWithContext
	NewNotLoginError         = core.NewNotLoginError
	NewPermissionDeniedError = core.NewPermissionDeniedError
	NewRoleDeniedError       = core.NewRoleDeniedError
	NewAccountDisabledError  = core.NewAccountDisabledError
)

// ============ Error Checking Helpers | 错误检查辅助函数 ============

var (
	IsNotLoginError         = core.IsNotLoginError
	IsPermissionDeniedError = core.IsPermissionDeniedError
	IsAccountDisabledError  = core.IsAccountDisabledError
	IsTokenError            = core.IsTokenError
	GetErrorCode            = core.GetErrorCode
)

// ============ Manager Management | Manager 管理 ============

// SetManager stores the manager-example in the global map using the specified autoType | 使用指定的 autoType 将管理器存储在全局 map 中
func SetManager(mgr *manager.Manager) {
	stputil.SetManager(mgr)
}

// GetManager retrieves the manager-example from the global map using the specified autoType | 使用指定的 autoType 从全局 map 中获取管理器
func GetManager(autoType ...string) (*manager.Manager, error) {
	return stputil.GetManager(autoType...)
}

// DeleteManager delete the specific manager-example for the given autoType and releases resources | 删除指定的管理器并释放资源
func DeleteManager(autoType ...string) error {
	return stputil.DeleteManager(autoType...)
}

// DeleteAllManager delete all managers in the global map and releases resources | 关闭所有管理器并释放资源
func DeleteAllManager() {
	stputil.DeleteAllManager()
}

// ============ Builder & Config | 构建器和配置 ============

// NewDefaultBuild creates a new default builder | 创建默认构建器
func NewDefaultBuild() *builder.Builder {
	return builder.NewBuilder()
}

// NewDefaultConfig creates a new default config | 创建默认配置
func NewDefaultConfig() *config.Config {
	return config.DefaultConfig()
}

// DefaultLoggerConfig returns the default logger config | 返回默认日志配置
func DefaultLoggerConfig() *slog.LoggerConfig {
	return slog.DefaultLoggerConfig()
}

// DefaultRenewPoolConfig returns the default renew pool config | 返回默认续期池配置
func DefaultRenewPoolConfig() *ants.RenewPoolConfig {
	return ants.DefaultRenewPoolConfig()
}

// ============ Codec Constructors | 编解码器构造函数 ============

// NewJSONSerializer creates a new JSON serializer | 创建JSON序列化器
func NewJSONSerializer() *json.JSONSerializer {
	return json.NewJSONSerializer()
}

// NewMsgPackSerializer creates a new MsgPack serializer | 创建MsgPack序列化器
func NewMsgPackSerializer() *msgpack.MsgPackSerializer {
	return msgpack.NewMsgPackSerializer()
}

// ============ Storage Constructors | 存储构造函数 ============

// NewMemoryStorage creates a new memory storage | 创建内存存储
func NewMemoryStorage() *memory.Storage {
	return memory.NewStorage()
}

// NewMemoryStorageWithCleanupInterval creates a new memory storage with cleanup interval | 创建带清理间隔的内存存储
func NewMemoryStorageWithCleanupInterval(interval time.Duration) *memory.Storage {
	return memory.NewStorageWithCleanupInterval(interval)
}

// NewRedisStorage creates a new Redis storage from URL | 通过URL创建Redis存储
func NewRedisStorage(url string) (*redis.Storage, error) {
	return redis.NewStorage(url)
}

// NewRedisStorageFromConfig creates a new Redis storage from config | 通过配置创建Redis存储
func NewRedisStorageFromConfig(cfg *redis.Config) (*redis.Storage, error) {
	return redis.NewStorageFromConfig(cfg)
}

// NewRedisBuilder creates a new Redis builder | 创建Redis构建器
func NewRedisBuilder() *redis.Builder {
	return redis.NewBuilder()
}

// ============ Logger Constructors | 日志构造函数 ============

// NewSlogLogger creates a new slog logger with config | 使用配置创建标准日志器
func NewSlogLogger(cfg *slog.LoggerConfig) (*slog.Logger, error) {
	return slog.NewLoggerWithConfig(cfg)
}

// NewNopLogger creates a new no-op logger | 创建空日志器
func NewNopLogger() *nop.NopLogger {
	return nop.NewNopLogger()
}

// ============ Generator Constructors | 生成器构造函数 ============

// NewTokenGenerator creates a new token generator | 创建Token生成器
func NewTokenGenerator(timeout int64, tokenStyle adapter.TokenStyle, jwtSecretKey string) *sgenerator.Generator {
	return sgenerator.NewGenerator(timeout, tokenStyle, jwtSecretKey)
}

// NewDefaultTokenGenerator creates a new default token generator | 创建默认Token生成器
func NewDefaultTokenGenerator() *sgenerator.Generator {
	return sgenerator.NewDefaultGenerator()
}

// ============ Pool Constructors | 协程池构造函数 ============

// NewRenewPoolManager creates a new renew pool manager-example with default config | 使用默认配置创建续期池管理器
func NewRenewPoolManager() *ants.RenewPoolManager {
	return ants.NewRenewPoolManagerWithDefaultConfig()
}

// NewRenewPoolManagerWithConfig creates a new renew pool manager-example with config | 使用配置创建续期池管理器
func NewRenewPoolManagerWithConfig(cfg *ants.RenewPoolConfig) (*ants.RenewPoolManager, error) {
	return ants.NewRenewPoolManagerWithConfig(cfg)
}

// ============ Token Style Constants | Token风格常量 ============

const (
	// TokenStyleUUID UUID style | UUID风格
	TokenStyleUUID = adapter.TokenStyleUUID
	// TokenStyleSimple Simple random string | 简单随机字符串
	TokenStyleSimple = adapter.TokenStyleSimple
	// TokenStyleRandom32 32-bit random string | 32位随机字符串
	TokenStyleRandom32 = adapter.TokenStyleRandom32
	// TokenStyleRandom64 64-bit random string | 64位随机字符串
	TokenStyleRandom64 = adapter.TokenStyleRandom64
	// TokenStyleRandom128 128-bit random string | 128位随机字符串
	TokenStyleRandom128 = adapter.TokenStyleRandom128
	// TokenStyleJWT JWT style | JWT风格
	TokenStyleJWT = adapter.TokenStyleJWT
	// TokenStyleHash SHA256 hash-based style | SHA256哈希风格
	TokenStyleHash = adapter.TokenStyleHash
	// TokenStyleTimestamp Timestamp-based style | 时间戳风格
	TokenStyleTimestamp = adapter.TokenStyleTimestamp
	// TokenStyleTik Short ID style (like TikTok) | Tik风格短ID
	TokenStyleTik = adapter.TokenStyleTik
)

// ============ Log Level Constants | 日志级别常量 ============

const (
	// LogLevelDebug Debug level | 调试级别
	LogLevelDebug = adapter.LogLevelDebug
	// LogLevelInfo Info level | 信息级别
	LogLevelInfo = adapter.LogLevelInfo
	// LogLevelWarn Warn level | 警告级别
	LogLevelWarn = adapter.LogLevelWarn
	// LogLevelError Error level | 错误级别
	LogLevelError = adapter.LogLevelError
)

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func Login(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (string, error) {
	return stputil.Login(ctx, loginID, deviceOrAutoType...)
}

// LoginByToken performs login with specified token | 使用指定Token登录
func LoginByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.LoginByToken(ctx, tokenValue, authType...)
}

// Logout performs user logout | 用户登出
func Logout(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	return stputil.Logout(ctx, loginID, deviceOrAutoType...)
}

// LogoutByToken performs logout by token | 根据Token登出
func LogoutByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.LogoutByToken(ctx, tokenValue, authType...)
}

// Kickout kicks out a user session | 踢人下线
func Kickout(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	return stputil.Kickout(ctx, loginID, deviceOrAutoType...)
}

// KickoutByToken Kick user offline | 根据Token踢人下线
func KickoutByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.KickoutByToken(ctx, tokenValue, authType...)
}

// Replace user offline by login ID and device | 根据账号和设备顶人下线
func Replace(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	return stputil.Replace(ctx, loginID, deviceOrAutoType...)
}

// ReplaceByToken Replace user offline by token | 根据Token顶人下线
func ReplaceByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.ReplaceByToken(ctx, tokenValue, authType...)
}

// ============ Token Validation | Token验证 ============

// IsLogin checks if the user is logged in | 检查用户是否已登录
func IsLogin(ctx context.Context, tokenValue string, authType ...string) bool {
	return stputil.IsLogin(ctx, tokenValue, authType...)
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func CheckLogin(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.CheckLogin(ctx, tokenValue, authType...)
}

// CheckLoginWithState checks the login status (returns error to determine the reason if not logged in) | 检查登录状态（未登录时根据错误确定原因）
func CheckLoginWithState(ctx context.Context, tokenValue string, authType ...string) (bool, error) {
	return stputil.CheckLoginWithState(ctx, tokenValue, authType...)
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func GetLoginID(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	return stputil.GetLoginID(ctx, tokenValue, authType...)
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查登录状态）
func GetLoginIDNotCheck(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	return stputil.GetLoginIDNotCheck(ctx, tokenValue, authType...)
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func GetTokenValue(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (string, error) {
	return stputil.GetTokenValue(ctx, loginID, deviceOrAutoType...)
}

// GetTokenInfo gets token information | 获取Token信息
func GetTokenInfo(ctx context.Context, tokenValue string, authType ...string) (*manager.TokenInfo, error) {
	return stputil.GetTokenInfo(ctx, tokenValue, authType...)
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func Disable(ctx context.Context, loginID interface{}, duration time.Duration, authType ...string) error {
	return stputil.Disable(ctx, loginID, duration, authType...)
}

// DisableByToken disables the account associated with the given token for a duration | 根据指定 Token 封禁其对应的账号
func DisableByToken(ctx context.Context, tokenValue string, duration time.Duration, authType ...string) error {
	return stputil.DisableByToken(ctx, tokenValue, duration, authType...)
}

// Untie re-enables a disabled account | 解封账号
func Untie(ctx context.Context, loginID interface{}, authType ...string) error {
	return stputil.Untie(ctx, loginID, authType...)
}

// UntieByToken re-enables a disabled account by token | 根据Token解封账号
func UntieByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.UntieByToken(ctx, tokenValue, authType...)
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func IsDisable(ctx context.Context, loginID interface{}, authType ...string) bool {
	return stputil.IsDisable(ctx, loginID, authType...)
}

// IsDisableByToken checks if an account is disabled by token | 根据Token检查账号是否被封禁
func IsDisableByToken(ctx context.Context, tokenValue string, authType ...string) bool {
	return stputil.IsDisableByToken(ctx, tokenValue, authType...)
}

// GetDisableTime gets remaining disable time in seconds | 获取剩余封禁时间（秒）
func GetDisableTime(ctx context.Context, loginID interface{}, authType ...string) (int64, error) {
	return stputil.GetDisableTime(ctx, loginID, authType...)
}

// GetDisableTimeByToken gets remaining disable time by token | 根据Token获取剩余封禁时间（秒）
func GetDisableTimeByToken(ctx context.Context, tokenValue string, authType ...string) (int64, error) {
	return stputil.GetDisableTimeByToken(ctx, tokenValue, authType...)
}

// CheckDisableWithInfo gets disable info | 获取封禁信息
func CheckDisableWithInfo(ctx context.Context, loginID interface{}, authType ...string) (*manager.DisableInfo, error) {
	return stputil.CheckDisableWithInfo(ctx, loginID, authType...)
}

// CheckDisableWithInfoByToken gets disable info by token | 根据Token获取封禁信息
func CheckDisableWithInfoByToken(ctx context.Context, tokenValue string, authType ...string) (*manager.DisableInfo, error) {
	return stputil.CheckDisableWithInfoByToken(ctx, tokenValue, authType...)
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 根据登录ID获取Session
func GetSession(ctx context.Context, loginID interface{}, authType ...string) (*session.Session, error) {
	return stputil.GetSession(ctx, loginID, authType...)
}

// GetSessionByToken gets session by token | 根据Token获取Session
func GetSessionByToken(ctx context.Context, tokenValue string, authType ...string) (*session.Session, error) {
	return stputil.GetSessionByToken(ctx, tokenValue, authType...)
}

// DeleteSession deletes a session | 删除Session
func DeleteSession(ctx context.Context, loginID interface{}, authType ...string) error {
	return stputil.DeleteSession(ctx, loginID, authType...)
}

// DeleteSessionByToken Deletes session by token | 根据Token删除Session
func DeleteSessionByToken(ctx context.Context, tokenValue string, authType ...string) error {
	return stputil.DeleteSessionByToken(ctx, tokenValue, authType...)
}

// HasSession checks if session exists | 检查Session是否存在
func HasSession(ctx context.Context, loginID interface{}, authType ...string) bool {
	return stputil.HasSession(ctx, loginID, authType...)
}

// RenewSession renews session TTL | 续期Session
func RenewSession(ctx context.Context, loginID interface{}, ttl time.Duration, authType ...string) error {
	return stputil.RenewSession(ctx, loginID, ttl, authType...)
}

// RenewSessionByToken renews session TTL by token | 根据Token续期Session
func RenewSessionByToken(ctx context.Context, tokenValue string, ttl time.Duration, authType ...string) error {
	return stputil.RenewSessionByToken(ctx, tokenValue, ttl, authType...)
}

// ============ Permission Verification | 权限验证 ============

// SetPermissions sets permissions for a login ID | 设置用户权限
func SetPermissions(ctx context.Context, loginID interface{}, permissions []string, authType ...string) error {
	return stputil.SetPermissions(ctx, loginID, permissions, authType...)
}

// SetPermissionsByToken sets permissions by token | 根据 Token 设置对应账号的权限
func SetPermissionsByToken(ctx context.Context, tokenValue string, permissions []string, authType ...string) error {
	return stputil.SetPermissionsByToken(ctx, tokenValue, permissions, authType...)
}

// RemovePermissions removes specified permissions for a login ID | 删除用户指定权限
func RemovePermissions(ctx context.Context, loginID interface{}, permissions []string, authType ...string) error {
	return stputil.RemovePermissions(ctx, loginID, permissions, authType...)
}

// RemovePermissionsByToken removes specified permissions by token | 根据 Token 删除对应账号的指定权限
func RemovePermissionsByToken(ctx context.Context, tokenValue string, permissions []string, authType ...string) error {
	return stputil.RemovePermissionsByToken(ctx, tokenValue, permissions, authType...)
}

// GetPermissions gets permission list | 获取权限列表
func GetPermissions(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	return stputil.GetPermissions(ctx, loginID, authType...)
}

// GetPermissionsByToken gets permission list by token | 根据 Token 获取对应账号的权限列表
func GetPermissionsByToken(ctx context.Context, tokenValue string, authType ...string) ([]string, error) {
	return stputil.GetPermissionsByToken(ctx, tokenValue, authType...)
}

// HasPermission checks if has specified permission | 检查是否拥有指定权限
func HasPermission(ctx context.Context, loginID interface{}, permission string, authType ...string) bool {
	return stputil.HasPermission(ctx, loginID, permission, authType...)
}

// HasPermissionByToken checks if the token has the specified permission | 检查Token是否拥有指定权限
func HasPermissionByToken(ctx context.Context, tokenValue string, permission string, authType ...string) bool {
	return stputil.HasPermissionByToken(ctx, tokenValue, permission, authType...)
}

// HasPermissionsAnd checks if has all permissions (AND logic) | 检查是否拥有所有权限（AND逻辑）
func HasPermissionsAnd(ctx context.Context, loginID interface{}, permissions []string, authType ...string) bool {
	return stputil.HasPermissionsAnd(ctx, loginID, permissions, authType...)
}

// HasPermissionsAndByToken checks if the token has all specified permissions | 检查Token是否拥有所有指定权限
func HasPermissionsAndByToken(ctx context.Context, tokenValue string, permissions []string, authType ...string) bool {
	return stputil.HasPermissionsAndByToken(ctx, tokenValue, permissions, authType...)
}

// HasPermissionsOr checks if has any permission (OR logic) | 检查是否拥有任一权限（OR逻辑）
func HasPermissionsOr(ctx context.Context, loginID interface{}, permissions []string, authType ...string) bool {
	return stputil.HasPermissionsOr(ctx, loginID, permissions, authType...)
}

// HasPermissionsOrByToken checks if the token has any of the specified permissions | 检查Token是否拥有任一指定权限
func HasPermissionsOrByToken(ctx context.Context, tokenValue string, permissions []string, authType ...string) bool {
	return stputil.HasPermissionsOrByToken(ctx, tokenValue, permissions, authType...)
}

// ============ Role Management | 角色管理 ============

// SetRoles sets roles for a login ID | 设置用户角色
func SetRoles(ctx context.Context, loginID interface{}, roles []string, authType ...string) error {
	return stputil.SetRoles(ctx, loginID, roles, authType...)
}

// SetRolesByToken sets roles by token | 根据 Token 设置对应账号的角色
func SetRolesByToken(ctx context.Context, tokenValue string, roles []string, authType ...string) error {
	return stputil.SetRolesByToken(ctx, tokenValue, roles, authType...)
}

// RemoveRoles removes specified roles for a login ID | 删除用户指定角色
func RemoveRoles(ctx context.Context, loginID interface{}, roles []string, authType ...string) error {
	return stputil.RemoveRoles(ctx, loginID, roles, authType...)
}

// RemoveRolesByToken removes specified roles by token | 根据 Token 删除对应账号的指定角色
func RemoveRolesByToken(ctx context.Context, tokenValue string, roles []string, authType ...string) error {
	return stputil.RemoveRolesByToken(ctx, tokenValue, roles, authType...)
}

// GetRoles gets role list | 获取角色列表
func GetRoles(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	return stputil.GetRoles(ctx, loginID, authType...)
}

// GetRolesByToken gets role list by token | 根据 Token 获取对应账号的角色列表
func GetRolesByToken(ctx context.Context, tokenValue string, authType ...string) ([]string, error) {
	return stputil.GetRolesByToken(ctx, tokenValue, authType...)
}

// HasRole checks if has specified role | 检查是否拥有指定角色
func HasRole(ctx context.Context, loginID interface{}, role string, authType ...string) bool {
	return stputil.HasRole(ctx, loginID, role, authType...)
}

// HasRoleByToken checks if the token has the specified role | 检查 Token 是否拥有指定角色
func HasRoleByToken(ctx context.Context, tokenValue string, role string, authType ...string) bool {
	return stputil.HasRoleByToken(ctx, tokenValue, role, authType...)
}

// HasRolesAnd checks if has all roles (AND logic) | 检查是否拥有所有角色（AND逻辑）
func HasRolesAnd(ctx context.Context, loginID interface{}, roles []string, authType ...string) bool {
	return stputil.HasRolesAnd(ctx, loginID, roles, authType...)
}

// HasRolesAndByToken checks if the token has all specified roles | 检查 Token 是否拥有所有指定角色
func HasRolesAndByToken(ctx context.Context, tokenValue string, roles []string, authType ...string) bool {
	return stputil.HasRolesAndByToken(ctx, tokenValue, roles, authType...)
}

// HasRolesOr checks if has any role (OR logic) | 检查是否拥有任一角色（OR逻辑）
func HasRolesOr(ctx context.Context, loginID interface{}, roles []string, authType ...string) bool {
	return stputil.HasRolesOr(ctx, loginID, roles, authType...)
}

// HasRolesOrByToken checks if the token has any of the specified roles | 检查 Token 是否拥有任一指定角色
func HasRolesOrByToken(ctx context.Context, tokenValue string, roles []string, authType ...string) bool {
	return stputil.HasRolesOrByToken(ctx, tokenValue, roles, authType...)
}

// ============ Token Tag | Token标签 ============

// SetTokenTag sets token tag | 设置Token标签
func SetTokenTag(ctx context.Context, tokenValue, tag string, authType ...string) error {
	return stputil.SetTokenTag(ctx, tokenValue, tag, authType...)
}

// GetTokenTag gets token tag | 获取Token标签
func GetTokenTag(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	return stputil.GetTokenTag(ctx, tokenValue, authType...)
}

// ============ Session Query | 会话查询 ============

// GetTokenValueListByLoginID gets all tokens for a login ID | 获取指定账号的所有Token
func GetTokenValueListByLoginID(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	return stputil.GetTokenValueListByLoginID(ctx, loginID, authType...)
}

// GetSessionCountByLoginID gets session count for a login ID | 获取指定账号的Session数量
func GetSessionCountByLoginID(ctx context.Context, loginID interface{}, authType ...string) (int, error) {
	return stputil.GetSessionCountByLoginID(ctx, loginID, authType...)
}

// ============ Security Features | 安全特性 ============

// Generate Generates a one-time nonce | 生成一次性随机数
func Generate(ctx context.Context, authType ...string) (string, error) {
	return stputil.Generate(ctx, authType...)
}

// Verify Verifies a nonce | 验证随机数
func Verify(ctx context.Context, nonce string, authType ...string) bool {
	return stputil.Verify(ctx, nonce, authType...)
}

// VerifyAndConsume Verifies and consumes nonce, returns error if invalid | 验证并消费nonce，无效时返回错误
func VerifyAndConsume(ctx context.Context, nonce string, authType ...string) error {
	return stputil.VerifyAndConsume(ctx, nonce, authType...)
}

// IsValidNonce Checks if nonce is valid without consuming it | 检查nonce是否有效（不消费）
func IsValidNonce(ctx context.Context, nonce string, authType ...string) bool {
	return stputil.IsValidNonce(ctx, nonce, authType...)
}

// GenerateTokenPair Create access + refresh token | 生成访问令牌和刷新令牌
func GenerateTokenPair(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (*security.RefreshTokenInfo, error) {
	return stputil.GenerateTokenPair(ctx, loginID, deviceOrAutoType...)
}

// VerifyAccessToken verifies access token validity | 验证访问令牌是否有效
func VerifyAccessToken(ctx context.Context, accessToken string, authType ...string) bool {
	return stputil.VerifyAccessToken(ctx, accessToken, authType...)
}

// VerifyAccessTokenAndGetInfo verifies access token and returns token info | 验证访问令牌并返回Token信息
func VerifyAccessTokenAndGetInfo(ctx context.Context, accessToken string, authType ...string) (*security.AccessTokenInfo, bool) {
	return stputil.VerifyAccessTokenAndGetInfo(ctx, accessToken, authType...)
}

// GetRefreshTokenInfo gets refresh token information | 获取刷新令牌信息
func GetRefreshTokenInfo(ctx context.Context, refreshToken string, authType ...string) (*security.RefreshTokenInfo, error) {
	return stputil.GetRefreshTokenInfo(ctx, refreshToken, authType...)
}

// RefreshAccessToken refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func RefreshAccessToken(ctx context.Context, refreshToken string, authType ...string) (*security.RefreshTokenInfo, error) {
	return stputil.RefreshAccessToken(ctx, refreshToken, authType...)
}

// RevokeRefreshToken Revokes refresh token | 撤销刷新令牌
func RevokeRefreshToken(ctx context.Context, refreshToken string, authType ...string) error {
	return stputil.RevokeRefreshToken(ctx, refreshToken, authType...)
}

// IsValid checks whether token is valid | 检查Token是否有效
func IsValid(ctx context.Context, refreshToken string, authType ...string) bool {
	return stputil.IsValid(ctx, refreshToken, authType...)
}

// ============ OAuth2 Features | OAuth2 功能 ============

// RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func RegisterClient(ctx context.Context, client *oauth2.Client, authType ...string) error {
	return stputil.RegisterClient(ctx, client, authType...)
}

// UnregisterClient unregisters an OAuth2 client | 注销OAuth2客户端
func UnregisterClient(ctx context.Context, clientID string, authType ...string) error {
	return stputil.UnregisterClient(ctx, clientID, authType...)
}

// GetClient gets OAuth2 client information | 获取OAuth2客户端信息
func GetClient(ctx context.Context, clientID string, authType ...string) (*oauth2.Client, error) {
	return stputil.GetClient(ctx, clientID, authType...)
}

// GenerateAuthorizationCode creates an authorization code | 创建授权码
func GenerateAuthorizationCode(ctx context.Context, clientID, loginID, redirectURI string, scope []string, authType ...string) (*oauth2.AuthorizationCode, error) {
	return stputil.GenerateAuthorizationCode(ctx, clientID, loginID, redirectURI, scope, authType...)
}

// ExchangeCodeForToken exchanges authorization code for token | 使用授权码换取令牌
func ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.ExchangeCodeForToken(ctx, code, clientID, clientSecret, redirectURI, authType...)
}

// ValidateAccessToken verifies OAuth2 access token | 验证OAuth2访问令牌
func ValidateAccessToken(ctx context.Context, accessToken string, authType ...string) bool {
	return stputil.ValidateAccessToken(ctx, accessToken, authType...)
}

// ValidateAccessTokenAndGetInfo verifies OAuth2 access token and get info | 验证OAuth2访问令牌并获取信息
func ValidateAccessTokenAndGetInfo(ctx context.Context, accessToken string, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.ValidateAccessTokenAndGetInfo(ctx, accessToken, authType...)
}

// OAuth2RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌(OAuth2)
func OAuth2RefreshAccessToken(ctx context.Context, clientID, refreshToken, clientSecret string, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.OAuth2RefreshAccessToken(ctx, clientID, refreshToken, clientSecret, authType...)
}

// RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func RevokeToken(ctx context.Context, accessToken string, authType ...string) error {
	return stputil.RevokeToken(ctx, accessToken, authType...)
}

// OAuth2Token Unified token endpoint that dispatches to appropriate handler based on grant type | 统一的令牌端点
func OAuth2Token(ctx context.Context, req *oauth2.TokenRequest, validateUser oauth2.UserValidator, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.OAuth2Token(ctx, req, validateUser, authType...)
}

// OAuth2ClientCredentialsToken Gets access token using client credentials grant | 使用客户端凭证模式获取访问令牌
func OAuth2ClientCredentialsToken(ctx context.Context, clientID, clientSecret string, scopes []string, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.OAuth2ClientCredentialsToken(ctx, clientID, clientSecret, scopes, authType...)
}

// OAuth2PasswordGrantToken Gets access token using resource owner password credentials grant | 使用密码模式获取访问令牌
func OAuth2PasswordGrantToken(ctx context.Context, clientID, clientSecret, username, password string, scopes []string, validateUser oauth2.UserValidator, authType ...string) (*oauth2.AccessToken, error) {
	return stputil.OAuth2PasswordGrantToken(ctx, clientID, clientSecret, username, password, scopes, validateUser, authType...)
}

// ============ OAuth2 Grant Type Constants | OAuth2授权类型常量 ============

const (
	// GrantTypeAuthorizationCode Authorization code grant type | 授权码模式
	GrantTypeAuthorizationCode = oauth2.GrantTypeAuthorizationCode
	// GrantTypeClientCredentials Client credentials grant type | 客户端凭证模式
	GrantTypeClientCredentials = oauth2.GrantTypeClientCredentials
	// GrantTypePassword Password grant type | 密码模式
	GrantTypePassword = oauth2.GrantTypePassword
	// GrantTypeRefreshToken Refresh token grant type | 刷新令牌模式
	GrantTypeRefreshToken = oauth2.GrantTypeRefreshToken
)

// ============ Public Getters | 公共获取器 ============

// GetConfig returns the manager-example configuration | 获取 Manager 当前使用的配置
func GetConfig(ctx context.Context, authType ...string) *config.Config {
	return stputil.GetConfig(ctx, authType...)
}

// GetStorage returns the storage adapter | 获取 Manager 使用的存储适配器
func GetStorage(ctx context.Context, authType ...string) adapter.Storage {
	return stputil.GetStorage(ctx, authType...)
}

// GetCodec returns the codec (serializer) | 获取 Manager 使用的编解码器
func GetCodec(ctx context.Context, authType ...string) adapter.Codec {
	return stputil.GetCodec(ctx, authType...)
}

// GetLog returns the logger adapter | 获取 Manager 使用的日志适配器
func GetLog(ctx context.Context, authType ...string) adapter.Log {
	return stputil.GetLog(ctx, authType...)
}

// GetPool returns the goroutine pool | 获取 Manager 使用的协程池
func GetPool(ctx context.Context, authType ...string) adapter.Pool {
	return stputil.GetPool(ctx, authType...)
}

// GetGenerator returns the token generator | 获取 Token 生成器
func GetGenerator(ctx context.Context, authType ...string) adapter.Generator {
	return stputil.GetGenerator(ctx, authType...)
}

// GetNonceManager returns the nonce manager-example | 获取随机串管理器
func GetNonceManager(ctx context.Context, authType ...string) *security.NonceManager {
	return stputil.GetNonceManager(ctx, authType...)
}

// GetRefreshManager returns the refresh token manager-example | 获取刷新令牌管理器
func GetRefreshManager(ctx context.Context, authType ...string) *security.RefreshTokenManager {
	return stputil.GetRefreshManager(ctx, authType...)
}

// GetEventManager returns the event manager-example | 获取事件管理器
func GetEventManager(ctx context.Context, authType ...string) *listener.Manager {
	return stputil.GetEventManager(ctx, authType...)
}

// GetOAuth2Server Gets OAuth2 server instance | 获取OAuth2服务器实例
func GetOAuth2Server(ctx context.Context, authType ...string) *oauth2.OAuth2Server {
	return stputil.GetOAuth2Server(ctx, authType...)
}

// ============ Event Management | 事件管理 ============

// RegisterFunc registers a function as an event listener | 注册函数作为事件监听器
func RegisterFunc(event listener.Event, fn func(*listener.EventData), authType ...string) {
	stputil.RegisterFunc(event, fn, authType...)
}

// Register registers an event listener | 注册事件监听器
func Register(event listener.Event, l listener.Listener, authType ...string) string {
	return stputil.Register(event, l, authType...)
}

// RegisterWithConfig registers an event listener with config | 注册带配置的事件监听器
func RegisterWithConfig(event listener.Event, l listener.Listener, cfg listener.ListenerConfig, authType ...string) string {
	return stputil.RegisterWithConfig(event, l, cfg, authType...)
}

// Unregister removes an event listener by ID | 根据ID移除事件监听器
func Unregister(id string, authType ...string) bool {
	return stputil.Unregister(id, authType...)
}

// TriggerEvent manually triggers an event | 手动触发事件
func TriggerEvent(data *listener.EventData, authType ...string) {
	stputil.TriggerEvent(data, authType...)
}

// TriggerEventAsync triggers an event asynchronously and returns immediately | 异步触发事件并立即返回
func TriggerEventAsync(data *listener.EventData, authType ...string) {
	stputil.TriggerEventAsync(data, authType...)
}

// TriggerEventSync triggers an event synchronously and waits for all listeners | 同步触发事件并等待所有监听器完成
func TriggerEventSync(data *listener.EventData, authType ...string) {
	stputil.TriggerEventSync(data, authType...)
}

// WaitEvents waits for all async event listeners to complete | 等待所有异步事件监听器完成
func WaitEvents(authType ...string) {
	stputil.WaitEvents(authType...)
}

// ClearEventListeners removes all listeners for a specific event | 清除指定事件的所有监听器
func ClearEventListeners(event listener.Event, authType ...string) {
	stputil.ClearEventListeners(event, authType...)
}

// ClearAllEventListeners removes all listeners | 清除所有事件监听器
func ClearAllEventListeners(authType ...string) {
	stputil.ClearAllEventListeners(authType...)
}

// CountEventListeners returns the number of listeners for a specific event | 获取指定事件监听器数量
func CountEventListeners(event listener.Event, authType ...string) int {
	return stputil.CountEventListeners(event, authType...)
}

// CountAllListeners returns the total number of registered listeners | 获取已注册监听器总数
func CountAllListeners(authType ...string) int {
	return stputil.CountAllListeners(authType...)
}

// GetEventListenerIDs returns all listener IDs for a specific event | 获取指定事件的所有监听器ID
func GetEventListenerIDs(event listener.Event, authType ...string) []string {
	return stputil.GetEventListenerIDs(event, authType...)
}

// GetAllRegisteredEvents returns all events that have registered listeners | 获取所有已注册事件
func GetAllRegisteredEvents(authType ...string) []listener.Event {
	return stputil.GetAllRegisteredEvents(authType...)
}

// HasEventListeners checks if there are any listeners for a specific event | 检查指定事件是否有监听器
func HasEventListeners(event listener.Event, authType ...string) bool {
	return stputil.HasEventListeners(event, authType...)
}
