package core

import (
	"errors"
	"fmt"
)

// Common error definitions for better error handling and internationalization support
// 常见错误定义，用于更好的错误处理和国际化支持

// ============ Authentication Errors | 认证错误 ============

var (
	// ErrNotLogin indicates the user is not logged in | 用户未登录错误
	ErrNotLogin = fmt.Errorf("authentication required: user not logged in")

	// ErrTokenInvalid indicates the provided token is invalid or malformed | Token无效或格式错误
	ErrTokenInvalid = fmt.Errorf("invalid token: the token is malformed or corrupted")

	// ErrTokenExpired indicates the token has expired | Token已过期
	ErrTokenExpired = fmt.Errorf("token expired: please login again to get a new token")

	// ErrTokenKickout indicates the token has been kicked out | Token 已被踢下线
	ErrTokenKickout = fmt.Errorf("authentication required: token has been kicked out")

	// ErrTokenReplaced indicates the token has been replaced | Token 已被顶下线
	ErrTokenReplaced = fmt.Errorf("authentication required: token has been replaced")

	// ErrInvalidLoginID indicates the login ID is invalid | 登录ID无效
	ErrInvalidLoginID = fmt.Errorf("invalid login ID: the login identifier cannot be empty")

	// ErrInvalidDevice indicates the device identifier is invalid | 设备标识无效
	ErrInvalidDevice = fmt.Errorf("invalid device: the device identifier is not valid")

	// ErrTokenNotFound indicates the token does not exist | Token 不存在
	ErrTokenNotFound = fmt.Errorf("authentication required: token not found")
)

// ============ Authorization Errors | 授权错误 ============

var (
	// ErrPermissionDenied indicates insufficient permissions | 权限不足
	ErrPermissionDenied = fmt.Errorf("permission denied: you don't have the required permission")

	// ErrRoleDenied indicates insufficient role | 角色权限不足
	ErrRoleDenied = fmt.Errorf("role denied: you don't have the required role")
)

// ============ Account Errors | 账号错误 ============

var (
	// ErrAccountDisabled indicates the account has been disabled or banned | 账号已被禁用
	ErrAccountDisabled = fmt.Errorf("account disabled: this account has been temporarily or permanently disabled")

	// ErrAccountNotFound indicates the account doesn't exist | 账号不存在
	ErrAccountNotFound = fmt.Errorf("account not found: no account associated with this identifier")

	// ErrLoginLimitExceeded indicates login count exceeds the maximum limit | 超出最大登录数量限制
	ErrLoginLimitExceeded = fmt.Errorf("account error: login count exceeds the maximum limit")
)

// ============ Session Errors | 会话错误 ============

var (
	// ErrSessionNotFound indicates the session doesn't exist | Session不存在
	ErrSessionNotFound = fmt.Errorf("session not found: the session may have expired or been deleted")

	// ErrActiveTimeout indicates the session has been inactive for too long | Session活跃超时
	ErrActiveTimeout = fmt.Errorf("session inactive: the session has exceeded the inactivity timeout")
)

// ============ Security Errors | Security 错误 ============

var (
	// ErrInvalidNonce indicates the nonce is invalid or expired | Nonce 无效或已过期
	ErrInvalidNonce = fmt.Errorf("invalid nonce: nonce is invalid or expired")

	// ErrRefreshTokenExpired indicates the refresh token has expired | 刷新令牌已过期
	ErrRefreshTokenExpired = fmt.Errorf("refresh token expired: please request a new token")

	// ErrNonceInvalidRefreshToken indicates the refresh token is invalid | 刷新令牌无效
	ErrNonceInvalidRefreshToken = fmt.Errorf("invalid refresh token: token is malformed or does not exist")

	// ErrInvalidLoginIDEmpty indicates loginID is empty | 登录ID不能为空
	ErrInvalidLoginIDEmpty = fmt.Errorf("invalid loginID: loginID cannot be empty")
)

// ============ OAuth2 Errors | OAuth2 错误 ============

var (
	// ErrClientOrClientIDEmpty indicates client or clientID is empty | 客户端或客户端ID为空
	ErrClientOrClientIDEmpty = fmt.Errorf("invalid client: clientID is required")

	// ErrClientNotFound indicates the client does not exist | 客户端不存在
	ErrClientNotFound = fmt.Errorf("client error: client not found")

	// ErrUserIDEmpty indicates userID is empty | 用户ID不能为空
	ErrUserIDEmpty = fmt.Errorf("invalid user: userID cannot be empty")

	// ErrInvalidRedirectURI indicates redirect URI is invalid | 回调URI非法
	ErrInvalidRedirectURI = fmt.Errorf("invalid redirect uri: redirectUri is not allowed")

	// ErrInvalidClientCredentials indicates incorrect client credentials | 客户端凭证无效
	ErrInvalidClientCredentials = fmt.Errorf("invalid client credentials: authentication failed")

	// ErrInvalidAuthCode indicates an invalid authorization code | 授权码无效
	ErrInvalidAuthCode = fmt.Errorf("invalid authorization code: code is malformed or does not exist")

	// ErrAuthCodeUsed indicates the authorization code has already been used | 授权码已被使用
	ErrAuthCodeUsed = fmt.Errorf("authorization code error: code already used")

	// ErrAuthCodeExpired indicates the authorization code has expired | 授权码已过期
	ErrAuthCodeExpired = fmt.Errorf("authorization code expired: please restart authorization process")

	// ErrClientMismatch indicates client mismatch | 客户端不匹配
	ErrClientMismatch = fmt.Errorf("client mismatch: clientID does not match the authorization code")

	// ErrRedirectURIMismatch indicates redirect URI mismatch | 回调URI不匹配
	ErrRedirectURIMismatch = fmt.Errorf("redirect uri mismatch: callback URL does not match registered value")

	// ErrInvalidAccessToken indicates access token invalid | 访问令牌无效
	ErrInvalidAccessToken = fmt.Errorf("invalid access token: token is malformed or expired")

	// ErrInvalidRefreshToken indicates refresh token invalid | 刷新令牌无效
	ErrInvalidRefreshToken = fmt.Errorf("invalid refresh token: token is malformed or expired")

	// ErrInvalidScope indicates requested scope is not allowed | 请求的权限范围不被允许
	ErrInvalidScope = fmt.Errorf("invalid scope: requested scope is not allowed for this client")
)

// ============ Session Errors | Session 错误 ============

var (
	// ErrSessionInvalidDataKey indicates a session data key is empty or invalid | Session 数据的 key 为空或非法
	ErrSessionInvalidDataKey = fmt.Errorf("invalid session data key: key cannot be empty")

	// ErrSessionIDEmpty indicates that a session ID is empty or missing | Session ID 为空或缺失
	ErrSessionIDEmpty = errors.New("session id cannot be empty")
)

// ============ System Errors | 系统错误 ============

var (
	// ErrStorageUnavailable indicates the storage backend is unavailable | 存储后端不可用
	ErrStorageUnavailable = fmt.Errorf("storage unavailable: unable to connect to storage backend")

	// ErrSerializeFailed indicates serialization failed | 序列化失败
	ErrSerializeFailed = fmt.Errorf("serialize failed: unable to encode data")

	// ErrDeserializeFailed indicates deserialization failed | 反序列化失败
	ErrDeserializeFailed = fmt.Errorf("deserialize failed: unable to decode data")

	// ErrTypeConvert indicates a type conversion failed | 类型转换失败
	ErrTypeConvert = fmt.Errorf("type conversion failed: unable to convert value to target type")
)

// ============ Custom Error Type | 自定义错误类型 ============

// SaTokenError Represents a custom error with error code and context | 自定义错误类型，包含错误码和上下文信息
type SaTokenError struct {
	Code    int            // Error code for programmatic handling | 错误码，用于程序化处理
	Message string         // Human-readable error message | 可读的错误消息
	Err     error          // Underlying error (if any) | 底层错误（如果有）
	Context map[string]any // Additional context information | 额外的上下文信息
}

// Error Implements the error interface | 实现 error 接口
func (e *SaTokenError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (code: %d): %v", e.Message, e.Code, e.Err)
	}
	return fmt.Sprintf("%s (code: %d)", e.Message, e.Code)
}

// Unwrap Implements the unwrap interface for error chains | 实现 unwrap 接口，支持错误链
func (e *SaTokenError) Unwrap() error {
	return e.Err
}

// WithContext Adds context information to the error | 为错误添加上下文信息
func (e *SaTokenError) WithContext(key string, value any) *SaTokenError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// GetContext Gets context value | 获取上下文值
func (e *SaTokenError) GetContext(key string) (any, bool) {
	if e.Context == nil {
		return nil, false
	}
	val, exists := e.Context[key]
	return val, exists
}

// Is Implements errors.Is for error comparison | 实现 errors.Is 进行错误比较
func (e *SaTokenError) Is(target error) bool {
	t, ok := target.(*SaTokenError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// ============ Error Constructors | 错误构造函数 ============

// NewError Creates a new Sa-Token error | 创建新的 Sa-Token 错误
func NewError(code int, message string, err error) *SaTokenError {
	return &SaTokenError{
		Code:    code,
		Message: message,
		Err:     err,
		Context: make(map[string]any),
	}
}

// NewErrorWithContext Creates a new Sa-Token error with context | 创建带上下文的 Sa-Token 错误
func NewErrorWithContext(code int, message string, err error, context map[string]any) *SaTokenError {
	return &SaTokenError{
		Code:    code,
		Message: message,
		Err:     err,
		Context: context,
	}
}

// NewNotLoginError Creates a not login error | 创建未登录错误
func NewNotLoginError() *SaTokenError {
	return NewError(CodeNotLogin, "user not logged in", ErrNotLogin)
}

// NewPermissionDeniedError Creates a permission denied error | 创建权限拒绝错误
func NewPermissionDeniedError(permission string) *SaTokenError {
	return NewError(CodePermissionDenied, "permission denied", ErrPermissionDenied).
		WithContext("permission", permission)
}

// NewRoleDeniedError Creates a role denied error | 创建角色拒绝错误
func NewRoleDeniedError(role string) *SaTokenError {
	return NewError(CodePermissionDenied, "role denied", ErrRoleDenied).
		WithContext("role", role)
}

// NewAccountDisabledError Creates an account disabled error | 创建账号禁用错误
func NewAccountDisabledError(loginID string) *SaTokenError {
	return NewError(CodeAccountDisabled, "account disabled", ErrAccountDisabled).
		WithContext("loginID", loginID)
}

// ============ Error Checking Helpers | 错误检查辅助函数 ============

// IsNotLoginError Checks if error is a not login error | 检查是否为未登录错误
func IsNotLoginError(err error) bool {
	return errors.Is(err, ErrNotLogin)
}

// IsPermissionDeniedError Checks if error is a permission denied error | 检查是否为权限拒绝错误
func IsPermissionDeniedError(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// IsAccountDisabledError Checks if error is an account disabled error | 检查是否为账号禁用错误
func IsAccountDisabledError(err error) bool {
	return errors.Is(err, ErrAccountDisabled)
}

// IsTokenError Checks if error is a token-related error | 检查是否为Token相关错误
func IsTokenError(err error) bool {
	return errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenExpired)
}

// GetErrorCode Extracts error code from SaTokenError | 从SaTokenError中提取错误码
func GetErrorCode(err error) int {
	var saErr *SaTokenError
	if errors.As(err, &saErr) {
		return saErr.Code
	}
	return CodeServerError
}

// ============ Error Code Definitions | 错误码定义 ============

const (
	// Standard HTTP status codes | 标准 HTTP 状态码
	CodeSuccess          = 200 // Request successful | 请求成功
	CodeBadRequest       = 400 // Bad request | 错误的请求
	CodeNotLogin         = 401 // Not authenticated | 未认证
	CodePermissionDenied = 403 // Permission denied | 权限不足
	CodeNotFound         = 404 // Resource not found | 资源未找到
	CodeServerError      = 500 // Internal server error | 服务器内部错误

	// Sa-Token specific error codes (10000-19999) | Sa-Token 特定错误码 (10000-19999)
	CodeTokenInvalid     = 10001 // Token is invalid or malformed | Token无效或格式错误
	CodeTokenExpired     = 10002 // Token has expired | Token已过期
	CodeAccountDisabled  = 10003 // Account is disabled | 账号已被禁用
	CodeKickedOut        = 10004 // User has been kicked out | 用户已被踢下线
	CodeActiveTimeout    = 10005 // Session inactive timeout | Session活跃超时
	CodeMaxLoginCount    = 10006 // Maximum login count reached | 达到最大登录数量
	CodeStorageError     = 10007 // Storage backend error | 存储后端错误
	CodeInvalidParameter = 10008 // Invalid parameter | 无效参数
	CodeSessionError     = 10009 // Session operation error | Session操作错误
)
