// @Author daixk 2025/11/25 9:34:00
package serror

import (
	"errors"
)

// 此模块只需要把公共的err定义在这里统一使用 模块内部的err在文件内定义就可以了

// Common Errors | Common 错误
var (
	ErrCommonMarshal   = errors.New("failed to marshal data")   // failed to marshal data | 序列化数据失败
	ErrCommonUnmarshal = errors.New("failed to unmarshal data") // failed to unmarshal data | 反序列化数据失败

	ErrDataNotByte = errors.New("data cannot be converted to byte slice")
)

// RenewPool Errors | RenewPool 错误
var (
	ErrRenewPoolNotStarted = errors.New("renew pool not started") // renew pool not started | 续期线程池未启动
)

// Session Errors | Session 错误
var (
	ErrSessionNotFound = errors.New("session not found")           // session not found | 会话不存在
	ErrSessionKeyEmpty = errors.New("session key cannot be empty") // session key cannot be empty | Session 键不能为空
)

// Manager Errors | Manager 错误
var (
	ErrTokenNotFound    = errors.New("token not found")           // token not found | Token 不存在
	ErrInvalidTokenData = errors.New("invalid token data")        // invalid token data | Token 数据无效
	ErrTokenKickout     = errors.New("token has been kicked out") // token has been kicked out | Token 已被踢下线
	ErrTokenReplaced    = errors.New("token has been replaced")   // token has been replaced | Token 已被顶下线

	ErrNotLogin           = errors.New("not login")                             // not login | 未登录
	ErrAccountDisabled    = errors.New("account is disabled")                   // account is disabled | 账号已被禁用
	ErrLoginLimitExceeded = errors.New("login count exceeds the maximum limit") // login count exceeds the maximum limit | 超出最大登录数量限制
)

// Oauth2 Errors | Oauth2 错误
var (
	ErrClientOrClientIDEmpty = errors.New("invalid client: clientID is required")

	ErrClientNotFound           = errors.New("client not found")
	ErrInvalidRedirectURI       = errors.New("invalid redirect_uri")
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrInvalidAuthCode          = errors.New("invalid authorization code")
	ErrAuthCodeUsed             = errors.New("authorization code already used")
	ErrAuthCodeExpired          = errors.New("authorization code expired")
	ErrClientMismatch           = errors.New("client mismatch")
	ErrRedirectURIMismatch      = errors.New("redirect_uri mismatch")
	ErrInvalidAccessToken       = errors.New("invalid access token")
	//ErrInvalidTokenData         = errors.New("invalid token data")
)
