// @Author daixk 2025/11/25 9:34:00
package serror

import "fmt"

// Common Errors | Common 错误
var (
	ErrCommonMarshal   = fmt.Errorf("failed to marshal data")   // failed to marshal data | 序列化数据失败
	ErrCommonUnmarshal = fmt.Errorf("failed to unmarshal data") // failed to unmarshal data | 反序列化数据失败
)

// RenewPool Errors | RenewPool 错误
var (
	ErrRenewPoolNotStarted = fmt.Errorf("renew pool not started") // renew pool not started | 续期线程池未启动
)

// Session Errors | Session 错误
var (
	ErrSessionNotFound = fmt.Errorf("session not found")           // session not found | 会话不存在
	ErrSessionIDEmpty  = fmt.Errorf("session id cannot be empty")  // session id cannot be empty | Session ID 不能为空
	ErrSessionKeyEmpty = fmt.Errorf("session key cannot be empty") // session key cannot be empty | Session 键不能为空
)

// Manager Errors | Manager 错误
var (
	ErrTokenNotFound    = fmt.Errorf("token not found")           // token not found | Token 不存在
	ErrInvalidTokenData = fmt.Errorf("invalid token data")        // invalid token data | Token 数据无效
	ErrTokenKickout     = fmt.Errorf("token has been kicked out") // token has been kicked out | Token 已被踢下线
	ErrTokenReplaced    = fmt.Errorf("token has been replaced")   // token has been replaced | Token 已被顶下线

	ErrNotLogin           = fmt.Errorf("not login")                             // not login | 未登录
	ErrAccountDisabled    = fmt.Errorf("account is disabled")                   // account is disabled | 账号已被禁用
	ErrLoginLimitExceeded = fmt.Errorf("login count exceeds the maximum limit") // login count exceeds the maximum limit | 超出最大登录数量限制
)
