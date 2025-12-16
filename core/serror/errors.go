// @Author daixk 2025/11/25 9:34:00
package serror

import (
	"errors"
)

var (
	ErrCommonEncode = errors.New("failed to encode data") // failed to marshal data | 序列化数据失败
	ErrCommonDecode = errors.New("failed to decode data") // failed to unmarshal data | 反序列化数据失败

	ErrRenewPoolNotStarted = errors.New("renew pool not started") // renew pool not started | 续期线程池未启动

	ErrTokenNotFound      = errors.New("token not found")                       // token not found | Token 不存在
	ErrInvalidTokenData   = errors.New("invalid token data")                    // invalid token data | Token 数据无效
	ErrTokenKickout       = errors.New("token has been kicked out")             // token has been kicked out | Token 已被踢下线
	ErrTokenReplaced      = errors.New("token has been replaced")               // token has been replaced | Token 已被顶下线
	ErrNotLogin           = errors.New("not login")                             // not login | 未登录
	ErrAccountDisabled    = errors.New("account is disabled")                   // account is disabled | 账号已被禁用
	ErrLoginLimitExceeded = errors.New("login count exceeds the maximum limit") // login count exceeds the maximum limit | 超出最大登录数量限制

	ErrClientOrClientIDEmpty    = errors.New("invalid client: clientID is required") // client or clientID is empty | 客户端或客户端ID为空
	ErrClientNotFound           = errors.New("client not found")                     // client not found | 客户端不存在
	ErrUserIDEmpty              = errors.New("userID cannot be empty")               // userID is empty | 用户ID不能为空
	ErrInvalidRedirectURI       = errors.New("invalid redirectUri")                  // invalid redirect URI | 回调URI非法
	ErrInvalidClientCredentials = errors.New("invalid client credentials")           // invalid client credentials | 客户端凭证无效
	ErrInvalidAuthCode          = errors.New("invalid authorization code")           // invalid authorization code | 授权码无效
	ErrAuthCodeUsed             = errors.New("authorization code already used")      // authorization code already used | 授权码已被使用
	ErrAuthCodeExpired          = errors.New("authorization code expired")           // authorization code expired | 授权码已过期
	ErrClientMismatch           = errors.New("client mismatch")                      // client mismatch | 客户端不匹配
	ErrRedirectURIMismatch      = errors.New("redirectUri mismatch")                 // redirect URI mismatch | 回调URI不匹配
	ErrInvalidAccessToken       = errors.New("invalid access token")                 // invalid access token | 访问令牌无效
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")                // invalid refresh token | 刷新令牌无效

	ErrInvalidNonce        = errors.New("invalid or expired nonce") // invalid or expired nonce | Nonce 无效或已过期
	ErrInvalidLoginIDEmpty = errors.New("loginID cannot be empty")  // loginID is empty | 登录ID不能为空

	ErrRefreshTokenExpired = errors.New("refresh token expired") // refresh token expired | 刷新令牌已过期
)
