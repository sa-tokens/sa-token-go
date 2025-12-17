// @Author daixk 2025/11/25 9:34:00
package serror

import (
	"fmt"
)

var (
	ErrCommonEncode = fmt.Errorf("failed to encode data") // failed to marshal data | 序列化数据失败
	ErrCommonDecode = fmt.Errorf("failed to decode data") // failed to unmarshal data | 反序列化数据失败

	ErrRenewPoolNotStarted = fmt.Errorf("renew pool not started") // renew pool not started | 续期线程池未启动

	ErrTokenNotFound      = fmt.Errorf("token not found")                       // token not found | Token 不存在
	ErrTokenKickout       = fmt.Errorf("token has been kicked out")             // token has been kicked out | Token 已被踢下线
	ErrTokenReplaced      = fmt.Errorf("token has been replaced")               // token has been replaced | Token 已被顶下线
	ErrNotLogin           = fmt.Errorf("not login")                             // not login | 未登录
	ErrAccountDisabled    = fmt.Errorf("account is disabled")                   // account is disabled | 账号已被禁用
	ErrLoginLimitExceeded = fmt.Errorf("login count exceeds the maximum limit") // login count exceeds the maximum limit | 超出最大登录数量限制

	ErrClientOrClientIDEmpty    = fmt.Errorf("invalid client: clientID is required") // client or clientID is empty | 客户端或客户端ID为空
	ErrClientNotFound           = fmt.Errorf("client not found")                     // client not found | 客户端不存在
	ErrUserIDEmpty              = fmt.Errorf("userID cannot be empty")               // userID is empty | 用户ID不能为空
	ErrInvalidRedirectURI       = fmt.Errorf("invalid redirectUri")                  // invalid redirect URI | 回调URI非法
	ErrInvalidClientCredentials = fmt.Errorf("invalid client credentials")           // invalid client credentials | 客户端凭证无效
	ErrInvalidAuthCode          = fmt.Errorf("invalid authorization code")           // invalid authorization code | 授权码无效
	ErrAuthCodeUsed             = fmt.Errorf("authorization code already used")      // authorization code already used | 授权码已被使用
	ErrAuthCodeExpired          = fmt.Errorf("authorization code expired")           // authorization code expired | 授权码已过期
	ErrClientMismatch           = fmt.Errorf("client mismatch")                      // client mismatch | 客户端不匹配
	ErrRedirectURIMismatch      = fmt.Errorf("redirectUri mismatch")                 // redirect URI mismatch | 回调URI不匹配
	ErrInvalidAccessToken       = fmt.Errorf("invalid access token")                 // invalid access token | 访问令牌无效
	ErrInvalidRefreshToken      = fmt.Errorf("invalid refresh token")                // invalid refresh token | 刷新令牌无效

	ErrInvalidNonce        = fmt.Errorf("invalid or expired nonce") // invalid or expired nonce | Nonce 无效或已过期
	ErrInvalidLoginIDEmpty = fmt.Errorf("loginID cannot be empty")  // loginID is empty | 登录ID不能为空

	ErrRefreshTokenExpired = fmt.Errorf("refresh token expired") // refresh token expired | 刷新令牌已过期

	ErrInvalidToken            = fmt.Errorf("invalid token")
	ErrUnexpectedSigningMethod = fmt.Errorf("unexpected signing method")
)
