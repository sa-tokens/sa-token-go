// @Author daixk 2025/12/22 16:08:00
package sgenerator

// TokenStyle Token generation style | Token生成风格
type TokenStyle string

const (
	// TokenStyleUUID UUID style | UUID风格
	TokenStyleUUID TokenStyle = "uuid"
	// TokenStyleSimple Simple random string | 简单随机字符串
	TokenStyleSimple TokenStyle = "simple"
	// TokenStyleRandom32 32-bit random string | 32位随机字符串
	TokenStyleRandom32 TokenStyle = "random32"
	// TokenStyleRandom64 64-bit random string | 64位随机字符串
	TokenStyleRandom64 TokenStyle = "random64"
	// TokenStyleRandom128 128-bit random string | 128位随机字符串
	TokenStyleRandom128 TokenStyle = "random128"
	// TokenStyleJWT JWT style | JWT风格
	TokenStyleJWT TokenStyle = "jwt"
	// TokenStyleHash SHA256 hash-based style | SHA256哈希风格
	TokenStyleHash TokenStyle = "hash"
	// TokenStyleTimestamp Timestamp-based style | 时间戳风格
	TokenStyleTimestamp TokenStyle = "timestamp"
	// TokenStyleTik Short ID style (like TikTok) | Tik风格短ID（类似抖音）
	TokenStyleTik TokenStyle = "tik"
)

// IsValidTokenStyle checks if the TokenStyle is valid | 检查TokenStyle是否有效
func (ts TokenStyle) IsValidTokenStyle() bool {
	switch ts {
	case TokenStyleUUID, TokenStyleSimple, TokenStyleRandom32,
		TokenStyleRandom64, TokenStyleRandom128, TokenStyleJWT,
		TokenStyleHash, TokenStyleTimestamp, TokenStyleTik:
		return true
	default:
		return false
	}
}

// Constants for token generation | Token生成常量
const (
	DefaultTimeout      = 2592000          // 30 days (seconds) | 30天（秒）
	DefaultJWTSecret    = "log-secret-key" // Should be overridden in production | 生产环境应覆盖
	TikTokenLength      = 11               // TikTok-style short ID length | Tik风格短ID长度
	TikCharset          = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	HashRandomBytesLen  = 16 // Random bytes length for hash token | 哈希Token的随机字节长度
	TimestampRandomLen  = 8  // Random bytes length for timestamp token | 时间戳Token的随机字节长度
	DefaultSimpleLength = 16 // Default simple token length | 默认简单Token长度
)
