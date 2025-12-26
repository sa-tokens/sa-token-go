// @Author daixk 2025/12/5 15:52:00
package adapter

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

// IsValid checks if the TokenStyle is valid | 检查TokenStyle是否有效
func (ts TokenStyle) IsValid() bool {
	switch ts {
	case TokenStyleUUID, TokenStyleSimple, TokenStyleRandom32,
		TokenStyleRandom64, TokenStyleRandom128, TokenStyleJWT,
		TokenStyleHash, TokenStyleTimestamp, TokenStyleTik:
		return true
	default:
		return false
	}
}

// Generator token generation interface | Token生成接口
type Generator interface {
	// Generate generates token based on implementation | 生成Token（由实现决定具体规则）
	Generate(loginID, device string) (string, error)
}
