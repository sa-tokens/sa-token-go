// @Author daixk 2025/12/7 15:34:00
package config

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

// SameSiteMode Cookie SameSite attribute values | Cookie的SameSite属性值
type SameSiteMode string

const (
	// SameSiteStrict Strict mode | 严格模式
	SameSiteStrict SameSiteMode = "Strict"
	// SameSiteLax Lax mode | 宽松模式
	SameSiteLax SameSiteMode = "Lax"
	// SameSiteNone None mode | 无限制模式
	SameSiteNone SameSiteMode = "None"
)

// Default configuration constants | 默认配置常量
const (
	DefaultTokenName     = "satoken"          // Default token name | 默认Token名称
	DefaultKeyPrefix     = "satoken:"         // Default Redis key prefix | 默认Redis键前缀
	DefaultAuthType      = "defaultAuthType:" // Default AuthType | 默认认证体系键前缀
	DefaultTimeout       = 2592000            // 30 days (seconds) | 30天（秒）
	DefaultMaxLoginCount = 12                 // Maximum concurrent logins | 最大并发登录数
	DefaultCookiePath    = "/"                // Default cookie path | 默认Cookie路径
	NoLimit              = -1                 // No limit flag | 不限制标志
)

const (
	CtxAutoType   = "SaTokenCtxAutoType"
	CtxTokenValue = "CtxTokenValue"
)
