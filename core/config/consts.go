// @Author daixk 2025/12/7 15:34:00
package config

const (
	CtxAutoType   = "CtxAutoType"
	CtxTokenValue = "CtxTokenValue"
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
	DefaultJwtSecretKey  = ""
)
