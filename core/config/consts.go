// @Author daixk 2025/12/7 15:34:00
package config

import "time"

const (
	CtxAutoType   = "CtxAutoType"
	CtxTokenValue = "CtxTokenValue"
)

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
	DefaultJwtSecretKey  = ""
)

// LogLevel defines severity level | 日志级别定义
type LogLevel int

const (
	LevelDebug LogLevel = iota + 1 // Debug level | 调试级别
	LevelInfo                      // Info level | 信息级别
	LevelWarn                      // Warn level | 警告级别
	LevelError                     // Error level | 错误级别（最高）
)

const (
	DefaultPrefix            = "[SA-TOKEN-GO] "              // Default log prefix | 默认日志前缀
	DefaultFileFormat        = "SA-TOKEN-GO_{Y}-{m}-{d}.log" // Default log filename format | 默认文件命名格式
	DefaultTimeFormat        = "2006-01-02 15:04:05"         // Default time format | 默认时间格式
	DefaultDirName           = "sa_token_go_logs"            // Default log directory name | 默认日志目录名
	DefaultBaseName          = "SA-TOKEN-GO"                 // Default log filename prefix | 默认日志文件基础前缀
	DefaultRotateSize        = 10 * 1024 * 1024              // Rotate threshold (10MB) | 文件滚动大小阈值
	DefaultRotateExpire      = 24 * time.Hour                // Rotate by time interval (1 day) | 时间滚动间隔
	DefaultRotateBackupLimit = 10                            // Max number of backups | 最大备份数量
	DefaultRotateBackupDays  = 7                             // Retain logs for 7 days | 备份保留天数
)

// Default configuration constants | 默认配置常量
const (
	DefaultMinSize       = 100              // Minimum pool size | 最小协程数
	DefaultMaxSize       = 2000             // Maximum pool size | 最大协程数
	DefaultScaleUpRate   = 0.8              // Scale-up threshold | 扩容阈值
	DefaultScaleDownRate = 0.3              // Scale-down threshold | 缩容阈值
	DefaultCheckInterval = time.Minute      // Interval for auto-scaling checks | 检查间隔
	DefaultExpiry        = 10 * time.Second // Idle worker expiry duration | 空闲协程过期时间
)
