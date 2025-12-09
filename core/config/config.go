package config

import (
	"fmt"
	"github.com/click33/sa-token-go/core/pool"
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
	DefaultTokenName     = "satoken"
	DefaultTimeout       = 2592000 // 30 days in seconds | 30天（秒）
	DefaultMaxLoginCount = 12      // Maximum concurrent logins | 最大并发登录数
	DefaultCookiePath    = "/"
	NoLimit              = -1 // No limit flag | 不限制标志
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

// Config Sa-Token configuration | Sa-Token配置
type Config struct {
	// TokenName Token name (also used as Cookie name) | Token名称（同时也是Cookie名称）
	TokenName string

	// Timeout Token expiration time in seconds, -1 for never expire | Token超时时间（单位：秒，-1代表永不过期）
	Timeout int64

	// MaxRefresh Threshold for triggering async token renewal (in seconds) | Token自动续期触发阈值（单位：秒，当剩余有效期低于该值时触发异步续期 -1或0代表不限制）
	MaxRefresh int64

	// RenewInterval Minimum interval between token renewals (ms) | Token最小续期间隔（单位：秒，同一个Token在此时间内只会续期一次 -1或0代表不限制）
	RenewInterval int64

	// ActiveTimeout Token minimum activity frequency in seconds. If Token is not accessed for this time, it will be frozen. -1 means no limit | Token最低活跃频率（单位：秒），如果Token超过此时间没有访问，则会被冻结。-1代表不限制，永不冻结
	ActiveTimeout int64

	// IsConcurrent Allow concurrent login for the same account (true=allow concurrent login, false=new login kicks out old login) | 是否允许同一账号并发登录（为true时允许一起登录，为false时新登录挤掉旧登录）
	IsConcurrent bool

	// IsShare Share the same Token for concurrent logins (true=share one Token, false=create new Token for each login) | 在多人登录同一账号时，是否共用一个Token（为true时所有登录共用一个Token，为false时每次登录新建一个Token）
	IsShare bool

	// MaxLoginCount Maximum number of concurrent logins for the same account, -1 means no limit (only effective when IsConcurrent=true and IsShare=false) | 同一账号最大登录数量，-1代表不限（只有在IsConcurrent=true，IsShare=false时此配置才有效）
	MaxLoginCount int

	// IsReadBody Try to read Token from request body (default: false) | 是否尝试从请求体里读取Token（默认：false）
	IsReadBody bool

	// IsReadHeader Try to read Token from HTTP Header (default: true, recommended) | 是否尝试从Header里读取Token（默认：true，推荐）
	IsReadHeader bool

	// IsReadCookie Try to read Token from Cookie (default: false) | 是否尝试从Cookie里读取Token（默认：false）
	IsReadCookie bool

	// TokenStyle Token generation style | Token风格
	TokenStyle TokenStyle

	// DataRefreshPeriod Auto-refresh period in seconds, -1 means no auto-refresh | 自动续签（单位：秒），-1代表不自动续签
	DataRefreshPeriod int64

	// TokenSessionCheckLogin Check if Token-Session is kicked out when logging in (true=check on login, false=skip check) | Token-Session在登录时是否检查（true=登录时验证是否被踢下线，false=不作此检查）
	TokenSessionCheckLogin bool

	// AutoRenew Auto-renew Token expiration time on each validation | 是否自动续期（每次验证Token时，都会延长Token的有效期）
	AutoRenew bool

	// JwtSecretKey JWT secret key (only effective when TokenStyle=JWT) | JWT密钥（只有TokenStyle=JWT时，此配置才生效）
	JwtSecretKey string

	// IsLog Enable operation logging | 是否输出操作日志
	IsLog bool

	// IsPrintBanner Print startup banner (default: true) | 是否打印启动 Banner（默认：true）
	IsPrintBanner bool

	// KeyPrefix Storage key prefix for Redis isolation (default: "satoken:") | 存储键前缀，用于Redis隔离（默认："satoken:"）
	// Set to empty "" to be compatible with Java sa-token default behavior | 设置为空""以兼容Java sa-token默认行为
	KeyPrefix string

	// CookieConfig Cookie configuration | Cookie配置
	CookieConfig *CookieConfig

	// RenewPoolConfig Configuration for renewal pool manager | 续期池配置
	RenewPoolConfig *pool.RenewPoolConfig
}

// CookieConfig Cookie configuration | Cookie配置
type CookieConfig struct {
	// Domain Cookie domain | 作用域
	Domain string

	// Path Cookie path | 路径
	Path string

	// Secure Only effective under HTTPS | 是否只在HTTPS下生效
	Secure bool

	// HttpOnly Prevent JavaScript access to Cookie | 是否禁止JS操作Cookie
	HttpOnly bool

	// SameSite SameSite attribute (Strict, Lax, None) | SameSite属性（Strict、Lax、None）
	SameSite SameSiteMode

	// MaxAge Cookie expiration time in seconds | 过期时间（单位：秒）
	MaxAge int
}

// DefaultConfig Returns default configuration | 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		TokenName:              DefaultTokenName,
		Timeout:                DefaultTimeout,
		MaxRefresh:             DefaultTimeout / 2,
		RenewInterval:          NoLimit,
		ActiveTimeout:          NoLimit,
		IsConcurrent:           true,
		IsShare:                true,
		MaxLoginCount:          DefaultMaxLoginCount,
		IsReadBody:             false,
		IsReadHeader:           true,
		IsReadCookie:           false,
		TokenStyle:             TokenStyleUUID,
		DataRefreshPeriod:      NoLimit,
		TokenSessionCheckLogin: true,
		AutoRenew:              true,
		JwtSecretKey:           "",
		IsLog:                  false,
		IsPrintBanner:          true,
		KeyPrefix:              "satoken:",
		CookieConfig: &CookieConfig{
			Domain:   "",
			Path:     DefaultCookiePath,
			Secure:   false,
			HttpOnly: true,
			SameSite: SameSiteLax,
			MaxAge:   0,
		},
	}
}

// Validate validates the configuration | 验证配置是否合理
func (c *Config) Validate() error {
	// Check TokenName
	if c.TokenName == "" {
		return fmt.Errorf("TokenName cannot be empty")
	}

	// Check TokenStyle
	if !c.TokenStyle.IsValid() {
		return fmt.Errorf("invalid TokenStyle: %s", c.TokenStyle)
	}

	// Check JWT secret key when using JWT style
	if c.TokenStyle == TokenStyleJWT && c.JwtSecretKey == "" {
		return fmt.Errorf("JwtSecretKey is required when TokenStyle is JWT")
	}

	// Check Timeout
	if c.Timeout < NoLimit {
		return fmt.Errorf("Timeout must be >= -1, got: %d", c.Timeout)
	}

	// Check MaxRefresh
	if c.MaxRefresh < NoLimit {
		return fmt.Errorf("MaxRefresh must be >= -1, got: %d", c.MaxRefresh)
	}

	// Adjust MaxRefresh if it exceeds Timeout | 如果 MaxRefresh 大于 Timeout，则自动调整为 Timeout/2
	if c.Timeout != NoLimit && c.MaxRefresh > c.Timeout {
		c.MaxRefresh = c.Timeout / 2
		if c.MaxRefresh < 1 {
			c.MaxRefresh = 1
		}
	}

	// Check RenewInterval
	if c.RenewInterval < NoLimit {
		return fmt.Errorf("RenewInterval must be >= -1, got: %d", c.RenewInterval)
	}

	// Check ActiveTimeout
	if c.ActiveTimeout < NoLimit {
		return fmt.Errorf("ActiveTimeout must be >= -1, got: %d", c.ActiveTimeout)
	}

	// Check MaxLoginCount
	if c.MaxLoginCount < NoLimit {
		return fmt.Errorf("MaxLoginCount must be >= -1, got: %d", c.MaxLoginCount)
	}

	// Check if at least one read source is enabled
	if !c.IsReadHeader && !c.IsReadCookie && !c.IsReadBody {
		return fmt.Errorf("at least one of IsReadHeader, IsReadCookie, or IsReadBody must be true")
	}

	// Validate RenewPoolConfig if set | 如果设置了续期池配置，进行验证
	if c.RenewPoolConfig != nil {
		// Check MinSize and MaxSize | 检查最小和最大协程池大小
		if c.RenewPoolConfig.MinSize <= 0 {
			return fmt.Errorf("RenewPoolConfig.MinSize must be > 0") // 最小协程池大小必须大于0
		}
		if c.RenewPoolConfig.MaxSize < c.RenewPoolConfig.MinSize {
			return fmt.Errorf("RenewPoolConfig.MaxSize must be >= RenewPoolConfig.MinSize") // 最大协程池大小必须大于等于最小协程池大小
		}

		// Check ScaleUpRate and ScaleDownRate | 检查扩容和缩容阈值
		if c.RenewPoolConfig.ScaleUpRate <= 0 || c.RenewPoolConfig.ScaleUpRate > 1 {
			return fmt.Errorf("RenewPoolConfig.ScaleUpRate must be between 0 and 1") // 扩容阈值必须在0和1之间
		}
		if c.RenewPoolConfig.ScaleDownRate < 0 || c.RenewPoolConfig.ScaleDownRate > 1 {
			return fmt.Errorf("RenewPoolConfig.ScaleDownRate must be between 0 and 1") // 缩容阈值必须在0和1之间
		}

		// Check CheckInterval | 检查检查间隔
		if c.RenewPoolConfig.CheckInterval <= 0 {
			return fmt.Errorf("RenewPoolConfig.CheckInterval must be a positive duration") // 检查间隔必须是一个正值
		}

		// Check Expiry | 检查过期时间
		if c.RenewPoolConfig.Expiry <= 0 {
			return fmt.Errorf("RenewPoolConfig.Expiry must be a positive duration") // 过期时间必须是正值
		}
	}

	return nil
}

// Clone Clone configuration | 克隆配置
func (c *Config) Clone() *Config {
	newConfig := *c
	if c.CookieConfig != nil {
		cookieConfig := *c.CookieConfig
		newConfig.CookieConfig = &cookieConfig
	}
	return &newConfig
}

// SetTokenName Set Token name | 设置Token名称
func (c *Config) SetTokenName(name string) *Config {
	c.TokenName = name
	return c
}

// SetTimeout Set timeout duration | 设置超时时间
func (c *Config) SetTimeout(timeout int64) *Config {
	c.Timeout = timeout
	return c
}

// SetMaxRefresh Set threshold for async token renewal | 设置Token自动续期触发阈值
func (c *Config) SetMaxRefresh(refresh int64) *Config {
	c.MaxRefresh = refresh
	return c
}

// SetRenewInterval Set minimum interval between token renewals | 设置Token最小续期间隔
func (c *Config) SetRenewInterval(interval int64) *Config {
	c.RenewInterval = interval
	return c
}

// SetActiveTimeout Set active timeout duration | 设置活跃超时时间
func (c *Config) SetActiveTimeout(timeout int64) *Config {
	c.ActiveTimeout = timeout
	return c
}

// SetIsConcurrent Set whether to allow concurrent login | 设置是否允许并发登录
func (c *Config) SetIsConcurrent(isConcurrent bool) *Config {
	c.IsConcurrent = isConcurrent
	return c
}

// SetIsShare Set whether to share Token | 设置是否共享Token
func (c *Config) SetIsShare(isShare bool) *Config {
	c.IsShare = isShare
	return c
}

// SetMaxLoginCount Set maximum login count | 设置最大登录数量
func (c *Config) SetMaxLoginCount(count int) *Config {
	c.MaxLoginCount = count
	return c
}

// SetIsReadBody Set whether to read Token from body | 设置是否从请求体读取Token
func (c *Config) SetIsReadBody(isReadBody bool) *Config {
	c.IsReadBody = isReadBody
	return c
}

// SetIsReadHeader Set whether to read Token from header | 设置是否从Header读取Token
func (c *Config) SetIsReadHeader(isReadHeader bool) *Config {
	c.IsReadHeader = isReadHeader
	return c
}

// SetIsReadCookie Set whether to read Token from cookie | 设置是否从Cookie读取Token
func (c *Config) SetIsReadCookie(isReadCookie bool) *Config {
	c.IsReadCookie = isReadCookie
	return c
}

// SetTokenStyle Set Token generation style | 设置Token风格
func (c *Config) SetTokenStyle(style TokenStyle) *Config {
	c.TokenStyle = style
	return c
}

// SetDataRefreshPeriod Set data refresh period | 设置数据刷新周期
func (c *Config) SetDataRefreshPeriod(period int64) *Config {
	c.DataRefreshPeriod = period
	return c
}

// SetTokenSessionCheckLogin Set whether to check token session on login | 设置登录时是否检查token会话
func (c *Config) SetTokenSessionCheckLogin(check bool) *Config {
	c.TokenSessionCheckLogin = check
	return c
}

// SetJwtSecretKey Set JWT secret key | 设置JWT密钥
func (c *Config) SetJwtSecretKey(key string) *Config {
	c.JwtSecretKey = key
	return c
}

// SetAutoRenew Set whether to auto-renew Token | 设置是否自动续期
func (c *Config) SetAutoRenew(autoRenew bool) *Config {
	c.AutoRenew = autoRenew
	return c
}

// SetIsLog Set whether to enable logging | 设置是否输出日志
func (c *Config) SetIsLog(isLog bool) *Config {
	c.IsLog = isLog
	return c
}

// SetIsPrintBanner Set whether to print banner | 设置是否打印Banner
func (c *Config) SetIsPrintBanner(isPrint bool) *Config {
	c.IsPrintBanner = isPrint
	return c
}

// SetKeyPrefix Set storage key prefix | 设置存储键前缀
func (c *Config) SetKeyPrefix(prefix string) *Config {
	c.KeyPrefix = prefix
	return c
}

// SetCookieConfig Set cookie configuration | 设置Cookie配置
func (c *Config) SetCookieConfig(cookieConfig *CookieConfig) *Config {
	c.CookieConfig = cookieConfig
	return c
}

// SetRenewPoolConfig Set renewal pool configuration | 设置续期池配置
func (c *Config) SetRenewPoolConfig(renewPoolConfig *pool.RenewPoolConfig) *Config {
	c.RenewPoolConfig = renewPoolConfig
	return c
}
