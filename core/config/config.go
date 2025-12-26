package config

import (
	"fmt"
	"github.com/click33/sa-token-go/core/adapter"
	"strings"
)

// Config Sa-Token configuration | Sa-Token配置
type Config struct {
	// TokenName Token name (also used as Cookie name) | Token名称（同时也是Cookie名称）
	TokenName string

	// Timeout Token expiration time (in seconds); -1 means never expire | Token超时时间（单位：秒，-1代表永不过期）
	Timeout int64

	// MaxRefresh Threshold (in seconds) to trigger async token renewal; when remaining lifetime is below this, renewal is triggered; -1 means no limit | Token自动续期触发阈值（单位：秒，当剩余有效期低于该值时触发异步续期，-1代表不限制）
	MaxRefresh int64

	// RenewInterval Minimum interval (in seconds) between two renewals for the same token; -1 means no limit | 同一Token两次续期的最小间隔时间（单位：秒，-1代表不限制）
	RenewInterval int64

	// ActiveTimeout Maximum inactivity duration (in seconds); if the Token is not accessed within this time, it will be frozen. -1 means no limit | Token最大不活跃时长（单位：秒），超过此时间未访问则被踢出，-1代表不限制
	ActiveTimeout int64

	// IsConcurrent Allow concurrent login for the same account (true=allow, false=new login kicks old) | 是否允许同一账号并发登录（true=允许并发，false=新登录挤掉旧登录）
	IsConcurrent bool

	// IsShare Share the same Token for concurrent logins (true=share one, false=create new for each login) | 并发登录是否共用同一个Token（true=共用一个，false=每次登录新建一个）
	IsShare bool

	// MaxLoginCount Maximum concurrent login count for the same account; -1 means unlimited (only effective when IsConcurrent=true and IsShare=false) | 同一账号最大登录数量，-1代表不限（仅当IsConcurrent=true且IsShare=false时生效）
	MaxLoginCount int64

	// IsReadBody Try to read Token from the request body (log: false) | 是否尝试从请求体读取Token（默认：false）
	IsReadBody bool

	// IsReadHeader Try to read Token from the HTTP Header (log: true, recommended) | 是否尝试从Header读取Token（默认：true，推荐）
	IsReadHeader bool

	// IsReadCookie Try to read Token from the Cookie (log: false) | 是否尝试从Cookie读取Token（默认：false）
	IsReadCookie bool

	// TokenStyle Token generation style | Token生成风格
	TokenStyle adapter.TokenStyle

	// TokenSessionCheckLogin Whether to check if Token-Session is kicked out when logging in (true=check, false=skip) | 登录时是否检查Token-Session是否被踢下线（true=检查，false=不检查）
	TokenSessionCheckLogin bool

	// AutoRenew Automatically renew Token expiration time on each validation | 是否在每次验证Token时自动续期（延长Token有效期）
	AutoRenew bool

	// JwtSecretKey Secret key for JWT mode (effective only when TokenStyle=JWT) | JWT模式的密钥（仅当TokenStyle=JWT时生效）
	JwtSecretKey string

	// IsLog Enable operation logging | 是否开启操作日志
	IsLog bool

	// IsPrintBanner Print the startup banner (log: true) | 是否打印启动Banner（默认：true）
	IsPrintBanner bool

	// KeyPrefix Storage key prefix for Storage isolation | 存储键前缀
	KeyPrefix string

	// CookieConfig Cookie configuration | Cookie配置
	CookieConfig *CookieConfig

	// Authentication system type | 认证体系类型
	AuthType string
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
	MaxAge int64
}

// DefaultConfig Returns log configuration | 返回默认配置
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
		TokenStyle:             adapter.TokenStyleUUID,
		TokenSessionCheckLogin: true,
		AutoRenew:              true,
		JwtSecretKey:           "",
		IsLog:                  false,
		IsPrintBanner:          true,
		KeyPrefix:              DefaultKeyPrefix,
		CookieConfig:           DefaultCookieConfig(),
		AuthType:               DefaultAuthType,
	}
}

// Validate validates the configuration | 验证配置是否合理
func (c *Config) Validate() error {
	// Check TokenStyle validity | 检查 Token 风格是否合法
	if !c.TokenStyle.IsValid() {
		return fmt.Errorf("invalid TokenStyle: %s", c.TokenStyle)
	}

	// Validate numeric fields that must be -1 (no limit) or >0 (valid) | 验证必须为-1（无限制）或>0（有效）的数值字段
	if err := c.checkNoLimits(); err != nil {
		return err
	}

	// Check TokenName | 检查 Token 名称
	if c.TokenName == "" {
		return fmt.Errorf("TokenName cannot be empty")
	}

	// Check JwtSecretKey if TokenStyle is JWT | 如果 Token 风格为 JWT，则检查密钥是否设置
	if c.TokenStyle == adapter.TokenStyleJWT && c.JwtSecretKey == "" {
		return fmt.Errorf("JwtSecretKey is required when TokenStyle is JWT")
	}

	// MaxRefresh must not exceed Timeout | MaxRefresh 不能大于 Timeout
	if c.Timeout != NoLimit && c.MaxRefresh > c.Timeout {
		return fmt.Errorf(
			"MaxRefresh (%d) must be <= Timeout (%d)",
			c.MaxRefresh,
			c.Timeout,
		)
	}

	// RenewInterval must not exceed MaxRefresh | RenewInterval 不能大于 MaxRefresh
	if c.MaxRefresh != NoLimit && c.RenewInterval != NoLimit && c.RenewInterval > c.MaxRefresh {
		return fmt.Errorf(
			"RenewInterval (%d) must be <= MaxRefresh (%d)",
			c.RenewInterval,
			c.MaxRefresh,
		)
	}

	// Check if at least one read source is enabled | 检查是否至少启用了一个 Token 读取来源
	if !c.IsReadHeader && !c.IsReadCookie && !c.IsReadBody {
		return fmt.Errorf("at least one of IsReadHeader, IsReadCookie, or IsReadBody must be true")
	}

	// Check KeyPrefix validity | 检查 KeyPrefix 合法性
	if c.KeyPrefix == "" {
		return fmt.Errorf("KeyPrefix cannot be empty") // KeyPrefix不能为空
	}
	if strings.ContainsAny(c.KeyPrefix, " \t\r\n") {
		return fmt.Errorf("KeyPrefix cannot contain whitespace characters, got: %q", c.KeyPrefix)
	}
	if len(c.KeyPrefix) > 64 {
		return fmt.Errorf("KeyPrefix too long (max 64 chars), got length: %d", len(c.KeyPrefix))
	}

	// Check authType validity | 校验 AuthType 的合法性
	if c.AuthType == "" {
		return fmt.Errorf("AuthType cannot be empty") // AuthType不能为空
	}
	if strings.ContainsAny(c.AuthType, " \t\r\n") {
		return fmt.Errorf("AuthType cannot contain whitespace characters, got: %q", c.AuthType)
	}
	if len(c.AuthType) > 64 {
		return fmt.Errorf("AuthType too long (max 64 chars), got length: %d", len(c.AuthType))
	}

	// Validate CookieConfig if set | 验证 Cookie 配置（如果设置）
	if c.CookieConfig != nil {
		// Check Path | 检查路径
		if c.CookieConfig.Path == "" {
			return fmt.Errorf("CookieConfig.Path cannot be empty")
		}
		// Check SameSite | 检查 SameSite 值是否合法
		switch c.CookieConfig.SameSite {
		case SameSiteLax, SameSiteStrict, SameSiteNone:
		default:
			return fmt.Errorf("invalid CookieConfig.SameSite value: %v", c.CookieConfig.SameSite)
		}
	}

	// All checks passed | 所有配置验证通过
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
func (c *Config) SetMaxLoginCount(count int64) *Config {
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
func (c *Config) SetTokenStyle(style adapter.TokenStyle) *Config {
	c.TokenStyle = style
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
	if cookieConfig != nil {
		c.CookieConfig = cookieConfig
	}
	return c
}

// SetAuthType Set authentication system type | 设置认证体系类型
func (c *Config) SetAuthType(authType string) *Config {
	c.AuthType = authType
	return c
}

// ============ Internal Helper Methods | 内部辅助方法 ============

// checkNoLimits validates that all numeric fields must be -1 (no limit) or >0 (valid) | 验证所有数值字段必须为 -1（无限制）或 >0（有效）
func (c *Config) checkNoLimits() error {
	// Define fields to validate | 定义需要验证的字段
	fields := map[string]int64{
		"Timeout":       c.Timeout,
		"MaxRefresh":    c.MaxRefresh,
		"RenewInterval": c.RenewInterval,
		"ActiveTimeout": c.ActiveTimeout,
		"MaxLoginCount": c.MaxLoginCount,
	}

	// Iterate through fields and validate each one | 遍历字段并验证
	for name, value := range fields {
		// Must be -1 (no limit) or >0 (valid) | 必须为 -1（无限制）或 >0（有效）
		if value == -1 || value > 0 {
			continue
		}

		// Return error if invalid | 若不合法则返回错误
		return fmt.Errorf("%s must be -1 (no limit) or >0 (valid), got: %d", name, value)
	}

	// All numeric fields are valid | 所有数值字段均验证通过
	return nil
}

// DefaultCookieConfig returns the log Cookie configuration | 返回默认的 Cookie 配置
func DefaultCookieConfig() *CookieConfig {
	return &CookieConfig{
		Domain:   "",
		Path:     DefaultCookiePath,
		Secure:   false,
		HttpOnly: true,
		SameSite: SameSiteLax,
		MaxAge:   0,
	}
}
