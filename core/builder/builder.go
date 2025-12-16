package builder

import (
	"fmt"
	"github.com/click33/sa-token-go/core/pool"
	"strings"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/banner"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
)

// Builder Sa-Token builder for fluent configuration | Sa-Token构建器，用于流式配置
type Builder struct {
	storage                adapter.Storage
	tokenName              string
	timeout                int64
	maxRefresh             int64
	renewInterval          int64
	activeTimeout          int64
	isConcurrent           bool
	isShare                bool
	maxLoginCount          int
	tokenStyle             config.TokenStyle
	autoRenew              bool
	jwtSecretKey           string
	isLog                  bool
	isPrintBanner          bool
	isReadBody             bool
	isReadHeader           bool
	isReadCookie           bool
	dataRefreshPeriod      int64
	tokenSessionCheckLogin bool
	keyPrefix              string
	cookieConfig           *config.CookieConfig
	renewPoolConfig        *pool.RenewPoolConfig
}

// NewBuilder creates a new builder with default configuration | 创建新的构建器（使用默认配置）
func NewBuilder() *Builder {
	return &Builder{
		tokenName:              config.DefaultTokenName,
		timeout:                config.DefaultTimeout,
		maxRefresh:             config.DefaultTimeout / 2,
		renewInterval:          config.NoLimit,
		activeTimeout:          config.NoLimit,
		isConcurrent:           true,
		isShare:                true,
		maxLoginCount:          config.DefaultMaxLoginCount,
		tokenStyle:             config.TokenStyleUUID,
		autoRenew:              true,
		isLog:                  false,
		isPrintBanner:          true,
		isReadBody:             false,
		isReadHeader:           true,
		isReadCookie:           false,
		dataRefreshPeriod:      config.NoLimit,
		tokenSessionCheckLogin: true,
		keyPrefix:              "satoken:",
		cookieConfig: &config.CookieConfig{
			Domain:   "",
			Path:     config.DefaultCookiePath,
			Secure:   false,
			HttpOnly: true,
			SameSite: config.SameSiteLax,
			MaxAge:   0,
		},
	}
}

// Storage sets storage adapter | 设置存储适配器
func (b *Builder) Storage(storage adapter.Storage) *Builder {
	b.storage = storage
	return b
}

// TokenName sets token name | 设置Token名称
func (b *Builder) TokenName(name string) *Builder {
	b.tokenName = name
	return b
}

// Timeout sets timeout in seconds | 设置超时时间（秒）
func (b *Builder) Timeout(seconds int64) *Builder {
	b.timeout = seconds
	return b
}

// TimeoutDuration sets timeout with duration | 设置超时时间（时间段）
func (b *Builder) TimeoutDuration(d time.Duration) *Builder {
	b.timeout = int64(d.Seconds())
	return b
}

// MaxRefresh sets threshold for async token renewal | 设置Token自动续期触发阈值
func (b *Builder) MaxRefresh(seconds int64) *Builder {
	b.maxRefresh = seconds
	return b
}

// RenewInterval sets minimum interval between token renewals | 设置Token最小续期间隔
func (b *Builder) RenewInterval(seconds int64) *Builder {
	b.renewInterval = seconds
	return b
}

// ActiveTimeout sets active timeout in seconds | 设置活跃超时（秒）
func (b *Builder) ActiveTimeout(seconds int64) *Builder {
	b.activeTimeout = seconds
	return b
}

// IsConcurrent sets whether to allow concurrent login | 设置是否允许并发登录
func (b *Builder) IsConcurrent(concurrent bool) *Builder {
	b.isConcurrent = concurrent
	return b
}

// IsShare sets whether to share token | 设置是否共享Token
func (b *Builder) IsShare(share bool) *Builder {
	b.isShare = share
	return b
}

// MaxLoginCount sets maximum login count | 设置最大登录数量
func (b *Builder) MaxLoginCount(count int) *Builder {
	b.maxLoginCount = count
	return b
}

// TokenStyle sets token generation style | 设置Token风格
func (b *Builder) TokenStyle(style config.TokenStyle) *Builder {
	b.tokenStyle = style
	return b
}

// AutoRenew sets whether to auto-renew token | 设置是否自动续期
func (b *Builder) AutoRenew(autoRenew bool) *Builder {
	b.autoRenew = autoRenew
	return b
}

// JwtSecretKey sets JWT secret key | 设置JWT密钥
func (b *Builder) JwtSecretKey(key string) *Builder {
	b.jwtSecretKey = key
	return b
}

// IsLog sets whether to enable logging | 设置是否输出日志
func (b *Builder) IsLog(isLog bool) *Builder {
	b.isLog = isLog
	return b
}

// IsPrintBanner sets whether to print startup banner | 设置是否打印启动Banner
func (b *Builder) IsPrintBanner(isPrint bool) *Builder {
	b.isPrintBanner = isPrint
	return b
}

// IsReadBody sets whether to read token from request body | 设置是否从请求体读取Token
func (b *Builder) IsReadBody(isRead bool) *Builder {
	b.isReadBody = isRead
	return b
}

// IsReadHeader sets whether to read token from header | 设置是否从Header读取Token
func (b *Builder) IsReadHeader(isRead bool) *Builder {
	b.isReadHeader = isRead
	return b
}

// IsReadCookie sets whether to read token from cookie | 设置是否从Cookie读取Token
func (b *Builder) IsReadCookie(isRead bool) *Builder {
	b.isReadCookie = isRead
	return b
}

// DataRefreshPeriod sets data refresh period | 设置数据刷新周期
func (b *Builder) DataRefreshPeriod(seconds int64) *Builder {
	b.dataRefreshPeriod = seconds
	return b
}

// TokenSessionCheckLogin sets whether to check token session on login | 设置登录时是否检查Token会话
func (b *Builder) TokenSessionCheckLogin(check bool) *Builder {
	b.tokenSessionCheckLogin = check
	return b
}

// CookieDomain sets cookie domain | 设置Cookie域名
func (b *Builder) CookieDomain(domain string) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.Domain = domain
	return b
}

// CookiePath sets cookie path | 设置Cookie路径
func (b *Builder) CookiePath(path string) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.Path = path
	return b
}

// CookieSecure sets cookie secure flag | 设置Cookie的Secure标志
func (b *Builder) CookieSecure(secure bool) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.Secure = secure
	return b
}

// CookieHttpOnly sets cookie httpOnly flag | 设置Cookie的HttpOnly标志
func (b *Builder) CookieHttpOnly(httpOnly bool) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.HttpOnly = httpOnly
	return b
}

// CookieSameSite sets cookie sameSite attribute | 设置Cookie的SameSite属性
func (b *Builder) CookieSameSite(sameSite config.SameSiteMode) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.SameSite = sameSite
	return b
}

// CookieMaxAge sets cookie max age | 设置Cookie的最大年龄
func (b *Builder) CookieMaxAge(maxAge int) *Builder {
	if b.cookieConfig == nil {
		b.cookieConfig = &config.CookieConfig{}
	}
	b.cookieConfig.MaxAge = maxAge
	return b
}

// CookieConfig sets complete cookie configuration | 设置完整的Cookie配置
func (b *Builder) CookieConfig(cfg *config.CookieConfig) *Builder {
	b.cookieConfig = cfg
	return b
}

// RenewPoolConfig sets the token renewal pool configuration | 设置Token续期池配置
func (b *Builder) RenewPoolConfig(cfg *pool.RenewPoolConfig) *Builder {
	b.renewPoolConfig = cfg
	return b
}

// KeyPrefix sets storage key prefix | 设置存储键前缀
// Automatically adds ":" suffix if not present (except for empty string) | 自动添加 ":" 后缀（空字符串除外）
// Examples: "satoken" -> "satoken:", "myapp" -> "myapp:", "" -> ""
// Use empty string "" for Java sa-token compatibility | 使用空字符串 "" 兼容 Java sa-token
func (b *Builder) KeyPrefix(prefix string) *Builder {
	// 如果前缀不为空且不以 : 结尾，自动添加 :
	if prefix != "" && !strings.HasSuffix(prefix, ":") {
		b.keyPrefix = prefix + ":"
	} else {
		b.keyPrefix = prefix
	}
	return b
}

// NeverExpire sets token to never expire | 设置Token永不过期
func (b *Builder) NeverExpire() *Builder {
	b.timeout = config.NoLimit
	return b
}

// NoActiveTimeout disables active timeout | 禁用活跃超时
func (b *Builder) NoActiveTimeout() *Builder {
	b.activeTimeout = config.NoLimit
	return b
}

// UnlimitedLogin allows unlimited concurrent logins | 允许无限并发登录
func (b *Builder) UnlimitedLogin() *Builder {
	b.maxLoginCount = config.NoLimit
	return b
}

// Validate validates the builder configuration | 验证构建器配置
func (b *Builder) Validate() error {
	if b.storage == nil {
		return fmt.Errorf("storage is required, please call Storage() method")
	}

	if b.tokenName == "" {
		return fmt.Errorf("tokenName cannot be empty")
	}

	if b.tokenStyle == config.TokenStyleJWT && b.jwtSecretKey == "" {
		return fmt.Errorf("jwtSecretKey is required when TokenStyle is JWT")
	}

	if !b.isReadHeader && !b.isReadCookie && !b.isReadBody {
		return fmt.Errorf("at least one of IsReadHeader, IsReadCookie, or IsReadBody must be true")
	}

	// Check MaxRefresh
	if b.maxRefresh < config.NoLimit {
		return fmt.Errorf("MaxRefresh must be >= -1, got: %d", b.maxRefresh)
	}

	// Adjust MaxRefresh if it exceeds Timeout | 如果 MaxRefresh 大于 Timeout，则自动调整为 Timeout/2
	if b.timeout != config.NoLimit && b.maxRefresh > b.timeout {
		b.maxRefresh = b.timeout / 2
		if b.maxRefresh < 1 {
			b.maxRefresh = 1
		}
	}

	// Check RenewInterval
	if b.renewInterval < config.NoLimit {
		return fmt.Errorf("RenewInterval must be >= -1, got: %d", b.renewInterval)
	}

	// Validate RenewPoolConfig if set | 如果设置了续期池配置，进行验证
	if b.renewPoolConfig != nil {
		// Check MinSize and MaxSize | 检查最小和最大协程池大小
		if b.renewPoolConfig.MinSize <= 0 {
			return fmt.Errorf("RenewPoolConfig.MinSize must be > 0") // 最小协程池大小必须大于0
		}
		if b.renewPoolConfig.MaxSize < b.renewPoolConfig.MinSize {
			return fmt.Errorf("RenewPoolConfig.MaxSize must be >= RenewPoolConfig.MinSize") // 最大协程池大小必须大于等于最小协程池大小
		}

		// Check ScaleUpRate and ScaleDownRate | 检查扩容和缩容阈值
		if b.renewPoolConfig.ScaleUpRate <= 0 || b.renewPoolConfig.ScaleUpRate > 1 {
			return fmt.Errorf("RenewPoolConfig.ScaleUpRate must be between 0 and 1") // 扩容阈值必须在0和1之间
		}
		if b.renewPoolConfig.ScaleDownRate < 0 || b.renewPoolConfig.ScaleDownRate > 1 {
			return fmt.Errorf("RenewPoolConfig.ScaleDownRate must be between 0 and 1") // 缩容阈值必须在0和1之间
		}

		// Check CheckInterval | 检查检查间隔
		if b.renewPoolConfig.CheckInterval <= 0 {
			return fmt.Errorf("RenewPoolConfig.CheckInterval must be a positive duration") // 检查间隔必须是一个正值
		}

		// Check Expiry | 检查过期时间
		if b.renewPoolConfig.Expiry <= 0 {
			return fmt.Errorf("RenewPoolConfig.Expiry must be a positive duration") // 过期时间必须是正值
		}
	}

	return nil
}

// Build builds Manager and prints startup banner | 构建Manager并打印启动Banner
func (b *Builder) Build() *manager.Manager {
	// Validate configuration | 验证配置
	if err := b.Validate(); err != nil {
		panic(fmt.Sprintf("invalid configuration: %v", err))
	}

	// Automatically adjust MaxRefresh if user customized Timeout but didn't set MaxRefresh | 自动调整MaxRefresh逻辑
	if b.timeout != config.DefaultTimeout && b.maxRefresh == config.DefaultTimeout/2 {
		b.maxRefresh = b.timeout / 2
	}

	cfg := &config.Config{
		TokenName:              b.tokenName,
		Timeout:                b.timeout,
		MaxRefresh:             b.maxRefresh,
		RenewInterval:          b.renewInterval,
		ActiveTimeout:          b.activeTimeout,
		IsConcurrent:           b.isConcurrent,
		IsShare:                b.isShare,
		MaxLoginCount:          b.maxLoginCount,
		IsReadBody:             b.isReadBody,
		IsReadHeader:           b.isReadHeader,
		IsReadCookie:           b.isReadCookie,
		TokenStyle:             b.tokenStyle,
		DataRefreshPeriod:      b.dataRefreshPeriod,
		TokenSessionCheckLogin: b.tokenSessionCheckLogin,
		AutoRenew:              b.autoRenew,
		JwtSecretKey:           b.jwtSecretKey,
		IsLog:                  b.isLog,
		IsPrintBanner:          b.isPrintBanner,
		KeyPrefix:              b.keyPrefix,
		CookieConfig:           b.cookieConfig,
		RenewPoolConfig:        b.renewPoolConfig,
	}

	// Print startup banner with full configuration | 打印启动Banner和完整配置
	// Only skip printing when both IsLog=false AND IsPrintBanner=false | 只有当 IsLog=false 且 IsPrintBanner=false 时才不打印
	if b.isPrintBanner || b.isLog {
		banner.PrintWithConfig(cfg)
	}

	mgr := manager.NewManager(b.storage, cfg)

	// Note: If you use the stputil package, it will automatically set the global Manager | 注意：如果你使用了 stputil 包，它会自动设置全局 Manager
	// We don't directly call stputil.SetManager here to avoid hard dependencies | 这里不直接调用 stputil.SetManager，避免强依赖

	return mgr
}

// MustBuild builds Manager and panics if validation fails | 构建Manager，验证失败时panic
func (b *Builder) MustBuild() *manager.Manager {
	return b.Build()
}
