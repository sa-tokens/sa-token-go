package builder

import (
	"github.com/click33/sa-token-go/core/codec"
	"github.com/click33/sa-token-go/core/dep"
	"github.com/click33/sa-token-go/core/log"
	"github.com/click33/sa-token-go/core/pool"
	"strings"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/banner"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
)

// Builder provides fluent configuration for Sa-Token | Sa-Token 构建器用于流式配置
type Builder struct {
	storage                adapter.Storage       // Storage adapter | 存储适配器
	tokenName              string                // Token name used by client | 客户端 Token 名称
	timeout                int64                 // Token timeout seconds | Token 过期时间（秒）
	maxRefresh             int64                 // Max auto-refresh duration | 最大无感刷新时间
	renewInterval          int64                 // Min renewal interval seconds | 最小续期间隔（秒）
	activeTimeout          int64                 // Force offline when idle | 活跃超时时间（秒）
	isConcurrent           bool                  // Allow concurrent login | 是否允许并发登录
	isShare                bool                  // Share same token among devices | 是否共用 Token
	maxLoginCount          int64                 // Max concurrent login count | 最大并发登录数
	tokenStyle             config.TokenStyle     // Token generation style | Token 生成方式
	autoRenew              bool                  // Enable renewal | 是否启用自动续期
	jwtSecretKey           string                // JWT secret key | JWT 密钥
	isLog                  bool                  // Enable log output | 是否启用日志
	isPrintBanner          bool                  // Print startup banner | 是否打印启动 Banner
	isReadBody             bool                  // Read token from body | 是否从 Body 读取 Token
	isReadHeader           bool                  // Read token from header | 是否从 Header 读取 Token
	isReadCookie           bool                  // Read token from cookie | 是否从 Cookie 读取 Token
	tokenSessionCheckLogin bool                  // Check login before Session | 读取 Session 时是否检查登录
	keyPrefix              string                // Storage key prefix | 存储键前缀
	cookieConfig           *config.CookieConfig  // Cookie config | Cookie 配置
	renewPoolConfig        *pool.RenewPoolConfig // Renew pool config | 续期协程池配置
	authType               string                // Authentication system type | 认证体系类型
	codec                  codec.Adapter         // codec Codec adapter for encoding and decoding operations | 编解码操作的编码器适配器
	log                    log.Adapter           // log Log adapter for logging operations | 日志记录操作的适配器
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
		tokenSessionCheckLogin: true,
		keyPrefix:              config.DefaultKeyPrefix,
		cookieConfig:           config.DefaultCookieConfig(),
		renewPoolConfig:        pool.DefaultRenewPoolConfig(),
		authType:               config.DefaultAuthType,
		codec:                  codec.GetDefaultSerializer(),
		log:                    log.GetDefaultLogger(),
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
func (b *Builder) MaxLoginCount(count int64) *Builder {
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
func (b *Builder) CookieMaxAge(maxAge int64) *Builder {
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

// RenewPoolMinSize sets the minimum pool size | 设置最小协程数
func (b *Builder) RenewPoolMinSize(size int) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.MinSize = size
	return b
}

// RenewPoolMaxSize sets the maximum pool size | 设置最大协程数
func (b *Builder) RenewPoolMaxSize(size int) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.MaxSize = size
	return b
}

// RenewPoolScaleUpRate sets the scale-up threshold | 设置扩容阈值
func (b *Builder) RenewPoolScaleUpRate(rate float64) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.ScaleUpRate = rate
	return b
}

// RenewPoolScaleDownRate sets the scale-down threshold | 设置缩容阈值
func (b *Builder) RenewPoolScaleDownRate(rate float64) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.ScaleDownRate = rate
	return b
}

// RenewPoolCheckInterval sets the interval for auto-scale checking | 设置自动扩缩容检查间隔
func (b *Builder) RenewPoolCheckInterval(interval time.Duration) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.CheckInterval = interval
	return b
}

// RenewPoolExpiry sets the idle worker expiry duration | 设置空闲协程过期时间
func (b *Builder) RenewPoolExpiry(duration time.Duration) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.Expiry = duration
	return b
}

// RenewPoolPrintStatusInterval sets the status printing interval | 设置状态打印间隔
func (b *Builder) RenewPoolPrintStatusInterval(interval time.Duration) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.PrintStatusInterval = interval
	return b
}

// RenewPoolPreAlloc sets whether to pre-allocate memory | 设置是否预分配内存
func (b *Builder) RenewPoolPreAlloc(preAlloc bool) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.PreAlloc = preAlloc
	return b
}

// RenewPoolNonBlocking sets whether the pool works in non-blocking mode | 设置是否为非阻塞模式
func (b *Builder) RenewPoolNonBlocking(nonBlocking bool) *Builder {
	if b.renewPoolConfig == nil {
		b.renewPoolConfig = pool.DefaultRenewPoolConfig()
	}
	b.renewPoolConfig.NonBlocking = nonBlocking
	return b
}

// RenewPoolConfig sets the token renewal pool configuration | 设置完整的Token续期池配置
func (b *Builder) RenewPoolConfig(cfg *pool.RenewPoolConfig) *Builder {
	b.renewPoolConfig = cfg
	return b
}

// SetCodec sets the codec for encoding and decoding operations | 设置编解码器适配器
func (b *Builder) SetCodec(codec codec.Adapter) *Builder {
	b.codec = codec
	return b
}

// SetLog sets the log adapter for logging operations | 设置日志记录适配器
func (b *Builder) SetLog(log log.Adapter) *Builder {
	b.log = log
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

// AuthType sets authentication system type | 设置认证体系类型
func (b *Builder) AuthType(authType string) *Builder {
	// 如果前缀不为空且不以 : 结尾，自动添加 :
	if authType != "" && !strings.HasSuffix(authType, ":") {
		b.authType = authType + ":"
	} else {
		b.authType = authType
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

// NoBanner disables startup banner printing | 禁用启动Banner打印
func (b *Builder) NoBanner() *Builder {
	b.isPrintBanner = false
	return b
}

// NoLog disables log output | 禁用日志输出
func (b *Builder) NoLog() *Builder {
	b.isLog = false
	return b
}

// DisableAutoRenew disables token auto-renewal | 禁用Token自动续期
func (b *Builder) DisableAutoRenew() *Builder {
	b.autoRenew = false
	return b
}

// Jwt sets TokenStyle to JWT and sets secret key | 设置为JWT模式并指定密钥
func (b *Builder) Jwt(secret string) *Builder {
	b.tokenStyle = config.TokenStyleJWT
	b.jwtSecretKey = secret
	return b
}

// Clone creates a deep copy of the builder | 克隆当前构建器
func (b *Builder) Clone() *Builder {
	clone := *b
	if b.cookieConfig != nil {
		cookieCopy := *b.cookieConfig
		clone.cookieConfig = &cookieCopy
	}
	if b.renewPoolConfig != nil {
		poolCopy := *b.renewPoolConfig
		clone.renewPoolConfig = &poolCopy
	}
	return &clone
}

// Build builds Manager and prints startup banner | 构建Manager并打印启动Banner
func (b *Builder) Build() *manager.Manager {
	// Validate storage | 验证存储
	if b.storage == nil {
		panic("storage cannot be nil") // storage 不能为空
	}

	// Validate codec | 验证codec
	if b.codec == nil {
		panic("codec cannot be nil") // codec 不能为空
	}

	// Validate log | 验证log
	if b.log == nil {
		panic("log cannot be nil") // log 不能为空
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
		TokenSessionCheckLogin: b.tokenSessionCheckLogin,
		AutoRenew:              b.autoRenew,
		JwtSecretKey:           b.jwtSecretKey,
		IsLog:                  b.isLog,
		IsPrintBanner:          b.isPrintBanner,
		KeyPrefix:              b.keyPrefix,
		CookieConfig:           b.cookieConfig,
		RenewPoolConfig:        b.renewPoolConfig,
		AuthType:               b.authType,
	}

	// Validate configuration | 验证配置
	err := cfg.Validate()
	if err != nil {
		panic(err)
	}

	// Print startup banner with full configuration | 打印启动Banner和完整配置
	if b.isPrintBanner {
		banner.PrintWithConfig(cfg)
	}

	// Build Manager | 构建 Manager
	mgr := manager.NewManager(cfg, b.storage, dep.NewDefaultDep(b.codec, b.log))

	// Note: If you use the stputil package, it will automatically set the global Manager | 注意：如果你使用了 stputil 包，它会自动设置全局 Manager
	// We don't directly call stputil.SetManager here to avoid hard dependencies | 这里不直接调用 stputil.SetManager，避免强依赖
	return mgr
}

// MustBuild builds Manager and panics if validation fails | 构建Manager，验证失败时panic
func (b *Builder) MustBuild() *manager.Manager {
	return b.Build()
}
