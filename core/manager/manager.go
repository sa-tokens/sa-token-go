package manager

import (
	"context"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/utils"
	"github.com/click33/sa-token-go/generator/sgenerator"
	"github.com/click33/sa-token-go/log/nop"
	"github.com/click33/sa-token-go/pool/ants"
	"github.com/click33/sa-token-go/storage/memory"
	"strings"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/listener"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
)

// TokenInfo Token information | Token 信息
type TokenInfo struct {
	AuthType   string `json:"authType"`      // Authentication system type | 认证体系类型
	LoginID    string `json:"loginId"`       // Login ID | 登录 ID
	Device     string `json:"device"`        // Device type | 设备类型
	CreateTime int64  `json:"createTime"`    // Token creation timestamp | 创建时间戳
	ActiveTime int64  `json:"activeTime"`    // Last active time | 最后活跃时间戳
	Tag        string `json:"tag,omitempty"` // Custom tag for additional data | 自定义标记字段（可选）
}

// DisableInfo Account disable information | 封禁信息结构体
type DisableInfo struct {
	DisableTime   int64  `json:"disableTime"`   // Disable timestamp | 封禁时间戳
	DisableReason string `json:"disableReason"` // Reason for account disable | 账号封禁原因说明
}

// Manager Authentication manager-example | 认证管理器
type Manager struct {
	config         *config.Config                // Global authentication configuration | 全局认证配置
	nonceManager   *security.NonceManager        // Nonce manager-example for preventing replay attacks | 随机串管理器
	refreshManager *security.RefreshTokenManager // Refresh token manager-example | 刷新令牌管理器
	oauth2Server   *oauth2.OAuth2Server          // OAuth2 authorization server | OAuth2 授权服务器
	eventManager   *listener.Manager             // Event manager-example | 事件管理器

	generator  adapter.Generator // Token generator | Token 生成器
	storage    adapter.Storage   // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
	serializer adapter.Codec     // Codec adapter for encoding and decoding operations | 编解码器适配器
	logger     adapter.Log       // Log adapter for logging operations | 日志适配器
	pool       adapter.Pool      // Async task pool component | 异步任务协程池组件

	CustomPermissionListFunc func(loginID string) ([]string, error) // Custom permission func | 自定义权限获取函数
	CustomRoleListFunc       func(loginID string) ([]string, error) // Custom role func | 自定义角色获取函数
}

// NewManager creates and initializes a new Manager instance | 创建并初始化一个新的 Manager 实例
func NewManager(cfg *config.Config, generator adapter.Generator, storage adapter.Storage, serializer adapter.Codec, logger adapter.Log, pool adapter.Pool, customPermissionListFunc, CustomRoleListFunc func(loginID string) ([]string, error)) *Manager {

	// Use default configuration if cfg is nil | 如果未传入配置，则使用默认配置
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Initialize token generator if generator is nil | 如果未传入 Token 生成器，则创建默认生成器
	if generator == nil {
		generator = sgenerator.NewGenerator(cfg.Timeout, cfg.TokenStyle, cfg.JwtSecretKey)
	}

	// Use in-memory storage if storage is nil | 如果未传入存储实现，则使用内存存储
	if storage == nil {
		storage = memory.NewStorage()
	}

	// Use JSON serializer if serializer is nil | 如果未传入序列化器，则使用 JSON 序列化器
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	if cfg.IsLog && logger == nil {
		logger = nop.NewNopLogger()
	}

	if cfg.AutoRenew && pool == nil {
		// Use default goroutine pool if pool is nil | 如果未传入协程池，则使用默认协程池
		pool = ants.NewRenewPoolManagerWithDefaultConfig()
	}

	// Return the new manager-example instance with initialized sub-managers | 返回已初始化各子模块的管理器实例
	return &Manager{
		// Store global configuration | 保存全局配置
		config: cfg,

		// Token generator used for creating access/refresh tokens | 用于生成访问令牌和刷新令牌的生成器
		generator: generator,

		// Nonce manager-example for replay-attack protection | 防重放攻击的 Nonce 管理器
		nonceManager: security.NewNonceManager(
			cfg.AuthType,
			cfg.KeyPrefix,
			storage,
			DefaultNonceTTL,
		),

		// Refresh token manager-example for token renewal logic | 刷新令牌管理器，用于令牌续期逻辑
		refreshManager: security.NewRefreshTokenManager(
			cfg.AuthType,
			cfg.KeyPrefix,
			TokenKeyPrefix,
			generator,
			time.Duration(cfg.Timeout)*time.Second,
			storage,
			serializer,
		),

		// OAuth2 server for authorization and token exchange | OAuth2 授权与令牌颁发服务
		oauth2Server: oauth2.NewOAuth2Server(
			cfg.AuthType,
			cfg.KeyPrefix,
			storage,
			serializer,
		),

		// Event manager-example for lifecycle and auth events | 生命周期与认证事件管理器
		eventManager: listener.NewManager(logger),

		// Storage adapter for persistence layer | 持久化存储适配器
		storage: storage,

		// Serializer for encoding/decoding data | 数据编解码序列化器
		serializer: serializer,

		// Logger for internal logging | 内部日志记录器
		logger: logger,

		// Goroutine pool for async task execution | 用于异步任务执行的协程池
		pool: pool,

		// Custom permission list provider | 自定义权限列表获取函数
		CustomPermissionListFunc: customPermissionListFunc,

		// Custom role list provider | 自定义角色列表获取函数
		CustomRoleListFunc: CustomRoleListFunc,
	}
}

// CloseManager Closes the manager-example and releases all resources | 关闭管理器并释放所有资源
func (m *Manager) CloseManager() {
	// Close logger if it implements LogControl | 如果日志实现了 LogControl 接口，则关闭日志
	if logControl, ok := m.logger.(adapter.LogControl); ok {
		logControl.Flush()
		logControl.Close()
	}

	if m.pool != nil {
		// Safely close the renewPool | 安全关闭 renewPool
		m.pool.Stop()
		// Set renewPool to nil | 将 renewPool 设置为 nil
		m.pool = nil
	}
}

// ============ Login Authentication | 登录认证 ============

// Login Performs user login and returns token | 登录 返回Token
func (m *Manager) Login(ctx context.Context, loginID string, device ...string) (string, error) {
	// Check if account is disabled | 检查账号是否被封禁
	if m.IsDisable(ctx, loginID) {
		return "", core.ErrAccountDisabled
	}

	// Get device type | 获取设备类型
	deviceType := getDevice(device)

	// Get account key | 获取账号存储键
	accountKey := m.getAccountKey(loginID, deviceType)

	// Handle shared token for concurrent login | 处理多人登录共用 Token 的情况
	if m.config.IsShare {
		// Look for existing token of this account + device | 查找账号 + 设备下是否已有登录 Token
		existingToken, err := m.storage.Get(ctx, accountKey)
		if err == nil && existingToken != nil {
			if existingTokenStr, ok := assertString(existingToken); ok && m.IsLogin(ctx, existingTokenStr) {
				// If valid token exists, return it directly | 如果已有 Token 且有效，则直接返回
				return existingTokenStr, nil
			}
		}
	}

	// Handle concurrent login behavior | 处理并发登录逻辑
	if !m.config.IsConcurrent {
		// Concurrent login not allowed → replace previous login on the same device | 不允许并发登录 顶掉同设备下已存在的登录会话
		_ = m.replace(ctx, loginID, deviceType)

	} else if m.config.MaxLoginCount > 0 && !m.config.IsShare {
		// Concurrent login allowed but limited by MaxLoginCount | 允许并发登录但受 MaxLoginCount 限制
		tokens, _ := m.GetTokenValueListByLoginID(ctx, loginID)
		if int64(len(tokens)) >= m.config.MaxLoginCount {
			return "", core.ErrLoginLimitExceeded
		}
	}

	// Generate token | 生成Token
	tokenValue, err := m.generator.Generate(loginID, deviceType)
	if err != nil {
		return "", err
	}

	// Current timestamp | 当前时间戳
	nowTime := time.Now().Unix()
	// Calculate expiration time | 计算过期时间
	expiration := m.getExpiration()

	// Prepare TokenInfo object and serialize to JSON | 准备Token信息对象并序列化
	tokenInfo, err := m.serializer.Encode(TokenInfo{
		AuthType:   m.config.AuthType,
		LoginID:    loginID,
		Device:     deviceType,
		CreateTime: nowTime,
		ActiveTime: nowTime,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	// Save token-tokenInfo mapping | 保存 TokenKey-TokenInfo 映射
	tokenKey := m.getTokenKey(tokenValue)
	if err = m.storage.Set(ctx, tokenKey, tokenInfo, expiration); err != nil {
		return "", fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// Save account-token mapping | 保存 AccountKey-Token 映射
	if err = m.storage.Set(ctx, accountKey, tokenValue, expiration); err != nil {
		return "", fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// Create session | 创建Session
	if err = session.
		NewSession(m.config.AuthType, m.config.KeyPrefix, loginID, m.storage, m.serializer).
		SetMulti(
			ctx,
			map[string]any{
				SessionKeyLoginID:   loginID,
				SessionKeyDevice:    deviceType,
				SessionKeyLoginTime: nowTime,
			},
			expiration,
		); err != nil {
		return "", err
	}

	// Trigger login event | 触发登录事件
	if m.eventManager != nil {
		m.eventManager.Trigger(&listener.EventData{
			Event:    listener.EventLogin,
			AuthType: m.config.AuthType,
			LoginID:  loginID,
			Device:   deviceType,
			Token:    tokenValue,
		})
	}

	return tokenValue, nil
}

// LoginByToken Login with specified token (for seamless token refresh) | 使用指定Token登录（用于token无感刷新）
func (m *Manager) LoginByToken(ctx context.Context, tokenValue string) error {
	info, err := m.getTokenInfo(ctx, tokenValue)
	if err != nil {
		return err
	}

	// Check if the account is disabled | 检查账号是否被封禁
	if m.IsDisable(ctx, info.LoginID) {
		return core.ErrAccountDisabled
	}

	// Renews token expiration asynchronously | 异步续期Token
	m.renewToken(ctx, tokenValue, info)

	return nil
}

// Logout Performs user logout | 登出
func (m *Manager) Logout(ctx context.Context, loginID string, device ...string) error {
	// Get account key | 获取账号存储键
	accountKey := m.getAccountKey(loginID, getDevice(device))

	// Get token value | 获取Token值
	tokenValue, err := m.storage.Get(ctx, accountKey)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}
	if tokenValue == nil {
		return nil
	}

	// Assert token value type | 类型断言为字符串
	tokenValueStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(ctx, tokenValueStr, nil, listener.EventLogout)
}

// LogoutByToken Logout by token | 根据Token登出
func (m *Manager) LogoutByToken(ctx context.Context, tokenValue string) error {
	return m.removeTokenChain(ctx, tokenValue, nil, listener.EventLogout)
}

// kickout Kick user offline (private) | 踢人下线（私有）
func (m *Manager) kickout(ctx context.Context, loginID string, device string) error {
	accountKey := m.getAccountKey(loginID, device)
	tokenValue, err := m.storage.Get(ctx, accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	if tokenValueStr, ok := assertString(tokenValue); ok {
		return m.removeTokenChain(ctx, tokenValueStr, nil, listener.EventKickout)
	}

	return nil
}

// Kickout Kick user offline (public method) | 踢人下线（公开方法）
func (m *Manager) Kickout(ctx context.Context, loginID string, device ...string) error {
	return m.kickout(ctx, loginID, getDevice(device))
}

// kickoutByToken Kick user offline (private) | 根据Token踢人下线（私有）
func (m *Manager) kickoutByToken(ctx context.Context, tokenValue string) error {
	return m.removeTokenChain(ctx, tokenValue, nil, listener.EventKickout)
}

// KickoutByToken Kick user offline (public method) | 根据Token踢人下线（公开方法）
func (m *Manager) KickoutByToken(ctx context.Context, tokenValue string) error {
	return m.kickoutByToken(ctx, tokenValue)
}

// replace Replace user offline by login ID and device (private) | 根据账号和设备顶人下线（私有）
func (m *Manager) replace(ctx context.Context, loginID string, device string) error {
	accountKey := m.getAccountKey(loginID, device)
	tokenValue, err := m.storage.Get(ctx, accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	if tokenValueStr, ok := assertString(tokenValue); ok {
		return m.removeTokenChain(ctx, tokenValueStr, nil, listener.EventReplace)
	}

	return nil
}

// Replace user offline by login ID and device (public method) | 根据账号和设备顶人下线（公开方法）
func (m *Manager) Replace(ctx context.Context, loginID string, device ...string) error {
	return m.replace(ctx, loginID, getDevice(device))
}

// replaceByToken Replace user offline by token (private) | 根据Token顶人下线（私有）
func (m *Manager) replaceByToken(ctx context.Context, tokenValue string) error {
	return m.removeTokenChain(ctx, tokenValue, nil, listener.EventReplace)
}

// ReplaceByToken Replace user offline by token (public method) | 根据Token顶人下线（公开方法）
func (m *Manager) ReplaceByToken(ctx context.Context, tokenValue string) error {
	return m.replaceByToken(ctx, tokenValue)
}

// ============ Token Validation | Token验证 ============

// IsLogin Checks if the user is logged in | 检查用户是否登录
func (m *Manager) IsLogin(ctx context.Context, tokenValue string) bool {
	info, err := m.getTokenInfo(ctx, tokenValue)
	if err != nil {
		return false
	}

	// Check if the token has exceeded the active timeout | 检查Token是否超过活跃超时时间
	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理Token相关数据
			_ = m.removeTokenChain(ctx, tokenValue, info, listener.EventKickout)
			return false
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(tokenValue)

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(ctx, tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(ctx, m.getRenewKey(tokenValue))) {
				renewFunc := func() { m.renewToken(ctx, tokenValue, info) }

				// Submit renewal task to the pool if configured, otherwise use a goroutine | 如果配置了续期池，则提交续期任务到池中，否则使用协程
				if m.pool != nil {
					_ = m.pool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
				} else {
					go renewFunc() // Fallback to goroutine if pool is not configured | 如果没有配置续期池，使用普通协程
				}
			}
		}
	}

	return true
}

// CheckLogin Checks login status (throws serror if not logged in) | 检查登录（未登录抛出错误）
func (m *Manager) CheckLogin(ctx context.Context, tokenValue string) error {
	if !m.IsLogin(ctx, tokenValue) {
		return core.ErrNotLogin
	}

	return nil
}

// CheckLoginWithState Checks if user is logged in | 检查是否登录（返回详细状态err）
func (m *Manager) CheckLoginWithState(ctx context.Context, tokenValue string) (bool, error) {
	// Try to get token info with state check | 尝试获取Token信息（包含状态检查）
	info, err := m.getTokenInfo(ctx, tokenValue, true)
	if err != nil {
		return false, err
	}

	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理Token相关数据
			_ = m.removeTokenChain(ctx, tokenValue, info, listener.EventKickout)
			return false, core.ErrTokenKickout
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(tokenValue)

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(ctx, tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(ctx, m.getRenewKey(tokenValue))) {
				renewFunc := func() { m.renewToken(ctx, tokenValue, info) }

				// Submit renewal task to the pool if configured, otherwise use a goroutine | 如果配置了续期池，则提交续期任务到池中，否则使用协程
				if m.pool != nil {
					_ = m.pool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
				} else {
					go renewFunc() // Fallback to goroutine if pool is not configured | 如果没有配置续期池，使用普通协程
				}
			}
		}
	}

	return true, nil
}

// GetLoginID Gets login ID from token | 根据Token获取登录ID
func (m *Manager) GetLoginID(ctx context.Context, tokenValue string) (string, error) {
	// Check if the user is logged in | 检查用户是否已登录
	isLogin := m.IsLogin(ctx, tokenValue)
	if !isLogin {
		return "", core.ErrNotLogin
	}

	// Retrieve the login ID without checking token validity | 获取登录ID，不检查Token有效性
	return m.GetLoginIDNotCheck(ctx, tokenValue)
}

// GetLoginIDNotCheck Gets login ID without checking token validity | 获取登录ID（不检查Token是否有效）
func (m *Manager) GetLoginIDNotCheck(ctx context.Context, tokenValue string) (string, error) {
	// Get token info | 获取Token信息
	info, err := m.getTokenInfo(ctx, tokenValue)
	if err != nil {
		return "", err
	}

	return info.LoginID, nil
}

// GetTokenValue Gets token by login ID and device | 根据登录ID以及设备获取Token
func (m *Manager) GetTokenValue(ctx context.Context, loginID string, device ...string) (string, error) {
	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(loginID, getDevice(device))

	// Retrieve the token value from storage | 从存储中获取Token值
	tokenValue, err := m.storage.Get(ctx, accountKey)
	if err != nil || tokenValue == nil {
		return "", core.ErrTokenNotFound
	}

	// Assert token value as a string | 断言Token值为字符串
	tokenValueStr, ok := assertString(tokenValue)
	if !ok {
		return "", core.ErrTokenNotFound
	}

	return tokenValueStr, nil
}

// GetTokenInfoByToken Gets token information | 获取Token信息
func (m *Manager) GetTokenInfoByToken(ctx context.Context, tokenValue string) (*TokenInfo, error) {
	return m.getTokenInfo(ctx, tokenValue)
}

// ============ Account Disable | 账号封禁 ============

// Disable Disables an account | 封禁账号
func (m *Manager) Disable(ctx context.Context, loginID string, duration time.Duration, reason ...string) error {
	// Check if the account has active sessions and force logout | 检查账号是否有活跃会话并强制下线
	tokens, err := m.GetTokenValueListByLoginID(ctx, loginID)
	if err == nil && len(tokens) > 0 {
		for _, tokenValue := range tokens {
			// Force kick out each active token | 强制踢出所有活跃的Token
			_ = m.removeTokenChain(ctx, tokenValue, nil, listener.EventKickout, true)
		}
	}

	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	disableKeyKey := m.getDisableKey(loginID)

	// Prepare disable information | 准备封禁信息
	disableInfo := DisableInfo{
		DisableTime:   time.Now().Unix(),
		DisableReason: "",
	}
	if len(reason) > 0 {
		disableInfo.DisableReason = reason[0]
	}

	// Encode disable information into storage format | 将封禁信息序列化为存储格式
	encodeData, err := m.serializer.Encode(disableInfo)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	// Set disable flag with specified duration | 设置封禁标记并指定封禁时长
	err = m.storage.Set(ctx, disableKeyKey, encodeData, duration)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// Untie Re-enables a disabled account | 解封账号
func (m *Manager) Untie(ctx context.Context, loginID string) error {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	disableKeyKey := m.getDisableKey(loginID)

	// Remove the disable flag from storage | 删除封禁标记
	err := m.storage.Delete(ctx, disableKeyKey)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// IsDisable Checks if account is disabled | 检查账号是否被封禁
func (m *Manager) IsDisable(ctx context.Context, loginID string) bool {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	disableKeyKey := m.getDisableKey(loginID)

	// Check if the disable flag exists in storage | 检查封禁标记是否存在
	return m.storage.Exists(ctx, disableKeyKey)
}

// CheckDisableWithInfo get disable info | 获取封禁信息
func (m *Manager) CheckDisableWithInfo(ctx context.Context, loginID string) (*DisableInfo, error) {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	disableKeyKey := m.getDisableKey(loginID)

	// Get disable data from storage | 从存储中获取封禁信息
	data, err := m.storage.Get(ctx, disableKeyKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}
	if data == nil {
		return nil, nil
	}

	// 将数据转换为字节数组
	raw, err := utils.ToBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrTypeConvert, err)
	}

	// Decode stored disable information | 反序列化封禁信息
	var disableInfo DisableInfo
	if err := m.serializer.Decode(raw, &disableInfo); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrDeserializeFailed, err)
	}

	return &disableInfo, nil
}

// GetDisableTTL Gets remaining disable time in seconds | 获取账号剩余封禁时间（秒）
func (m *Manager) GetDisableTTL(ctx context.Context, loginID string) (int64, error) {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	disableKeyKey := m.getDisableKey(loginID)

	// Retrieve the TTL (Time to Live) for the disable flag | 获取封禁标记的TTL（剩余时间）
	ttl, err := m.storage.TTL(ctx, disableKeyKey)
	if err != nil {
		return -2, err
	}

	// Return the remaining disable time in seconds | 返回剩余封禁时间（秒）
	return int64(ttl.Seconds()), nil
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 获取 Session
func (m *Manager) GetSession(ctx context.Context, loginID string) (*session.Session, error) {
	if loginID == "" {
		return nil, core.ErrSessionIDEmpty
	}

	key := m.config.KeyPrefix + m.config.AuthType + session.SessionKeyPrefix + loginID
	data, err := m.GetStorage().Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// If found, decode session | 如果找到 Session，则解码
	var sess *session.Session
	if data != nil {
		raw, err := utils.ToBytes(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", core.ErrTypeConvert, err)
		}

		sess = &session.Session{}
		if err := m.GetCodec().Decode(raw, sess); err != nil {
			return nil, fmt.Errorf("%w: %v", core.ErrDeserializeFailed, err)
		}

		// Set internal dependencies after decoding | 解码后设置内部依赖
		sess.SetDependencies(m.config.KeyPrefix, m.storage, m.serializer)
	}

	// If not exist, create new session | 没找到就创建新的 Session
	if sess == nil {
		sess = session.NewSession(m.config.AuthType, m.config.KeyPrefix, loginID, m.storage, m.serializer)
	}

	return sess, nil
}

// GetSessionByToken Gets session by token | 根据Token获取Session
func (m *Manager) GetSessionByToken(ctx context.Context, tokenValue string) (*session.Session, error) {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return nil, err
	}

	return m.GetSession(ctx, loginID)
}

// DeleteSession Deletes session | 删除Session
func (m *Manager) DeleteSession(ctx context.Context, loginID string) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	return sess.Destroy(ctx)
}

// DeleteSessionByToken Deletes session by token | 根据Token删除Session
func (m *Manager) DeleteSessionByToken(ctx context.Context, tokenValue string) error {
	sess, err := m.GetSessionByToken(ctx, tokenValue)
	if err != nil {
		return err
	}

	return sess.Destroy(ctx)
}

// HasSession Checks if session exists | 检查Session是否存在
func (m *Manager) HasSession(ctx context.Context, loginID string) bool {
	if loginID == "" {
		return false
	}

	key := m.config.KeyPrefix + m.config.AuthType + session.SessionKeyPrefix + loginID
	return m.GetStorage().Exists(ctx, key)
}

// RenewSession Renews session TTL | 续期Session
func (m *Manager) RenewSession(ctx context.Context, loginID string, ttl time.Duration) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	return sess.Renew(ctx, ttl)
}

// ============ Permission Validation | 权限验证 ============

// SetPermissions Sets permissions for user | 设置权限
func (m *Manager) SetPermissions(ctx context.Context, loginID string, permissions []string) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	permissionsFromSession, ok := sess.Get(SessionKeyPermissions)
	if ok {
		permissions = append(permissions, m.toStringSlice(permissionsFromSession)...)
		permissions = removeDuplicateStrings(permissions)
	}

	return sess.Set(ctx, SessionKeyPermissions, permissions, m.getExpiration())
}

// SetPermissionsByToken Sets permissions by token | 根据Token设置权限
func (m *Manager) SetPermissionsByToken(ctx context.Context, tokenValue string, permissions []string) error {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return err
	}

	return m.SetPermissions(ctx, loginID, permissions)
}

// RemovePermissions removes specified permissions for user | 删除用户指定权限
func (m *Manager) RemovePermissions(ctx context.Context, loginID string, permissions []string) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	permissionsFromSession, ok := sess.Get(SessionKeyPermissions)
	if !ok {
		return nil
	}

	existingPerms := m.toStringSlice(permissionsFromSession)
	if len(existingPerms) == 0 {
		return nil
	}

	// Build a set for fast lookup of permissions to remove | 构建待删除权限集合
	removeSet := make(map[string]struct{}, len(permissions))
	for _, p := range permissions {
		removeSet[p] = struct{}{}
	}

	// Filter out permissions to be removed | 过滤掉需要删除的权限
	newPerms := make([]string, 0, len(existingPerms))
	for _, p := range existingPerms {
		if _, shouldRemove := removeSet[p]; !shouldRemove {
			newPerms = append(newPerms, p)
		}
	}

	return sess.Set(ctx, SessionKeyPermissions, newPerms, m.getExpiration())
}

// RemovePermissionsByToken removes specified permissions by token | 根据Token删除指定权限
func (m *Manager) RemovePermissionsByToken(ctx context.Context, tokenValue string, permissions []string) error {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return err
	}

	return m.RemovePermissions(ctx, loginID, permissions)
}

// GetPermissions Gets permission list | 获取权限列表
func (m *Manager) GetPermissions(ctx context.Context, loginID string) ([]string, error) {
	if m.CustomPermissionListFunc != nil {
		perms, err := m.CustomPermissionListFunc(loginID)
		if err != nil {
			return nil, err
		}
		return perms, nil
	}

	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return nil, err
	}

	perms, exists := sess.Get(SessionKeyPermissions)
	if !exists {
		return []string{}, nil
	}

	return m.toStringSlice(perms), nil
}

// GetPermissionsByToken Gets permission list by token | 根据Token获取权限列表
func (m *Manager) GetPermissionsByToken(ctx context.Context, tokenValue string) ([]string, error) {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return nil, err
	}

	return m.GetPermissions(ctx, loginID)
}

// HasPermission checks whether the specified loginID has the given permission | 检查指定账号是否拥有指定权限
func (m *Manager) HasPermission(ctx context.Context, loginID string, permission string) bool {
	perms, err := m.GetPermissions(ctx, loginID)
	if err != nil {
		return false
	}

	for _, p := range perms {
		if m.matchPermission(p, permission) {
			return true
		}
	}

	return false
}

// HasPermissionByToken checks whether the current token subject has the specified permission | 根据当前 Token 判断是否拥有指定权限
func (m *Manager) HasPermissionByToken(ctx context.Context, tokenValue string, permission string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasPermission(ctx, loginID, permission)
}

// HasPermissionsAnd Checks whether the user has all permissions (AND) | 是否拥有所有权限（AND）
func (m *Manager) HasPermissionsAnd(ctx context.Context, loginID string, permissions []string) bool {
	userPerms, err := m.GetPermissions(ctx, loginID)
	if err != nil || len(userPerms) == 0 {
		return false
	}

	// Check every required permission | 校验每一个必需权限
	for _, need := range permissions {
		if !m.hasPermissionInList(userPerms, need) {
			return false
		}
	}

	return true
}

// HasPermissionsAndByToken checks whether the current token subject has all specified permissions (AND) | 根据当前 Token 判断是否拥有所有指定权限（AND）
func (m *Manager) HasPermissionsAndByToken(ctx context.Context, tokenValue string, permissions []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasPermissionsAnd(ctx, loginID, permissions)
}

// HasPermissionsOr Checks whether the user has any permission (OR) | 是否拥有任一权限（OR）
func (m *Manager) HasPermissionsOr(ctx context.Context, loginID string, permissions []string) bool {
	// Get all permissions once | 一次性获取用户权限
	userPerms, err := m.GetPermissions(ctx, loginID)
	if err != nil || len(userPerms) == 0 {
		return false
	}

	// Check if any permission matches | 任一权限匹配即通过
	for _, need := range permissions {
		if m.hasPermissionInList(userPerms, need) {
			return true
		}
	}
	return false
}

// HasPermissionsOrByToken checks whether the current token subject has any of the specified permissions (OR) | 根据当前 Token 判断是否拥有任一指定权限（OR）
func (m *Manager) HasPermissionsOrByToken(ctx context.Context, tokenValue string, permissions []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasPermissionsOr(ctx, loginID, permissions)
}

// matchPermission Matches permission with wildcards support | 权限匹配（支持通配符）
func (m *Manager) matchPermission(pattern, permission string) bool {
	// Exact match or wildcard | 精确匹配或通配符
	if pattern == PermissionWildcard || pattern == permission {
		return true
	}

	// Pattern like "user:*" matches "user:add", "user:delete", etc. | 支持通配符，例如 user:* 匹配 user:add, user:delete等
	wildcardSuffix := PermissionSeparator + PermissionWildcard
	if strings.HasSuffix(pattern, wildcardSuffix) {
		prefix := strings.TrimSuffix(pattern, PermissionWildcard)
		return strings.HasPrefix(permission, prefix)
	}

	// Pattern like "user:*:view" | 支持 user:*:view 这样的模式
	if strings.Contains(pattern, PermissionWildcard) {
		parts := strings.Split(pattern, PermissionSeparator)
		permParts := strings.Split(permission, PermissionSeparator)
		if len(parts) != len(permParts) {
			return false
		}
		for i, part := range parts {
			if part != PermissionWildcard && part != permParts[i] {
				return false
			}
		}
		return true
	}

	return false
}

// hasPermissionInList checks whether permission exists in permission list | 判断权限是否存在于权限列表中
func (m *Manager) hasPermissionInList(perms []string, permission string) bool {
	for _, p := range perms {
		if m.matchPermission(p, permission) {
			return true
		}
	}
	return false
}

// ============ Role Validation | 角色验证 ============

// SetRoles Sets roles for user | 设置角色
func (m *Manager) SetRoles(ctx context.Context, loginID string, roles []string) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	rolesFromSession, ok := sess.Get(SessionKeyRoles)
	if ok {
		roles = append(roles, m.toStringSlice(rolesFromSession)...)
		roles = removeDuplicateStrings(roles)
	}

	return sess.Set(ctx, SessionKeyRoles, roles, m.getExpiration())
}

// SetRolesByToken Sets roles by token | 根据Token设置角色
func (m *Manager) SetRolesByToken(ctx context.Context, tokenValue string, roles []string) error {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return err
	}

	return m.SetRoles(ctx, loginID, roles)
}

// RemoveRoles removes specified roles for user | 删除用户指定角色
func (m *Manager) RemoveRoles(ctx context.Context, loginID string, roles []string) error {
	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return err
	}

	// Load existing roles | 加载已有角色
	rolesFromSession, ok := sess.Get(SessionKeyRoles)
	if !ok {
		return nil // No roles to remove | 没有角色可删除
	}

	existingRoles := m.toStringSlice(rolesFromSession)
	if len(existingRoles) == 0 {
		return nil
	}

	// Build lookup set for roles to remove | 构建待删除角色集合
	removeSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		removeSet[r] = struct{}{}
	}

	// Filter existing roles | 过滤掉需要删除的角色
	newRoles := make([]string, 0, len(existingRoles))
	for _, r := range existingRoles {
		if _, remove := removeSet[r]; !remove {
			newRoles = append(newRoles, r)
		}
	}

	// Save updated roles | 保存更新后的角色列表
	return sess.Set(ctx, SessionKeyRoles, newRoles, m.getExpiration())
}

// RemoveRolesByToken removes specified roles by token | 根据Token删除指定角色
func (m *Manager) RemoveRolesByToken(ctx context.Context, tokenValue string, roles []string) error {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return err
	}

	return m.RemoveRoles(ctx, loginID, roles)
}

// GetRoles gets role list for the specified loginID | 获取指定账号的角色列表
func (m *Manager) GetRoles(ctx context.Context, loginID string) ([]string, error) {
	if m.CustomRoleListFunc != nil {
		perms, err := m.CustomRoleListFunc(loginID)
		if err != nil {
			return nil, err
		}
		return perms, nil
	}

	sess, err := m.GetSession(ctx, loginID)
	if err != nil {
		return nil, err
	}

	roles, exists := sess.Get(SessionKeyRoles)
	if !exists {
		return []string{}, nil
	}

	return m.toStringSlice(roles), nil
}

// GetRolesByToken Gets role list by token | 根据Token获取角色列表
func (m *Manager) GetRolesByToken(ctx context.Context, tokenValue string) ([]string, error) {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return nil, err
	}

	return m.GetRoles(ctx, loginID)
}

// HasRole checks whether the specified loginID has the given role | 检查指定账号是否拥有指定角色
func (m *Manager) HasRole(ctx context.Context, loginID string, role string) bool {
	roles, err := m.GetRoles(ctx, loginID)
	if err != nil {
		return false
	}

	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasRoleByToken checks whether the current token subject has the specified role | 根据当前 Token 判断是否拥有指定角色
func (m *Manager) HasRoleByToken(ctx context.Context, tokenValue string, role string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasRole(ctx, loginID, role)
}

// HasRolesAnd Checks whether the user has all roles (AND) | 是否拥有所有角色（AND）
func (m *Manager) HasRolesAnd(ctx context.Context, loginID string, roles []string) bool {
	userRoles, err := m.GetRoles(ctx, loginID)
	if err != nil || len(userRoles) == 0 {
		return false
	}

	for _, need := range roles {
		if !m.hasRoleInList(userRoles, need) {
			return false
		}
	}
	return true
}

// HasRolesAndByToken checks whether the current token subject has all specified roles (AND) | 根据当前 Token 判断是否拥有所有指定角色（AND）
func (m *Manager) HasRolesAndByToken(ctx context.Context, tokenValue string, roles []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasRolesAnd(ctx, loginID, roles)
}

// HasRolesOr Checks whether the user has any role (OR) | 是否拥有任一角色（OR）
func (m *Manager) HasRolesOr(ctx context.Context, loginID string, roles []string) bool {
	userRoles, err := m.GetRoles(ctx, loginID)
	if err != nil || len(userRoles) == 0 {
		return false
	}

	for _, need := range roles {
		if m.hasRoleInList(userRoles, need) {
			return true
		}
	}
	return false
}

// HasRolesOrByToken checks whether the current token subject has any of the specified roles (OR) | 根据当前 Token 判断是否拥有任一指定角色（OR）
func (m *Manager) HasRolesOrByToken(ctx context.Context, tokenValue string, roles []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx, tokenValue)
	if err != nil {
		return false
	}

	return m.HasRolesOr(ctx, loginID, roles)
}

// hasPermissionInList checks whether permission exists in permission list | 判断权限是否存在于权限列表中
func (m *Manager) hasRoleInList(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// ============ Token Tags | Token标签 ============

// SetTokenTag Sets token tag | 设置Token标签
func (m *Manager) SetTokenTag(tag string) error {
	// Tag feature not supported to comply with Java sa-token design
	// If you need custom metadata, use Session instead
	return fmt.Errorf("token tag feature not supported (use Session for custom metadata)")
}

// GetTokenTag Gets token tag | 获取Token标签
func (m *Manager) GetTokenTag(ctx context.Context) (string, error) {
	// Tag feature not supported to comply with Java sa-token design
	return "", fmt.Errorf("token tag feature not supported (use Session for custom metadata)")
}

// ============ Session Query | 会话查询 ============

// GetTokenValueListByLoginID Gets all tokens for specified account | 获取指定账号的所有Token
func (m *Manager) GetTokenValueListByLoginID(ctx context.Context, loginID string) ([]string, error) {
	// Construct the pattern for account key | 构造账号存储键的匹配模式
	pattern := m.config.KeyPrefix + m.config.AuthType + AccountKeyPrefix + loginID + TokenValueListLastKey

	// Retrieve keys matching the pattern from storage | 从存储中获取匹配的键
	keys, err := m.storage.Keys(ctx, pattern)
	if err != nil {
		return nil, err // Return error if key retrieval fails | 如果获取键失败，则返回错误
	}

	// Initialize a slice to hold the token strings | 初始化切片来存储Token字符串
	tokens := make([]string, 0, len(keys))

	// Loop through the keys and retrieve the associated token values | 遍历键并获取关联的Token值
	for _, key := range keys {
		value, err := m.storage.Get(ctx, key)
		if err == nil && value != nil {
			// Assert value as string and add to tokens slice | 将值断言为字符串并添加到Token切片
			if tokenStr, ok := assertString(value); ok {
				tokens = append(tokens, tokenStr)
			}
		}
	}

	// Return the list of token strings | 返回Token字符串列表
	return tokens, nil
}

// GetSessionCountByLoginID Gets session count for specified account | 获取指定账号的Session数量
func (m *Manager) GetSessionCountByLoginID(ctx context.Context, loginID string) (int, error) {
	// Get the list of token values for the specified login ID | 获取指定登录ID的Token值列表
	tokens, err := m.GetTokenValueListByLoginID(ctx, loginID)
	if err != nil {
		return 0, err // Return error if token list retrieval fails | 如果获取Token列表失败，则返回错误
	}

	// Return the count of tokens as the session count | 返回Token数量作为Session数量
	return len(tokens), nil
}

// ============ Event Management | 事件管理 ============

// RegisterFunc registers a function as an event listener | 注册函数作为事件监听器
func (m *Manager) RegisterFunc(event listener.Event, fn func(*listener.EventData)) {
	m.eventManager.RegisterFunc(event, fn)
}

// Register registers an event listener | 注册事件监听器
func (m *Manager) Register(event listener.Event, listener listener.Listener) string {
	return m.eventManager.Register(event, listener)
}

// RegisterWithConfig registers an event listener with config | 注册带配置的事件监听器
func (m *Manager) RegisterWithConfig(event listener.Event, listener listener.Listener, config listener.ListenerConfig) string {
	return m.eventManager.RegisterWithConfig(event, listener, config)
}

// Unregister removes an event listener by ID | 根据ID移除事件监听器
func (m *Manager) Unregister(id string) bool {
	return m.eventManager.Unregister(id)
}

// TriggerEvent manually triggers an event | 手动触发事件
func (m *Manager) TriggerEvent(data *listener.EventData) {
	m.eventManager.Trigger(data)
}

// TriggerEventAsync triggers an event asynchronously and returns immediately | 异步触发事件并立即返回
func (m *Manager) TriggerEventAsync(data *listener.EventData) {
	m.eventManager.TriggerAsync(data)
}

// TriggerEventSync triggers an event synchronously and waits for all listeners | 同步触发事件并等待所有监听器完成
func (m *Manager) TriggerEventSync(data *listener.EventData) {
	m.eventManager.TriggerSync(data)
}

// WaitEvents waits for all async event listeners to complete | 等待所有异步事件监听器完成
func (m *Manager) WaitEvents() {
	m.eventManager.Wait()
}

// ClearEventListeners removes all listeners for a specific event | 清除指定事件的所有监听器
func (m *Manager) ClearEventListeners(event listener.Event) {
	m.eventManager.ClearEvent(event)
}

// ClearAllEventListeners removes all listeners | 清除所有事件监听器
func (m *Manager) ClearAllEventListeners() {
	m.eventManager.Clear()
}

// CountEventListeners returns the number of listeners for a specific event | 获取指定事件监听器数量
func (m *Manager) CountEventListeners(event listener.Event) int {
	return m.eventManager.CountForEvent(event)
}

// CountAllListeners returns the total number of registered listeners | 获取已注册监听器总数
func (m *Manager) CountAllListeners() int {
	return m.eventManager.Count()
}

// GetEventListenerIDs returns all listener IDs for a specific event | 获取指定事件的所有监听器ID
func (m *Manager) GetEventListenerIDs(event listener.Event) []string {
	return m.eventManager.GetListenerIDs(event)
}

// GetAllRegisteredEvents returns all events that have registered listeners | 获取所有已注册事件
func (m *Manager) GetAllRegisteredEvents() []listener.Event {
	return m.eventManager.GetAllEvents()
}

// HasEventListeners checks if there are any listeners for a specific event | 检查指定事件是否有监听器
func (m *Manager) HasEventListeners(event listener.Event) bool {
	return m.eventManager.HasListeners(event)
}

// ============ Security Features | 安全特性 ============

// SecurityGenerateNonce Generates a one-time nonce | 生成一次性随机数
func (m *Manager) SecurityGenerateNonce(ctx context.Context) (string, error) {
	return m.nonceManager.Generate(ctx)
}

// SecurityVerifyNonce Verifies a nonce | 验证随机数
func (m *Manager) SecurityVerifyNonce(ctx context.Context, nonce string) bool {
	return m.nonceManager.Verify(ctx, nonce)
}

// SecurityVerifyAndConsumeNonce Verifies and consumes nonce, returns error if invalid | 验证并消费nonce，无效时返回错误
func (m *Manager) SecurityVerifyAndConsumeNonce(ctx context.Context, nonce string) error {
	return m.nonceManager.VerifyAndConsume(ctx, nonce)
}

// SecurityIsValidNonce Checks if nonce is valid without consuming it | 检查nonce是否有效（不消费）
func (m *Manager) SecurityIsValidNonce(ctx context.Context, nonce string) bool {
	return m.nonceManager.IsValid(ctx, nonce)
}

// SecurityGenerateTokenPair Create access + refresh token | 生成访问令牌和刷新令牌
func (m *Manager) SecurityGenerateTokenPair(ctx context.Context, loginID string, device ...string) (*security.RefreshTokenInfo, error) {
	deviceType := getDevice(device)
	return m.refreshManager.GenerateTokenPair(ctx, loginID, deviceType)
}

// SecurityVerifyAccessToken Check token exists | 验证访问令牌是否存在
func (m *Manager) SecurityVerifyAccessToken(ctx context.Context, accessToken string) bool {
	return m.refreshManager.VerifyAccessToken(ctx, accessToken)
}

// SecurityVerifyAccessTokenAndGetInfo Verify and get info | 验证访问令牌并获取信息
func (m *Manager) SecurityVerifyAccessTokenAndGetInfo(ctx context.Context, accessToken string) (*security.AccessTokenInfo, bool) {
	return m.refreshManager.VerifyAccessTokenAndGetInfo(ctx, accessToken)
}

// SecurityRefreshAccessToken Refresh access token by refresh token | 使用刷新令牌刷新访问令牌
func (m *Manager) SecurityRefreshAccessToken(ctx context.Context, refreshToken string) (*security.RefreshTokenInfo, error) {
	return m.refreshManager.RefreshAccessToken(ctx, refreshToken)
}

// SecurityGetRefreshTokenInfo Get refresh token info by token | 根据刷新令牌获取刷新令牌信息
func (m *Manager) SecurityGetRefreshTokenInfo(ctx context.Context, refreshToken string) (*security.RefreshTokenInfo, error) {
	return m.refreshManager.GetRefreshTokenInfo(ctx, refreshToken)
}

// SecurityRevokeRefreshToken Remove refresh token | 撤销刷新令牌
func (m *Manager) SecurityRevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return m.refreshManager.RevokeRefreshToken(ctx, refreshToken)
}

// SecurityIsRefreshTokenValid Check refresh token valid | 判断刷新令牌是否有效
func (m *Manager) SecurityIsRefreshTokenValid(ctx context.Context, refreshToken string) bool {
	return m.refreshManager.IsValid(ctx, refreshToken)
}

// ============ OAuth2 Features | Oauth2特性 ============

// OAuth2RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func (m *Manager) OAuth2RegisterClient(client *oauth2.Client) error {
	return m.oauth2Server.RegisterClient(client)
}

// OAuth2UnregisterClient Unregisters an OAuth2 client | 注销OAuth2客户端
func (m *Manager) OAuth2UnregisterClient(clientID string) {
	m.oauth2Server.UnregisterClient(clientID)
}

// OAuth2GetClient Gets client by ID | 根据ID获取客户端
func (m *Manager) OAuth2GetClient(clientID string) (*oauth2.Client, error) {
	return m.oauth2Server.GetClient(clientID)
}

// OAuth2GenerateAuthorizationCode Generates authorization code | 生成授权码
func (m *Manager) OAuth2GenerateAuthorizationCode(ctx context.Context, clientID, userID, redirectURI string, scopes []string) (*oauth2.AuthorizationCode, error) {
	return m.oauth2Server.GenerateAuthorizationCode(ctx, clientID, userID, redirectURI, scopes)
}

// OAuth2ExchangeCodeForToken Exchanges authorization code for access token | 用授权码换取访问令牌
func (m *Manager) OAuth2ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string) (*oauth2.AccessToken, error) {
	return m.oauth2Server.ExchangeCodeForToken(ctx, code, clientID, clientSecret, redirectURI)
}

// OAuth2ValidateAccessToken Validates access token | 验证访问令牌
func (m *Manager) OAuth2ValidateAccessToken(ctx context.Context, accessToken string) bool {
	return m.oauth2Server.ValidateAccessToken(ctx, accessToken)
}

// OAuth2ValidateAccessTokenAndGetInfo Validates access token and get info | 验证访问令牌并获取信息
func (m *Manager) OAuth2ValidateAccessTokenAndGetInfo(ctx context.Context, accessToken string) (*oauth2.AccessToken, error) {
	return m.oauth2Server.ValidateAccessTokenAndGetInfo(ctx, accessToken)
}

// OAuth2RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func (m *Manager) OAuth2RefreshAccessToken(ctx context.Context, clientID, refreshToken, clientSecret string) (*oauth2.AccessToken, error) {
	return m.oauth2Server.RefreshAccessToken(ctx, clientID, refreshToken, clientSecret)
}

// OAuth2RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func (m *Manager) OAuth2RevokeToken(ctx context.Context, accessToken string) error {
	return m.oauth2Server.RevokeToken(ctx, accessToken)
}

// OAuth2Token Unified token endpoint that dispatches to appropriate handler based on grant type | 统一的令牌端点，根据授权类型分发到相应的处理逻辑
func (m *Manager) OAuth2Token(ctx context.Context, req *oauth2.TokenRequest, validateUser oauth2.UserValidator) (*oauth2.AccessToken, error) {
	return m.oauth2Server.Token(ctx, req, validateUser)
}

// OAuth2ClientCredentialsToken Gets access token using client credentials grant | 使用客户端凭证模式获取访问令牌
func (m *Manager) OAuth2ClientCredentialsToken(ctx context.Context, clientID, clientSecret string, scopes []string) (*oauth2.AccessToken, error) {
	return m.oauth2Server.ClientCredentialsToken(ctx, clientID, clientSecret, scopes)
}

// OAuth2PasswordGrantToken Gets access token using resource owner password credentials grant | 使用密码模式获取访问令牌
func (m *Manager) OAuth2PasswordGrantToken(ctx context.Context, clientID, clientSecret, username, password string, scopes []string, validateUser oauth2.UserValidator) (*oauth2.AccessToken, error) {
	return m.oauth2Server.PasswordGrantToken(ctx, clientID, clientSecret, username, password, scopes, validateUser)
}

// ============ Public Getters | 公共获取器 ============

// GetConfig returns the manager-example configuration | 获取 Manager 当前使用的配置
func (m *Manager) GetConfig() *config.Config {
	return m.config
}

// GetStorage returns the storage adapter | 获取 Manager 使用的存储适配器
func (m *Manager) GetStorage() adapter.Storage {
	return m.storage
}

// GetCodec returns the codec (serializer) | 获取 Manager 使用的编解码器
func (m *Manager) GetCodec() adapter.Codec {
	return m.serializer
}

// GetLog returns the logger adapter | 获取 Manager 使用的日志适配器
func (m *Manager) GetLog() adapter.Log {
	return m.logger
}

// GetLogControl returns the logger control interface if available | 获取日志控制接口（如果支持）
func (m *Manager) GetLogControl() adapter.LogControl {
	if logControl, ok := m.logger.(adapter.LogControl); ok {
		return logControl
	}
	return nil
}

// GetPool returns the goroutine pool | 获取 Manager 使用的协程池
func (m *Manager) GetPool() adapter.Pool {
	return m.pool
}

// GetGenerator returns the token generator | 获取 Token 生成器
func (m *Manager) GetGenerator() adapter.Generator {
	return m.generator
}

// GetNonceManager returns the nonce manager-example | 获取随机串管理器
func (m *Manager) GetNonceManager() *security.NonceManager {
	return m.nonceManager
}

// GetRefreshManager returns the refresh token manager-example | 获取刷新令牌管理器
func (m *Manager) GetRefreshManager() *security.RefreshTokenManager {
	return m.refreshManager
}

// GetEventManager returns the event manager-example | 获取事件管理器
func (m *Manager) GetEventManager() *listener.Manager {
	return m.eventManager
}

// GetOAuth2Server Gets OAuth2 server instance | 获取OAuth2服务器实例
func (m *Manager) GetOAuth2Server() *oauth2.OAuth2Server {
	return m.oauth2Server
}

// GetDevice extracts device type from optional parameter | 从可选参数中提取设备类型 公开方法
func (m *Manager) GetDevice(device []string) string {
	if len(device) > 0 && strings.TrimSpace(device[0]) != "" {
		return device[0]
	}
	return DefaultDevice
}

// ============ Internal Methods | 内部方法 ============

// getTokenInfo Gets token information by token value | 通过Token值获取Token信息
func (m *Manager) getTokenInfo(ctx context.Context, tokenValue string, checkState ...bool) (*TokenInfo, error) {
	// Retrieve data from storage using the token key | 使用Token键从存储中获取数据
	data, err := m.storage.Get(ctx, m.getTokenKey(tokenValue))
	if err != nil || data == nil {
		return nil, core.ErrTokenNotFound
	}

	// Convert data to raw byte slice | 将数据转换为原始字节切片
	raw, err := utils.ToBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrTypeConvert, err)
	}

	// Check for special token states (if enabled) | 检查是否为特殊状态
	if len(checkState) > 0 && checkState[0] {
		switch string(raw) {
		case string(TokenStateKickout):
			// Token has been kicked out | Token已被踢下线
			return nil, core.ErrTokenKickout
		case string(TokenStateReplaced):
			// Token has been replaced | Token已被顶下线
			return nil, core.ErrTokenReplaced
		}
	}

	// Parse TokenInfo | 解析Token信息
	var info TokenInfo
	if err = m.serializer.Decode(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrDeserializeFailed, err)
	}

	return &info, nil
}

// renewToken Renews token expiration asynchronously | 异步续期Token
func (m *Manager) renewToken(ctx context.Context, tokenValue string, info *TokenInfo) {
	// If info is nil, retrieve token information | 如果info为空，获取Token信息
	if info == nil {
		var err error
		if info, err = m.getTokenInfo(ctx, tokenValue); err != nil || info == nil {
			return
		}
	}

	// Get expiration time | 获取过期时间
	exp := m.getExpiration()

	// Update ActiveTime | 更新ActiveTime
	info.ActiveTime = time.Now().Unix()
	// Renew token TTL | 续期Token的TTL
	if tokenInfo, err := m.serializer.Encode(info); err == nil {
		_ = m.storage.Set(ctx, m.getTokenKey(tokenValue), tokenInfo, exp)
	}

	// Renew accountKey TTL | 续期账号映射的TTL
	_ = m.storage.Expire(ctx, m.getAccountKey(info.LoginID, info.Device), exp)

	// Renew session TTL | 续期Session的TTL
	_ = m.RenewSession(ctx, info.LoginID, exp)

	// Set minimal renewal interval marker | 设置最小续期间隔标记
	if m.config.RenewInterval > 0 {
		_ = m.storage.Set(
			ctx,
			m.getRenewKey(tokenValue),
			time.Now().Unix(),
			time.Duration(m.config.RenewInterval)*time.Second,
		)
	}
}

// removeTokenChain Removes all related keys and triggers event | 删除Token相关的所有键并触发事件
func (m *Manager) removeTokenChain(ctx context.Context, tokenValue string, info *TokenInfo, event listener.Event, destroySession ...bool) error {
	// If info is nil, retrieve token information | 如果info为空，获取Token信息
	if info == nil {
		var err error
		if info, err = m.getTokenInfo(ctx, tokenValue); err != nil {
			return err
		}
	}

	// Delete token-info mapping | 删除Token信息映射
	_ = m.storage.Delete(ctx, m.getTokenKey(tokenValue))
	// Delete account-token mapping | 删除账号映射
	_ = m.storage.Delete(ctx, m.getAccountKey(info.LoginID, info.Device))
	// Delete renew key | 删除续期标记
	_ = m.storage.Delete(ctx, m.getRenewKey(tokenValue))
	// Optionally destroy session | 可选销毁Session
	if len(destroySession) > 0 && destroySession[0] {
		_ = m.DeleteSession(ctx, info.LoginID)
	}

	// Trigger event notification | 触发事件通知
	if m.eventManager != nil {
		m.eventManager.Trigger(&listener.EventData{
			Event:    event,
			AuthType: m.config.AuthType,
			LoginID:  info.LoginID,
			Device:   info.Device,
			Token:    tokenValue,
		})
	}

	return nil
}

// ============ Internal Helper Methods | 内部辅助方法 ============

// getTokenKey Gets token storage key | 获取Token存储键
func (m *Manager) getTokenKey(tokenValue string) string {
	return m.config.KeyPrefix + m.config.AuthType + TokenKeyPrefix + tokenValue
}

// getAccountKey Gets account storage key | 获取账号存储键
func (m *Manager) getAccountKey(loginID, device string) string {
	return m.config.KeyPrefix + m.config.AuthType + AccountKeyPrefix + loginID + PermissionSeparator + device
}

// getRenewKey Gets token renewal tracking key | 获取Token续期追踪键
func (m *Manager) getRenewKey(tokenValue string) string {
	return m.config.KeyPrefix + m.config.AuthType + RenewKeyPrefix + tokenValue
}

// getDisableKey Gets disable storage key | 获取禁用存储键
func (m *Manager) getDisableKey(loginID string) string {
	return m.config.KeyPrefix + m.config.AuthType + DisableKeyPrefix + loginID
}

// getDevice extracts device type from optional parameter | 从可选参数中提取设备类型
func getDevice(device []string) string {
	if len(device) > 0 && strings.TrimSpace(device[0]) != "" {
		return device[0]
	}
	return DefaultDevice
}

// getExpiration calculates expiration duration from config | 从配置计算过期时间
func (m *Manager) getExpiration() time.Duration {
	if m.config.Timeout > 0 {
		return time.Duration(m.config.Timeout) * time.Second
	}
	return 0
}

// assertString asserts value as string safely | 安全断言值为字符串
func assertString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// toStringSlice Converts any to []string | 将any转换为[]string
func (m *Manager) toStringSlice(v any) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

// removeDuplicateStrings removes duplicate elements from []string | 去重字符串切片
func removeDuplicateStrings(list []string) []string {
	seen := make(map[string]struct{}, len(list))
	result := make([]string, 0, len(list))

	for _, v := range list {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}
