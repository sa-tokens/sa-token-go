package manager

import (
	"context"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
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

// Manager Authentication manager | 认证管理器
type Manager struct {
	config         *config.Config                // Global authentication configuration | 全局认证配置
	nonceManager   *security.NonceManager        // Nonce manager for preventing replay attacks | 随机串管理器
	refreshManager *security.RefreshTokenManager // Refresh token manager | 刷新令牌管理器
	oauth2Server   *oauth2.OAuth2Server          // OAuth2 authorization server | OAuth2 授权服务器
	eventManager   *listener.Manager             // Event manager | 事件管理器

	generator  adapter.Generator // Token generator | Token 生成器
	storage    adapter.Storage   // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
	serializer adapter.Codec     // Codec adapter for encoding and decoding operations | 编解码器适配器
	logger     adapter.Log       // Log adapter for logging operations | 日志适配器
	pool       adapter.Pool      // Async task pool component | 异步任务协程池组件

	CustomPermissionListFunc func(ctx context.Context, loginID string) ([]string, error) // Custom permission func | 自定义权限获取函数
	CustomRoleListFunc       func(ctx context.Context, loginID string) ([]string, error) // Custom role func | 自定义角色获取函数
}

// NewManager creates and initializes a new Manager instance | 创建并初始化一个新的 Manager 实例
func NewManager(cfg *config.Config, generator adapter.Generator, storage adapter.Storage, serializer adapter.Codec, logger adapter.Log, pool adapter.Pool, customPermissionListFunc, CustomRoleListFunc func(ctx context.Context, loginID string) ([]string, error)) *Manager {

	// Use default configuration if cfg is nil | 如果未传入配置，则使用默认配置
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// generator
	if generator == nil {
		generator = sgenerator.NewGenerator(cfg)
	}

	// Use in-memory storage if storage is nil | 如果未传入存储实现，则使用内存存储
	if storage == nil {
		storage = memory.NewStorage()
	}

	// Use JSON serializer if serializer is nil | 如果未传入序列化器，则使用 JSON 序列化器
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	// Use no-op logger if logger is nil | 如果未传入日志实现，则使用空日志（不输出）
	if logger == nil {
		logger = nop.NewNopLogger()
	}

	// 如果启用了自动续期并且pool为nil
	if cfg.AutoRenew && pool == nil {
		// Use default goroutine pool if pool is nil | 如果未传入协程池，则使用默认协程池
		pool = ants.NewRenewPoolManagerWithDefaultConfig()
	}

	// Return the new manager instance with initialized sub-managers | 返回已初始化各子模块的管理器实例
	return &Manager{
		// Store global configuration | 保存全局配置
		config: cfg,

		// Token generator used for creating access/refresh tokens | 用于生成访问令牌和刷新令牌的生成器
		generator: generator,

		// Nonce manager for replay-attack protection | 防重放攻击的 Nonce 管理器
		nonceManager: security.NewNonceManager(
			cfg.AuthType,
			cfg.KeyPrefix,
			storage,
			DefaultNonceTTL,
		),

		// Refresh token manager for token renewal logic | 刷新令牌管理器，用于令牌续期逻辑
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

		// Event manager for lifecycle and auth events | 生命周期与认证事件管理器
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

// CloseManager Closes the manager and releases all resources | 关闭管理器并释放所有资源
func (m *Manager) CloseManager() {
	if m.pool != nil {
		// Safely close the renewPool | 安全关闭 renewPool
		m.pool.Stop()
		// Set renewPool to nil | 将 renewPool 设置为 nil
		m.pool = nil
	}
}

// ============ Login Authentication | 登录认证 ============

// Login Performs user login and returns token | 登录，返回Token TODO 后续参数可以修改为结构体
func (m *Manager) Login(ctx context.Context, loginID string, device ...string) (string, error) {
	// Check if account is disabled | 检查账号是否被封禁
	if m.IsDisable(ctx, loginID) {
		return "", ErrAccountDisabled
	}

	// 获取设备类型
	deviceType := getDevice(device)
	// 获取账号存储键
	accountKey := m.getAccountKey(ctx, loginID, deviceType)

	// Handle shared token for concurrent login | 处理多人登录共用 Token 的情况
	if m.config.IsShare {
		// Look for existing token of this account + device | 查找账号 + 设备下是否已有登录 Token
		existingToken, err := m.storage.Get(accountKey)
		if err == nil && existingToken != nil {
			// 校验一下如果登录Token有效
			if tokenStr, ok := assertString(existingToken); ok && m.IsLogin(context.WithValue(ctx, config.CtxTokenValue, existingToken)) {
				// If valid token exists, return it directly | 如果已有 Token 且有效，则直接返回
				return tokenStr, nil
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
			// Reached maximum concurrent login count | 已达到最大并发登录数 如需也可改为 踢掉最早Token
			return "", ErrLoginLimitExceeded
		}
	}

	// Generate token | 生成Token
	tokenValue, err := m.generator.Generate(loginID, deviceType)
	if err != nil {
		return "", err
	}

	// 当前时间戳
	nowTime := time.Now().Unix()
	// 计算过期时间
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
		return "", fmt.Errorf("%w: %v", fmt.Errorf("failed to encode data"), err)
	}

	// 生成新的ctx
	ctx = context.WithValue(ctx, config.CtxTokenValue, tokenValue)

	// Save token-tokenInfo mapping | 保存 TokenKey-TokenInfo 映射
	tokenKey := m.getTokenKey(ctx)
	if err = m.storage.Set(tokenKey, tokenInfo, expiration); err != nil {
		return "", err
	}

	// Save account-token mapping | 保存 AccountKey-Token 映射
	if err = m.storage.Set(accountKey, tokenValue, expiration); err != nil {
		return "", err
	}

	// Create session | 创建Session
	err = session.
		NewSession(m.config.AuthType, m.config.KeyPrefix, loginID, m.storage, m.serializer).
		SetMulti(
			map[string]any{
				SessionKeyLoginID:   loginID,
				SessionKeyDevice:    deviceType,
				SessionKeyLoginTime: nowTime,
			},
			expiration,
		)
	if err != nil {
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
func (m *Manager) LoginByToken(ctx context.Context) error {
	info, err := m.getTokenInfoByTokenValue(ctx)
	if err != nil {
		return err
	}

	// Check if the account is disabled | 检查账号是否被封禁
	if m.IsDisable(ctx, info.LoginID) {
		return ErrAccountDisabled
	}

	// Renews token expiration asynchronously | 异步续期Token
	m.renewToken(ctx, info)

	return nil
}

// Logout Performs user logout | 登出
func (m *Manager) Logout(ctx context.Context, loginID string, device ...string) error {
	// Get account key | 获取账号存储键
	accountKey := m.getAccountKey(ctx, loginID, getDevice(device))

	// Get token value | 获取Token值
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	// Assert token value type | 类型断言为字符串
	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(context.WithValue(ctx, config.CtxTokenValue, tokenStr), false, nil, listener.EventLogout)
}

// LogoutByToken Logout by token | 根据Token登出
func (m *Manager) LogoutByToken(ctx context.Context) error {
	return m.removeTokenChain(ctx, false, nil, listener.EventLogout)
}

// kickout Kick user offline (private) | 踢人下线（私有）
func (m *Manager) kickout(ctx context.Context, loginID string, device string) error {
	accountKey := m.getAccountKey(ctx, loginID, device)
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(context.WithValue(ctx, config.CtxTokenValue, tokenStr), false, nil, listener.EventKickout)
}

// Kickout Kick user offline (public method) | 踢人下线（公开方法）
func (m *Manager) Kickout(ctx context.Context, loginID string, device ...string) error {
	deviceType := getDevice(device)
	return m.kickout(ctx, loginID, deviceType)
}

// kickoutByToken Kick user offline (private) | 根据Token踢人下线（私有）
func (m *Manager) kickoutByToken(ctx context.Context) error {
	return m.removeTokenChain(ctx, false, nil, listener.EventKickout)
}

// KickoutByToken Kick user offline (public method) | 根据Token踢人下线（公开方法）
func (m *Manager) KickoutByToken(ctx context.Context) error {
	return m.kickoutByToken(ctx)
}

// replace Replace user offline by login ID and device (private) | 根据账号和设备顶人下线（私有）
func (m *Manager) replace(ctx context.Context, loginID string, device string) error {
	accountKey := m.getAccountKey(ctx, loginID, device)
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(context.WithValue(ctx, config.CtxTokenValue, tokenStr), false, nil, listener.EventReplace)
}

// Replace user offline by login ID and device (public method) | 根据账号和设备顶人下线（公开方法）
func (m *Manager) Replace(ctx context.Context, loginID string, device ...string) error {
	deviceType := getDevice(device)
	return m.replace(ctx, loginID, deviceType)
}

// replaceByToken Replace user offline by token (private) | 根据Token顶人下线（私有）
func (m *Manager) replaceByToken(ctx context.Context) error {
	return m.removeTokenChain(ctx, false, nil, listener.EventReplace)
}

// ReplaceByToken Replace user offline by token (public method) | 根据Token顶人下线（公开方法）
func (m *Manager) ReplaceByToken(ctx context.Context) error {
	return m.replaceByToken(ctx)
}

// ============ Token Validation | Token验证 ============

// IsLogin Checks if the user is logged in | 检查用户是否登录
func (m *Manager) IsLogin(ctx context.Context) bool {
	// Retrieve token information using the token value from context | 从上下文中获取Token值并检索Token信息
	info, err := m.getTokenInfoByTokenValue(ctx)
	if err != nil {
		return false // Return false if token info retrieval fails | 如果获取Token信息失败，则返回false
	}

	// Check if the token has exceeded the active timeout | 检查Token是否超过活跃超时时间
	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理Token相关数据
			_ = m.removeTokenChain(ctx, false, info, listener.EventKickout)
			return false // Return false if the token has expired | 如果Token超时，则返回false
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(ctx)

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(ctx))) {
				renewFunc := func() { m.renewToken(ctx, info) }

				// Submit renewal task to the pool if configured, otherwise use a goroutine | 如果配置了续期池，则提交续期任务到池中，否则使用协程
				if m.pool != nil {
					_ = m.pool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
				} else {
					go renewFunc() // Fallback to goroutine if pool is not configured | 如果没有配置续期池，使用普通协程
				}
			}
		}
	}

	return true // Return true if the user is logged in | 如果用户已登录，则返回true
}

// CheckLogin Checks login status (throws serror if not logged in) | 检查登录（未登录抛出错误）
func (m *Manager) CheckLogin(ctx context.Context) error {
	if !m.IsLogin(ctx) {
		return ErrNotLogin
	}
	return nil
}

// CheckLoginWithState Checks if user is logged in | 检查是否登录（返回详细状态err）
func (m *Manager) CheckLoginWithState(ctx context.Context) (bool, error) {
	// Try to get token info with state check | 尝试获取Token信息（包含状态检查）
	info, err := m.getTokenInfoByTokenValue(ctx, true)
	if err != nil {
		return false, err
	}

	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理Token相关数据
			_ = m.removeTokenChain(ctx, false, info, listener.EventKickout)
			return false, ErrTokenKickout
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(ctx)

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(ctx))) {
				renewFunc := func() { m.renewToken(ctx, info) }

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
func (m *Manager) GetLoginID(ctx context.Context) (string, error) {
	// Check if the user is logged in | 检查用户是否已登录
	isLogin := m.IsLogin(ctx)
	if !isLogin {
		return "", ErrNotLogin // Return error if not logged in | 如果未登录，则返回错误
	}

	// Retrieve the login ID without checking token validity | 获取登录ID，不检查Token有效性
	return m.GetLoginIDNotCheck(ctx)
}

// GetLoginIDNotCheck Gets login ID without checking token validity | 获取登录ID（不检查Token是否有效）
func (m *Manager) GetLoginIDNotCheck(ctx context.Context) (string, error) {
	// Retrieve token information using the token value from context | 从上下文中获取Token值并检索Token信息
	info, err := m.getTokenInfoByTokenValue(ctx)
	if err != nil {
		return "", err // Return error if token info retrieval fails | 如果获取Token信息失败，返回错误
	}

	return info.LoginID, nil // Return the login ID from the token info | 返回Token信息中的登录ID
}

// GetTokenValue Gets token by login ID and device | 根据登录ID以及设备获取Token
func (m *Manager) GetTokenValue(ctx context.Context, loginID string, device ...string) (string, error) {
	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, loginID, getDevice(device))

	// Retrieve the token value from storage | 从存储中获取Token值
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return "", ErrTokenNotFound // Return error if token not found | 如果未找到Token，则返回错误
	}

	// Assert token value as a string | 断言Token值为字符串
	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return "", ErrTokenNotFound // Return error if token is not a valid string | 如果Token不是有效字符串，则返回错误
	}

	// Return the token string | 返回Token字符串
	return tokenStr, nil
}

// GetTokenInfo Gets token information | 获取Token信息
func (m *Manager) GetTokenInfo(ctx context.Context) (*TokenInfo, error) {
	return m.getTokenInfoByTokenValue(ctx)
}

// ============ Account Disable | 账号封禁 ============

// Disable Disables an account | 封禁账号
func (m *Manager) Disable(ctx context.Context, loginID string, duration time.Duration) error {
	// Check if the account has active sessions and force logout | 检查账号是否有活跃会话并强制下线
	tokens, err := m.GetTokenValueListByLoginID(ctx, loginID)
	if err == nil && len(tokens) > 0 {
		for _, tokenValue := range tokens {
			// Force kick out each active token | 强制踢出所有活跃的Token
			_ = m.removeTokenChain(context.WithValue(ctx, config.CtxTokenValue, tokenValue), true, nil, listener.EventKickout)
		}
	}

	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	key := m.getDisableKey(ctx, loginID)

	// Set disable flag with specified duration | 设置封禁标记并指定封禁时长
	return m.storage.Set(key, DisableValue, duration)
}

// Untie Re-enables a disabled account | 解封账号
func (m *Manager) Untie(ctx context.Context, loginID string) error {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	key := m.getDisableKey(ctx, loginID)

	// Remove the disable flag from storage | 删除封禁标记
	return m.storage.Delete(key)
}

// IsDisable Checks if account is disabled | 检查账号是否被封禁
func (m *Manager) IsDisable(ctx context.Context, loginID string) bool {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	key := m.getDisableKey(ctx, loginID)

	// Check if the disable flag exists in storage | 检查封禁标记是否存在
	return m.storage.Exists(key)
}

// GetDisableTime Gets remaining disable time in seconds | 获取账号剩余封禁时间（秒）
func (m *Manager) GetDisableTime(ctx context.Context, loginID string) (int64, error) {
	// Retrieve the disable flag storage key | 获取封禁标记的存储键
	key := m.getDisableKey(ctx, loginID)

	// Retrieve the TTL (Time to Live) for the disable flag | 获取封禁标记的TTL（剩余时间）
	ttl, err := m.storage.TTL(key)
	if err != nil {
		return -2, err // Return -2 if TTL retrieval fails | 如果获取TTL失败，返回-2
	}

	// Return the remaining disable time in seconds | 返回剩余封禁时间（秒）
	return int64(ttl.Seconds()), nil
}

// ============ Session Management | Session管理 ============

// GetSession Gets session by login ID | 获取Session
func (m *Manager) GetSession(ctx context.Context, loginID string) (*session.Session, error) {
	sess, err := session.Load(ctx, loginID, m)
	if err != nil {
		sess = session.NewSession(m.config.AuthType, m.config.KeyPrefix, loginID, m.storage, m.serializer)
	}

	return sess, nil
}

// GetSessionByToken Gets session by token | 根据Token获取Session
func (m *Manager) GetSessionByToken(ctx context.Context) (*session.Session, error) {
	loginID, err := m.GetLoginID(ctx)
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

	return sess.Destroy()
}

// DeleteSessionByToken Deletes session by token | 根据Token删除Session
func (m *Manager) DeleteSessionByToken(ctx context.Context) error {
	sess, err := m.GetSessionByToken(ctx)
	if err != nil {
		return err
	}

	return sess.Destroy()
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

	return sess.Set(SessionKeyPermissions, permissions, m.getExpiration())
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

	return sess.Set(SessionKeyPermissions, newPerms, m.getExpiration())
}

// GetPermissions Gets permission list | 获取权限列表
func (m *Manager) GetPermissions(ctx context.Context, loginID string) ([]string, error) {
	if m.CustomPermissionListFunc != nil {
		perms, err := m.CustomPermissionListFunc(ctx, loginID)
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

// HasPermission checks whether the specified loginID has the given permission | 检查指定账号是否拥有指定权限
func (m *Manager) HasPermission(ctx context.Context, loginID string, permission string) bool {
	perms, err := m.GetPermissions(ctx, loginID)
	if err != nil {
		return false
	}

	for _, p := range perms {
		if m.matchPermission(ctx, p, permission) {
			return true
		}
	}

	return false
}

// HasPermissionByToken checks whether the current token subject has the specified permission | 根据当前 Token 判断是否拥有指定权限
func (m *Manager) HasPermissionByToken(ctx context.Context, permission string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

	perms, err := m.GetPermissions(ctx, loginID)
	if err != nil {
		return false
	}

	for _, p := range perms {
		if m.matchPermission(ctx, p, permission) {
			return true
		}
	}

	return false
}

// HasPermissionsAnd Checks whether the user has all permissions (AND) | 是否拥有所有权限（AND）
func (m *Manager) HasPermissionsAnd(ctx context.Context, loginID string, permissions []string) bool {
	// Get all permissions once | 一次性获取用户权限
	userPerms, err := m.GetPermissions(ctx, loginID)
	if err != nil || len(userPerms) == 0 {
		return false
	}

	// Check every required permission | 校验每一个必需权限
	for _, need := range permissions {
		if !m.hasPermissionInList(ctx, userPerms, need) {
			return false
		}
	}
	return true
}

// HasPermissionsAndByToken checks whether the current token subject has all specified permissions (AND) | 根据当前 Token 判断是否拥有所有指定权限（AND）
func (m *Manager) HasPermissionsAndByToken(ctx context.Context, permissions []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

	// Get all permissions once | 一次性获取用户权限
	userPerms, err := m.GetPermissions(ctx, loginID)
	if err != nil || len(userPerms) == 0 {
		return false
	}

	// Check every required permission | 校验每一个必需权限
	for _, need := range permissions {
		if !m.hasPermissionInList(ctx, userPerms, need) {
			return false
		}
	}
	return true
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
		if m.hasPermissionInList(ctx, userPerms, need) {
			return true
		}
	}
	return false
}

// HasPermissionsOrByToken checks whether the current token subject has any of the specified permissions (OR) | 根据当前 Token 判断是否拥有任一指定权限（OR）
func (m *Manager) HasPermissionsOrByToken(ctx context.Context, permissions []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

	// Get all permissions once | 一次性获取用户权限
	userPerms, err := m.GetPermissions(ctx, loginID)
	if err != nil || len(userPerms) == 0 {
		return false
	}

	// Check if any permission matches | 任一权限匹配即通过
	for _, need := range permissions {
		if m.hasPermissionInList(ctx, userPerms, need) {
			return true
		}
	}
	return false
}

// matchPermission Matches permission with wildcards support | 权限匹配（支持通配符）
func (m *Manager) matchPermission(_ context.Context, pattern, permission string) bool {
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
func (m *Manager) hasPermissionInList(ctx context.Context, perms []string, permission string) bool {
	for _, p := range perms {
		if m.matchPermission(ctx, p, permission) {
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

	return sess.Set(SessionKeyRoles, roles, m.getExpiration())
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
	return sess.Set(SessionKeyRoles, newRoles, m.getExpiration())
}

// GetRoles gets role list for the specified loginID | 获取指定账号的角色列表
func (m *Manager) GetRoles(ctx context.Context, loginID string) ([]string, error) {
	if m.CustomRoleListFunc != nil {
		perms, err := m.CustomRoleListFunc(ctx, loginID)
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
func (m *Manager) HasRoleByToken(ctx context.Context, role string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

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
func (m *Manager) HasRolesAndByToken(ctx context.Context, roles []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

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
func (m *Manager) HasRolesOrByToken(ctx context.Context, roles []string) bool {
	loginID, err := m.GetLoginIDNotCheck(ctx)
	if err != nil {
		return false
	}

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
func (m *Manager) SetTokenTag(ctx context.Context, tag string) error {
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
func (m *Manager) GetTokenValueListByLoginID(_ context.Context, loginID string) ([]string, error) {
	// Construct the pattern for account key | 构造账号存储键的匹配模式
	pattern := m.config.KeyPrefix + m.config.AuthType + AccountKeyPrefix + loginID + TokenValueListLastKey

	// Retrieve keys matching the pattern from storage | 从存储中获取匹配的键
	keys, err := m.storage.Keys(pattern)
	if err != nil {
		return nil, err // Return error if key retrieval fails | 如果获取键失败，则返回错误
	}

	// Initialize a slice to hold the token strings | 初始化切片来存储Token字符串
	tokens := make([]string, 0, len(keys))

	// Loop through the keys and retrieve the associated token values | 遍历键并获取关联的Token值
	for _, key := range keys {
		value, err := m.storage.Get(key)
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
	if m.eventManager != nil {
		m.eventManager.RegisterFunc(event, fn)
	}
}

// Register registers an event listener | 注册事件监听器
func (m *Manager) Register(event listener.Event, listener listener.Listener) string {
	if m.eventManager != nil {
		return m.eventManager.Register(event, listener)
	}
	return ""
}

// RegisterWithConfig registers an event listener with config | 注册带配置的事件监听器
func (m *Manager) RegisterWithConfig(event listener.Event, listener listener.Listener, config listener.ListenerConfig) string {
	if m.eventManager != nil {
		return m.eventManager.RegisterWithConfig(event, listener, config)
	}
	return ""
}

// Unregister removes an event listener by ID | 根据ID移除事件监听器
func (m *Manager) Unregister(id string) bool {
	if m.eventManager != nil {
		return m.eventManager.Unregister(id)
	}
	return false
}

// TriggerEvent manually triggers an event | 手动触发事件
func (m *Manager) TriggerEvent(data *listener.EventData) {
	if m.eventManager != nil {
		m.eventManager.Trigger(data)
	}
}

// WaitEvents waits for all async event listeners to complete | 等待所有异步事件监听器完成
func (m *Manager) WaitEvents() {
	if m.eventManager != nil {
		m.eventManager.Wait()
	}
}

// ============ Security Features | 安全特性 ============

//// GenerateNonce Generates a one-time nonce | 生成一次性随机数
//func (m *Manager) GenerateNonce(_ context.Context) (string, error) {
//	return m.nonceManager.Generate()
//}
//
//// VerifyNonce Verifies a nonce | 验证随机数
//func (m *Manager) VerifyNonce(_ context.Context, nonce string) bool {
//	return m.nonceManager.Verify(nonce)
//}
//
//// LoginWithRefreshToken Logs in with refresh token | 使用刷新令牌登录
//func (m *Manager) LoginWithRefreshToken(_ context.Context, loginID string, device ...string) (*security.RefreshTokenInfo, error) {
//	deviceType := getDevice(device)
//	return m.refreshManager.GenerateTokenPair(loginID, deviceType)
//}
//
//// RefreshAccessToken Refreshes access token | 刷新访问令牌
//func (m *Manager) RefreshAccessToken(ctx context.Context) (*security.RefreshTokenInfo, error) {
//	return m.refreshManager.RefreshAccessToken(utils.GetCtxValue(ctx, config.CtxTokenValue))
//}
//
//// RevokeRefreshToken Revokes refresh token | 撤销刷新令牌
//func (m *Manager) RevokeRefreshToken(ctx context.Context) error {
//	return m.refreshManager.RevokeRefreshToken(utils.GetCtxValue(ctx, config.CtxTokenValue))
//}

// ============ Public Getters | 公共获取器 ============

// GetConfig returns the manager configuration | 获取 Manager 当前使用的配置
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

// GetPool returns the goroutine pool | 获取 Manager 使用的协程池
func (m *Manager) GetPool() adapter.Pool {
	return m.pool
}

// GetGenerator returns the token generator | 获取 Token 生成器
func (m *Manager) GetGenerator() adapter.Generator {
	return m.generator
}

// GetNonceManager returns the nonce manager | 获取随机串管理器
func (m *Manager) GetNonceManager() *security.NonceManager {
	return m.nonceManager
}

// GetRefreshManager returns the refresh token manager | 获取刷新令牌管理器
func (m *Manager) GetRefreshManager() *security.RefreshTokenManager {
	return m.refreshManager
}

// GetEventManager returns the event manager | 获取事件管理器
func (m *Manager) GetEventManager() *listener.Manager {
	return m.eventManager
}

// GetOAuth2Server Gets OAuth2 server instance | 获取OAuth2服务器实例
func (m *Manager) GetOAuth2Server() *oauth2.OAuth2Server {
	return m.oauth2Server
}

// ============ Internal Methods | 内部方法 ============

// getTokenInfoByTokenValue Gets token information by token value | 通过Token值获取Token信息
func (m *Manager) getTokenInfoByTokenValue(ctx context.Context, checkState ...bool) (*TokenInfo, error) {
	// Construct the token storage key | 构造Token存储键
	tokenKey := m.getTokenKey(ctx)

	// Retrieve data from storage using the token key | 使用Token键从存储中获取数据
	data, err := m.storage.Get(tokenKey)
	if err != nil {
		return nil, err // Return error if data retrieval fails | 如果数据获取失败，返回错误
	}
	if data == nil {
		return nil, ErrTokenNotFound // Return error if token is not found | 如果Token未找到，返回错误
	}

	// Convert data to raw byte slice | 将数据转换为原始字节切片
	raw, err := utils.ToBytes(data)
	if err != nil {
		return nil, err // Return error if conversion fails | 如果转换失败，返回错误
	}

	// Check for special token states (if enabled) | 检查是否为特殊状态（当启用检查时）
	// If checkState is provided and the first value is true, check for token states | 如果提供了checkState且第一个值为true，检查Token状态
	if len(checkState) > 0 && checkState[0] {
		// Convert raw bytes to string and check the token state | 将原始数据转换为字符串，并检查Token状态
		switch string(raw) {
		case string(TokenStateKickout):
			// Token has been kicked out | Token已被踢下线
			return nil, ErrTokenKickout // Return error if token is kicked out | 如果Token被踢下线，返回错误
		case string(TokenStateReplaced):
			// Token has been replaced | Token已被顶下线
			return nil, ErrTokenReplaced // Return error if token is replaced | 如果Token被顶下线，返回错误
		}
	}

	// Parse TokenInfo | 解析Token信息
	var info TokenInfo
	// Use the serializer to decode the raw data | 使用序列化器来解码原始数据
	if err = m.serializer.Decode(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", fmt.Errorf("failed to decode data"), err) // Return error if decoding fails | 如果解码失败，返回错误
	}

	return &info, nil // Return the parsed TokenInfo | 返回解析后的Token信息
}

// renewToken Renews token expiration asynchronously | 异步续期Token
func (m *Manager) renewToken(ctx context.Context, info *TokenInfo) {
	// If info is nil, retrieve token information | 如果info为空，获取Token信息
	if info == nil {
		var err error
		info, err = m.getTokenInfoByTokenValue(ctx)
		if err != nil {
			return // Return if token info retrieval fails | 如果获取Token信息失败，返回
		}
	}

	// Construct the token storage key | 构造Token存储键
	tokenKey := m.getTokenKey(ctx)
	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, info.LoginID, info.Device)
	// Get expiration time | 获取过期时间
	exp := m.getExpiration()

	// Update ActiveTime | 更新ActiveTime
	info.ActiveTime = time.Now().Unix()
	if tokenInfo, err := m.serializer.Encode(info); err == nil {
		// Renew token TTL | 续期Token的TTL
		_ = m.storage.Set(tokenKey, tokenInfo, exp)
	}

	// Renew accountKey TTL | 续期账号映射的TTL
	_ = m.storage.Expire(accountKey, exp)

	// Renew session TTL | 续期Session的TTL
	if sess, err := m.GetSession(ctx, info.LoginID); err == nil && sess != nil {
		_ = sess.Renew(exp) // Renew the session expiration | 续期Session的过期时间
	}

	// Set minimal renewal interval marker | 设置最小续期间隔标记（用于限流续期频率）
	if m.config.RenewInterval > 0 {
		_ = m.storage.Set(
			m.getRenewKey(ctx),
			DefaultRenewValue,
			time.Duration(m.config.RenewInterval)*time.Second,
		)
	}
}

// removeTokenChain Removes all related keys and triggers event | 删除Token相关的所有键并触发事件
func (m *Manager) removeTokenChain(ctx context.Context, destroySession bool, info *TokenInfo, event listener.Event) error {
	// If info is nil, retrieve token information | 如果info为空，获取Token信息
	if info == nil {
		var err error
		info, err = m.getTokenInfoByTokenValue(ctx)
		if err != nil {
			return err // Return err if token info retrieval fails | 如果获取Token信息失败，返回err
		}
	}

	// Construct the token storage key | 构造Token存储键
	tokenKey := m.getTokenKey(ctx)
	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, info.LoginID, info.Device)
	// Construct the renewal key | 构造续期标记
	renewKey := m.getRenewKey(ctx)

	// Handle different events | 处理不同的事件
	switch event {

	// EventLogout User logout | 用户主动登出
	case listener.EventLogout:
		_ = m.storage.Delete(tokenKey)   // Delete token-info mapping | 删除Token信息映射
		_ = m.storage.Delete(accountKey) // Delete account-token mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)   // Delete renew key | 删除续期标记
		if destroySession {              // Optionally destroy session | 可选销毁Session
			_ = m.DeleteSession(ctx, info.LoginID)
		}

	// EventKickout User kicked offline (keep session) | 用户被踢下线（保留Session，自动过期）
	case listener.EventKickout:
		_ = m.storage.SetKeepTTL(tokenKey, string(TokenStateKickout)) // Mark token as kicked out (preserve original TTL for cleanup) | 将Token标记为“被踢下线”（保留原TTL以便自动清理）
		_ = m.storage.Delete(accountKey)                              // Delete account mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)                                // Delete renew key | 删除续期标记

	// EventReplace User replaced by new login (keep session) | 用户被顶下线（保留Session，自动过期）
	case listener.EventReplace:
		_ = m.storage.SetKeepTTL(tokenKey, string(TokenStateReplaced)) // Mark as replaced but keep TTL | 标记为“被顶下线”，保留原TTL
		_ = m.storage.Delete(accountKey)                               // Remove account → token mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)                                 // Remove renew mark | 删除续期标记

	// Default Unknown event type | 未知事件类型（默认删除）
	default:
		_ = m.storage.Delete(tokenKey)   // Delete token-info mapping | 删除Token信息映射
		_ = m.storage.Delete(accountKey) // Delete account-token mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)   // Delete renew key | 删除续期标记
		if destroySession {              // Optionally destroy session | 可选销毁Session
			_ = m.DeleteSession(ctx, info.LoginID)
		}
	}

	// Trigger event notification | 触发事件通知
	if m.eventManager != nil {
		m.eventManager.Trigger(&listener.EventData{
			Event:    event,                                        // Event type | 事件类型
			AuthType: m.config.AuthType,                            // Auth type from context | 从上下文中获取认证类型
			LoginID:  info.LoginID,                                 // Login ID of the user | 用户的登录ID
			Device:   info.Device,                                  // Device type | 设备类型
			Token:    utils.GetCtxValue(ctx, config.CtxTokenValue), // Token value from context | 从上下文中获取Token值
		})
	}

	return nil
}

// ============ Internal Helper Methods | 内部辅助方法 ============

// getTokenKey Gets token storage key | 获取Token存储键
func (m *Manager) getTokenKey(ctx context.Context) string {
	return m.config.KeyPrefix + m.config.AuthType + TokenKeyPrefix + utils.GetCtxValue(ctx, config.CtxTokenValue)
}

// getAccountKey Gets account storage key | 获取账号存储键
func (m *Manager) getAccountKey(_ context.Context, loginID, device string) string {
	return m.config.KeyPrefix + m.config.AuthType + AccountKeyPrefix + loginID + PermissionSeparator + device
}

// getRenewKey Gets token renewal tracking key | 获取Token续期追踪键
func (m *Manager) getRenewKey(ctx context.Context) string {
	return m.config.KeyPrefix + m.config.AuthType + RenewKeyPrefix + utils.GetCtxValue(ctx, config.CtxTokenValue)
}

// getDisableKey Gets disable storage key | 获取禁用存储键
func (m *Manager) getDisableKey(_ context.Context, loginID string) string {
	return m.config.KeyPrefix + m.config.AuthType + DisableKeyPrefix + loginID
}

// getDevice extracts device type from optional parameter | 从可选参数中提取设备类型
func getDevice(device []string) string {
	if len(device) > 0 && strings.TrimSpace(device[0]) != "" {
		return device[0]
	}
	return DefaultDevice
}

// GetDevice extracts device type from optional parameter | 从可选参数中提取设备类型 公开方法
func (m *Manager) GetDevice(device []string) string {
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
