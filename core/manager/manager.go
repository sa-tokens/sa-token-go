package manager

import (
	"context"
	"fmt"
	"github.com/click33/sa-token-go/core/codec"
	"github.com/click33/sa-token-go/core/dep"
	"github.com/click33/sa-token-go/core/serror"
	"strings"
	"time"

	"github.com/click33/sa-token-go/core/pool"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/listener"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
	"github.com/click33/sa-token-go/core/token"
)

// TokenInfo Token information | Token 信息
type TokenInfo struct {
	LoginID    string `json:"loginId"`       // Login ID | 登录 ID
	Device     string `json:"device"`        // Device type | 设备类型
	CreateTime int64  `json:"createTime"`    // Token creation timestamp | 创建时间戳
	ActiveTime int64  `json:"activeTime"`    // Last active time | 最后活跃时间戳
	AuthType   string `json:"authType"`      // Authentication system type | 认证体系类型
	Tag        string `json:"tag,omitempty"` // Custom tag for additional data | 自定义标记字段（可选）
}

// Manager Authentication manager | 认证管理器
type Manager struct {
	prefix         string                        // Key prefix for all storage operations | 所有存储操作使用的键前缀
	authType       string                        // Authentication system type | 认证体系类型
	storage        adapter.Storage               // Storage adapter (Redis, Memory, etc.) | 存储适配器（例如 Redis、内存）
	config         *config.Config                // Global authentication configuration | 全局认证配置
	generator      *token.Generator              // Token generator | Token 生成器
	nonceManager   *security.NonceManager        // Nonce manager for preventing replay attacks | 随机串管理器
	refreshManager *security.RefreshTokenManager // Refresh token manager | 刷新令牌管理器
	oauth2Server   *oauth2.OAuth2Server          // OAuth2 authorization server | OAuth2 授权服务器
	renewPool      *pool.RenewPoolManager        // Token renewal task pool | Token 自动续期的任务池
	eventManager   *listener.Manager             // Event manager | 事件管理器
	deps           *dep.Dep                      // Dependencies manager | 依赖管理器
}

// NewManager Creates a new manager | 创建管理器
func NewManager(cfg *config.Config, storage adapter.Storage, deps *dep.Dep) *Manager {
	// If no configuration is provided, use the default configuration | 如果没有提供配置，使用默认配置
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// If no dependencies are provided, create a default Dep instance | 如果没有提供依赖管理器，创建默认的 Dep 实例
	if deps == nil {
		deps = dep.NewDefaultDep(nil, nil)
	}

	// Initialize the renew pool manager if the renew pool configuration is provided | 如果提供了续期池配置，则初始化续期池管理器
	var renewPoolManager *pool.RenewPoolManager
	if cfg.RenewPoolConfig != nil {
		renewPoolManager, _ = pool.NewRenewPoolManagerWithConfig(&pool.RenewPoolConfig{
			MinSize:             cfg.RenewPoolConfig.MinSize,             // Minimum pool size | 最小协程数
			MaxSize:             cfg.RenewPoolConfig.MaxSize,             // Maximum pool size | 最大协程数
			ScaleUpRate:         cfg.RenewPoolConfig.ScaleUpRate,         // Scale-up threshold | 扩容阈值
			ScaleDownRate:       cfg.RenewPoolConfig.ScaleDownRate,       // Scale-down threshold | 缩容阈值
			CheckInterval:       cfg.RenewPoolConfig.CheckInterval,       // Auto-scale check interval | 自动缩放检查间隔
			Expiry:              cfg.RenewPoolConfig.Expiry,              // Idle worker expiry duration | 空闲协程过期时间
			PrintStatusInterval: cfg.RenewPoolConfig.PrintStatusInterval, // Interval for periodic status printing | 定时打印池状态的间隔
			PreAlloc:            cfg.RenewPoolConfig.PreAlloc,            // Whether to pre-allocate memory | 是否预分配内存
			NonBlocking:         cfg.RenewPoolConfig.NonBlocking,         // Whether to use non-blocking mode | 是否为非阻塞模式
		})
	}

	// Return the new manager instance with the initialized components | 返回初始化后的管理器实例
	return &Manager{
		prefix:         cfg.KeyPrefix,
		authType:       cfg.AuthType,
		storage:        storage,
		config:         cfg,
		generator:      token.NewGenerator(cfg),
		nonceManager:   security.NewNonceManager(storage, cfg.KeyPrefix, DefaultNonceTTL),
		refreshManager: security.NewRefreshTokenManager(storage, cfg.KeyPrefix, TokenKeyPrefix, cfg),
		oauth2Server:   oauth2.NewOAuth2Server(storage, deps, cfg.KeyPrefix),
		eventManager:   listener.NewManager(),
		renewPool:      renewPoolManager,
		deps:           deps,
	}
}

// CloseManager Closes the manager and releases all resources | 关闭管理器并释放所有资源
func (m *Manager) CloseManager() {
	if m.renewPool != nil {
		// Safely close the renewPool | 安全关闭 renewPool
		m.renewPool.Stop()
		// Set renewPool to nil | 将 renewPool 设置为 nil
		m.renewPool = nil
	}
}

// ============ Login Authentication | 登录认证 ============

// Login Performs user login and returns token | 登录，返回Token
// TODO 后续参数可以抽象为结构体
func (m *Manager) Login(ctx context.Context, loginID string, device ...string) (string, error) {
	// Check if account is disabled | 检查账号是否被封禁
	if m.IsDisable(ctx, loginID) {
		return "", serror.ErrAccountDisabled
	}

	deviceType := getDevice(device)
	accountKey := m.getAccountKey(ctx, m.authType, loginID, deviceType)

	// Handle shared token for concurrent login | 处理多人登录共用 Token 的情况
	if m.config.IsShare {
		// Look for existing token of this account + device | 查找账号 + 设备下是否已有登录 Token
		existingToken, err := m.storage.Get(accountKey)
		if err == nil && existingToken != nil {
			if tokenStr, ok := assertString(existingToken); ok && m.IsLogin(context.WithValue(ctx, config.CtxTokenValue, existingToken)) {
				// If valid token exists, return it directly | 如果已有 Token 且有效，则直接返回
				return tokenStr, nil
			}
		}
	}

	// Handle concurrent login behavior | 处理并发登录逻辑
	if !m.config.IsConcurrent {
		// Concurrent login not allowed → replace previous login on the same device | 不允许并发登录 → 顶掉同设备下已存在的登录会话
		_ = m.replace(loginID, deviceType)

	} else if m.config.MaxLoginCount > 0 && !m.config.IsShare {
		// Concurrent login allowed but limited by MaxLoginCount | 允许并发登录但受 MaxLoginCount 限制
		// This limit applies to all tokens of this account across devices | 该限制针对账号所有设备的登录 Token 数量
		tokens, _ := m.GetTokenValueListByLoginID(loginID)
		if int64(len(tokens)) >= m.config.MaxLoginCount {
			// Reached maximum concurrent login count | 已达到最大并发登录数
			// You may change to "kick out earliest token" if desired | 如需也可改为“踢掉最早 Token”
			return "", serror.ErrLoginLimitExceeded
		}
	}

	// Generate token | 生成Token
	tokenValue, err := m.generator.Generate(loginID, deviceType)
	if err != nil {
		return "", err
	}

	nowTime := time.Now().Unix()
	expiration := m.getExpiration()

	// Prepare TokenInfo object and serialize to JSON | 准备Token信息对象并序列化
	tokenInfo, err := codec.Encode(TokenInfo{
		LoginID:    loginID,
		Device:     deviceType,
		CreateTime: nowTime,
		ActiveTime: nowTime,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", serror.ErrCommonMarshal, err)
	}

	// Save token-tokenInfo mapping | 保存 TokenKey-TokenInfo 映射
	tokenKey := m.getTokenKey(tokenValue)
	if err = m.storage.Set(tokenKey, tokenInfo, expiration); err != nil {
		return "", err
	}

	// Save account-token mapping | 保存 AccountKey-Token 映射
	if err = m.storage.Set(accountKey, tokenValue, expiration); err != nil {
		return "", err
	}

	// Create session | 创建Session
	err = session.
		NewSession(loginID, m.storage, m.prefix).
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
			Event:   listener.EventLogin,
			LoginID: loginID,
			Token:   tokenValue,
			Device:  deviceType,
		})
	}

	return tokenValue, nil
}

// LoginByToken Login with specified token (for seamless token refresh) | 使用指定Token登录（用于token无感刷新）
func (m *Manager) LoginByToken(ctx context.Context) error {
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return err
	}

	// Check if the account is disabled | 检查账号是否被封禁
	if m.IsDisable(info.LoginID) {
		return serror.ErrAccountDisabled
	}

	now := time.Now().Unix()
	expiration := m.getExpiration()

	// Update last active time only | 更新活跃时间（轻量刷新）
	info.ActiveTime = now

	// Write back updated TokenInfo (保留原TTL)
	data, err := codec.Encode(info)
	if err != nil {
		return fmt.Errorf("%w: %v", serror.ErrCommonMarshal, err)
	}
	if err = m.storage.SetKeepTTL(m.getTokenKey(tokenValue), data); err != nil {
		return err
	}

	// Extend TTL for token, account, session | 延长Token、账号、Session的过期时间
	if expiration > 0 {
		_ = m.storage.Expire(m.getTokenKey(tokenValue), expiration)
		_ = m.storage.Expire(m.getAccountKey(info.LoginID, info.Device), expiration)
		if sess, err := m.GetSession(info.LoginID); err == nil && sess != nil {
			_ = sess.Renew(expiration)
		}
	}

	return nil
}

// Logout Performs user logout | 登出
func (m *Manager) Logout(loginID string, device ...string) error {
	deviceType := getDevice(device)
	accountKey := m.getAccountKey(loginID, deviceType)

	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		// Already logged out | 已经登出
		return nil
	}

	// Assert token value type | 类型断言为字符串
	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(tokenStr, false, nil, listener.EventLogout)
}

// LogoutByToken Logout by token | 根据Token登出
func (m *Manager) LogoutByToken(ctx context.Context) error {
	if tokenValue == "" {
		return nil
	}

	return m.removeTokenChain(tokenValue, false, nil, listener.EventLogout)
}

// kickout Kick user offline (private) | 踢人下线（私有）
func (m *Manager) kickout(loginID string, device string) error {
	accountKey := m.getAccountKey(loginID, device)
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return nil
	}

	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(tokenStr, false, nil, listener.EventKickout)
}

// Kickout Kick user offline (public method) | 踢人下线（公开方法）
func (m *Manager) Kickout(loginID string, device ...string) error {
	deviceType := getDevice(device)
	return m.kickout(loginID, deviceType)
}

// kickoutByToken Kick user offline (private) | 根据Token踢人下线（私有）
func (m *Manager) kickoutByToken(ctx context.Context) error {
	return m.removeTokenChain(tokenValue, false, nil, listener.EventKickout)
}

// KickoutByToken Kick user offline (public method) | 根据Token踢人下线（公开方法）
func (m *Manager) KickoutByToken(ctx context.Context) error {
	return m.kickoutByToken(tokenValue)
}

// replace Replace user offline by login ID and device (private) | 根据账号和设备顶人下线（私有）
func (m *Manager) replace(loginID string, device string) error {
	accountKey := m.getAccountKey(loginID, device)
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		// No active login to replace | 无活跃登录，无需处理
		return nil
	}

	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return nil
	}

	return m.removeTokenChain(tokenStr, false, nil, listener.EventReplace)
}

// Replace Replace user offline by login ID and device (public method) | 根据账号和设备顶人下线（公开方法）
func (m *Manager) Replace(loginID string, device ...string) error {
	deviceType := getDevice(device)
	return m.replace(loginID, deviceType)
}

// replaceByToken Replace user offline by token (private) | 根据Token顶人下线（私有）
func (m *Manager) replaceByToken(ctx context.Context) error {
	return m.removeTokenChain(tokenValue, false, nil, listener.EventReplace)
}

// ReplaceByToken Replace user offline by token (public method) | 根据Token顶人下线（公开方法）
func (m *Manager) ReplaceByToken(ctx context.Context) error {
	if tokenValue == "" {
		return nil
	}
	return m.replaceByToken(tokenValue)
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
	// Note: ActiveTimeout feature removed to comply with Java sa-token design | 注意：为了符合Java版sa-token的设计，移除了ActiveTimeout特性
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue)))) {
				renewFunc := func() { m.renewToken(ctx, info) }

				// Submit renewal task to the pool if configured, otherwise use a goroutine | 如果配置了续期池，则提交续期任务到池中，否则使用协程
				if m.renewPool != nil {
					_ = m.renewPool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
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
		return serror.ErrNotLogin
	}
	return nil
}

// CheckLoginWithState Checks if user is logged in | 检查是否登录（返回详细状态）
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
			return false, serror.ErrTokenKickout
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	// Note: ActiveTimeout feature removed to comply with Java sa-token design | 注意：为了符合Java版sa-token的设计，移除了ActiveTimeout特性
	if m.config.AutoRenew && m.config.Timeout > 0 {
		// Construct the token storage key | 构造Token存储键
		tokenKey := m.getTokenKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

		// Check if token renewal is needed | 检查是否需要进行续期
		if ttl, err := m.storage.TTL(tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | 如果TTL小于MaxRefresh阈值且RenewInterval允许，则进行续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue)))) {
				renewFunc := func() { m.renewToken(ctx, info) }

				// Submit renewal task to the pool if configured, otherwise use a goroutine | 如果配置了续期池，则提交续期任务到池中，否则使用协程
				if m.renewPool != nil {
					_ = m.renewPool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
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
		return "", serror.ErrNotLogin // Return error if not logged in | 如果未登录，则返回错误
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
	// Retrieve the device type from the provided device parameter | 从提供的设备参数中获取设备类型
	deviceType := getDevice(device)

	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, m.authType, loginID, deviceType)

	// Retrieve the token value from storage | 从存储中获取Token值
	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return "", serror.ErrTokenNotFound // Return error if token not found | 如果未找到Token，则返回错误
	}

	// Assert token value as a string | 断言Token值为字符串
	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return "", serror.ErrTokenNotFound // Return error if token is not a valid string | 如果Token不是有效字符串，则返回错误
	}

	// Return the token string | 返回Token字符串
	return tokenStr, nil
}

// GetTokenInfo Gets token information | 获取Token信息
func (m *Manager) GetTokenInfo(tokenValue string) (*TokenInfo, error) {
	return m.getTokenInfoByTokenValue(context.WithValue(context.Background(), config.CtxTokenValue, tokenValue))
}

// ============ Account Disable | 账号封禁 ============

// Disable Disables an account | 封禁账号
func (m *Manager) Disable(loginID string, duration time.Duration) error {
	// Check if the account has active sessions and force logout | 检查账号是否有活跃会话并强制下线
	tokens, err := m.GetTokenValueListByLoginID(loginID)
	if err == nil && len(tokens) > 0 {
		for _, tokenValue := range tokens {
			// Force kick out each active token | 强制踢出所有活跃的Token
			_ = m.removeTokenChain(tokenValue, true, nil, listener.EventKickout)
		}
	}

	key := m.getDisableKey(loginID)
	// Set disable flag with specified duration | 设置封禁标记并指定封禁时长
	return m.storage.Set(key, DisableValue, duration)
}

// Untie Re-enables a disabled account | 解封账号
func (m *Manager) Untie(loginID string) error {
	key := m.getDisableKey(loginID)
	return m.storage.Delete(key)
}

// IsDisable Checks if account is disabled | 检查账号是否被封禁
func (m *Manager) IsDisable(ctx context.Context, loginID string) bool {
	key := m.getDisableKey(ctx, m.authType, loginID)
	return m.storage.Exists(key)
}

// GetDisableTime Gets remaining disable time in seconds | 获取账号剩余封禁时间（秒）
func (m *Manager) GetDisableTime(loginID string) (int64, error) {
	key := m.getDisableKey(loginID)
	ttl, err := m.storage.TTL(key)
	if err != nil {
		return -2, err
	}
	return int64(ttl.Seconds()), nil
}

// ============ Session Management | Session管理 ============

// GetSession Gets session by login ID | 获取Session
func (m *Manager) GetSession(ctx context.Context, loginID string) (*session.Session, error) {
	sess, err := session.Load(loginID, m.storage, m.prefix)
	if err != nil {
		sess = session.NewSession(loginID, m.storage, m.prefix)
	}
	return sess, nil
}

// GetSessionByToken Gets session by token | 根据Token获取Session
func (m *Manager) GetSessionByToken(tokenValue string) (*session.Session, error) {
	loginID, err := m.GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return m.GetSession(loginID)
}

// DeleteSession Deletes session | 删除Session
func (m *Manager) DeleteSession(loginID string) error {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return err
	}
	return sess.Destroy()
}

// DeleteSessionByToken Deletes session by token | 根据Token删除Session
func (m *Manager) DeleteSessionByToken(tokenValue string) error {
	sess, err := m.GetSessionByToken(tokenValue)
	if err != nil {
		return err
	}
	return sess.Destroy()
}

// ============ Permission Validation | 权限验证 ============

// SetPermissions Sets permissions for user | 设置权限
func (m *Manager) SetPermissions(loginID string, permissions []string) error {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return err
	}
	permissionsFromSession, b := sess.Get(SessionKeyPermissions)
	if b {
		permissions = append(permissions, m.toStringSlice(permissionsFromSession)...)
		permissions = removeDuplicateStrings(permissions)
	}
	return sess.Set(SessionKeyPermissions, permissions, m.getExpiration())
}

// RemovePermissions removes specified permissions for user | 删除用户指定权限
func (m *Manager) RemovePermissions(loginID string, permissions []string) error {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return err
	}

	// Load existing permissions | 加载已有权限
	existing, ok := sess.Get(SessionKeyPermissions)
	if !ok {
		return nil // No permissions to remove | 没有权限可删除
	}

	existingPerms := m.toStringSlice(existing)
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

	// Save updated permissions | 保存更新后的权限列表
	return sess.Set(SessionKeyPermissions, newPerms, m.getExpiration())
}

// GetPermissions Gets permission list | 获取权限列表
func (m *Manager) GetPermissions(loginID string) ([]string, error) {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return nil, err
	}

	perms, exists := sess.Get(SessionKeyPermissions)
	if !exists {
		return []string{}, nil
	}

	return m.toStringSlice(perms), nil
}

// HasPermission 检查是否有指定权限
func (m *Manager) HasPermission(loginID string, permission string) bool {
	perms, err := m.GetPermissions(loginID)
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

// HasPermissionsAnd 检查是否拥有所有权限（AND）
func (m *Manager) HasPermissionsAnd(loginID string, permissions []string) bool {
	for _, perm := range permissions {
		if !m.HasPermission(loginID, perm) {
			return false
		}
	}
	return true
}

// HasPermissionsOr 检查是否拥有任一权限（OR）
func (m *Manager) HasPermissionsOr(loginID string, permissions []string) bool {
	for _, perm := range permissions {
		if m.HasPermission(loginID, perm) {
			return true
		}
	}
	return false
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

// ============ Role Validation | 角色验证 ============

// SetRoles Sets roles for user | 设置角色
func (m *Manager) SetRoles(loginID string, roles []string) error {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return err
	}
	rolesFromSession, b := sess.Get(SessionKeyRoles)
	if b {
		roles = append(roles, m.toStringSlice(rolesFromSession)...)
		roles = removeDuplicateStrings(roles)
	}
	return sess.Set(SessionKeyRoles, roles, m.getExpiration())
}

// RemoveRoles removes specified roles for user | 删除用户指定角色
func (m *Manager) RemoveRoles(loginID string, roles []string) error {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return err
	}

	// Load existing roles | 加载已有角色
	existing, ok := sess.Get(SessionKeyRoles)
	if !ok {
		return nil // No roles to remove | 没有角色可删除
	}

	existingRoles := m.toStringSlice(existing)
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

// GetRoles Gets role list | 获取角色列表
func (m *Manager) GetRoles(loginID string) ([]string, error) {
	sess, err := m.GetSession(loginID)
	if err != nil {
		return nil, err
	}

	roles, exists := sess.Get(SessionKeyRoles)
	if !exists {
		return []string{}, nil
	}

	return m.toStringSlice(roles), nil
}

// HasRole 检查是否有指定角色
func (m *Manager) HasRole(loginID string, role string) bool {
	roles, err := m.GetRoles(loginID)
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

// HasRolesAnd 检查是否拥有所有角色（AND）
func (m *Manager) HasRolesAnd(loginID string, roles []string) bool {
	for _, role := range roles {
		if !m.HasRole(loginID, role) {
			return false
		}
	}
	return true
}

// HasRolesOr 检查是否拥有任一角色（OR）
func (m *Manager) HasRolesOr(loginID string, roles []string) bool {
	for _, role := range roles {
		if m.HasRole(loginID, role) {
			return true
		}
	}
	return false
}

// ============ Token Tags | Token标签 ============

// SetTokenTag Sets token tag | 设置Token标签
func (m *Manager) SetTokenTag(tokenValue, tag string) error {
	// Tag feature not supported to comply with Java sa-token design
	// If you need custom metadata, use Session instead
	return fmt.Errorf("token tag feature not supported (use Session for custom metadata)")
}

// GetTokenTag Gets token tag | 获取Token标签
func (m *Manager) GetTokenTag(tokenValue string) (string, error) {
	// Tag feature not supported to comply with Java sa-token design
	return "", fmt.Errorf("token tag feature not supported (use Session for custom metadata)")
}

// ============ Session Query | 会话查询 ============

// GetTokenValueListByLoginID Gets all tokens for specified account | 获取指定账号的所有Token
func (m *Manager) GetTokenValueListByLoginID(loginID string) ([]string, error) {
	pattern := m.prefix + AccountKeyPrefix + loginID + ":*"
	keys, err := m.storage.Keys(pattern)
	if err != nil {
		return nil, err
	}

	tokens := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := m.storage.Get(key)
		if err == nil && value != nil {
			if tokenStr, ok := assertString(value); ok {
				tokens = append(tokens, tokenStr)
			}
		}
	}

	return tokens, nil
}

// GetSessionCountByLoginID Gets session count for specified account | 获取指定账号的Session数量
func (m *Manager) GetSessionCountByLoginID(loginID string) (int, error) {
	tokens, err := m.GetTokenValueListByLoginID(loginID)
	if err != nil {
		return 0, err
	}
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

// GetEventManager gets the event manager | 获取事件管理器
func (m *Manager) GetEventManager() *listener.Manager {
	return m.eventManager
}

// ============ Public Getters | 公共获取器 ============

// GetConfig Gets configuration | 获取配置
func (m *Manager) GetConfig() *config.Config {
	return m.config
}

// GetStorage Gets storage | 获取存储
func (m *Manager) GetStorage() adapter.Storage {
	return m.storage
}

// ============ Security Features | 安全特性 ============

// GenerateNonce Generates a one-time nonce | 生成一次性随机数
func (m *Manager) GenerateNonce() (string, error) {
	return m.nonceManager.Generate()
}

// VerifyNonce Verifies a nonce | 验证随机数
func (m *Manager) VerifyNonce(nonce string) bool {
	return m.nonceManager.Verify(nonce)
}

// LoginWithRefreshToken Logs in with refresh token | 使用刷新令牌登录
func (m *Manager) LoginWithRefreshToken(loginID, device string) (*security.RefreshTokenInfo, error) {
	deviceType := getDevice([]string{device})

	accessToken, err := m.Login(loginID, deviceType)
	if err != nil {
		return nil, err
	}

	return m.refreshManager.GenerateTokenPair(loginID, deviceType, accessToken)
}

// RefreshAccessToken Refreshes access token | 刷新访问令牌
func (m *Manager) RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	return m.refreshManager.RefreshAccessToken(refreshToken)
}

// RevokeRefreshToken Revokes refresh token | 撤销刷新令牌
func (m *Manager) RevokeRefreshToken(refreshToken string) error {
	return m.refreshManager.RevokeRefreshToken(refreshToken)
}

// GetOAuth2Server Gets OAuth2 server instance | 获取OAuth2服务器实例
func (m *Manager) GetOAuth2Server() *oauth2.OAuth2Server {
	return m.oauth2Server
}

// ============ Internal Methods | 内部方法 ============

// getTokenInfoByTokenValue Gets token information by token value | 通过Token值获取Token信息
func (m *Manager) getTokenInfoByTokenValue(ctx context.Context, checkState ...bool) (*TokenInfo, error) {
	// Construct the token storage key | 构造Token存储键
	tokenKey := m.getTokenKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

	// Retrieve data from storage using the token key | 使用Token键从存储中获取数据
	data, err := m.storage.Get(tokenKey)
	if err != nil {
		return nil, err // Return error if data retrieval fails | 如果数据获取失败，返回错误
	}
	if data == nil {
		return nil, serror.ErrTokenNotFound // Return error if token is not found | 如果Token未找到，返回错误
	}

	// Convert data to raw byte slice | 将数据转换为原始字节切片
	raw, err := codec.UnifyToBytes(data)
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
			return nil, serror.ErrTokenKickout // Return error if token is kicked out | 如果Token被踢下线，返回错误
		case string(TokenStateReplaced):
			// Token has been replaced | Token已被顶下线
			return nil, serror.ErrTokenReplaced // Return error if token is replaced | 如果Token被顶下线，返回错误
		}
	}

	// Parse TokenInfo | 解析Token信息
	var info TokenInfo
	// Use the serializer to decode the raw data | 使用序列化器来解码原始数据
	if err = m.deps.GetSerializer().Decode(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonUnmarshal, err) // Return error if decoding fails | 如果解码失败，返回错误
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
	tokenKey := m.getTokenKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, m.authType, info.LoginID, info.Device)

	// Get expiration time | 获取过期时间
	exp := m.getExpiration()

	// Update ActiveTime and keep original TTL | 更新ActiveTime，保持原TTL不变
	info.ActiveTime = time.Now().Unix()
	if tokenInfo, err := m.deps.GetSerializer().Encode(info); err == nil {
		_ = m.storage.SetKeepTTL(tokenKey, tokenInfo) // Store the updated token information while keeping the original TTL | 存储更新后的Token信息，保持原TTL
	}

	// Renew token TTL | 续期Token的TTL
	_ = m.storage.Expire(tokenKey, exp)

	// Renew accountKey TTL | 续期账号映射的TTL
	_ = m.storage.Expire(accountKey, exp)

	// Renew session TTL | 续期Session的TTL
	if sess, err := m.GetSession(ctx, info.LoginID); err == nil && sess != nil {
		_ = sess.Renew(exp) // Renew the session expiration | 续期Session的过期时间
	}

	// Set minimal renewal interval marker | 设置最小续期间隔标记（用于限流续期频率）
	if m.config.RenewInterval > 0 {
		_ = m.storage.Set(
			m.getRenewKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue)),
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
	tokenKey := m.getTokenKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

	// Construct the account storage key | 构造账号存储键
	accountKey := m.getAccountKey(ctx, m.authType, info.LoginID, info.Device)

	// Construct the renewal key | 构造续期标记
	renewKey := m.getRenewKey(ctx, m.authType, getCtxValue(ctx, config.CtxTokenValue))

	// Handle different events | 处理不同的事件
	switch event {

	// EventLogout User logout | 用户主动登出
	case listener.EventLogout:
		_ = m.storage.Delete(tokenKey)   // Delete token-info mapping | 删除Token信息映射
		_ = m.storage.Delete(accountKey) // Delete account-token mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)   // Delete renew key | 删除续期标记
		if destroySession {              // Optionally destroy session | 可选销毁Session
			_ = m.DeleteSession(info.LoginID)
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
			_ = m.DeleteSession(info.LoginID)
		}
	}

	// Trigger event notification | 触发事件通知
	if m.eventManager != nil {
		m.eventManager.Trigger(&listener.EventData{
			Event:    event,                                  // Event type | 事件类型
			AuthType: getCtxValue(ctx, config.CtxAutoType),   // Auth type from context | 从上下文中获取认证类型
			LoginID:  info.LoginID,                           // Login ID of the user | 用户的登录ID
			Token:    getCtxValue(ctx, config.CtxTokenValue), // Token value from context | 从上下文中获取Token值
			Device:   info.Device,                            // Device type | 设备类型
		})
	}

	return nil
}

// ============ Internal Helper Methods | 内部辅助方法 ============

// getTokenKey Gets token storage key | 获取Token存储键
func (m *Manager) getTokenKey(_ context.Context, autoType, tokenValue string) string {
	return m.prefix + autoType + TokenKeyPrefix + tokenValue
}

// getAccountKey Gets account storage key | 获取账号存储键
func (m *Manager) getAccountKey(_ context.Context, autoType, loginID, device string) string {
	return m.prefix + autoType + AccountKeyPrefix + loginID + PermissionSeparator + device
}

// getRenewKey Gets token renewal tracking key | 获取Token续期追踪键
func (m *Manager) getRenewKey(_ context.Context, autoType, tokenValue string) string {
	return m.prefix + autoType + RenewKeyPrefix + tokenValue
}

// getDisableKey Gets disable storage key | 获取禁用存储键
func (m *Manager) getDisableKey(_ context.Context, autoType, loginID string) string {
	return m.prefix + autoType + DisableKeyPrefix + loginID
}

// getCtxValue Returns the value for the given key in the context as a string or the defaultValue if the value is not of type string | 从上下文中获取指定key的值，如果值不是字符串则返回默认值
func getCtxValue(ctx context.Context, valueKey string, defaultValue ...string) string {
	val := ctx.Value(valueKey) // 从上下文中获取值 | Retrieve the value from the context

	// Check if the value is a non-empty string | 检查值是否是非空字符串
	if v, ok := val.(string); ok && v != "" {
		return v // If it's a non-empty string, return it | 如果是非空字符串，返回该值
	}

	// If defaultValue is provided, return it, otherwise return an empty string | 如果提供了默认值，返回默认值，否则返回空字符串
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Otherwise, return an empty string | 否则返回空字符串
	return ""
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

// assertString safely converts interface to string | 安全地将interface转换为string
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
