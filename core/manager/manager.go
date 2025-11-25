package manager

import (
	"fmt"
	"github.com/click33/sa-token-go/core/codec"
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

// Constants for storage keys and default values | 存储键和默认值常量
const (
	DefaultDevice     = "default"
	DefaultPrefix     = "satoken"
	DisableValue      = "1"
	DefaultRenewValue = "1"
	DefaultNonceTTL   = 5 * time.Minute

	// Key prefixes | 键前缀
	TokenKeyPrefix   = "token:"
	AccountKeyPrefix = "account:"
	DisableKeyPrefix = "disable:"
	RenewKeyPrefix   = "renew:"

	// Session keys | Session键
	SessionKeyLoginID     = "loginId"
	SessionKeyDevice      = "device"
	SessionKeyLoginTime   = "loginTime"
	SessionKeyPermissions = "permissions"
	SessionKeyRoles       = "roles"

	// Wildcard for permissions | 权限通配符
	PermissionWildcard  = "*"
	PermissionSeparator = ":"
)

// TokenState 表示 Token 的逻辑状态
type TokenState string

const (
	TokenStateLogout   TokenState = "LOGOUT"      // Logout state | 主动登出
	TokenStateKickout  TokenState = "KICK_OUT"    // Kickout state | 被踢下线
	TokenStateReplaced TokenState = "BE_REPLACED" // Replaced state | 被顶下线
)

// TokenInfo Token information | Token信息
type TokenInfo struct {
	LoginID    string `json:"loginId"`
	Device     string `json:"device"`
	CreateTime int64  `json:"createTime"`
	ActiveTime int64  `json:"activeTime"` // Last active time | 最后活跃时间
	Tag        string `json:"tag,omitempty"`
}

// Manager Authentication manager | 认证管理器
type Manager struct {
	prefix         string
	storage        adapter.Storage
	config         *config.Config
	generator      *token.Generator
	nonceManager   *security.NonceManager
	refreshManager *security.RefreshTokenManager
	oauth2Server   *oauth2.OAuth2Server
	renewPool      *pool.RenewPoolManager
	eventManager   *listener.Manager
}

// NewManager Creates a new manager | 创建管理器
func NewManager(storage adapter.Storage, cfg *config.Config) *Manager {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// Use configured prefix, fallback to default | 使用配置的前缀，回退到默认值
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = DefaultPrefix
	}

	// Initialize renew pool manager if configuration is provided | 如果配置了续期池，初始化续期池管理器
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

	return &Manager{
		storage:        storage,
		config:         cfg,
		generator:      token.NewGenerator(cfg),
		prefix:         prefix,
		nonceManager:   security.NewNonceManager(storage, prefix, DefaultNonceTTL),
		refreshManager: security.NewRefreshTokenManager(storage, prefix, TokenKeyPrefix, cfg),
		oauth2Server:   oauth2.NewOAuth2Server(storage, prefix),
		eventManager:   listener.NewManager(),
		renewPool:      renewPoolManager,
	}
}

// CloseManager Closes the manager and releases all resources | 关闭管理器并释放所有资源
func (m *Manager) CloseManager() {
	if m.renewPool != nil {
		// 安全关闭 renewPool
		m.renewPool.Stop()
		m.renewPool = nil
	}
}

// ============ Helper Methods | 辅助方法 ============

// getDevice extracts device type from optional parameter | 从可选参数中提取设备类型
func getDevice(device []string) string {
	if len(device) > 0 && device[0] != "" {
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

// ============ Login Authentication | 登录认证 ============

// Login Performs user login and returns token | 登录，返回Token
func (m *Manager) Login(loginID string, device ...string) (string, error) {
	// Check if account is disabled | 检查账号是否被封禁
	if m.IsDisable(loginID) {
		return "", serror.ErrAccountDisabled
	}

	deviceType := getDevice(device)
	accountKey := m.getAccountKey(loginID, deviceType)

	// Handle shared token for concurrent login | 处理多人登录共用 Token 的情况
	if m.config.IsShare {
		// Look for existing token of this account + device | 查找账号 + 设备下是否已有登录 Token
		existingToken, err := m.storage.Get(accountKey)
		if err == nil && existingToken != nil {
			if tokenStr, ok := assertString(existingToken); ok && m.IsLogin(tokenStr) {
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
		if len(tokens) >= m.config.MaxLoginCount {
			// Reached maximum concurrent login count | 已达到最大并发登录数
			// You may change to "kick out earliest token" if desired | 如需也可改为“踢掉最早 Token”
			return "", serror.ErrLoginLimitExceeded
		}
	}

	// Generate token | 生成Token
	tokenValue, err := m.generator.Generate(loginID, deviceType)
	if err != nil {
		return "", fmt.Errorf("%w: %v", serror.ErrTokenGenerateFailed, err)
	}

	nowTime := time.Now().Unix()
	expiration := m.getExpiration()

	// Prepare TokenInfo object and serialize to JSON | 准备Token信息对象并序列化
	tokenInfo, err := codec.DefaultSerializer.Marshal(TokenInfo{
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
		return "", fmt.Errorf("%w: %v", serror.ErrCommonStoreFailed, err)
	}

	// Save account-token mapping | 保存 AccountKey-Token 映射
	if err = m.storage.Set(accountKey, tokenValue, expiration); err != nil {
		return "", fmt.Errorf("%w: %v", serror.ErrCommonStoreFailed, err)
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
func (m *Manager) LoginByToken(loginID string, tokenValue string, device ...string) error {
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return err
	}
	if info == nil {
		return serror.ErrInvalidTokenData
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
	if data, err := codec.DefaultSerializer.Marshal(info); err == nil {
		_ = m.storage.SetKeepTTL(m.getTokenKey(tokenValue), data)
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
func (m *Manager) LogoutByToken(tokenValue string) error {
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
func (m *Manager) kickoutByToken(tokenValue string) error {
	return m.removeTokenChain(tokenValue, false, nil, listener.EventKickout)
}

// KickoutByToken Kick user offline (public method) | 根据Token踢人下线（公开方法）
func (m *Manager) KickoutByToken(tokenValue string) error {
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
func (m *Manager) replaceByToken(tokenValue string) error {
	return m.removeTokenChain(tokenValue, false, nil, listener.EventReplace)
}

// ReplaceByToken Replace user offline by token (public method) | 根据Token顶人下线（公开方法）
func (m *Manager) ReplaceByToken(tokenValue string) error {
	if tokenValue == "" {
		return nil
	}
	return m.replaceByToken(tokenValue)
}

// ============ Token Validation | Token验证 ============

// IsLogin Checks if user is logged in | 检查是否登录
func (m *Manager) IsLogin(tokenValue string) bool {
	if tokenValue == "" {
		return false
	}
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return false
	}

	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		// Check if token has exceeded active timeout | 检查 Token 是否超过活跃超时时间
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理 Token 相关数据
			_ = m.removeTokenChain(tokenValue, false, info, listener.EventKickout)
			return false
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	// Note: ActiveTimeout feature removed to comply with Java sa-token design
	if m.config.AutoRenew && m.config.Timeout > 0 {
		tokenKey := m.getTokenKey(tokenValue)
		if ttl, err := m.storage.TTL(tokenKey); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | TTL和RenewInterval同时满足条件才续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(tokenValue))) {
				renewFunc := func() { m.renewToken(tokenValue, info) }

				// Submit to pool if configured, otherwise use goroutine | 使用续期池或协程执行续期
				if m.renewPool != nil {
					_ = m.renewPool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
				} else {
					go renewFunc() // Fallback to goroutine if pool is not configured | 如果续期池未配置，使用普通协程
				}
			}
		}
	}

	return true
}

// CheckLogin Checks login status (throws serror if not logged in) | 检查登录（未登录抛出错误）
func (m *Manager) CheckLogin(tokenValue string) error {
	if !m.IsLogin(tokenValue) {
		return serror.ErrNotLogin
	}
	return nil
}

// CheckLoginWithState Checks if user is logged in | 检查是否登录（返回详细状态）
func (m *Manager) CheckLoginWithState(tokenValue string) (bool, error) {
	if tokenValue == "" {
		return false, nil
	}

	// Try to get token info with state check | 尝试获取Token信息（包含状态检查）
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return false, err
	}

	if m.config.ActiveTimeout > 0 {
		now := time.Now().Unix()
		// Check if token has exceeded active timeout | 检查 Token 是否超过活跃超时时间
		if now-info.ActiveTime > m.config.ActiveTimeout {
			// Force logout and clean up token data | 强制登出并清理 Token 相关数据
			_ = m.removeTokenChain(tokenValue, false, info, listener.EventKickout)
			return false, serror.ErrTokenKickout
		}
	}

	// Async auto-renew for better performance | 异步自动续期（提高性能）
	// Note: ActiveTimeout feature removed to comply with Java sa-token design
	if m.config.AutoRenew && m.config.Timeout > 0 {
		if ttl, err := m.storage.TTL(m.getTokenKey(tokenValue)); err == nil {
			ttlSeconds := int64(ttl.Seconds())

			// Perform renewal if TTL is below MaxRefresh threshold and RenewInterval allows | TTL和RenewInterval同时满足条件才续期
			if ttlSeconds > 0 && (m.config.MaxRefresh <= 0 || ttlSeconds <= m.config.MaxRefresh) && (m.config.RenewInterval <= 0 || !m.storage.Exists(m.getRenewKey(tokenValue))) {
				renewFunc := func() { m.renewToken(tokenValue, info) }

				// Submit to pool if configured, otherwise use goroutine | 使用续期池或协程执行续期
				if m.renewPool != nil {
					_ = m.renewPool.Submit(renewFunc) // Submit token renewal task to the pool | 提交Token续期任务到续期池
				} else {
					go renewFunc() // Fallback to goroutine if pool is not configured | 如果续期池未配置，使用普通协程
				}
			}
		}
	}

	return true, nil
}

// GetLoginID Gets login ID from token | 根据Token获取登录ID
func (m *Manager) GetLoginID(tokenValue string) (string, error) {
	if !m.IsLogin(tokenValue) {
		return "", serror.ErrNotLogin
	}

	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", serror.ErrInvalidTokenData
	}

	return info.LoginID, nil
}

// GetLoginIDNotCheck Gets login ID without checking token validity | 获取登录ID（不检查Token是否有效）
func (m *Manager) GetLoginIDNotCheck(tokenValue string) (string, error) {
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", serror.ErrInvalidTokenData
	}
	return info.LoginID, err
}

// GetTokenValue Gets token by login ID and device | 根据登录ID以及设备获取Token
func (m *Manager) GetTokenValue(loginID string, device ...string) (string, error) {
	deviceType := getDevice(device)
	accountKey := m.getAccountKey(loginID, deviceType)

	tokenValue, err := m.storage.Get(accountKey)
	if err != nil || tokenValue == nil {
		return "", serror.ErrTokenNotFound
	}

	tokenStr, ok := assertString(tokenValue)
	if !ok {
		return "", serror.ErrTokenNotFound
	}

	return tokenStr, nil
}

// GetTokenInfo Gets token information | 获取Token信息
func (m *Manager) GetTokenInfo(tokenValue string) (*TokenInfo, error) {
	return m.getTokenInfo(tokenValue)
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
func (m *Manager) IsDisable(loginID string) bool {
	key := m.getDisableKey(loginID)
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

// getDisableKey Gets disable storage key | 获取禁用存储键
func (m *Manager) getDisableKey(loginID string) string {
	return m.prefix + DisableKeyPrefix + loginID
}

// ============ Session Management | Session管理 ============

// GetSession Gets session by login ID | 获取Session
func (m *Manager) GetSession(loginID string) (*session.Session, error) {
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

// ============ Internal Helper Methods | 内部辅助方法 ============

// getTokenKey Gets token storage key | 获取Token存储键
func (m *Manager) getTokenKey(tokenValue string) string {
	return m.prefix + TokenKeyPrefix + tokenValue
}

// getAccountKey Gets account storage key | 获取账号存储键
func (m *Manager) getAccountKey(loginID, device string) string {
	return m.prefix + AccountKeyPrefix + loginID + PermissionSeparator + device
}

// getRenewKey Gets token renewal tracking key | 获取Token续期追踪键
func (m *Manager) getRenewKey(tokenValue string) string {
	return m.prefix + RenewKeyPrefix + tokenValue
}

// getLoginIDByToken Gets loginID by token (符合 Java sa-token 设计) | 通过 Token 获取 loginID
func (m *Manager) getLoginIDByToken(tokenValue string) (string, error) {
	info, err := m.getTokenInfo(tokenValue)
	if err != nil {
		return "", err
	}
	return info.LoginID, nil
}

// getTokenInfo Gets token information | 获取Token信息
func (m *Manager) getTokenInfo(tokenValue string, checkState ...bool) (*TokenInfo, error) {
	tokenKey := m.getTokenKey(tokenValue)
	data, err := m.storage.Get(tokenKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonGetFailed, err)
	}
	if data == nil {
		return nil, serror.ErrTokenNotFound
	}

	raw, err := codec.UnifyToBytes(data)
	if err != nil {
		return nil, err
	}

	// Check for special token states (if enabled) | 检查是否为特殊状态（当启用检查时）
	str := string(raw)
	if len(checkState) == 0 || checkState[0] {
		switch str {
		case string(TokenStateKickout):
			return nil, serror.ErrTokenKickout // 被踢下线
		case string(TokenStateReplaced):
			return nil, serror.ErrTokenReplaced // 被顶下线
		}
	}

	// Parse TokenInfo | 解析Token信息
	var info TokenInfo
	if err = codec.DefaultSerializer.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrInvalidTokenData, err)
	}

	return &info, nil
}

// renewToken Renews token expiration asynchronously | 异步续期Token
func (m *Manager) renewToken(tokenValue string, info *TokenInfo) {
	tokenKey := m.getTokenKey(tokenValue)
	if info == nil {
		var err error
		info, err = m.getTokenInfo(tokenValue)
		if err != nil {
			return
		}
	}

	// Basic validation | 基本校验
	if info == nil || info.LoginID == "" || info.Device == "" {
		return
	}

	// Update ActiveTime and keep original TTL | 更新 ActiveTime，保持原 TTL 不变
	info.ActiveTime = time.Now().Unix()
	if tokenInfo, err := codec.DefaultSerializer.Marshal(info); err == nil {
		_ = m.storage.SetKeepTTL(tokenKey, tokenInfo)
	}

	// Extend TTL for token and its accountKey | 为 Token 与对应 accountKey 延长 TTL
	exp := m.getExpiration()

	// Renew token TTL | 续期 Token TTL
	_ = m.storage.Expire(tokenKey, exp)
	// Renew accountKey TTL | 续期账号映射 TTL
	accountKey := m.getAccountKey(info.LoginID, info.Device)
	_ = m.storage.Expire(accountKey, exp)
	// Renew session TTL | 续期 Session TTL
	if sess, err := m.GetSession(info.LoginID); err == nil && sess != nil {
		_ = sess.Renew(exp)
	}

	// Set minimal renewal interval marker | 设置最小续期间隔标记（限流续期频率）
	if m.config.RenewInterval > 0 {
		_ = m.storage.Set(
			m.getRenewKey(tokenValue),
			DefaultRenewValue,
			time.Duration(m.config.RenewInterval)*time.Second,
		)
	}
}

// removeTokenChain Removes all related keys and triggers event | 删除Token相关的所有键并触发事件
func (m *Manager) removeTokenChain(tokenValue string, destroySession bool, info *TokenInfo, event listener.Event) error {
	if info == nil {
		if tokenValue == "" {
			return nil
		}

		// Get TokenInfo  | 获取Token信息
		var err error
		info, err = m.getTokenInfo(tokenValue, false)
		if err != nil {
			return err
		}
		if info == nil {
			return serror.ErrInvalidTokenData
		}
	}

	tokenKey := m.getTokenKey(tokenValue)                    // Token存储键 | Token storage key
	accountKey := m.getAccountKey(info.LoginID, info.Device) // Account映射键 | Account mapping key
	renewKey := m.getRenewKey(tokenValue)                    // 续期追踪键 | Token renewal tracking key

	switch event {

	// EventLogout User logout | 用户主动登出
	case listener.EventLogout:
		_ = m.storage.Delete(tokenKey)   // Delete token-info mapping | 删除Token信息映射
		_ = m.storage.Delete(accountKey) // Delete account-token mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)   // Delete renew key | 删除续期标记
		if destroySession {              // Optionally destroy session | 可选销毁Session
			_ = m.DeleteSession(info.LoginID)
		}

	// EventKickout User kicked offline (keep session) | 用户被踢下线（保留Session）
	case listener.EventKickout:
		_ = m.storage.SetKeepTTL(tokenKey, string(TokenStateKickout)) // Mark token as kicked out (preserve original TTL for cleanup) | 将Token标记为“被踢下线”（保留原TTL以便自动清理）
		_ = m.storage.Delete(accountKey)                              // Delete account mapping | 删除账号映射
		_ = m.storage.Delete(renewKey)                                // Delete renew key | 删除续期标记

	// EventReplace User replaced by new login (keep session) | 用户被顶下线（保留Session）
	case listener.EventReplace:
		_ = m.storage.SetKeepTTL(tokenKey, string(TokenStateReplaced)) // Mark as replaced but keep TTL | 标记为被顶下线，保留原TTL
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
			Event:   event,
			LoginID: info.LoginID,
			Token:   tokenValue,
			Device:  info.Device,
		})
	}

	return nil
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
