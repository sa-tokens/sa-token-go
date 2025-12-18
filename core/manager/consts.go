// @Author daixk 2025/12/4 17:58:00
package manager

import "time"

// Constants for storage keys and log values | 存储键和默认值常量
const (
	DefaultDevice     = "default"       // Default device type | 默认设备类型
	DefaultPrefix     = "satoken"       // Default key prefix | 默认键前缀
	DisableValue      = "1"             // Disabled flag value | 被禁用标记值
	DefaultRenewValue = "1"             // Default renew flag value | 默认续期标记值
	DefaultNonceTTL   = 5 * time.Minute // Default nonce expiration time | 默认随机令牌有效期

	// Key prefixes | 键前缀
	TokenKeyPrefix        = "token:"   // Token storage prefix | Token 存储前缀
	AccountKeyPrefix      = "account:" // Account storage prefix | 账号存储前缀
	DisableKeyPrefix      = "disable:" // Disable state prefix | 禁用状态存储前缀
	RenewKeyPrefix        = "renew:"   // Token renew prefix | Token 续期存储前缀
	TokenValueListLastKey = ":*"

	// Session keys | Session 键
	SessionKeyLoginID     = "loginId"     // Login ID | 登录 ID
	SessionKeyDevice      = "device"      // Device type | 设备类型
	SessionKeyLoginTime   = "loginTime"   // Login time | 登录时间
	SessionKeyPermissions = "permissions" // Permissions list | 权限列表
	SessionKeyRoles       = "roles"       // Roles list | 角色列表

	// Wildcard for permissions | 权限通配符
	PermissionWildcard  = "*" // Global permission wildcard | 全局权限通配符
	PermissionSeparator = ":" // Permission segment separator | 权限段分隔符
)

// TokenState 表示 Token 的逻辑状态
type TokenState string

const (
	TokenStateLogout   TokenState = "LOGOUT"      // Logout state | 主动登出
	TokenStateKickout  TokenState = "KICK_OUT"    // Kickout state | 被踢下线
	TokenStateReplaced TokenState = "BE_REPLACED" // Replaced state | 被顶下线
)
