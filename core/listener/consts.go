// @Author daixk 2025/12/14 20:49:00
package listener

// Event represents the type of authentication event | 认证事件类型
type Event string

const (
	// EventLogin fired when a user logs in | 用户登录事件
	EventLogin Event = "login"

	// EventLogout fired when a user logs out | 用户登出事件
	EventLogout Event = "logout"

	// EventKickout fired when a user is forcibly logged out | 用户被踢下线事件
	EventKickout Event = "kickout"

	// EventReplace fired when a user is replaced by a new login | 用户被顶下线事件
	EventReplace Event = "replace"

	// EventDisable fired when an account is disabled | 账号被禁用事件
	EventDisable Event = "disable"

	// EventUntie fired when an account is re-enabled | 账号解禁事件
	EventUntie Event = "untie"

	// EventRenew fired when a token is renewed | Token续期事件
	EventRenew Event = "renew"

	// EventCreateSession fired when a new session is created | Session创建事件
	EventCreateSession Event = "createSession"

	// EventDestroySession fired when a session is destroyed | Session销毁事件
	EventDestroySession Event = "destroySession"

	// EventPermissionCheck fired when a permission check is performed | 权限检查事件
	EventPermissionCheck Event = "permissionCheck"

	// EventRoleCheck fired when a role check is performed | 角色检查事件
	EventRoleCheck Event = "roleCheck"

	// EventAll is a wildcard event that matches all events | 通配符事件（匹配所有事件）
	EventAll Event = "*"
)
