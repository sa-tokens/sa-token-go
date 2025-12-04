package kratos

import (
	"context"
	"github.com/click33/sa-token-go/core"
)

// Checker 检查器接口
type Checker interface {
	// Check 执行检查
	Check(ctx context.Context, manager *core.Manager, loginID string) error
}

// ========== 登录检查 ==========

// LoginChecker 登录检查器
type LoginChecker struct{}

func (c *LoginChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if loginID == "" {
		return core.ErrNotLogin
	}
	return nil
}

// ========== 权限检查 ==========

// PermissionChecker 单个权限检查器
type PermissionChecker struct {
	permission string
}

func (c *PermissionChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if !manager.HasPermission(loginID, c.permission) {
		return core.ErrPermissionDenied
	}
	return nil
}

// PermissionsAndChecker 多个权限检查器（AND逻辑）
type PermissionsAndChecker struct {
	permissions []string
}

func (c *PermissionsAndChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	for _, permission := range c.permissions {
		if !manager.HasPermission(loginID, permission) {
			return core.ErrPermissionDenied
		}
	}
	return nil
}

// PermissionsOrChecker 多个权限检查器（OR逻辑）
type PermissionsOrChecker struct {
	permissions []string
}

func (c *PermissionsOrChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if len(c.permissions) == 0 {
		return nil
	}

	for _, permission := range c.permissions {
		if manager.HasPermission(loginID, permission) {
			return nil
		}
	}

	return core.ErrPermissionDenied
}

// ========== 角色检查 ==========

// RoleChecker 单个角色检查器
type RoleChecker struct {
	role string
}

func (c *RoleChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if !manager.HasRole(loginID, c.role) {
		return core.ErrRoleDenied
	}
	return nil
}

// RolesAndChecker 多个角色检查器（AND逻辑）
type RolesAndChecker struct {
	roles []string
}

func (c *RolesAndChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	for _, role := range c.roles {
		if !manager.HasRole(loginID, role) {
			return core.ErrRoleDenied
		}
	}
	return nil
}

// RolesOrChecker 多个角色检查器（OR逻辑）
type RolesOrChecker struct {
	roles []string
}

func (c *RolesOrChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if len(c.roles) == 0 {
		return nil
	}

	for _, role := range c.roles {
		if manager.HasRole(loginID, role) {
			return nil
		}
	}

	return core.ErrRoleDenied
}

// ========== 封禁检查 ==========

// DisableChecker 账号封禁检查器
type DisableChecker struct{}

func (c *DisableChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if manager.IsDisable(loginID) {
		return core.ErrAccountDisabled
	}
	return nil
}

// ========== 自定义检查 ==========

// CustomChecker 自定义检查器
type CustomChecker struct {
	fn func(ctx context.Context, manager *core.Manager, loginID string) error
}

func (c *CustomChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	return c.fn(ctx, manager, loginID)
}

// ========== 组合检查器 ==========

// AndChecker AND组合检查器（所有checker都通过才返回成功）
type AndChecker struct {
	checkers []Checker
}

func (c *AndChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	for _, checker := range c.checkers {
		if err := checker.Check(ctx, manager, loginID); err != nil {
			return err
		}
	}
	return nil
}

// OrChecker OR组合检查器（任一checker通过就返回成功）
type OrChecker struct {
	checkers []Checker
}

func (c *OrChecker) Check(ctx context.Context, manager *core.Manager, loginID string) error {
	if len(c.checkers) == 0 {
		return nil
	}

	var lastErr error
	for _, checker := range c.checkers {
		err := checker.Check(ctx, manager, loginID)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return lastErr
}

// ========== 便捷构造函数 ==========

// NewLoginChecker 创建登录检查器
func NewLoginChecker() Checker {
	return &LoginChecker{}
}

// NewPermissionChecker 创建权限检查器
func NewPermissionChecker(permission string) Checker {
	return &PermissionChecker{permission: permission}
}

// NewRoleChecker 创建角色检查器
func NewRoleChecker(role string) Checker {
	return &RoleChecker{role: role}
}

// NewDisableChecker 创建封禁检查器
func NewDisableChecker() Checker {
	return &DisableChecker{}
}

// NewCustomChecker 创建自定义检查器
func NewCustomChecker(fn func(ctx context.Context, manager *core.Manager, loginID string) error) Checker {
	return &CustomChecker{fn: fn}
}

// CheckerAnd 创建AND组合检查器
func CheckerAnd(checkers ...Checker) Checker {
	return &AndChecker{checkers: checkers}
}

// CheckerOr 创建OR组合检查器
func CheckerOr(checkers ...Checker) Checker {
	return &OrChecker{checkers: checkers}
}
