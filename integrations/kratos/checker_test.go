package kratos

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/storage/memory"
)

func TestLoginChecker(t *testing.T) {
	checker := &LoginChecker{}
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	tests := []struct {
		name    string
		loginID string
		wantErr bool
	}{
		{"with login ID", "user123", false},
		{"without login ID", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checker.Check(ctx, mgr, tt.loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoginChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	// Setup test data - login and set permissions
	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetPermissions(loginID, []string{"user:read", "user:write"})

	tests := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"has permission", "user:read", false},
		{"no permission", "user:delete", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &PermissionChecker{permission: tt.permission}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PermissionChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionsAndChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetPermissions(loginID, []string{"user:read", "user:write"})

	tests := []struct {
		name        string
		permissions []string
		wantErr     bool
	}{
		{"all permissions", []string{"user:read", "user:write"}, false},
		{"missing one", []string{"user:read", "user:delete"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &PermissionsAndChecker{permissions: tt.permissions}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PermissionsAndChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionsOrChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetPermissions(loginID, []string{"user:read"})

	tests := []struct {
		name        string
		permissions []string
		wantErr     bool
	}{
		{"has one permission", []string{"user:read", "user:write"}, false},
		{"has no permission", []string{"user:delete", "user:create"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &PermissionsOrChecker{permissions: tt.permissions}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("PermissionsOrChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRoleChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetRoles(loginID, []string{"admin", "user"})

	tests := []struct {
		name    string
		role    string
		wantErr bool
	}{
		{"has role", "admin", false},
		{"no role", "superadmin", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &RoleChecker{role: tt.role}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RoleChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRolesAndChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetRoles(loginID, []string{"admin", "user"})

	tests := []struct {
		name    string
		roles   []string
		wantErr bool
	}{
		{"all roles", []string{"admin", "user"}, false},
		{"missing one", []string{"admin", "superadmin"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &RolesAndChecker{roles: tt.roles}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RolesAndChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRolesOrChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetRoles(loginID, []string{"user"})

	tests := []struct {
		name    string
		roles   []string
		wantErr bool
	}{
		{"has one role", []string{"user", "admin"}, false},
		{"has no role", []string{"admin", "superadmin"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &RolesOrChecker{roles: tt.roles}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RolesOrChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDisableChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()
	checker := &DisableChecker{}

	loginID := "user123"
	mgr.Login(loginID, "")

	// Test not disabled
	err := checker.Check(ctx, mgr, loginID)
	if err != nil {
		t.Errorf("DisableChecker.Check() error = %v, want nil", err)
	}

	// Test disabled
	mgr.Disable(loginID, 3600*time.Second)
	err = checker.Check(ctx, mgr, loginID)
	if err == nil {
		t.Error("DisableChecker.Check() should return error when disabled")
	}
}

func TestCustomChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"

	tests := []struct {
		name    string
		fn      func(ctx context.Context, manager *manager.Manager, loginID string) error
		wantErr bool
	}{
		{
			name: "pass check",
			fn: func(ctx context.Context, manager *manager.Manager, loginID string) error {
				return nil
			},
			wantErr: false,
		},
		{
			name: "fail check",
			fn: func(ctx context.Context, manager *manager.Manager, loginID string) error {
				return fmt.Errorf("check failed")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &CustomChecker{name: "custom", fn: tt.fn}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAndChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetPermissions(loginID, []string{"user:read"})
	mgr.SetRoles(loginID, []string{"user"})

	tests := []struct {
		name     string
		checkers []Checker
		wantErr  bool
	}{
		{
			name: "all pass",
			checkers: []Checker{
				&LoginChecker{},
				&PermissionChecker{permission: "user:read"},
			},
			wantErr: false,
		},
		{
			name: "one fails",
			checkers: []Checker{
				&LoginChecker{},
				&PermissionChecker{permission: "admin:write"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &AndChecker{checkers: tt.checkers}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("AndChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOrChecker(t *testing.T) {
	mgr := manager.NewManager(memory.NewStorage(), config.DefaultConfig())
	ctx := context.Background()

	loginID := "user123"
	mgr.Login(loginID, "")
	mgr.SetPermissions(loginID, []string{"user:read"})

	tests := []struct {
		name     string
		checkers []Checker
		wantErr  bool
	}{
		{
			name: "one passes",
			checkers: []Checker{
				&PermissionChecker{permission: "user:read"},
				&PermissionChecker{permission: "admin:write"},
			},
			wantErr: false,
		},
		{
			name: "all fail",
			checkers: []Checker{
				&PermissionChecker{permission: "admin:write"},
				&PermissionChecker{permission: "admin:delete"},
			},
			wantErr: true,
		},
		{
			name:     "empty list",
			checkers: []Checker{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &OrChecker{checkers: tt.checkers}
			err := checker.Check(ctx, mgr, loginID)
			if (err != nil) != tt.wantErr {
				t.Errorf("OrChecker.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckerConstructors(t *testing.T) {
	// Test NewLoginChecker
	if c := NewLoginChecker(); c == nil {
		t.Error("NewLoginChecker() should return non-nil")
	}

	// Test NewPermissionChecker
	if c := NewPermissionChecker("test"); c == nil {
		t.Error("NewPermissionChecker() should return non-nil")
	}

	// Test NewRoleChecker
	if c := NewRoleChecker("admin"); c == nil {
		t.Error("NewRoleChecker() should return non-nil")
	}

	// Test NewDisableChecker
	if c := NewDisableChecker(); c == nil {
		t.Error("NewDisableChecker() should return non-nil")
	}

	// Test NewCustomChecker
	if c := NewCustomChecker("test", func(ctx context.Context, manager *manager.Manager, loginID string) error {
		return nil
	}); c == nil {
		t.Error("NewCustomChecker() should return non-nil")
	}

	// Test CheckerAnd
	if c := CheckerAnd(&LoginChecker{}, &DisableChecker{}); c == nil {
		t.Error("CheckerAnd() should return non-nil")
	}

	// Test CheckerOr
	if c := CheckerOr(&LoginChecker{}, &DisableChecker{}); c == nil {
		t.Error("CheckerOr() should return non-nil")
	}
}
