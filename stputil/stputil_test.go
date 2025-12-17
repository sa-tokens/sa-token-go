package stputil

import (
	"testing"
	"time"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/stretchr/testify/assert"
)

// setupTestManager 初始化内存存储和全局 Manager
func setupTestManager() {
	storage := memory.NewStorage()
	cfg := &config.Config{
		TokenName:     "satoken",
		Timeout:       3600,
		IsConcurrent:  true,
		IsShare:       true,
		MaxLoginCount: -1,
	}
	mgr := manager.NewManager(storage, cfg)
	SetManager(mgr)
}

func TestLoginAndIsLogin(t *testing.T) {
	setupTestManager()

	token, err := Login("user1")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	assert.True(t, IsLogin(token))

	loginID, err := GetLoginID(token)
	assert.NoError(t, err)
	assert.Equal(t, "user1", loginID)
}

func TestPermissionsHelpers(t *testing.T) {
	setupTestManager()

	token, err := Login("user2")
	assert.NoError(t, err)

	err = SetPermissions("user2", []string{"user.read", "user.write"})
	assert.NoError(t, err)

	// HasPermission / CheckPermission
	assert.True(t, HasPermission("user2", "user.read"))
	assert.NoError(t, CheckPermission(token, "user.read"))

	// AND / OR helpers
	assert.True(t, HasPermissionsAnd("user2", []string{"user.read", "user.write"}))
	assert.True(t, HasPermissionsOr("user2", []string{"user.delete", "user.read"}))

	// Permission list by token
	perms, err := GetPermissionList(token)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"user.read", "user.write"}, perms)
}

func TestRoleHelpers(t *testing.T) {
	setupTestManager()

	token, err := Login("user3")
	assert.NoError(t, err)

	err = SetRoles("user3", []string{"Admin", "User"})
	assert.NoError(t, err)

	// HasRole / CheckRole
	assert.True(t, HasRole("user3", "Admin"))
	assert.NoError(t, CheckRole(token, "Admin"))

	// AND / OR helpers
	assert.True(t, HasRolesAnd("user3", []string{"Admin", "User"}))
	assert.True(t, HasRolesOr("user3", []string{"Guest", "Admin"}))

	// Role list by token
	roles, err := GetRoleList(token)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"Admin", "User"}, roles)
}

func TestDisableAndCheckDisable(t *testing.T) {
	setupTestManager()

	token, err := Login("user4")
	assert.NoError(t, err)

	// 初始未封禁
	assert.NoError(t, CheckDisable(token))

	// 封禁账号
	err = Disable("user4", time.Hour)
	assert.NoError(t, err)

	// 现在 CheckDisable 应返回错误（可能是“未登录”或“已封禁”等）
	err = CheckDisable(token)
	assert.Error(t, err)

	disabled := IsDisable("user4")
	assert.True(t, disabled)
}

func TestToStringHelpers(t *testing.T) {
	assert.Equal(t, "123", toString(123))
	assert.Equal(t, "-5", toString(int(-5)))
	assert.Equal(t, "0", toString(int64(0)))
	assert.Equal(t, "42", toString(uint(42)))
	assert.Equal(t, "", toString(struct{}{}))
}

// TestLoginWithRefreshToken_IsLogin 验证双 Token 登录场景下，access token 能正常通过 IsLogin/CheckLogin
func TestLoginWithRefreshToken_IsLogin(t *testing.T) {
	setupTestManager()

	// 使用双 token 登录
	tokenInfo, err := LoginWithRefreshToken("user-refresh", "web")
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenInfo.AccessToken)
	assert.NotEmpty(t, tokenInfo.RefreshToken)

	// 刚登录的 access token 应该是“已登录”
	assert.True(t, IsLogin(tokenInfo.AccessToken))
	assert.NoError(t, CheckLogin(tokenInfo.AccessToken))
}


