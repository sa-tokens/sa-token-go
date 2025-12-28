package stputil

import (
	"testing"
	"time"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfig() *config.Config {
	return &config.Config{
		TokenName:     "satoken",
		Timeout:       3600,
		IsConcurrent:  true,
		IsShare:       true,
		MaxLoginCount: -1,
	}
}

func newTestStpLogic(t *testing.T) *StpLogic {
	t.Helper()

	storage := memory.NewStorage()
	mgr := manager.NewManager(storage, testConfig())
	logic := NewStpLogic(mgr)

	SetStpLogic(logic)

	t.Cleanup(func() {
		logic.CloseManager()
		SetStpLogic(nil)
	})

	return logic
}

func TestStpLogic_ManagerAccessors(t *testing.T) {
	logic := newTestStpLogic(t)

	mgr := logic.GetManager()
	require.NotNil(t, mgr)

	nextMgr := manager.NewManager(memory.NewStorage(), testConfig())
	logic.SetManager(nextMgr)
	assert.Equal(t, nextMgr, logic.GetManager())
}

func TestStpLogic_AuthAndSessionFlow(t *testing.T) {
	logic := newTestStpLogic(t)

	token, err := logic.Login("user-auth", "web")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	assert.NoError(t, logic.LoginByToken("user-auth", token, "web"))
	assert.True(t, logic.IsLogin(token))
	assert.NoError(t, logic.CheckLogin(token))

	loginID, err := logic.GetLoginID(token)
	require.NoError(t, err)
	assert.Equal(t, "user-auth", loginID)

	loginIDUnchecked, err := logic.GetLoginIDNotCheck(token)
	require.NoError(t, err)
	assert.Equal(t, "user-auth", loginIDUnchecked)

	tokenValue, err := logic.GetTokenValue("user-auth", "web")
	require.NoError(t, err)
	assert.Equal(t, token, tokenValue)

	tokenInfo, err := logic.GetTokenInfo(token)
	require.NoError(t, err)
	assert.Equal(t, "user-auth", tokenInfo.LoginID)

	sess, err := logic.GetSession("user-auth")
	require.NoError(t, err)
	assert.NotNil(t, sess)

	sessByToken, err := logic.GetSessionByToken(token)
	require.NoError(t, err)
	assert.NotNil(t, sessByToken)

	tokenSess, err := logic.GetTokenSession(token)
	require.NoError(t, err)
	assert.NotNil(t, tokenSess)

	tokenList, err := logic.GetTokenValueList("user-auth")
	require.NoError(t, err)
	assert.Contains(t, tokenList, token)

	sessCount, err := logic.GetSessionCount("user-auth")
	require.NoError(t, err)
	assert.Equal(t, 1, sessCount)

	require.NoError(t, logic.Logout("user-auth", "web"))
	assert.False(t, logic.IsLogin(token))

	token2, err := logic.Login("user-auth", "web")
	require.NoError(t, err)
	require.NoError(t, logic.LogoutByToken(token2))
	assert.False(t, logic.IsLogin(token2))

	token3, err := logic.Login("user-auth", "web")
	require.NoError(t, err)
	require.NoError(t, logic.Kickout("user-auth", "web"))
	assert.False(t, logic.IsLogin(token3))

	token4, err := logic.Login("user-auth", "web")
	require.NoError(t, err)
	require.NoError(t, logic.DeleteSession("user-auth"))
	sessAfterDelete, err := logic.GetSession("user-auth")
	require.NoError(t, err)
	assert.True(t, sessAfterDelete.IsEmpty())
	assert.True(t, logic.IsLogin(token4))
}

func TestStpLogic_Permissions(t *testing.T) {
	logic := newTestStpLogic(t)

	token, err := logic.Login("user-perm")
	require.NoError(t, err)

	perms := []string{"user.read", "user.write"}
	require.NoError(t, logic.SetPermissions("user-perm", perms))

	gotPerms, err := logic.GetPermissions("user-perm")
	require.NoError(t, err)
	assert.ElementsMatch(t, perms, gotPerms)

	assert.True(t, logic.HasPermission("user-perm", "user.read"))
	assert.True(t, logic.HasPermissionsAnd("user-perm", []string{"user.read", "user.write"}))
	assert.True(t, logic.HasPermissionsOr("user-perm", []string{"user.delete", "user.read"}))

	assert.NoError(t, logic.CheckPermission(token, "user.read"))
	assert.NoError(t, logic.CheckPermissionAnd(token, []string{"user.read", "user.write"}))
	assert.NoError(t, logic.CheckPermissionOr(token, []string{"user.delete", "user.read"}))

	err = logic.CheckPermission(token, "user.delete")
	assert.Error(t, err)

	permList, err := logic.GetPermissionList(token)
	require.NoError(t, err)
	assert.ElementsMatch(t, perms, permList)
}

func TestStpLogic_Roles(t *testing.T) {
	logic := newTestStpLogic(t)

	token, err := logic.Login("user-role")
	require.NoError(t, err)

	roles := []string{"Admin", "User"}
	require.NoError(t, logic.SetRoles("user-role", roles))

	gotRoles, err := logic.GetRoles("user-role")
	require.NoError(t, err)
	assert.ElementsMatch(t, roles, gotRoles)

	assert.True(t, logic.HasRole("user-role", "Admin"))
	assert.True(t, logic.HasRolesAnd("user-role", []string{"Admin", "User"}))
	assert.True(t, logic.HasRolesOr("user-role", []string{"Guest", "Admin"}))

	assert.NoError(t, logic.CheckRole(token, "Admin"))
	assert.NoError(t, logic.CheckRoleAnd(token, []string{"Admin", "User"}))
	assert.NoError(t, logic.CheckRoleOr(token, []string{"Guest", "Admin"}))

	err = logic.CheckRole(token, "Guest")
	assert.Error(t, err)

	roleList, err := GetRoleList(token)
	require.NoError(t, err)
	assert.ElementsMatch(t, roles, roleList)
}

func TestStpLogic_DisableAndUntie(t *testing.T) {
	logic := newTestStpLogic(t)

	token, err := logic.Login("user-disable")
	require.NoError(t, err)

	assert.NoError(t, logic.CheckDisable(token))

	require.NoError(t, logic.Disable("user-disable", time.Minute))
	assert.True(t, logic.IsDisable("user-disable"))

	disableTTL, err := logic.GetDisableTime("user-disable")
	require.NoError(t, err)
	assert.Greater(t, disableTTL, int64(0))

	assert.Error(t, logic.CheckDisable(token))

	require.NoError(t, logic.Untie("user-disable"))
	assert.False(t, logic.IsDisable("user-disable"))

	newToken, err := logic.Login("user-disable")
	require.NoError(t, err)
	assert.NoError(t, logic.CheckDisable(newToken))
}

func TestStpLogic_TokenTags(t *testing.T) {
	logic := newTestStpLogic(t)

	err := logic.SetTokenTag("token-tag", "demo")
	assert.Error(t, err)

	_, err = logic.GetTokenTag("token-tag")
	assert.Error(t, err)
}

func TestStpLogic_Nonce(t *testing.T) {
	logic := newTestStpLogic(t)

	nonce, err := logic.GenerateNonce()
	require.NoError(t, err)
	require.NotEmpty(t, nonce)

	assert.True(t, logic.VerifyNonce(nonce))
	assert.False(t, logic.VerifyNonce(nonce))
}

func TestStpLogic_RefreshTokenFlow(t *testing.T) {
	logic := newTestStpLogic(t)

	tokenInfo, err := logic.LoginWithRefreshToken("user-refresh", "mobile")
	require.NoError(t, err)
	require.NotEmpty(t, tokenInfo.AccessToken)
	require.NotEmpty(t, tokenInfo.RefreshToken)

	assert.True(t, logic.IsLogin(tokenInfo.AccessToken))

	refreshed, err := logic.RefreshAccessToken(tokenInfo.RefreshToken)
	if err == nil {
		require.NotEmpty(t, refreshed.AccessToken)
		assert.True(t, logic.IsLogin(refreshed.AccessToken))
	} else {
		assert.ErrorIs(t, err, security.ErrInvalidRefreshData)
	}

	require.NoError(t, logic.RevokeRefreshToken(tokenInfo.RefreshToken))
	_, err = logic.RefreshAccessToken(tokenInfo.RefreshToken)
	assert.ErrorIs(t, err, security.ErrInvalidRefreshToken)
}

func TestStpLogic_OAuth2AndClose(t *testing.T) {
	logic := newTestStpLogic(t)

	assert.NotNil(t, logic.GetOAuth2Server())
	assert.NotPanics(t, func() { logic.CloseManager() })
}
