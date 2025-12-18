package stputil

import (
	"context"
	"errors"
	"fmt"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/listener"
	"strings"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
)

var (
	globalManagerMap sync.Map
)

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func Login(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (string, error) {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return "", err
	}

	if id, err := toString(loginID); err != nil {
		return "", err
	} else {
		return mgr.Login(ctx, id, deviceOrAutoType...)
	}
}

// LoginByToken performs login with specified token | 使用指定Token登录
func LoginByToken(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.LoginByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// Logout performs user logout | 用户登出
func Logout(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.Logout(ctx, id, deviceOrAutoType...)
	}
}

// LogoutByToken performs logout by token | 根据Token登出
func LogoutByToken(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.LogoutByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// Kickout kicks out a user session | 踢人下线
func Kickout(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.Kickout(ctx, id, deviceOrAutoType...)
	}
}

// KickoutByToken Kick user offline | 根据Token踢人下线
func KickoutByToken(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.KickoutByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// Replace user offline by login ID and device | 根据账号和设备顶人下线
func Replace(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) error {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.Replace(ctx, id, deviceOrAutoType...)
	}
}

// ReplaceByToken Replace user offline by token | 根据Token顶人下线
func ReplaceByToken(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.ReplaceByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// ============ Token Validation | Token验证 ============

// IsLogin checks if the user is logged in | 检查用户是否已登录
func IsLogin(ctx context.Context, tokenValue string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	return mgr.IsLogin(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func CheckLogin(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.CheckLogin(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// CheckLoginWithState checks the login status (returns error to determine the reason if not logged in) | 检查登录状态（未登录时根据错误确定原因）
func CheckLoginWithState(ctx context.Context, tokenValue string, authType ...string) (bool, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false, err
	}

	return mgr.CheckLoginWithState(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func GetLoginID(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return "", err
	}

	return mgr.GetLoginID(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查）
func GetLoginIDNotCheck(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return "", err
	}

	return mgr.GetLoginIDNotCheck(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func GetTokenValue(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (string, error) {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return "", err
	}

	if id, err := toString(loginID); err != nil {
		return "", err
	} else {
		return mgr.GetTokenValue(ctx, id, deviceOrAutoType...)
	}
}

// GetTokenInfo gets token information | 获取Token信息
func GetTokenInfo(ctx context.Context, tokenValue string, authType ...string) (*manager.TokenInfo, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetTokenInfo(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func Disable(ctx context.Context, loginID interface{}, duration time.Duration, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.Disable(ctx, id, duration)
	}
}

// Untie re-enables a disabled account | 解封账号
func Untie(ctx context.Context, loginID interface{}, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.Untie(ctx, id)
	}
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func IsDisable(ctx context.Context, loginID interface{}, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.IsDisable(ctx, id)
	}
}

// GetDisableTime gets remaining disable time in seconds | 获取剩余封禁时间（秒）
func GetDisableTime(ctx context.Context, loginID interface{}, authType ...string) (int64, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return 0, err
	}

	if id, err := toString(loginID); err != nil {
		return 0, err
	} else {
		return mgr.GetDisableTime(ctx, id)
	}
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 根据登录ID获取Session
func GetSession(ctx context.Context, loginID interface{}, authType ...string) (*session.Session, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	if id, err := toString(loginID); err != nil {
		return nil, err
	} else {
		return mgr.GetSession(ctx, id)
	}
}

// GetSessionByToken gets session by token | 根据Token获取Session
func GetSessionByToken(ctx context.Context, tokenValue string, authType ...string) (*session.Session, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetSessionByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// DeleteSession deletes a session | 删除Session
func DeleteSession(ctx context.Context, loginID interface{}, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.DeleteSession(ctx, id)
	}
}

// DeleteSessionByToken Deletes session by token | 根据Token删除Session
func DeleteSessionByToken(ctx context.Context, tokenValue string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.DeleteSessionByToken(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// ============ Permission Verification | 权限验证 ============

// SetPermissions sets permissions for a login ID | 设置用户权限
func SetPermissions(ctx context.Context, loginID interface{}, permissions []string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.SetPermissions(ctx, id, permissions)
	}
}

// RemovePermissions removes specified permissions for a login ID | 删除用户指定权限
func RemovePermissions(ctx context.Context, loginID interface{}, permissions []string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.RemovePermissions(ctx, id, permissions)
	}
}

// GetPermissions gets permission list | 获取权限列表
func GetPermissions(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	if id, err := toString(loginID); err != nil {
		return nil, err
	} else {
		return mgr.GetPermissions(ctx, id)
	}
}

// HasPermission checks if has specified permission | 检查是否拥有指定权限
func HasPermission(ctx context.Context, loginID interface{}, permissions string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasPermission(ctx, id, permissions)
	}
}

// HasPermissionsAnd checks if has all permissions (AND logic) | 检查是否拥有所有权限（AND逻辑）
func HasPermissionsAnd(ctx context.Context, loginID interface{}, permissions []string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasPermissionsAnd(ctx, id, permissions)
	}
}

// HasPermissionsOr checks if has any permission (OR logic) | 检查是否拥有任一权限（OR逻辑）
func HasPermissionsOr(ctx context.Context, loginID interface{}, permissions []string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasPermissionsOr(ctx, id, permissions)
	}
}

// ============ Role Management | 角色管理 ============

// SetRoles sets roles for a login ID | 设置用户角色
func SetRoles(ctx context.Context, loginID interface{}, roles []string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.SetRoles(ctx, id, roles)
	}
}

// RemoveRoles removes specified roles for a login ID | 删除用户指定角色
func RemoveRoles(ctx context.Context, loginID interface{}, roles []string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	if id, err := toString(loginID); err != nil {
		return err
	} else {
		return mgr.RemoveRoles(ctx, id, roles)
	}
}

// GetRoles gets role list | 获取角色列表
func GetRoles(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	if id, err := toString(loginID); err != nil {
		return nil, err
	} else {
		return mgr.GetRoles(ctx, id)
	}
}

// HasRole checks if has specified role | 检查是否拥有指定角色
func HasRole(ctx context.Context, loginID interface{}, role string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasRole(ctx, id, role)
	}
}

// HasRolesAnd checks if has all roles (AND logic) | 检查是否拥有所有角色（AND逻辑）
func HasRolesAnd(ctx context.Context, loginID interface{}, roles []string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasRolesAnd(ctx, id, roles)
	}
}

// HasRolesOr 检查是否拥有任一角色（OR）
func HasRolesOr(ctx context.Context, loginID interface{}, roles []string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	if id, err := toString(loginID); err != nil {
		return false
	} else {
		return mgr.HasRolesOr(ctx, id, roles)
	}
}

// ============ Token标签 ============

// SetTokenTag 设置Token标签
func SetTokenTag(ctx context.Context, tokenValue, tag string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.SetTokenTag(context.WithValue(ctx, config.CtxTokenValue, tokenValue), tag)
}

// GetTokenTag 获取Token标签
func GetTokenTag(ctx context.Context, tokenValue string, authType ...string) (string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return "", err
	}

	return mgr.GetTokenTag(context.WithValue(ctx, config.CtxTokenValue, tokenValue))
}

// ============ 会话查询 ============

// GetTokenValueListByLoginID 获取指定账号的所有Token
func GetTokenValueListByLoginID(ctx context.Context, loginID interface{}, authType ...string) ([]string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	if id, err := toString(loginID); err != nil {
		return nil, err
	} else {
		return mgr.GetTokenValueListByLoginID(ctx, id)
	}
}

// GetSessionCountByLoginID 获取指定账号的Session数量
func GetSessionCountByLoginID(ctx context.Context, loginID interface{}, authType ...string) (int, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return 0, err
	}

	if id, err := toString(loginID); err != nil {
		return 0, err
	} else {
		return mgr.GetSessionCountByLoginID(ctx, id)
	}
}

// ============ Security Features | 安全特性 ============

// Generate Generates a one-time nonce | 生成一次性随机数
func Generate(ctx context.Context, authType ...string) (string, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return "", err
	}

	return mgr.GetNonceManager().Generate()
}

// Verify Verifies a nonce | 验证随机数
func Verify(ctx context.Context, nonce string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	return mgr.GetNonceManager().Verify(nonce)
}

// VerifyAndConsume Verifies and consumes nonce, returns error if invalid | 验证并消费nonce，无效时返回错误
func VerifyAndConsume(ctx context.Context, nonce string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.GetNonceManager().VerifyAndConsume(nonce)
}

// IsValidNonce Checks if nonce is valid without consuming it | 检查nonce是否有效（不消费）
func IsValidNonce(ctx context.Context, nonce string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	return mgr.GetNonceManager().IsValid(nonce)
}

// GenerateTokenPair Create access + refresh token | 生成访问令牌和刷新令牌
func GenerateTokenPair(ctx context.Context, loginID interface{}, deviceOrAutoType ...string) (*security.RefreshTokenInfo, error) {
	mgr, err := GetManager(deviceOrAutoType...)
	if err != nil {
		return nil, err
	}

	if id, err := toString(loginID); err != nil {
		return nil, err
	} else {
		return mgr.GetRefreshManager().GenerateTokenPair(id, mgr.GetDevice(deviceOrAutoType))
	}
}

// VerifyAccessToken verifies access token validity | 验证访问令牌是否有效
func VerifyAccessToken(ctx context.Context, accessToken string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	return mgr.GetRefreshManager().VerifyAccessToken(accessToken)
}

// VerifyAccessTokenAndGetInfo verifies access token and returns token info | 验证访问令牌并返回Token信息
func VerifyAccessTokenAndGetInfo(ctx context.Context, accessToken string, authType ...string) (*security.AccessTokenInfo, bool) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, false
	}

	return mgr.GetRefreshManager().VerifyAccessTokenAndGetInfo(accessToken)
}

// GetRefreshTokenInfo gets refresh token information | 获取刷新令牌信息
func GetRefreshTokenInfo(ctx context.Context, refreshToken string, authType ...string) (*security.RefreshTokenInfo, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetRefreshManager().GetRefreshTokenInfo(refreshToken)
}

// RevokeRefreshToken Revokes refresh token | 撤销刷新令牌
func RevokeRefreshToken(ctx context.Context, refreshToken string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.GetRefreshManager().RevokeRefreshToken(refreshToken)
}

// IsValid checks whether token is valid | 检查Token是否有效
func IsValid(ctx context.Context, refreshToken string, authType ...string) bool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return false
	}

	return mgr.GetRefreshManager().IsValid(refreshToken)
}

// ============ OAuth2 Features | OAuth2 功能 ============

// RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func RegisterClient(ctx context.Context, client *oauth2.Client, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.GetOAuth2Server().RegisterClient(client)
}

// UnregisterClient unregisters an OAuth2 client | 注销OAuth2客户端
func UnregisterClient(ctx context.Context, clientID string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	mgr.GetOAuth2Server().UnregisterClient(clientID)

	return nil
}

// GetClient gets OAuth2 client information | 获取OAuth2客户端信息
func GetClient(ctx context.Context, clientID string, authType ...string) (*oauth2.Client, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetOAuth2Server().GetClient(clientID)
}

// GenerateAuthorizationCode creates an authorization code | 创建授权码
func GenerateAuthorizationCode(ctx context.Context, clientID, loginID, redirectURI string, scope []string, authType ...string) (*oauth2.AuthorizationCode, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetOAuth2Server().GenerateAuthorizationCode(clientID, loginID, redirectURI, scope)
}

// ExchangeCodeForToken exchanges authorization code for token | 使用授权码换取令牌
func ExchangeCodeForToken(ctx context.Context, code, clientID, clientSecret, redirectURI string, authType ...string) (*oauth2.AccessToken, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetOAuth2Server().ExchangeCodeForToken(code, clientID, clientSecret, redirectURI)
}

// ValidateAccessToken verifies OAuth2 access token | 验证OAuth2访问令牌
func ValidateAccessToken(ctx context.Context, accessToken string, authType ...string) (*oauth2.AccessToken, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetOAuth2Server().ValidateAccessToken(accessToken)
}

// RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func RefreshAccessToken(ctx context.Context, refreshToken, clientID, clientSecret string, authType ...string) (*oauth2.AccessToken, error) {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil, err
	}

	return mgr.GetOAuth2Server().RefreshAccessToken(refreshToken, clientID, clientSecret)
}

// RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func RevokeToken(ctx context.Context, accessToken string, authType ...string) error {
	mgr, err := GetManager(authType...)
	if err != nil {
		return err
	}

	return mgr.GetOAuth2Server().RevokeToken(accessToken)
}

// ============ Public Getters | 公共获取器 ============

// GetConfig returns the manager configuration | 获取 Manager 当前使用的配置
func GetConfig(ctx context.Context, authType ...string) *config.Config {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetConfig()
}

// GetStorage returns the storage adapter | 获取 Manager 使用的存储适配器
func GetStorage(ctx context.Context, authType ...string) adapter.Storage {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetStorage()
}

// GetCodec returns the codec (serializer) | 获取 Manager 使用的编解码器
func GetCodec(ctx context.Context, authType ...string) adapter.Codec {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetCodec()
}

// GetLog returns the logger adapter | 获取 Manager 使用的日志适配器
func GetLog(ctx context.Context, authType ...string) adapter.Log {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetLog()
}

// GetPool returns the goroutine pool | 获取 Manager 使用的协程池
func GetPool(ctx context.Context, authType ...string) adapter.Pool {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetPool()
}

// GetGenerator returns the token generator | 获取 Token 生成器
func GetGenerator(ctx context.Context, authType ...string) adapter.Generator {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetGenerator()
}

// GetNonceManager returns the nonce manager | 获取随机串管理器
func GetNonceManager(ctx context.Context, authType ...string) *security.NonceManager {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetNonceManager()
}

// GetRefreshManager returns the refresh token manager | 获取刷新令牌管理器
func GetRefreshManager(ctx context.Context, authType ...string) *security.RefreshTokenManager {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetRefreshManager()
}

// GetEventManager returns the event manager | 获取事件管理器
func GetEventManager(ctx context.Context, authType ...string) *listener.Manager {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetEventManager()
}

// GetOAuth2Server Gets OAuth2 server instance | 获取OAuth2服务器实例
func GetOAuth2Server(ctx context.Context, authType ...string) *oauth2.OAuth2Server {
	mgr, err := GetManager(authType...)
	if err != nil {
		return nil
	}
	return mgr.GetOAuth2Server()
}

// ============ Check Functions for Token-based operations | 基于Token的检查函数 ============

// CheckDisable checks if the account associated with the token is disabled | 检查Token对应账号是否被封禁
func CheckDisable(tokenValue string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if IsDisable(loginID) {
		return fmt.Errorf("account is disabled")
	}
	return nil
}

// CheckPermission checks if the token has the specified permission | 检查Token是否拥有指定权限
func CheckPermission(tokenValue string, permission string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermission(loginID, permission) {
		return fmt.Errorf("permission denied: %s", permission)
	}
	return nil
}

// CheckPermissionAnd checks if the token has all specified permissions | 检查Token是否拥有所有指定权限
func CheckPermissionAnd(tokenValue string, permissions []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermissionsAnd(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// CheckPermissionOr checks if the token has any of the specified permissions | 检查Token是否拥有任一指定权限
func CheckPermissionOr(tokenValue string, permissions []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasPermissionsOr(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// GetPermissionList gets permission list for the token | 获取Token对应的权限列表
func GetPermissionList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetPermissions(loginID)
}

// CheckRole checks if the token has the specified role | 检查Token是否拥有指定角色
func CheckRole(tokenValue string, role string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRole(loginID, role) {
		return fmt.Errorf("role denied: %s", role)
	}
	return nil
}

// CheckRoleAnd checks if the token has all specified roles | 检查Token是否拥有所有指定角色
func CheckRoleAnd(tokenValue string, roles []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRolesAnd(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// CheckRoleOr checks if the token has any of the specified roles | 检查Token是否拥有任一指定角色
func CheckRoleOr(tokenValue string, roles []string) error {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !HasRolesOr(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// GetRoleList gets role list for the token | 获取Token对应的角色列表
func GetRoleList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetRoles(loginID)
}

// GetTokenSession gets session for the token | 获取Token对应的Session
func GetTokenSession(tokenValue string) (*session.Session, error) {
	return GetSessionByToken(tokenValue)
}

// ============ Internal Helper Methods | 内部辅助方法 ============

// SetManager stores the manager in the global map using the specified autoType | 使用指定的 autoType 将管理器存储在全局 map 中
func SetManager(mgr *manager.Manager) error {
	// Validate and get the autoType value | 验证并获取 autoType 值
	validAutoType := getAutoType(mgr.GetConfig().AuthType) // 获取 autoType，默认为 config.DefaultAuthType
	// Store the manager in the global map with the valid autoType | 使用有效的 autoType 将管理器存储在全局 map 中
	globalManagerMap.Store(validAutoType, mgr)
	return nil
}

// GetManager retrieves the manager from the global map using the specified autoType | 使用指定的 autoType 从全局 map 中获取管理器
func GetManager(autoType ...string) (*manager.Manager, error) {
	// Validate and get the autoType value | 验证并获取 autoType 值
	validAutoType := getAutoType(autoType...) // 获取 autoType，默认为 config.DefaultAuthType
	// Use LoadManager to retrieve the manager | 使用 LoadManager 方法来获取管理器
	return loadManager(validAutoType)
}

// DeleteManager delete the specific manager for the given autoType and releases resources | 删除指定的管理器并释放资源
func DeleteManager(autoType string) error {
	// Validate and get the autoType value | 验证并获取 autoType 值
	validAutoType := getAutoType(autoType) // 获取 autoType，默认为 config.DefaultAuthType
	// Load the manager from global map | 从全局 map 中加载管理器
	mgr, err := loadManager(validAutoType)
	if err != nil {
		return err
	}
	// Close the manager and release resources | 关闭管理器并释放资源
	mgr.CloseManager()
	// Remove the manager from the global map | 从全局 map 中移除该管理器
	globalManagerMap.Delete(validAutoType)
	return nil
}

// DeleteAllManager delete all managers in the global map and releases resources | 关闭所有管理器并释放资源
func DeleteAllManager() {
	// Iterate over all managers in the global map and close them | 遍历全局 map 中的所有管理器并关闭它们
	globalManagerMap.Range(func(key, value interface{}) bool {
		// Assert the value to the correct type | 将值断言为正确的类型
		mgr, ok := value.(*manager.Manager)
		if ok {
			// Close each manager | 关闭每个管理器
			mgr.CloseManager()
		}
		// Continue iterating | 继续遍历
		return true
	})
	// Clear the global map after closing all managers | 关闭所有管理器后清空全局 map
	globalManagerMap = sync.Map{}
}

// getAutoType checks if a valid autoType is provided, ensures it's trimmed, appends ":" if missing, and returns the value | 检查是否提供有效的 autoType，修剪空格，如果缺少 ":" 则添加，并返回值
func getAutoType(autoType ...string) string {
	// Check if autoType is provided and not empty, trim it and append ":" if missing | 检查是否提供了有效的 autoType，修剪空格，如果缺少 ":" 则添加
	if len(autoType) > 1 && strings.TrimSpace(autoType[1]) != "" {
		trimmed := strings.TrimSpace(autoType[1])
		// If it doesn't end with ":", append ":" | 如果 autoType 的值不以 ":" 结尾，则添加 ":"
		if !strings.HasSuffix(trimmed, ":") {
			trimmed = trimmed + ":"
		}
		return trimmed
	}
	// Return log autoType if autoType is empty or invalid | 如果 autoType 为空或无效，返回默认值
	return config.DefaultAuthType
}

// loadManager retrieves the manager from the global map using the valid autoType | 使用有效的 autoType 从全局 map 中加载管理器
func loadManager(autoType string) (*manager.Manager, error) {
	// Load the manager from the global map using the valid autoType | 使用有效的 autoType 从全局 map 中加载管理器
	value, ok := globalManagerMap.Load(autoType)
	if !ok {
		return nil, errors.New("manager not found for autoType: " + autoType)
	}
	// Assert the loaded value to the correct type | 将加载的值断言为正确的类型
	mgr, ok := value.(*manager.Manager)
	if !ok {
		return nil, errors.New("invalid manager type for autoType: " + autoType)
	}
	return mgr, nil
}

// toString Converts interface{} to string | 将interface{}转换为string
func toString(v interface{}) (string, error) {
	// Check the type and convert to string | 判断类型并转换为字符串
	switch val := v.(type) {
	case string:
		return val, nil // If it's a string, return it directly | 如果是字符串，直接返回
	case int:
		return intToString(val), nil // If it's int, convert to string | 如果是int，转换为string
	case int64:
		return int64ToString(val), nil // If it's int64, convert to string | 如果是int64，转换为string
	case uint:
		return uintToString(val), nil // If it's uint, convert to string | 如果是uint，转换为string
	case uint64:
		return uint64ToString(val), nil // If it's uint64, convert to string | 如果是uint64，转换为string
	default:
		return "", errors.New("Invalid type") // For other types, return error | 对于其他类型，返回错误
	}
}

// intToString Converts int to string | 将int转换为string
func intToString(i int) string {
	return int64ToString(int64(i)) // Call int64ToString to convert | 调用int64ToString进行转换
}

// int64ToString Converts int64 to string | 将int64转换为string
func int64ToString(i int64) string {
	// If it's zero, return "0" | 如果是零，返回 "0"
	if i == 0 {
		return "0"
	}

	// Check if it's negative and handle it | 判断是否为负数并处理
	negative := i < 0
	if negative {
		i = -i // Take the absolute value | 取绝对值
	}

	var result []byte
	// Process each digit and prepend to the result array | 将每一位数字依次处理并添加到结果数组
	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}

	// If it's negative, add the '-' sign | 如果是负数，添加负号
	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}

// uintToString Converts uint to string | 将uint转换为string
func uintToString(u uint) string {
	return uint64ToString(uint64(u)) // Call uint64ToString to convert | 调用uint64ToString进行转换
}

// uint64ToString Converts uint64 to string | 将uint64转换为string
func uint64ToString(u uint64) string {
	// If it's zero, return "0" | 如果是零，返回 "0"
	if u == 0 {
		return "0"
	}

	var result []byte
	// Process each digit and prepend to the result array | 将每一位数字依次处理并添加到结果数组
	for u > 0 {
		result = append([]byte{byte('0' + u%10)}, result...)
		u /= 10
	}

	return string(result)
}
