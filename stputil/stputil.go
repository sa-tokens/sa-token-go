package stputil

import (
	"fmt"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
)

// Global Manager instance | 全局Manager实例
var (
	globalManager *manager.Manager
	once          sync.Once
	mu            sync.RWMutex
)

// SetManager sets the global Manager (must be called first) | 设置全局Manager（必须先调用此方法）
func SetManager(mgr *manager.Manager) {
	mu.Lock()
	defer mu.Unlock()
	globalManager = mgr
}

// GetManager gets the global Manager | 获取全局Manager
func GetManager() *manager.Manager {
	mu.RLock()
	defer mu.RUnlock()
	if globalManager == nil {
		panic("StpUtil not initialized, please call SetManager() first or use builder.NewBuilder().Build()")
	}
	return globalManager
}

// CloseManager closes global Manager and releases resources | 关闭全局 Manager 并释放资源
func CloseManager() {
	mu.Lock()
	defer mu.Unlock()
	if globalManager != nil {
		globalManager.CloseManager()
		globalManager = nil // 置 nil 避免后续误用
	}
}

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func Login(loginID interface{}, device ...string) (string, error) {
	return GetManager().Login(toString(loginID), device...)
}

// LoginByToken performs login with specified token | 使用指定Token登录
func LoginByToken(loginID interface{}, tokenValue string, device ...string) error {
	return GetManager().LoginByToken(toString(loginID), tokenValue, device...)
}

// Logout performs user logout | 用户登出
func Logout(loginID interface{}, device ...string) error {
	return GetManager().Logout(toString(loginID), device...)
}

// LogoutByToken performs logout by token | 根据Token登出
func LogoutByToken(tokenValue string) error {
	return GetManager().LogoutByToken(tokenValue)
}

// IsLogin checks if the user is logged in | 检查用户是否已登录
func IsLogin(tokenValue string) bool {
	return GetManager().IsLogin(tokenValue)
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func CheckLogin(tokenValue string) error {
	return GetManager().CheckLogin(tokenValue)
}

// CheckLoginWithState checks the login status (returns error to determine the reason if not logged in) | 检查登录状态（未登录时根据错误确定原因）
func CheckLoginWithState(tokenValue string) (bool, error) {
	return GetManager().CheckLoginWithState(tokenValue)
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func GetLoginID(tokenValue string) (string, error) {
	return GetManager().GetLoginID(tokenValue)
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查）
func GetLoginIDNotCheck(tokenValue string) (string, error) {
	return GetManager().GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func GetTokenValue(loginID interface{}, device ...string) (string, error) {
	return GetManager().GetTokenValue(toString(loginID), device...)
}

// GetTokenInfo gets token information | 获取Token信息
func GetTokenInfo(tokenValue string) (*manager.TokenInfo, error) {
	return GetManager().GetTokenInfo(tokenValue)
}

// ============ Kickout | 踢人下线 ============

// Kickout kicks out a user session | 踢人下线
func Kickout(loginID interface{}, device ...string) error {
	return GetManager().Kickout(toString(loginID), device...)
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func Disable(loginID interface{}, duration time.Duration) error {
	return GetManager().Disable(toString(loginID), duration)
}

// Untie re-enables a disabled account | 解封账号
func Untie(loginID interface{}) error {
	return GetManager().Untie(toString(loginID))
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func IsDisable(loginID interface{}) bool {
	return GetManager().IsDisable(toString(loginID))
}

// GetDisableTime gets remaining disable time in seconds | 获取剩余封禁时间（秒）
func GetDisableTime(loginID interface{}) (int64, error) {
	return GetManager().GetDisableTime(toString(loginID))
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 根据登录ID获取Session
func GetSession(loginID interface{}) (*session.Session, error) {
	return GetManager().GetSession(toString(loginID))
}

// GetSessionByToken gets session by token | 根据Token获取Session
func GetSessionByToken(tokenValue string) (*session.Session, error) {
	return GetManager().GetSessionByToken(tokenValue)
}

// DeleteSession deletes a session | 删除Session
func DeleteSession(loginID interface{}) error {
	return GetManager().DeleteSession(toString(loginID))
}

// ============ Permission Verification | 权限验证 ============

// SetPermissions sets permissions for a login ID | 设置用户权限
func SetPermissions(loginID interface{}, permissions []string) error {
	return GetManager().SetPermissions(toString(loginID), permissions)
}

// RemovePermissions removes specified permissions for a login ID | 删除用户指定权限
func RemovePermissions(loginID interface{}, permissions []string) error {
	return GetManager().RemovePermissions(toString(loginID), permissions)
}

// GetPermissions gets permission list | 获取权限列表
func GetPermissions(loginID interface{}) ([]string, error) {
	return GetManager().GetPermissions(toString(loginID))
}

// HasPermission checks if has specified permission | 检查是否拥有指定权限
func HasPermission(loginID interface{}, permission string) bool {
	return GetManager().HasPermission(toString(loginID), permission)
}

// HasPermissionsAnd checks if has all permissions (AND logic) | 检查是否拥有所有权限（AND逻辑）
func HasPermissionsAnd(loginID interface{}, permissions []string) bool {
	return GetManager().HasPermissionsAnd(toString(loginID), permissions)
}

// HasPermissionsOr checks if has any permission (OR logic) | 检查是否拥有任一权限（OR逻辑）
func HasPermissionsOr(loginID interface{}, permissions []string) bool {
	return GetManager().HasPermissionsOr(toString(loginID), permissions)
}

// ============ Role Management | 角色管理 ============

// SetRoles sets roles for a login ID | 设置用户角色
func SetRoles(loginID interface{}, roles []string) error {
	return GetManager().SetRoles(toString(loginID), roles)
}

// RemoveRoles removes specified roles for a login ID | 删除用户指定角色
func RemoveRoles(loginID interface{}, roles []string) error {
	return GetManager().RemoveRoles(toString(loginID), roles)
}

// GetRoles gets role list | 获取角色列表
func GetRoles(loginID interface{}) ([]string, error) {
	return GetManager().GetRoles(toString(loginID))
}

// HasRole checks if has specified role | 检查是否拥有指定角色
func HasRole(loginID interface{}, role string) bool {
	return GetManager().HasRole(toString(loginID), role)
}

// HasRolesAnd checks if has all roles (AND logic) | 检查是否拥有所有角色（AND逻辑）
func HasRolesAnd(loginID interface{}, roles []string) bool {
	return GetManager().HasRolesAnd(toString(loginID), roles)
}

// HasRolesOr 检查是否拥有任一角色（OR）
func HasRolesOr(loginID interface{}, roles []string) bool {
	return GetManager().HasRolesOr(toString(loginID), roles)
}

// ============ Token标签 ============

// SetTokenTag 设置Token标签
func SetTokenTag(tokenValue, tag string) error {
	return GetManager().SetTokenTag(tokenValue, tag)
}

// GetTokenTag 获取Token标签
func GetTokenTag(tokenValue string) (string, error) {
	return GetManager().GetTokenTag(tokenValue)
}

// ============ 会话查询 ============

// GetTokenValueList 获取指定账号的所有Token
func GetTokenValueList(loginID interface{}) ([]string, error) {
	return GetManager().GetTokenValueListByLoginID(toString(loginID))
}

// GetSessionCount 获取指定账号的Session数量
func GetSessionCount(loginID interface{}) (int, error) {
	return GetManager().GetSessionCountByLoginID(toString(loginID))
}

// ============ 辅助方法 ============

// toString 将interface{}转换为string
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return intToString(val)
	case int64:
		return int64ToString(val)
	case uint:
		return uintToString(val)
	case uint64:
		return uint64ToString(val)
	default:
		return ""
	}
}

func intToString(i int) string {
	return int64ToString(int64(i))
}

func int64ToString(i int64) string {
	// 简单实现，可以用 strconv.FormatInt(i, 10) 但为了减少依赖
	if i == 0 {
		return "0"
	}

	negative := i < 0
	if negative {
		i = -i
	}

	var result []byte
	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}

	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}

func uintToString(u uint) string {
	return uint64ToString(uint64(u))
}

func uint64ToString(u uint64) string {
	if u == 0 {
		return "0"
	}

	var result []byte
	for u > 0 {
		result = append([]byte{byte('0' + u%10)}, result...)
		u /= 10
	}

	return string(result)
}

func GenerateNonce() (string, error) {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	return globalManager.GenerateNonce()
}

func VerifyNonce(nonce string) bool {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	return globalManager.VerifyNonce(nonce)
}

func LoginWithRefreshToken(loginID interface{}, device ...string) (*security.RefreshTokenInfo, error) {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	deviceType := "default"
	if len(device) > 0 {
		deviceType = device[0]
	}
	return globalManager.LoginWithRefreshToken(fmt.Sprintf("%v", loginID), deviceType)
}

func RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	return globalManager.RefreshAccessToken(refreshToken)
}

func RevokeRefreshToken(refreshToken string) error {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	return globalManager.RevokeRefreshToken(refreshToken)
}

func GetOAuth2Server() *oauth2.OAuth2Server {
	if globalManager == nil {
		panic("Manager not initialized. Call stputil.SetManager() first")
	}
	return globalManager.GetOAuth2Server()
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
