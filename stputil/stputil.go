package stputil

import (
	"errors"
	"fmt"
	"github.com/click33/sa-token-go/core/config"
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

// --------------------------辅助方法--------------------------

// getAutoType checks if a valid autoType is provided, ensures it's trimmed, appends ":" if missing, and returns the value | 检查是否提供有效的 autoType，修剪空格，如果缺少 ":" 则添加，并返回值
func getAutoType(autoType ...string) string {
	// Check if autoType is provided and not empty, trim it and append ":" if missing | 检查是否提供了有效的 autoType，修剪空格，如果缺少 ":" 则添加
	if len(autoType) > 0 && strings.TrimSpace(autoType[0]) != "" {
		trimmed := strings.TrimSpace(autoType[0])
		// If it doesn't end with ":", append ":" | 如果 autoType 的值不以 ":" 结尾，则添加 ":"
		if !strings.HasSuffix(trimmed, ":") {
			trimmed = trimmed + ":"
		}
		return trimmed
	}
	// Return default autoType if autoType is empty or invalid | 如果 autoType 为空或无效，返回默认值
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

// PutManager stores the manager in the global map using the specified autoType | 使用指定的 autoType 将管理器存储在全局 map 中
func PutManager(mgr *manager.Manager, autoType ...string) error {
	// Validate and get the autoType value | 验证并获取 autoType 值
	validAutoType := getAutoType(autoType...) // 获取 autoType，默认为 config.DefaultAuthType
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

// CloseManager closes the specific manager for the given autoType and releases resources | 关闭指定的管理器并释放资源
func CloseManager(autoType string) error {
	// Validate and get the autoType value | 验证并获取 autoType 值
	validAutoType := getAutoType(autoType) // 获取 autoType，默认为 config.DefaultAuthType
	// Load the manager from global map | 从全局 map 中加载管理器
	manager, err := loadManager(validAutoType)
	if err != nil {
		return err
	}
	// Close the manager and release resources | 关闭管理器并释放资源
	manager.CloseManager()
	// Remove the manager from the global map | 从全局 map 中移除该管理器
	globalManagerMap.Delete(validAutoType)
	return nil
}

// CloseAllManager closes all managers in the global map and releases resources | 关闭所有管理器并释放资源
func CloseAllManager() {
	// Iterate over all managers in the global map and close them | 遍历全局 map 中的所有管理器并关闭它们
	globalManagerMap.Range(func(key, value interface{}) bool {
		// Assert the value to the correct type | 将值断言为正确的类型
		manager, ok := value.(*manager.Manager)
		if ok {
			// Close each manager | 关闭每个管理器
			manager.CloseManager()
		}
		// Continue iterating | 继续遍历
		return true
	})
	// Clear the global map after closing all managers | 关闭所有管理器后清空全局 map
	globalManagerMap = sync.Map{}
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
