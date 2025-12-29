package stputil

import (
	"fmt"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/core/session"
	"sync"
	"time"
)

var (
	TokenValueKey  = "stplogic:tokenvalue"
	LoginIdKey     = "stplogic:loginid"
	PermissionsKey = "stplogic:permissions"
	RolesKey       = "stplogic:roles"
)

type StpLogic struct {
	manager *manager.Manager
	mu      sync.RWMutex
}

func NewStpLogic(mrg *manager.Manager) *StpLogic {
	return &StpLogic{manager: mrg}
}

// GetManager gets the global Manager | 获取全局Manager
func (s *StpLogic) GetManager() *manager.Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.manager == nil {
		panic("StpLogic not initialized.")
	}
	return s.manager
}

func (s *StpLogic) SetManager(manager *manager.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manager = manager
}

// ============ Authentication | 登录认证 ============

// Login performs user login | 用户登录
func (s *StpLogic) Login(loginID interface{}, device ...string) (string, error) {
	return s.manager.Login(toString(loginID), device...)
}

// LoginByToken performs login with specified token | 使用指定Token登录
func (s *StpLogic) LoginByToken(loginID interface{}, tokenValue string, device ...string) error {
	return s.manager.LoginByToken(toString(loginID), tokenValue, device...)
}

// Logout performs user logout | 用户登出
func (s *StpLogic) Logout(loginID interface{}, device ...string) error {
	return s.manager.Logout(toString(loginID), device...)
}

// LogoutByToken performs logout by token | 根据Token登出
func (s *StpLogic) LogoutByToken(tokenValue string) error {
	return s.manager.LogoutByToken(tokenValue)
}

// IsLogin checks if the user is logged in | 检查用户是否已登录
func (s *StpLogic) IsLogin(tokenValue string) bool {
	return s.manager.IsLogin(tokenValue)
}

// CheckLogin checks login status (throws error if not logged in) | 检查登录状态（未登录抛出错误）
func (s *StpLogic) CheckLogin(tokenValue string) error {
	return s.manager.CheckLogin(tokenValue)
}

// GetLoginID gets the login ID from token | 从Token获取登录ID
func (s *StpLogic) GetLoginID(tokenValue string) (string, error) {
	return s.manager.GetLoginID(tokenValue)
}

// GetLoginIDNotCheck gets login ID without checking | 获取登录ID（不检查）
func (s *StpLogic) GetLoginIDNotCheck(tokenValue string) (string, error) {
	return s.manager.GetLoginIDNotCheck(tokenValue)
}

// GetTokenValue gets the token value for a login ID | 获取登录ID对应的Token值
func (s *StpLogic) GetTokenValue(loginID interface{}, device ...string) (string, error) {
	return s.manager.GetTokenValue(toString(loginID), device...)
}

// GetTokenInfo gets token information | 获取Token信息
func (s *StpLogic) GetTokenInfo(tokenValue string) (*manager.TokenInfo, error) {
	return s.manager.GetTokenInfo(tokenValue)
}

// ============ Kickout | 踢人下线 ============

// Kickout kicks out a user session | 踢人下线
func (s *StpLogic) Kickout(loginID interface{}, device ...string) error {
	return s.manager.Kickout(toString(loginID), device...)
}

// ============ Account Disable | 账号封禁 ============

// Disable disables an account for specified duration | 封禁账号（指定时长）
func (s *StpLogic) Disable(loginID interface{}, duration time.Duration) error {
	return s.manager.Disable(toString(loginID), duration)
}

// Untie re-enables a disabled account | 解封账号
func (s *StpLogic) Untie(loginID interface{}) error {
	return s.manager.Untie(toString(loginID))
}

// IsDisable checks if an account is disabled | 检查账号是否被封禁
func (s *StpLogic) IsDisable(loginID interface{}) bool {
	return s.manager.IsDisable(toString(loginID))
}

// GetDisableTime gets remaining disable time in seconds | 获取剩余封禁时间（秒）
func (s *StpLogic) GetDisableTime(loginID interface{}) (int64, error) {
	return s.manager.GetDisableTime(toString(loginID))
}

// ============ Session Management | Session管理 ============

// GetSession gets session by login ID | 根据登录ID获取Session
func (s *StpLogic) GetSession(loginID interface{}) (*session.Session, error) {
	return s.manager.GetSession(toString(loginID))
}

// GetSessionByToken gets session by token | 根据Token获取Session
func (s *StpLogic) GetSessionByToken(tokenValue string) (*session.Session, error) {
	return s.manager.GetSessionByToken(tokenValue)
}

// DeleteSession deletes a session | 删除Session
func (s *StpLogic) DeleteSession(loginID interface{}) error {
	return s.manager.DeleteSession(toString(loginID))
}

// ============ Permission Verification | 权限验证 ============

// SetPermissions sets permissions for a login ID | 设置用户权限
func (s *StpLogic) SetPermissions(loginID interface{}, permissions []string) error {
	return s.manager.SetPermissions(toString(loginID), permissions)
}

// GetPermissions gets permission list | 获取权限列表
func (s *StpLogic) GetPermissions(loginID interface{}) ([]string, error) {
	return s.manager.GetPermissions(toString(loginID))
}

// HasPermission checks if has specified permission | 检查是否拥有指定权限
func (s *StpLogic) HasPermission(loginID interface{}, permission string) bool {
	return s.manager.HasPermission(toString(loginID), permission)
}

// HasPermissionsAnd checks if has all permissions (AND logic) | 检查是否拥有所有权限（AND逻辑）
func (s *StpLogic) HasPermissionsAnd(loginID interface{}, permissions []string) bool {
	return s.manager.HasPermissionsAnd(toString(loginID), permissions)
}

// HasPermissionsOr checks if has any permission (OR logic) | 检查是否拥有任一权限（OR逻辑）
func (s *StpLogic) HasPermissionsOr(loginID interface{}, permissions []string) bool {
	return s.manager.HasPermissionsOr(toString(loginID), permissions)
}

// ============ Role Management | 角色管理 ============

// SetRoles sets roles for a login ID | 设置用户角色
func (s *StpLogic) SetRoles(loginID interface{}, roles []string) error {
	return s.manager.SetRoles(toString(loginID), roles)
}

// GetRoles gets role list | 获取角色列表
func (s *StpLogic) GetRoles(loginID interface{}) ([]string, error) {
	return s.manager.GetRoles(toString(loginID))
}

// HasRole checks if has specified role | 检查是否拥有指定角色
func (s *StpLogic) HasRole(loginID interface{}, role string) bool {
	return s.manager.HasRole(toString(loginID), role)
}

// HasRolesAnd checks if has all roles (AND logic) | 检查是否拥有所有角色（AND逻辑）
func (s *StpLogic) HasRolesAnd(loginID interface{}, roles []string) bool {
	return s.manager.HasRolesAnd(toString(loginID), roles)
}

// HasRolesOr 检查是否拥有任一角色（OR）
func (s *StpLogic) HasRolesOr(loginID interface{}, roles []string) bool {
	return s.manager.HasRolesOr(toString(loginID), roles)
}

// ============ Token标签 ============

// SetTokenTag 设置Token标签
func (s *StpLogic) SetTokenTag(tokenValue, tag string) error {
	return s.manager.SetTokenTag(tokenValue, tag)
}

// GetTokenTag 获取Token标签
func (s *StpLogic) GetTokenTag(tokenValue string) (string, error) {
	return s.manager.GetTokenTag(tokenValue)
}

// ============ 会话查询 ============

// GetTokenValueList 获取指定账号的所有Token
func (s *StpLogic) GetTokenValueList(loginID interface{}) ([]string, error) {
	return s.manager.GetTokenValueListByLoginID(toString(loginID))
}

// GetSessionCount 获取指定账号的Session数量
func (s *StpLogic) GetSessionCount(loginID interface{}) (int, error) {
	return s.manager.GetSessionCountByLoginID(toString(loginID))
}

func (s *StpLogic) GenerateNonce() (string, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.GenerateNonce()
}

func (s *StpLogic) VerifyNonce(nonce string) bool {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.VerifyNonce(nonce)
}

func (s *StpLogic) LoginWithRefreshToken(loginID interface{}, device ...string) (*security.RefreshTokenInfo, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	deviceType := "default"
	if len(device) > 0 {
		deviceType = device[0]
	}
	return s.manager.LoginWithRefreshToken(fmt.Sprintf("%v", loginID), deviceType)
}

func (s *StpLogic) RefreshAccessToken(refreshToken string) (*security.RefreshTokenInfo, error) {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.RefreshAccessToken(refreshToken)
}

func (s *StpLogic) RevokeRefreshToken(refreshToken string) error {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.RevokeRefreshToken(refreshToken)
}

func (s *StpLogic) GetOAuth2Server() *oauth2.OAuth2Server {
	if s.manager == nil {
		panic("Manager not initialized.")
	}
	return s.manager.GetOAuth2Server()
}

// ============ Check Functions for Token-based operations | 基于Token的检查函数 ============

// CheckDisable checks if the account associated with the token is disabled | 检查Token对应账号是否被封禁
func (s *StpLogic) CheckDisable(tokenValue string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if s.IsDisable(loginID) {
		return fmt.Errorf("account is disabled")
	}
	return nil
}

// CheckPermission checks if the token has the specified permission | 检查Token是否拥有指定权限
func (s *StpLogic) CheckPermission(tokenValue string, permission string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermission(loginID, permission) {
		return fmt.Errorf("permission denied: %s", permission)
	}
	return nil
}

// CheckPermissionAnd checks if the token has all specified permissions | 检查Token是否拥有所有指定权限
func (s *StpLogic) CheckPermissionAnd(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsAnd(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// CheckPermissionOr checks if the token has any of the specified permissions | 检查Token是否拥有任一指定权限
func (s *StpLogic) CheckPermissionOr(tokenValue string, permissions []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasPermissionsOr(loginID, permissions) {
		return fmt.Errorf("permission denied: %v", permissions)
	}
	return nil
}

// GetPermissionList gets permission list for the token | 获取Token对应的权限列表
func (s *StpLogic) GetPermissionList(tokenValue string) ([]string, error) {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return s.GetPermissions(loginID)
}

// CheckRole checks if the token has the specified role | 检查Token是否拥有指定角色
func (s *StpLogic) CheckRole(tokenValue string, role string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRole(loginID, role) {
		return fmt.Errorf("role denied: %s", role)
	}
	return nil
}

// CheckRoleAnd checks if the token has all specified roles | 检查Token是否拥有所有指定角色
func (s *StpLogic) CheckRoleAnd(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesAnd(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// CheckRoleOr checks if the token has any of the specified roles | 检查Token是否拥有任一指定角色
func (s *StpLogic) CheckRoleOr(tokenValue string, roles []string) error {
	loginID, err := s.GetLoginID(tokenValue)
	if err != nil {
		return err
	}
	if !s.HasRolesOr(loginID, roles) {
		return fmt.Errorf("role denied: %v", roles)
	}
	return nil
}

// GetRoleList gets role list for the token | 获取Token对应的角色列表
func (s *StpLogic) GetRoleList(tokenValue string) ([]string, error) {
	loginID, err := GetLoginID(tokenValue)
	if err != nil {
		return nil, err
	}
	return GetRoles(loginID)
}

// GetTokenSession gets session for the token | 获取Token对应的Session
func (s *StpLogic) GetTokenSession(tokenValue string) (*session.Session, error) {
	return GetSessionByToken(tokenValue)
}

// CloseManager Closes the manager and releases all resources | 关闭管理器并释放所有资源
func (s *StpLogic) CloseManager() {
	s.manager.CloseManager()
}
