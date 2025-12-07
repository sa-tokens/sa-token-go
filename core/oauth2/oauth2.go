package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/dep"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

// OAuth2 Authorization Code Flow Implementation
// OAuth2 授权码模式实现
//
// Flow | 流程:
// 1. RegisterClient() - Register OAuth2 client | 注册OAuth2客户端
// 2. GenerateAuthorizationCode() - User authorizes, get code | 用户授权，获取授权码
// 3. ExchangeCodeForToken() - Exchange code for access token | 用授权码换取访问令牌
// 4. ValidateAccessToken() - Validate access token | 验证访问令牌
// 5. RefreshAccessToken() - Use refresh token to get new token | 用刷新令牌获取新令牌
//
// Usage | 用法:
//   server := oauth2.NewOAuth2Server(storage)
//   server.RegisterClient(&oauth2.Client{...})
//   authCode, _ := server.GenerateAuthorizationCode(...)
//   token, _ := server.ExchangeCodeForToken(...)

// Client OAuth2 client configuration | OAuth2客户端配置
type Client struct {
	ClientID     string      // Client ID | 客户端ID
	ClientSecret string      // Client secret | 客户端密钥
	RedirectURIs []string    // Allowed redirect URIs | 允许的回调URI
	GrantTypes   []GrantType // Allowed grant types | 允许的授权类型
	Scopes       []string    // Allowed scopes | 允许的权限范围
}

// AuthorizationCode authorization code information | 授权码信息
type AuthorizationCode struct {
	Code        string   // Authorization code | 授权码
	ClientID    string   // Client ID | 客户端ID
	RedirectURI string   // Redirect URI | 回调URI
	UserID      string   // User ID | 用户ID
	Scopes      []string // Requested scopes | 请求的权限范围
	CreateTime  int64    // Creation time | 创建时间
	ExpiresIn   int64    // Expiration time in seconds | 过期时间（秒）
	Used        bool     // Whether used | 是否已使用
}

// AccessToken access token information | 访问令牌信息
type AccessToken struct {
	Token        string   // Access token | 访问令牌
	TokenType    string   // Token type (Bearer) | 令牌类型（Bearer）
	ExpiresIn    int64    // Expiration time in seconds | 过期时间（秒）
	RefreshToken string   // Refresh token | 刷新令牌
	Scopes       []string // Granted scopes | 授予的权限范围
	UserID       string   // User ID | 用户ID
	ClientID     string   // Client ID | 客户端ID
}

// OAuth2Server OAuth2 authorization server | OAuth2授权服务器
type OAuth2Server struct {
	storage         adapter.Storage
	keyPrefix       string // Configurable prefix | 可配置的前缀
	clients         map[string]*Client
	clientsMu       sync.RWMutex   // Clients map lock | 客户端映射锁
	codeExpiration  time.Duration  // Authorization code expiration (10min) | 授权码过期时间（10分钟）
	tokenExpiration time.Duration  // Access token expiration (2h) | 访问令牌过期时间（2小时）
	globalConfig    *config.Config // Global authentication configuration | 全局认证配置
	deps            *dep.Dep       // Dependencies manager | 依赖管理器
}

// NewOAuth2Server Creates a new OAuth2 server | 创建新的OAuth2服务器
// prefix: key prefix (e.g., "satoken:" or "" for Java compatibility) | 键前缀（如："satoken:" 或 "" 兼容Java）
func NewOAuth2Server(storage adapter.Storage, deps *dep.Dep, prefix string) *OAuth2Server {
	return &OAuth2Server{
		storage:         storage,
		keyPrefix:       prefix,
		clients:         make(map[string]*Client),
		codeExpiration:  DefaultCodeExpiration,
		tokenExpiration: DefaultTokenExpiration,
		deps:            deps,
	}
}

// RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func (s *OAuth2Server) RegisterClient(client *Client) error {
	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client: clientID is required")
	}

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	s.clients[client.ClientID] = client
	return nil
}

// UnregisterClient Unregisters an OAuth2 client | 注销OAuth2客户端
func (s *OAuth2Server) UnregisterClient(clientID string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	delete(s.clients, clientID)
}

// GetClient Gets client by ID | 根据ID获取客户端
func (s *OAuth2Server) GetClient(clientID string) (*Client, error) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, ErrClientNotFound
	}
	return client, nil
}

// GenerateAuthorizationCode Generates authorization code | 生成授权码
func (s *OAuth2Server) GenerateAuthorizationCode(clientID, redirectURI, userID string, scopes []string) (*AuthorizationCode, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// Validate redirect URI | 验证回调URI
	if !s.isValidRedirectURI(client, redirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	// Generate code | 生成授权码
	codeBytes := make([]byte, CodeLength)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}
	code := hex.EncodeToString(codeBytes)

	authCode := &AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		UserID:      userID,
		Scopes:      scopes,
		CreateTime:  time.Now().Unix(),
		ExpiresIn:   int64(s.codeExpiration.Seconds()),
		Used:        false,
	}

	key := s.getCodeKey(code)
	if err := s.storage.Set(key, authCode, s.codeExpiration); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return authCode, nil
}

// isValidRedirectURI Checks if redirect URI is valid for client | 检查回调URI是否有效
func (s *OAuth2Server) isValidRedirectURI(client *Client, redirectURI string) bool {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// ExchangeCodeForToken Exchanges authorization code for access token | 用授权码换取访问令牌
func (s *OAuth2Server) ExchangeCodeForToken(code, clientID, clientSecret, redirectURI string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, ErrInvalidClientCredentials
	}

	// Get authorization code | 获取授权码
	key := s.getCodeKey(code)
	data, err := s.storage.Get(key)
	if err != nil || data == nil {
		return nil, ErrInvalidAuthCode
	}

	authCode, ok := data.(*AuthorizationCode)
	if !ok {
		return nil, fmt.Errorf("invalid code data")
	}

	// Validate authorization code | 验证授权码
	if authCode.Used {
		return nil, ErrAuthCodeUsed
	}

	if authCode.ClientID != clientID {
		return nil, ErrClientMismatch
	}

	if authCode.RedirectURI != redirectURI {
		return nil, ErrRedirectURIMismatch
	}

	if time.Now().Unix() > authCode.CreateTime+authCode.ExpiresIn {
		s.storage.Delete(key)
		return nil, ErrAuthCodeExpired
	}

	// Mark code as used | 标记为已使用
	authCode.Used = true
	s.storage.Set(key, authCode, time.Minute)

	return s.generateAccessToken(authCode.UserID, authCode.ClientID, authCode.Scopes)
}

// generateAccessToken Generates access token and refresh token | 生成访问令牌和刷新令牌
func (s *OAuth2Server) generateAccessToken(userID, clientID string, scopes []string) (*AccessToken, error) {
	// Generate access token | 生成访问令牌
	tokenBytes := make([]byte, AccessTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	accessToken := hex.EncodeToString(tokenBytes)

	// Generate refresh token | 生成刷新令牌
	refreshBytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := hex.EncodeToString(refreshBytes)

	token := &AccessToken{
		Token:        accessToken,
		TokenType:    TokenTypeBearer,
		ExpiresIn:    int64(s.tokenExpiration.Seconds()),
		RefreshToken: refreshToken,
		Scopes:       scopes,
		UserID:       userID,
		ClientID:     clientID,
	}

	tokenKey := s.getTokenKey(accessToken)
	refreshKey := s.getRefreshKey(refreshToken)

	// Store access token | 存储访问令牌
	if err := s.storage.Set(tokenKey, token, s.tokenExpiration); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store refresh token | 存储刷新令牌
	if err := s.storage.Set(refreshKey, token, DefaultRefreshTTL); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return token, nil
}

// ValidateAccessToken Validates access token | 验证访问令牌
func (s *OAuth2Server) ValidateAccessToken(tokenString string) (*AccessToken, error) {
	if tokenString == "" {
		return nil, ErrInvalidAccessToken
	}

	key := s.getTokenKey(tokenString)
	data, err := s.storage.Get(key)
	if err != nil || data == nil {
		return nil, ErrInvalidAccessToken
	}

	token, ok := data.(*AccessToken)
	if !ok {
		return nil, ErrInvalidTokenData
	}

	return token, nil
}

// RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func (s *OAuth2Server) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, ErrInvalidClientCredentials
	}

	// Get refresh token | 获取刷新令牌
	key := s.getRefreshKey(refreshToken)
	data, err := s.storage.Get(key)
	if err != nil || data == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	oldToken, ok := data.(*AccessToken)
	if !ok {
		return nil, fmt.Errorf("invalid refresh token data")
	}

	if oldToken.ClientID != clientID {
		return nil, ErrClientMismatch
	}

	// Delete old access token | 删除旧的访问令牌
	oldTokenKey := s.getTokenKey(oldToken.Token)
	s.storage.Delete(oldTokenKey)

	return s.generateAccessToken(oldToken.UserID, oldToken.ClientID, oldToken.Scopes)
}

// RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func (s *OAuth2Server) RevokeToken(tokenString string) error {
	if tokenString == "" {
		return nil
	}

	key := s.getTokenKey(tokenString)
	data, err := s.storage.Get(key)
	if err != nil {
		return err
	}

	// Revoke refresh token if exists | 如果存在则撤销刷新令牌
	if token, ok := data.(*AccessToken); ok && token.RefreshToken != "" {
		refreshKey := s.getRefreshKey(token.RefreshToken)
		s.storage.Delete(refreshKey)
	}

	return s.storage.Delete(key)
}

// ============ Helper Methods | 辅助方法 ============

// getCodeKey Gets storage key for authorization code | 获取授权码的存储键
func (s *OAuth2Server) getCodeKey(code string) string {
	return s.keyPrefix + CodeKeySuffix + code
}

// getTokenKey Gets storage key for access token | 获取访问令牌的存储键
func (s *OAuth2Server) getTokenKey(token string) string {
	return s.keyPrefix + TokenKeySuffix + token
}

// getRefreshKey Gets storage key for refresh token | 获取刷新令牌的存储键
func (s *OAuth2Server) getRefreshKey(refreshToken string) string {
	return s.keyPrefix + RefreshKeySuffix + refreshToken
}
