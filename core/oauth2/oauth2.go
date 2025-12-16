package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/serror"
	"github.com/click33/sa-token-go/core/utils"
	"github.com/click33/sa-token-go/storage/memory"
	"sync"
	"time"
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
	authType        string             // Authentication system type | 认证体系类型
	keyPrefix       string             // Configurable prefix | 可配置的前缀
	clients         map[string]*Client // client map | 客户端映射map
	clientsMu       sync.RWMutex       // Clients map lock | 客户端映射锁
	codeExpiration  time.Duration      // Authorization code expiration (10min) | 授权码过期时间（10分钟）
	tokenExpiration time.Duration      // Access token expiration (2h) | 访问令牌过期时间（2小时）
	serializer      adapter.Codec      // Codec adapter for encoding and decoding operations | 编解码器适配器
	storage         adapter.Storage    // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
}

// NewOAuth2Server Creates a new OAuth2 server | 创建新的OAuth2服务器
func NewOAuth2Server(authType, prefix string, storage adapter.Storage, serializer adapter.Codec) *OAuth2Server {
	if storage == nil {
		storage = memory.NewStorage() // default in-memory storage | 默认内存存储
	}
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer() // default JSON serializer | 默认 JSON 编解码器
	}

	return &OAuth2Server{
		authType:        authType,                 // Auth system identifier | 认证体系标识
		keyPrefix:       prefix,                   // Global key prefix | 全局Key前缀
		clients:         make(map[string]*Client), // Initialize client registry | 初始化客户端注册表
		codeExpiration:  DefaultCodeExpiration,    // Default auth code TTL | 默认授权码有效期
		tokenExpiration: DefaultTokenExpiration,   // Default access token TTL | 默认访问令牌有效期
		storage:         storage,                  // Storage backend | 存储后端
		serializer:      serializer,               // Codec implementation | 编解码实现
	}
}

// RegisterClient Registers an OAuth2 client | 注册OAuth2客户端
func (s *OAuth2Server) RegisterClient(client *Client) error {
	if client == nil || client.ClientID == "" {
		return serror.ErrClientOrClientIDEmpty
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
		return nil, serror.ErrClientNotFound
	}
	return client, nil
}

// GenerateAuthorizationCode Generates authorization code | 生成授权码
func (s *OAuth2Server) GenerateAuthorizationCode(clientID, userID, redirectURI string, scopes []string) (*AuthorizationCode, error) {
	if userID == "" {
		return nil, serror.ErrUserIDEmpty
	}

	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	// Validate redirect URI | 验证回调URI
	if !s.isValidRedirectURI(client, redirectURI) {
		return nil, serror.ErrInvalidRedirectURI
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

	encodeData, err := s.serializer.Encode(authCode)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonEncode, err)
	}

	key := s.getCodeKey(code)
	if err := s.storage.Set(key, encodeData, s.codeExpiration); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}

	return authCode, nil
}

// ExchangeCodeForToken Exchanges authorization code for access token | 用授权码换取访问令牌
func (s *OAuth2Server) ExchangeCodeForToken(code, clientID, clientSecret, redirectURI string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, serror.ErrInvalidClientCredentials
	}

	// Get authorization code | 获取授权码
	key := s.getCodeKey(code)
	data, err := s.storage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization data: %w", err)
	}
	if data == nil {
		return nil, serror.ErrInvalidAuthCode
	}

	rawData, err := utils.ToBytes(data)
	if err != nil {
		return nil, err
	}

	var authCode AuthorizationCode
	if err := s.serializer.Decode(rawData, &authCode); err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonDecode, err)
	}

	// Validate authorization code | 验证授权码
	if authCode.Used {
		return nil, serror.ErrAuthCodeUsed
	}

	if authCode.ClientID != clientID {
		return nil, serror.ErrClientMismatch
	}

	if authCode.RedirectURI != redirectURI {
		return nil, serror.ErrRedirectURIMismatch
	}

	if time.Now().Unix() > authCode.CreateTime+authCode.ExpiresIn {
		_ = s.storage.Delete(key)
		return nil, serror.ErrAuthCodeExpired
	}

	// Mark code as used | 标记为已使用
	authCode.Used = true

	encodeData, err := s.serializer.Encode(authCode)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonEncode, err)
	}

	_ = s.storage.Set(key, encodeData, time.Minute)

	return s.generateAccessToken(authCode.UserID, authCode.ClientID, authCode.Scopes)
}

// ValidateAccessToken Validates access token | 验证访问令牌
func (s *OAuth2Server) ValidateAccessToken(accessToken string) (*AccessToken, error) {
	if accessToken == "" {
		return nil, serror.ErrInvalidAccessToken
	}

	key := s.getTokenKey(accessToken)
	data, err := s.storage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token data: %w", err)
	}
	if data == nil {
		return nil, serror.ErrInvalidAccessToken
	}

	rawData, err := utils.ToBytes(data)
	if err != nil {
		return nil, err
	}

	var accessTokenInfo AccessToken
	err = s.serializer.Decode(rawData, &accessTokenInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonDecode, err)
	}

	return &accessTokenInfo, nil
}

// RefreshAccessToken Refreshes access token using refresh token | 使用刷新令牌刷新访问令牌
func (s *OAuth2Server) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*AccessToken, error) {
	// Verify client credentials | 验证客户端凭证
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	if client.ClientSecret != clientSecret {
		return nil, serror.ErrInvalidClientCredentials
	}

	// Get refresh token | 获取刷新令牌
	key := s.getRefreshKey(refreshToken)
	data, err := s.storage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token data: %w", err)
	}
	if data == nil {
		return nil, serror.ErrInvalidRefreshToken
	}

	rawData, err := utils.ToBytes(data)
	if err != nil {
		return nil, err
	}

	var accessTokenInfo AccessToken
	err = s.serializer.Decode(rawData, &accessTokenInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonDecode, err)
	}

	if accessTokenInfo.ClientID != clientID {
		return nil, serror.ErrClientMismatch
	}

	_ = s.storage.Delete(s.getTokenKey(accessTokenInfo.Token))

	return s.generateAccessToken(accessTokenInfo.UserID, accessTokenInfo.ClientID, accessTokenInfo.Scopes)
}

// RevokeToken Revokes access token and its refresh token | 撤销访问令牌及其刷新令牌
func (s *OAuth2Server) RevokeToken(accessToken string) error {
	if accessToken == "" {
		return nil
	}

	key := s.getTokenKey(accessToken)
	data, err := s.storage.Get(key)
	if err != nil {
		return fmt.Errorf("failed to get access token data: %w", err)
	}
	if data == nil {
		return serror.ErrInvalidAccessToken
	}

	rawData, err := utils.ToBytes(data)
	if err != nil {
		return err
	}

	var accessTokenInfo AccessToken
	err = s.serializer.Decode(rawData, &accessTokenInfo)
	if err != nil {
		return fmt.Errorf("%w: %v", serror.ErrCommonDecode, err)
	}

	if accessTokenInfo.RefreshToken != "" {
		refreshKey := s.getRefreshKey(accessTokenInfo.RefreshToken)
		_ = s.storage.Delete(refreshKey)
	}

	return s.storage.Delete(key)
}

// ============ Helper Methods | 辅助方法 ============

// getCodeKey Gets storage key for authorization code | 获取授权码的存储键
func (s *OAuth2Server) getCodeKey(code string) string {
	return s.keyPrefix + s.authType + CodeKeySuffix + code
}

// getTokenKey Gets storage key for access token | 获取访问令牌的存储键
func (s *OAuth2Server) getTokenKey(token string) string {
	return s.keyPrefix + s.authType + TokenKeySuffix + token
}

// getRefreshKey Gets storage key for refresh token | 获取刷新令牌的存储键
func (s *OAuth2Server) getRefreshKey(refreshToken string) string {
	return s.keyPrefix + s.authType + RefreshKeySuffix + refreshToken
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
	encodeData, err := s.serializer.Encode(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonEncode, err)
	}

	tokenKey := s.getTokenKey(accessToken)
	refreshKey := s.getRefreshKey(refreshToken)

	// Store access token | 存储访问令牌
	if err = s.storage.Set(tokenKey, encodeData, s.tokenExpiration); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// Store refresh token | 存储刷新令牌
	if err = s.storage.Set(refreshKey, encodeData, DefaultRefreshTTL); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return token, nil
}
