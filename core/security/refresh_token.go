package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/generator/sgenerator"
	"github.com/click33/sa-token-go/storage/memory"
	"time"

	"github.com/click33/sa-token-go/core/utils"
)

// Refresh Token Implementation | 刷新令牌实现
//
// Flow | 流程:
// 1. GenerateTokenPair() -> AccessToken + RefreshToken | 创建访问令牌 + 刷新令牌
// 2. AccessToken expires | 访问令牌过期
// 3. RefreshAccessToken() -> New AccessToken | 使用刷新令牌获取新访问令牌
// 4. RefreshToken expires -> Relogin | 刷新令牌过期需重新登录

// AccessTokenInfo Access token storage value | 访问令牌存储数据
type AccessTokenInfo struct {
	LoginID string `json:"loginID"` // User login ID | 用户登录ID
	Device  string `json:"device"`  // Device type | 设备类型
}

// RefreshTokenInfo Refresh token storage value | 刷新令牌存储数据
type RefreshTokenInfo struct {
	RefreshToken string `json:"refreshToken"` // Refresh token value | 刷新令牌值
	AccessToken  string `json:"accessToken"`  // Latest access token | 最新访问令牌
	LoginID      string `json:"loginID"`      // User login ID | 用户登录ID
	Device       string `json:"device"`       // Device type | 设备类型
	CreateTime   int64  `json:"createTime"`   // Create timestamp | 创建时间
	ExpireTime   int64  `json:"expireTime"`   // Expire timestamp | 过期时间
}

// RefreshTokenManager Refresh token manager-example | 刷新令牌管理器
type RefreshTokenManager struct {
	authType       string        // Auth system type | 认证体系类型
	keyPrefix      string        // Storage key prefix | 存储前缀
	tokenKeyPrefix string        // Token key prefix | Token 前缀
	refreshTTL     time.Duration // Refresh token TTL | 刷新令牌有效期
	accessTTL      time.Duration // Access token TTL | 访问令牌有效期

	tokenGen   adapter.Generator // Token generator | Token 生成器
	storage    adapter.Storage   // Storage adapter | 存储适配器
	serializer adapter.Codec     // Codec adapter | 编解码器
}

// NewRefreshTokenManager Create manager-example instance | 创建刷新令牌管理器
func NewRefreshTokenManager(
	authType, prefix, tokenKeyPrefix string,
	tokenGen adapter.Generator,
	accessTTL time.Duration,
	storage adapter.Storage,
	serializer adapter.Codec,
) *RefreshTokenManager {

	if tokenGen == nil {
		tokenGen = sgenerator.NewDefaultGenerator()
	}
	if accessTTL == 0 {
		accessTTL = DefaultAccessTTL
	}
	if storage == nil {
		storage = memory.NewStorage()
	}
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	return &RefreshTokenManager{
		authType:       authType,
		keyPrefix:      prefix,
		tokenKeyPrefix: tokenKeyPrefix,
		tokenGen:       tokenGen,
		refreshTTL:     DefaultRefreshTTL,
		accessTTL:      accessTTL,
		storage:        storage,
		serializer:     serializer,
	}
}

// GenerateTokenPair Create access + refresh token | 生成访问令牌和刷新令牌
func (rtm *RefreshTokenManager) GenerateTokenPair(ctx context.Context, loginID, device string) (*RefreshTokenInfo, error) {
	if loginID == "" {
		return nil, core.ErrInvalidLoginIDEmpty
	}

	// Generate access token | 生成访问令牌
	accessToken, err := rtm.tokenGen.Generate(loginID, device)
	if err != nil {
		return nil, err
	}

	random := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	// Generate refresh token | 生成刷新令牌
	refreshToken := hex.EncodeToString(random)

	now := time.Now()
	info := &RefreshTokenInfo{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		LoginID:      loginID,
		Device:       device,
		CreateTime:   now.Unix(),
		ExpireTime:   now.Add(rtm.refreshTTL).Unix(),
	}
	// Encode refresh token info | 编码刷新令牌信息
	refreshData, err := rtm.serializer.Encode(info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	// Encode access token info | 编码访问令牌信息
	accessData, err := rtm.serializer.Encode(&AccessTokenInfo{
		LoginID: loginID,
		Device:  device,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	// Store access token | 存储访问令牌
	if err = rtm.storage.Set(
		ctx,
		rtm.getTokenKey(accessToken),
		accessData,
		rtm.accessTTL,
	); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// Store refresh token | 存储刷新令牌
	if err := rtm.storage.Set(
		ctx,
		rtm.getRefreshKey(refreshToken),
		refreshData,
		rtm.refreshTTL,
	); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return info, nil
}

// VerifyAccessToken Check token exists | 验证访问令牌是否存在
func (rtm *RefreshTokenManager) VerifyAccessToken(ctx context.Context, accessToken string) bool {
	return rtm.storage.Exists(ctx, rtm.getTokenKey(accessToken))
}

// VerifyAccessTokenAndGetInfo Verify and get info | 验证访问令牌并获取信息
func (rtm *RefreshTokenManager) VerifyAccessTokenAndGetInfo(ctx context.Context, accessToken string) (*AccessTokenInfo, bool) {
	data, err := rtm.storage.Get(ctx, rtm.getTokenKey(accessToken))
	if err != nil || data == nil {
		return nil, false
	}

	bytes, err := utils.ToBytes(data)
	if err != nil {
		return nil, false
	}

	var info AccessTokenInfo
	if err := rtm.serializer.Decode(bytes, &info); err != nil {
		return nil, false
	}

	return &info, true
}

// RefreshAccessToken Refresh access token by refresh token | 使用刷新令牌刷新访问令牌
func (rtm *RefreshTokenManager) RefreshAccessToken(ctx context.Context, refreshToken string) (*RefreshTokenInfo, error) {
	if refreshToken == "" {
		return nil, core.ErrNonceInvalidRefreshToken
	}

	refreshKey := rtm.getRefreshKey(refreshToken)

	// Load refresh token | 读取刷新令牌
	data, err := rtm.storage.Get(ctx, refreshKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}
	if data == nil {
		return nil, core.ErrInvalidRefreshToken
	}

	bytes, err := utils.ToBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrTypeConvert, err)
	}

	var info RefreshTokenInfo
	if err := rtm.serializer.Decode(bytes, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrDeserializeFailed, err)
	}

	// Check expiration | 检查过期
	if time.Now().Unix() > info.ExpireTime {
		_ = rtm.storage.Delete(ctx, refreshKey)
		return nil, core.ErrRefreshTokenExpired
	}

	// Remove old access token | 删除旧访问令牌
	if info.AccessToken != "" {
		_ = rtm.storage.Delete(ctx, rtm.getTokenKey(info.AccessToken))
	}

	// Generate new access token | 生成新访问令牌
	newAccessToken, err := rtm.tokenGen.Generate(info.LoginID, info.Device)
	if err != nil {
		return nil, err
	}
	info.AccessToken = newAccessToken

	// Store new access token | 存储新访问令牌
	accessData, err := rtm.serializer.Encode(&AccessTokenInfo{
		LoginID: info.LoginID,
		Device:  info.Device,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}
	if err := rtm.storage.Set(
		ctx,
		rtm.getTokenKey(newAccessToken),
		accessData,
		rtm.accessTTL,
	); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// Update refresh token without extending TTL | 更新刷新令牌但不续期
	refreshData, err := rtm.serializer.Encode(&info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}
	if err = rtm.storage.SetKeepTTL(ctx, refreshKey, refreshData); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return &info, nil
}

// GetRefreshTokenInfo Get refresh token info by token | 根据刷新令牌获取刷新令牌信息
func (rtm *RefreshTokenManager) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (*RefreshTokenInfo, error) {
	if refreshToken == "" {
		return nil, core.ErrInvalidRefreshToken
	}

	refreshKey := rtm.getRefreshKey(refreshToken)

	// Load refresh token | 读取刷新令牌
	data, err := rtm.storage.Get(ctx, refreshKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}
	if data == nil {
		return nil, core.ErrInvalidRefreshToken
	}

	bytes, err := utils.ToBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrTypeConvert, err)
	}

	var info RefreshTokenInfo
	if err = rtm.serializer.Decode(bytes, &info); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrDeserializeFailed, err)
	}

	return &info, nil
}

// RevokeRefreshToken Remove refresh token | 撤销刷新令牌
func (rtm *RefreshTokenManager) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}

	err := rtm.storage.Delete(ctx, rtm.getRefreshKey(refreshToken))
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// IsValid Check refresh token valid | 判断刷新令牌是否有效
func (rtm *RefreshTokenManager) IsValid(ctx context.Context, refreshToken string) bool {
	data, err := rtm.storage.Get(ctx, rtm.getRefreshKey(refreshToken))
	if err != nil || data == nil {
		return false
	}

	bytes, err := utils.ToBytes(data)
	if err != nil {
		return false
	}

	var info RefreshTokenInfo
	if err = rtm.serializer.Decode(bytes, &info); err != nil {
		return false
	}

	return time.Now().Unix() <= info.ExpireTime
}

// getRefreshKey Build refresh token key | 构建刷新令牌 Key
func (rtm *RefreshTokenManager) getRefreshKey(refreshToken string) string {
	return rtm.keyPrefix + rtm.authType + RefreshKeySuffix + refreshToken
}

// getTokenKey Build access token key | 构建访问令牌 Key
func (rtm *RefreshTokenManager) getTokenKey(tokenValue string) string {
	return rtm.keyPrefix + rtm.authType + rtm.tokenKeyPrefix + tokenValue
}
