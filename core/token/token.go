package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Error variables | 错误变量
var (
	ErrInvalidToken            = fmt.Errorf("invalid token")
	ErrUnexpectedSigningMethod = fmt.Errorf("unexpected signing method")
)

// Generator Token generator | Token生成器
type Generator struct {
	config *config.Config
}

// NewGenerator Creates a new token generator | 创建新的Token生成器
func NewGenerator(cfg *config.Config) *Generator {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Generator{
		config: cfg,
	}
}

// ============ Public Methods | 公共方法 ============

// Generate Generates token based on configured style | 根据配置的风格生成Token
func (g *Generator) Generate(loginID string, device string) (string, error) {
	if loginID == "" {
		return "", fmt.Errorf("loginID cannot be empty")
	}

	switch g.config.TokenStyle {
	case config.TokenStyleUUID:
		return g.generateUUID()
	case config.TokenStyleSimple:
		return g.generateSimple(DefaultSimpleLength)
	case config.TokenStyleRandom32:
		return g.generateSimple(32)
	case config.TokenStyleRandom64:
		return g.generateSimple(64)
	case config.TokenStyleRandom128:
		return g.generateSimple(128)
	case config.TokenStyleJWT:
		return g.generateJWT(loginID, device)
	case config.TokenStyleHash:
		return g.generateHash(loginID, device)
	case config.TokenStyleTimestamp:
		return g.generateTimestamp(loginID, device)
	case config.TokenStyleTik:
		return g.generateTik()
	default:
		return g.generateUUID()
	}
}

// ============ Token Generation Methods | Token生成方法 ============

// generateUUID Generates UUID token | 生成UUID Token
func (g *Generator) generateUUID() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}
	return u.String(), nil
}

// generateSimple Generates simple random string token | 生成简单随机字符串Token
func (g *Generator) generateSimple(length int) (string, error) {
	if length <= 0 {
		length = DefaultSimpleLength
	}

	token := utils.RandomString(length)
	if token == "" {
		return "", fmt.Errorf("failed to generate random string")
	}
	return token, nil
}

// generateJWT Generates JWT token | 生成JWT Token
func (g *Generator) generateJWT(loginID string, device string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"loginId": loginID,
		"device":  device,
		"iat":     now.Unix(),
	}

	// Add expiration if timeout is configured | 如果配置了超时时间则添加过期时间
	if g.config.Timeout > 0 {
		claims["exp"] = now.Add(time.Duration(g.config.Timeout) * time.Second).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretKey := g.getJWTSecret()

	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return signedToken, nil
}

// getJWTSecret Gets JWT secret key with fallback | 获取JWT密钥（带默认值）
func (g *Generator) getJWTSecret() string {
	if g.config.JwtSecretKey != "" {
		return g.config.JwtSecretKey
	}
	return DefaultJWTSecret
}

// ============ JWT Helper Methods | JWT辅助方法 ============

// ParseJWT Parses JWT token and returns claims | 解析JWT Token并返回声明
func (g *Generator) ParseJWT(tokenStr string) (jwt.MapClaims, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("token string cannot be empty")
	}

	secretKey := g.getJWTSecret()

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		// Verify signing method | 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// ValidateJWT Validates JWT token | 验证JWT Token
func (g *Generator) ValidateJWT(tokenStr string) error {
	_, err := g.ParseJWT(tokenStr)
	return err
}

// GetLoginIDFromJWT Extracts login ID from JWT token | 从JWT Token中提取登录ID
func (g *Generator) GetLoginIDFromJWT(tokenStr string) (string, error) {
	claims, err := g.ParseJWT(tokenStr)
	if err != nil {
		return "", err
	}

	loginID, ok := claims["loginId"].(string)
	if !ok {
		return "", fmt.Errorf("loginId not found in token claims")
	}

	return loginID, nil
}

// generateHash Generates SHA256 hash-based token | 生成SHA256哈希风格Token
func (g *Generator) generateHash(loginID string, device string) (string, error) {
	// Combine loginID, device, timestamp and random bytes | 组合 loginID、device、时间戳和随机字节
	randomBytes := make([]byte, HashRandomBytesLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create hash input | 创建哈希输入
	data := fmt.Sprintf("%s:%s:%d:%s",
		loginID,
		device,
		time.Now().UnixNano(),
		hex.EncodeToString(randomBytes))

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// generateTimestamp Generates timestamp-based token | 生成时间戳风格Token
func (g *Generator) generateTimestamp(loginID string, device string) (string, error) {
	// Format: timestamp_loginID_random | 格式：时间戳_loginID_随机数
	randomBytes := make([]byte, TimestampRandomLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	timestamp := time.Now().UnixMilli()
	random := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("%d_%s_%s", timestamp, loginID, random), nil
}

// generateTik Generates short ID style token (like TikTok) | 生成Tik风格短ID Token（类似抖音）
func (g *Generator) generateTik() (string, error) {
	result := make([]byte, TikTokenLength)
	charsetLen := int64(len(TikCharset))

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(charsetLen))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result[i] = TikCharset[num.Int64()]
	}

	return string(result), nil
}
