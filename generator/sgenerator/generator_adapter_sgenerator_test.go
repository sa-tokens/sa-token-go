// @Author daixk 2025/12/28 10:00:00
package sgenerator

import (
	"strings"
	"testing"

	"github.com/click33/sa-token-go/core/adapter"
)

// ============ Constructor Tests | 构造函数测试 ============

func TestNewGenerator(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleUUID, "my-secret")

	if g.timeout != 3600 {
		t.Errorf("expected timeout 3600, got %d", g.timeout)
	}
	if g.tokenStyle != adapter.TokenStyleUUID {
		t.Errorf("expected tokenStyle uuid, got %s", g.tokenStyle)
	}
	if g.jwtSecretKey != "my-secret" {
		t.Errorf("expected jwtSecretKey my-secret, got %s", g.jwtSecretKey)
	}
}

func TestNewDefaultGenerator(t *testing.T) {
	g := NewDefaultGenerator()

	if g.timeout != DefaultTimeout {
		t.Errorf("expected default timeout %d, got %d", DefaultTimeout, g.timeout)
	}
	if g.tokenStyle != adapter.TokenStyleUUID {
		t.Errorf("expected default tokenStyle uuid, got %s", g.tokenStyle)
	}
	if g.jwtSecretKey != DefaultJWTSecret {
		t.Errorf("expected default jwtSecretKey, got %s", g.jwtSecretKey)
	}
}

// ============ Generate Tests | 生成测试 ============

func TestGenerate_EmptyLoginID(t *testing.T) {
	g := NewDefaultGenerator()

	_, err := g.Generate("", "pc")
	if err == nil {
		t.Error("expected error for empty loginID")
	}
}

func TestGenerate_UUID(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleUUID, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if len(token) != 36 {
		t.Errorf("expected UUID length 36, got %d", len(token))
	}
	if strings.Count(token, "-") != 4 {
		t.Errorf("expected 4 dashes in UUID, got %d", strings.Count(token, "-"))
	}
}

func TestGenerate_Simple(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleSimple, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(token) != DefaultSimpleLength {
		t.Errorf("expected length %d, got %d", DefaultSimpleLength, len(token))
	}
}

func TestGenerate_Random32(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleRandom32, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(token) != 32 {
		t.Errorf("expected length 32, got %d", len(token))
	}
}

func TestGenerate_Random64(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleRandom64, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(token) != 64 {
		t.Errorf("expected length 64, got %d", len(token))
	}
}

func TestGenerate_Random128(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleRandom128, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(token) != 128 {
		t.Errorf("expected length 128, got %d", len(token))
	}
}

func TestGenerate_JWT(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT with 3 parts, got %d", len(parts))
	}
}

func TestGenerate_Hash(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleHash, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SHA256 hex string length is 64
	if len(token) != 64 {
		t.Errorf("expected hash length 64, got %d", len(token))
	}
}

func TestGenerate_Timestamp(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleTimestamp, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Format: timestamp_loginID_random
	parts := strings.Split(token, "_")
	if len(parts) != 3 {
		t.Errorf("expected 3 parts separated by underscore, got %d", len(parts))
	}
	if parts[1] != "user123" {
		t.Errorf("expected loginID user123 in token, got %s", parts[1])
	}
}

func TestGenerate_Tik(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleTik, "")

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(token) != TikTokenLength {
		t.Errorf("expected tik length %d, got %d", TikTokenLength, len(token))
	}

	// Check all characters are in charset
	for _, c := range token {
		if !strings.ContainsRune(TikCharset, c) {
			t.Errorf("unexpected character %c in tik token", c)
		}
	}
}

func TestGenerate_DefaultStyle(t *testing.T) {
	g := &Generator{
		timeout:    3600,
		tokenStyle: "invalid_style",
	}

	token, err := g.Generate("user123", "pc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fallback to UUID
	if len(token) != 36 {
		t.Errorf("expected UUID fallback, got length %d", len(token))
	}
}

// ============ JWT Helper Tests | JWT辅助方法测试 ============

func TestParseJWT(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")

	token, err := g.Generate("user123", "mobile")
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	claims, err := g.ParseJWT(token)
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	if claims["loginId"] != "user123" {
		t.Errorf("expected loginId user123, got %v", claims["loginId"])
	}
	if claims["device"] != "mobile" {
		t.Errorf("expected device mobile, got %v", claims["device"])
	}
}

func TestParseJWT_EmptyToken(t *testing.T) {
	g := NewDefaultGenerator()

	_, err := g.ParseJWT("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestParseJWT_InvalidToken(t *testing.T) {
	g := NewDefaultGenerator()

	_, err := g.ParseJWT("invalid.token.string")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestParseJWT_WrongSecret(t *testing.T) {
	g1 := NewGenerator(3600, adapter.TokenStyleJWT, "secret1")
	g2 := NewGenerator(3600, adapter.TokenStyleJWT, "secret2")

	token, _ := g1.Generate("user123", "pc")

	_, err := g2.ParseJWT(token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestValidateJWT(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")

	token, _ := g.Generate("user123", "pc")

	err := g.ValidateJWT(token)
	if err != nil {
		t.Errorf("expected valid JWT, got error: %v", err)
	}
}

func TestValidateJWT_Invalid(t *testing.T) {
	g := NewDefaultGenerator()

	err := g.ValidateJWT("invalid.token")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestGetLoginIDFromJWT(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")

	token, _ := g.Generate("user456", "pc")

	loginID, err := g.GetLoginIDFromJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loginID != "user456" {
		t.Errorf("expected loginID user456, got %s", loginID)
	}
}

func TestGetLoginIDFromJWT_InvalidToken(t *testing.T) {
	g := NewDefaultGenerator()

	_, err := g.GetLoginIDFromJWT("invalid.token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

// ============ Uniqueness Tests | 唯一性测试 ============

func TestGenerate_Uniqueness(t *testing.T) {
	styles := []adapter.TokenStyle{
		adapter.TokenStyleUUID,
		adapter.TokenStyleSimple,
		adapter.TokenStyleRandom32,
		adapter.TokenStyleRandom64,
		adapter.TokenStyleHash,
		adapter.TokenStyleTimestamp,
		adapter.TokenStyleTik,
	}

	for _, style := range styles {
		t.Run(string(style), func(t *testing.T) {
			g := NewGenerator(3600, style, "test-secret")
			tokens := make(map[string]bool)
			count := 100

			for i := 0; i < count; i++ {
				token, err := g.Generate("user123", "pc")
				if err != nil {
					t.Fatalf("failed to generate token: %v", err)
				}

				if tokens[token] {
					t.Errorf("duplicate token generated: %s", token)
				}
				tokens[token] = true
			}
		})
	}
}

// ============ JWT Expiration Tests | JWT过期测试 ============

func TestGenerate_JWT_WithExpiration(t *testing.T) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")

	token, _ := g.Generate("user123", "pc")
	claims, _ := g.ParseJWT(token)

	if _, ok := claims["exp"]; !ok {
		t.Error("expected exp claim in JWT")
	}
	if _, ok := claims["iat"]; !ok {
		t.Error("expected iat claim in JWT")
	}
}

func TestGenerate_JWT_NoExpiration(t *testing.T) {
	g := NewGenerator(0, adapter.TokenStyleJWT, "test-secret")

	token, _ := g.Generate("user123", "pc")
	claims, _ := g.ParseJWT(token)

	if _, ok := claims["exp"]; ok {
		t.Error("expected no exp claim when timeout is 0")
	}
}

// ============ Benchmark Tests | 基准测试 ============

func BenchmarkGenerate_UUID(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleUUID, "")
	for i := 0; i < b.N; i++ {
		g.Generate("user123", "pc")
	}
}

func BenchmarkGenerate_Simple(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleSimple, "")
	for i := 0; i < b.N; i++ {
		g.Generate("user123", "pc")
	}
}

func BenchmarkGenerate_JWT(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")
	for i := 0; i < b.N; i++ {
		g.Generate("user123", "pc")
	}
}

func BenchmarkGenerate_Hash(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleHash, "")
	for i := 0; i < b.N; i++ {
		g.Generate("user123", "pc")
	}
}

func BenchmarkGenerate_Tik(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleTik, "")
	for i := 0; i < b.N; i++ {
		g.Generate("user123", "pc")
	}
}

func BenchmarkParseJWT(b *testing.B) {
	g := NewGenerator(3600, adapter.TokenStyleJWT, "test-secret")
	token, _ := g.Generate("user123", "pc")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.ParseJWT(token)
	}
}
