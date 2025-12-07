// @Author daixk 2025/12/5 15:52:00
package token

// TokenGenerator token generation interface | Token生成接口
type TokenGenerator interface {
	// Generate generates token based on implementation | 生成Token（由实现决定具体规则）
	Generate(loginID, device string) (string, error)
}

// Ensure Generator implements TokenGenerator | 确保Generator实现了TokenGenerator接口
var _ TokenGenerator = (*Generator)(nil)
