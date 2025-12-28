package main

import (
	"context"
	"fmt"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
)

func main() {
	fmt.Println("=== Sa-Token-Go JWT Example ===\n")

	// 初始化使用 JWT Token 风格
	stputil.SetManager(
		builder.NewBuilder().
			SetStorage(memory.NewStorage()).
			TokenName("Authorization").
			TokenStyle(adapter.TokenStyleJWT).            // 使用 JWT
			JwtSecretKey("your-256-bit-secret-key-here"). // JWT 密钥
			Timeout(3600).                                // 1小时过期
			MaxRefresh(1800).                             // 自动续期触发阈值
			Build(),
	)

	ctx := context.Background()

	fmt.Println("1. 使用 JWT 登录")
	token, err := stputil.Login(ctx, 1000)
	if err != nil {
		fmt.Printf("登录失败: %v\n", err)
		return
	}
	fmt.Printf("登录成功！JWT Token:\n%s\n\n", token)

	// JWT Token 格式：header.payload.signature
	// 你可以在 https://jwt.io 解析这个 Token

	fmt.Println("2. 验证 JWT Token")
	if stputil.IsLogin(ctx, token) {
		fmt.Println("✓ Token 有效")
	} else {
		fmt.Println("✗ Token 无效")
	}

	loginID, err := stputil.GetLoginID(ctx, token)
	if err != nil {
		fmt.Printf("获取登录ID失败: %v\n", err)
		return
	}
	fmt.Printf("登录ID: %s\n\n", loginID)

	fmt.Println("3. 设置权限和角色")
	_ = stputil.SetPermissions(ctx, 1000, []string{"user:read", "user:write", "admin:*"})
	_ = stputil.SetRoles(ctx, 1000, []string{"admin", "user"})
	fmt.Println("已设置权限: user:read, user:write, admin:*")
	fmt.Println("已设置角色: admin, user\n")

	fmt.Println("4. 检查权限")
	if stputil.HasPermission(ctx, 1000, "user:read") {
		fmt.Println("✓ 拥有 user:read 权限")
	}
	if stputil.HasPermission(ctx, 1000, "admin:delete") {
		fmt.Println("✓ 拥有 admin:delete 权限（通配符匹配）")
	}

	fmt.Println("\n5. 检查角色")
	if stputil.HasRole(ctx, 1000, "admin") {
		fmt.Println("✓ 拥有 admin 角色")
	}

	fmt.Println("\n6. 登出")
	_ = stputil.Logout(ctx, 1000)
	fmt.Println("已登出")

	if !stputil.IsLogin(ctx, token) {
		fmt.Println("✓ Token 已失效")
	}

	fmt.Println("\n=== JWT 示例完成 ===")
	fmt.Println("\n💡 提示:")
	fmt.Println("   • JWT Token 包含用户信息，可以在客户端解析")
	fmt.Println("   • 复制上面的 Token 到 https://jwt.io 查看内容")
	fmt.Println("   • JWT 适合无状态的分布式系统")
	fmt.Println("   • 请妥善保管 JWT 密钥")
}
