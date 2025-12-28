package main

import (
	"context"
	"fmt"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
)

func init() {
	stputil.SetManager(
		builder.NewBuilder().
			SetStorage(memory.NewStorage()).
			TokenName("Authorization").
			Timeout(86400).    // 24小时
			MaxRefresh(43200). // 12小时
			TokenStyle(adapter.TokenStyleUUID).
			Build(),
	)
}

func main() {
	fmt.Println("=== Sa-Token-Go 简洁使用示例 ===\n")

	ctx := context.Background()

	// 1. 登录（支持多种类型）
	fmt.Println("1. 登录测试")
	token1, _ := stputil.Login(ctx, 1000)
	fmt.Printf("   用户1000登录成功，Token: %s\n", token1)

	token2, _ := stputil.Login(ctx, "user123")
	fmt.Printf("   用户user123登录成功，Token: %s\n\n", token2)

	// 2. 检查登录
	fmt.Println("2. 检查登录")
	fmt.Printf("   Token1是否登录: %v\n", stputil.IsLogin(ctx, token1))
	fmt.Printf("   Token2是否登录: %v\n\n", stputil.IsLogin(ctx, token2))

	// 3. 获取登录ID
	fmt.Println("3. 获取登录ID")
	loginID1, _ := stputil.GetLoginID(ctx, token1)
	loginID2, _ := stputil.GetLoginID(ctx, token2)
	fmt.Printf("   Token1的登录ID: %s\n", loginID1)
	fmt.Printf("   Token2的登录ID: %s\n\n", loginID2)

	// 4. 权限管理
	fmt.Println("4. 权限管理")
	_ = stputil.SetPermissions(ctx, 1000, []string{"user:read", "user:write", "admin:*"})
	fmt.Println("   已设置权限: user:read, user:write, admin:*")

	fmt.Printf("   是否有user:read权限: %v\n", stputil.HasPermission(ctx, 1000, "user:read"))
	fmt.Printf("   是否有user:delete权限: %v\n", stputil.HasPermission(ctx, 1000, "user:delete"))
	fmt.Printf("   是否有admin:delete权限(通配符): %v\n\n", stputil.HasPermission(ctx, 1000, "admin:delete"))

	// 5. 角色管理
	fmt.Println("5. 角色管理")
	_ = stputil.SetRoles(ctx, 1000, []string{"admin", "manager-example"})
	fmt.Println("   已设置角色: admin, manager-example")

	fmt.Printf("   是否有admin角色: %v\n", stputil.HasRole(ctx, 1000, "admin"))
	fmt.Printf("   是否有user角色: %v\n\n", stputil.HasRole(ctx, 1000, "user"))

	// 6. Session管理
	fmt.Println("6. Session管理")
	sess, _ := stputil.GetSession(ctx, 1000)
	_ = sess.Set(ctx, "nickname", "张三")
	_ = sess.Set(ctx, "age", 25)
	fmt.Printf("   Session已设置: nickname=%s, age=%d\n", sess.GetString("nickname"), sess.GetInt("age"))

	// 7. 账号封禁
	fmt.Println("\n7. 账号封禁")
	_ = stputil.Disable(ctx, "user123", 1*time.Hour)
	fmt.Printf("   用户user123已被封禁1小时\n")
	fmt.Printf("   是否被封禁: %v\n", stputil.IsDisable(ctx, "user123"))

	remainingTime, _ := stputil.GetDisableTime(ctx, "user123")
	fmt.Printf("   剩余封禁时间: %d秒\n", remainingTime)

	// 8. 解封
	_ = stputil.Untie(ctx, "user123")
	fmt.Printf("   已解封，是否被封禁: %v\n\n", stputil.IsDisable(ctx, "user123"))

	// 9. Token信息
	fmt.Println("9. Token信息")
	info, _ := stputil.GetTokenInfo(ctx, token1)
	fmt.Printf("   登录ID: %s\n", info.LoginID)
	fmt.Printf("   设备: %s\n", info.Device)
	fmt.Printf("   创建时间: %d\n", info.CreateTime)
	fmt.Printf("   活跃时间: %d\n\n", info.ActiveTime)

	// 10. 登出
	fmt.Println("10. 登出")
	_ = stputil.Logout(ctx, 1000)
	fmt.Printf("   用户1000已登出\n")
	fmt.Printf("   Token1是否还有效: %v\n", stputil.IsLogin(ctx, token1))

	fmt.Println("\n=== 示例完成！ ===")
}
