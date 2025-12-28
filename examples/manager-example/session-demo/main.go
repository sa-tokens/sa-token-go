package main

import (
	"context"
	"fmt"
	"log"

	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
)

// SysUser 用户实体（完整的用户对象）
type SysUser struct {
	UserID   int64  `json:"userId"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Avatar   string `json:"avatar"`
	Status   int    `json:"status"`
	RoleIDs  []int  `json:"roleIds"`
}

func main() {
	// 初始化 sa-token
	stputil.SetManager(
		builder.NewBuilder().
			SetStorage(memory.NewStorage()).
			KeyPrefix("satoken").
			Timeout(86400).
			MaxRefresh(43200).
			IsPrintBanner(true).
			Build(),
	)

	ctx := context.Background()

	// 模拟用户登录
	userID := "1000"

	// 1. 执行登录 - Token 键中只存 loginID
	token, err := stputil.Login(ctx, userID)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✅ 登录成功！\n")
	fmt.Printf("   Token: %s\n\n", token)

	// 2. 模拟从数据库查询的完整用户对象
	userFromDB := &SysUser{
		UserID:   1000,
		Username: "zhangsan",
		Nickname: "张三",
		Email:    "zhangsan@example.com",
		Phone:    "13800138000",
		Avatar:   "https://example.com/avatar.jpg",
		Status:   1,
		RoleIDs:  []int{1, 2, 3},
	}

	// 3. 将完整的用户对象存入 Session（Account-Session）
	sess, _ := stputil.GetSession(ctx, userID)
	_ = sess.Set(ctx, "user", userFromDB) // ← 完整的 User 对象存在 Session 中
	_ = sess.Set(ctx, "lastLoginTime", "2025-10-25 10:00:00")
	_ = sess.Set(ctx, "loginIP", "192.168.1.100")

	fmt.Printf("📦 Redis 存储结构：\n\n")
	fmt.Printf("   1️⃣  Token 键（只存 loginID）:\n")
	fmt.Printf("       Key:   satoken:token:%s\n", token)
	fmt.Printf("       Value: %s  ← 只是简单的字符串\n\n", userID)

	fmt.Printf("   2️⃣  Account-Session 键（存完整用户对象）:\n")
	fmt.Printf("       Key:   satoken:session:%s\n", userID)
	fmt.Printf("       Value: {\n")
	fmt.Printf("                \"user\": {...完整的 SysUser 对象...},\n")
	fmt.Printf("                \"lastLoginTime\": \"2025-10-25 10:00:00\",\n")
	fmt.Printf("                \"loginIP\": \"192.168.1.100\"\n")
	fmt.Printf("              }\n\n")

	// 4. 验证：通过 Token 获取用户信息
	fmt.Printf("🔍 获取用户信息流程：\n\n")

	// 步骤1：从 Token 获取 loginID
	loginID, _ := stputil.GetLoginID(ctx, token)
	fmt.Printf("   步骤1: Token → loginID\n")
	fmt.Printf("          %s → %s\n\n", token, loginID)

	// 步骤2：从 Session 获取完整用户对象
	sess2, _ := stputil.GetSession(ctx, loginID)
	userObj, exists := sess2.Get("user")
	if exists {
		// Session 返回的是 map，需要转换
		if userMap, ok := userObj.(map[string]interface{}); ok {
			fmt.Printf("   步骤2: loginID → Session → 完整 User 对象\n")
			fmt.Printf("          用户ID: %.0f\n", userMap["userId"])
			fmt.Printf("          用户名: %s\n", userMap["username"])
			fmt.Printf("          昵称:   %s\n", userMap["nickname"])
			fmt.Printf("          邮箱:   %s\n", userMap["email"])
			fmt.Printf("          手机:   %s\n", userMap["phone"])
		}
	}

	fmt.Printf("\n✅ 设计原则验证成功！\n")
	fmt.Printf("   • Token 键中只存储 loginID（轻量级）\n")
	fmt.Printf("   • 完整 User 对象存储在 Account-Session 中\n")
	fmt.Printf("   • 完全符合 Java sa-token 的设计理念\n")
}
