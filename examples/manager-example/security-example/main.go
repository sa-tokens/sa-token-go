package main

import (
	"context"
	"fmt"
	"time"

	"github.com/click33/sa-token-go/core/security"
	"github.com/click33/sa-token-go/storage/memory"
)

func main() {
	fmt.Println("=== Sa-Token-Go Security Features Demo ===\n")

	ctx := context.Background()
	storage := memory.NewStorage()

	// 1. Nonce 防重放攻击示例
	demoNonceManager(ctx, storage)

	// 2. Refresh Token 示例
	demoRefreshTokenManager(ctx, storage)

	fmt.Println("=== Demo Complete ===")
}

// demoNonceManager 演示 Nonce 防重放攻击功能
func demoNonceManager(ctx context.Context, storage *memory.Storage) {
	fmt.Println("1. Nonce Manager - 防重放攻击")
	fmt.Println("----------------------------------------")

	// 创建 Nonce 管理器
	// 参数：authType, prefix, storage, ttl
	nonceManager := security.NewNonceManager("login", "sa:", storage, 5*time.Minute)

	// 生成 Nonce
	nonce1, err := nonceManager.Generate(ctx)
	if err != nil {
		fmt.Printf("   [ERROR] 生成 Nonce 失败: %v\n", err)
		return
	}
	fmt.Printf("   [OK] 生成 Nonce: %s\n", nonce1)

	// 检查 Nonce 是否有效（不消费）
	fmt.Printf("   [INFO] Nonce 是否有效（检查）: %v\n", nonceManager.IsValid(ctx, nonce1))

	// 验证并消费 Nonce（第一次）
	result1 := nonceManager.Verify(ctx, nonce1)
	fmt.Printf("   [VERIFY] 第一次验证 Nonce: %v (应该为 true)\n", result1)

	// 验证并消费 Nonce（第二次 - 重放攻击模拟）
	result2 := nonceManager.Verify(ctx, nonce1)
	fmt.Printf("   [BLOCKED] 第二次验证 Nonce: %v (应该为 false - 防止重放)\n", result2)

	// 使用 VerifyAndConsume 方法
	nonce2, _ := nonceManager.Generate(ctx)
	fmt.Printf("\n   [OK] 生成新 Nonce: %s\n", nonce2)
	err = nonceManager.VerifyAndConsume(ctx, nonce2)
	if err != nil {
		fmt.Printf("   [ERROR] VerifyAndConsume 失败: %v\n", err)
	} else {
		fmt.Printf("   [OK] VerifyAndConsume 成功\n")
	}

	// 再次使用已消费的 Nonce
	err = nonceManager.VerifyAndConsume(ctx, nonce2)
	if err != nil {
		fmt.Printf("   [BLOCKED] 重复使用 Nonce 被拒绝: %v\n", err)
	}

	fmt.Println()
}

// demoRefreshTokenManager 演示 Refresh Token 功能
func demoRefreshTokenManager(ctx context.Context, storage *memory.Storage) {
	fmt.Println("2. Refresh Token Manager - 令牌刷新")
	fmt.Println("----------------------------------------")

	// 创建 Refresh Token 管理器
	// 参数：authType, prefix, tokenKeyPrefix, tokenGen, accessTTL, storage, serializer
	rtManager := security.NewRefreshTokenManager(
		"login",     // authType
		"sa:",       // prefix
		"token:",    // tokenKeyPrefix
		nil,         // tokenGen (nil 使用默认)
		2*time.Hour, // accessTTL
		storage,     // storage
		nil,         // serializer (nil 使用默认 JSON)
	)

	// 生成令牌对（Access Token + Refresh Token）
	userID := "user1001"
	device := "web"

	tokenPair, err := rtManager.GenerateTokenPair(ctx, userID, device)
	if err != nil {
		fmt.Printf("   [ERROR] 生成令牌对失败: %v\n", err)
		return
	}

	fmt.Printf("   [OK] 生成令牌对成功\n")
	fmt.Printf("   Access Token:  %s\n", tokenPair.AccessToken)
	fmt.Printf("   Refresh Token: %s\n", tokenPair.RefreshToken)
	fmt.Printf("   Login ID:      %s\n", tokenPair.LoginID)
	fmt.Printf("   Device:        %s\n", tokenPair.Device)
	fmt.Printf("   创建时间:      %s\n", time.Unix(tokenPair.CreateTime, 0).Format("2006-01-02 15:04:05"))
	fmt.Printf("   过期时间:      %s\n", time.Unix(tokenPair.ExpireTime, 0).Format("2006-01-02 15:04:05"))

	// 验证 Access Token
	fmt.Printf("\n   [VERIFY] Access Token 是否有效: %v\n", rtManager.VerifyAccessToken(ctx, tokenPair.AccessToken))

	// 获取 Access Token 信息
	accessInfo, valid := rtManager.VerifyAccessTokenAndGetInfo(ctx, tokenPair.AccessToken)
	if valid {
		fmt.Printf("   [INFO] Access Token 信息:\n")
		fmt.Printf("      - LoginID: %s\n", accessInfo.LoginID)
		fmt.Printf("      - Device:  %s\n", accessInfo.Device)
	}

	// 检查 Refresh Token 是否有效
	fmt.Printf("\n   [VERIFY] Refresh Token 是否有效: %v\n", rtManager.IsValid(ctx, tokenPair.RefreshToken))

	// 使用 Refresh Token 刷新 Access Token
	fmt.Println("\n   [REFRESH] 刷新 Access Token...")
	newTokenPair, err := rtManager.RefreshAccessToken(ctx, tokenPair.RefreshToken)
	if err != nil {
		fmt.Printf("   [ERROR] 刷新失败: %v\n", err)
		return
	}

	fmt.Printf("   [OK] 刷新成功\n")
	fmt.Printf("   新 Access Token: %s\n", newTokenPair.AccessToken)
	fmt.Printf("   Refresh Token:   %s (保持不变)\n", newTokenPair.RefreshToken)

	// 验证旧 Access Token 已失效
	fmt.Printf("\n   [VERIFY] 旧 Access Token 是否有效: %v (应该为 false)\n", rtManager.VerifyAccessToken(ctx, tokenPair.AccessToken))
	fmt.Printf("   [VERIFY] 新 Access Token 是否有效: %v (应该为 true)\n", rtManager.VerifyAccessToken(ctx, newTokenPair.AccessToken))

	// 获取 Refresh Token 信息
	refreshInfo, err := rtManager.GetRefreshTokenInfo(ctx, tokenPair.RefreshToken)
	if err == nil {
		fmt.Printf("\n   [INFO] Refresh Token 信息:\n")
		fmt.Printf("      - LoginID:      %s\n", refreshInfo.LoginID)
		fmt.Printf("      - Device:       %s\n", refreshInfo.Device)
		fmt.Printf("      - AccessToken:  %s\n", refreshInfo.AccessToken)
	}

	// 撤销 Refresh Token
	fmt.Println("\n   [REVOKE] 撤销 Refresh Token...")
	err = rtManager.RevokeRefreshToken(ctx, tokenPair.RefreshToken)
	if err != nil {
		fmt.Printf("   [ERROR] 撤销失败: %v\n", err)
	} else {
		fmt.Printf("   [OK] 撤销成功\n")
		fmt.Printf("   [VERIFY] Refresh Token 是否有效: %v (应该为 false)\n", rtManager.IsValid(ctx, tokenPair.RefreshToken))
	}

	fmt.Println()
}
