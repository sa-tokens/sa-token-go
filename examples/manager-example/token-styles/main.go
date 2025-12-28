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

func main() {
	fmt.Println("Sa-Token-Go Token Styles Demo")
	fmt.Println("========================================\n")

	// Demo all token styles
	// 演示所有 Token 风格
	demoTokenStyle(adapter.TokenStyleUUID, "UUID Style")
	demoTokenStyle(adapter.TokenStyleSimple, "Simple Style")
	demoTokenStyle(adapter.TokenStyleRandom32, "Random32 Style")
	demoTokenStyle(adapter.TokenStyleRandom64, "Random64 Style")
	demoTokenStyle(adapter.TokenStyleRandom128, "Random128 Style")
	demoTokenStyle(adapter.TokenStyleJWT, "JWT Style")
	demoTokenStyle(adapter.TokenStyleHash, "Hash Style (SHA256)")
	demoTokenStyle(adapter.TokenStyleTimestamp, "Timestamp Style")
	demoTokenStyle(adapter.TokenStyleTik, "Tik Style (Short ID)")

	fmt.Println("\n========================================")
	fmt.Println("✅ All token styles demonstrated!")
}

func demoTokenStyle(style adapter.TokenStyle, name string) {
	fmt.Printf("📌 %s (%s)\n", name, style)
	fmt.Println("----------------------------------------")

	// Initialize manager with specific token style
	// 使用特定 Token 风格初始化管理器
	mgr := builder.NewBuilder().
		SetStorage(memory.NewStorage()).
		TokenStyle(style).
		Timeout(3600).
		MaxRefresh(1800).
		JwtSecretKey("my-secret-key-123"). // For JWT style | 用于JWT风格
		IsPrintBanner(false).
		Build()

	stputil.SetManager(mgr)

	ctx := context.Background()

	// Generate 3 tokens to show variety
	// 生成3个Token展示多样性
	for i := 1; i <= 3; i++ {
		loginID := fmt.Sprintf("user%d", 1000+i)
		token, err := stputil.Login(ctx, loginID)
		if err != nil {
			fmt.Printf("  ❌ Error generating token: %v\n", err)
			continue
		}
		fmt.Printf("  %d. Token for %s:\n     %s\n", i, loginID, token)
	}

	// Add spacing
	fmt.Println()
	time.Sleep(10 * time.Millisecond) // Small delay to show timestamp difference
}
