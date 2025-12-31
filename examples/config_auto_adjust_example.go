package main

import (
	"fmt"
	"github.com/click33/sa-token-go/core/config"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("示例 1: 用户只设置 Timeout = 1小时")
	fmt.Println("========================================")

	cfg1 := config.DefaultConfig()
	fmt.Printf("默认 Timeout: %d 秒\n", cfg1.Timeout)
	fmt.Printf("默认 MaxRefresh: %d 秒\n", cfg1.MaxRefresh)

	cfg1.SetTimeout(3600) // 设置为 1小时
	fmt.Printf("\n用户设置 Timeout: %d 秒 (1小时)\n", cfg1.Timeout)
	fmt.Printf("MaxRefresh 仍是: %d 秒 (15天)\n", cfg1.MaxRefresh)

	err := cfg1.Validate()
	if err != nil {
		fmt.Printf("❌ 修改前会报错: %v\n", err)
	} else {
		fmt.Printf("✅ 修改后自动调整成功!\n")
		fmt.Printf("   调整后 MaxRefresh: %d 秒 (30分钟)\n", cfg1.MaxRefresh)
	}

	fmt.Println("\n========================================")
	fmt.Println("示例 2: 用户设置 Timeout = 10秒（极小值）")
	fmt.Println("========================================")

	cfg2 := config.DefaultConfig()
	cfg2.SetTimeout(10)
	fmt.Printf("用户设置 Timeout: %d 秒\n", cfg2.Timeout)

	err = cfg2.Validate()
	if err == nil {
		fmt.Printf("✅ 自动调整成功!\n")
		fmt.Printf("   调整后 MaxRefresh: %d 秒\n", cfg2.MaxRefresh)
		fmt.Printf("   (因为 10/2=5，太小了，所以设为等于 Timeout)\n")
	}

	fmt.Println("\n========================================")
	fmt.Println("示例 3: RenewInterval 自动调整")
	fmt.Println("========================================")

	cfg3 := config.DefaultConfig()
	cfg3.SetTimeout(3600)
	cfg3.SetRenewInterval(5000) // 设置续期间隔为 5000秒

	fmt.Printf("用户设置 Timeout: %d 秒\n", cfg3.Timeout)
	fmt.Printf("用户设置 RenewInterval: %d 秒\n", cfg3.RenewInterval)

	err = cfg3.Validate()
	if err == nil {
		fmt.Printf("✅ 自动调整成功!\n")
		fmt.Printf("   调整后 MaxRefresh: %d 秒 (Timeout/2)\n", cfg3.MaxRefresh)
		fmt.Printf("   调整后 RenewInterval: %d 秒 (MaxRefresh/2)\n", cfg3.RenewInterval)
	}
}
