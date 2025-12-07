package banner

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/click33/sa-token-go/core/config"
)

// Version version number | 版本号 (此配置项需与satoken中的同步)
const Version = "0.1.3"

// Banner startup banner | 启动横幅
const Banner = `
   _____         ______      __                  ______     
  / ___/____ _  /_  __/___  / /_____  ____      / ____/____ 
  \__ \/ __  |   / / / __ \/ //_/ _ \/ __ \_____/ / __/ __ \
 ___/ / /_/ /   / / / /_/ / ,< /  __/ / / /_____/ /_/ / /_/ /
/____/\__,_/   /_/  \____/_/|_|\___/_/ /_/      \____/\____/ 
                                                             
:: Sa-Token-Go ::                                 v%s
`

const (
	boxWidth      = 57
	labelWidth    = 16
	neverExpire   = "Never Expire"
	noLimit       = "No Limit"
	configured    = "*** (configured)"
	secondsFormat = "%d seconds"
)

// Print prints startup banner | 打印启动横幅
func Print() {
	fmt.Printf(Banner, Version)
	fmt.Printf(":: Go Version ::                                 %s\n", runtime.Version())
	fmt.Printf(":: GOOS/GOARCH ::                                %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
}

// formatConfigLine formats configuration line with alignment and truncation | 格式化配置行（自动截断过长文本并保持对齐）
func formatConfigLine(label string, value any) string {
	if len(label) > labelWidth {
		label = label[:labelWidth-3] + "..."
	}
	valueStr := fmt.Sprintf("%v", value)

	valueWidth := boxWidth - labelWidth - 4 // 57 - 16 - 4 = 37
	if len(valueStr) > valueWidth {
		valueStr = valueStr[:valueWidth-3] + "..."
	}

	return fmt.Sprintf("│ %-*s: %-*s │\n", labelWidth, label, valueWidth, valueStr)
}

// formatTimeout formats timeout value (seconds or special text) | 格式化超时时间值
func formatTimeout(seconds int64) string {
	if seconds > 0 {
		if seconds >= 86400 {
			days := seconds / 86400
			return fmt.Sprintf("%d seconds (%d days)", seconds, days)
		}
		return fmt.Sprintf(secondsFormat, seconds)
	} else if seconds == 0 {
		return neverExpire
	}
	return noLimit
}

// formatCount formats count value (number or "No Limit") | 格式化数量值
func formatCount(count int64) string {
	if count > 0 {
		return fmt.Sprintf("%d", count)
	}
	return noLimit
}

// tokenReadSources returns a compact summary of token read sources | 返回 Token 读取来源的紧凑摘要
func tokenReadSources(cfg *config.Config) string {
	var parts []string
	if cfg.IsReadHeader {
		parts = append(parts, "Header")
	}
	if cfg.IsReadCookie {
		parts = append(parts, "Cookie")
	}
	if cfg.IsReadBody {
		parts = append(parts, "Body")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}

// PrintWithConfig prints startup banner with essential configuration | 打印启动横幅和核心配置信息
func PrintWithConfig(cfg *config.Config) {
	Print()

	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│                   Configuration                         │")
	fmt.Println("├─────────────────────────────────────────────────────────┤")

	// Basic Token Settings | Token 基础设置
	fmt.Print(formatConfigLine("Token Name", cfg.TokenName))
	fmt.Print(formatConfigLine("Token Style", cfg.TokenStyle))
	fmt.Print(formatConfigLine("Key Prefix", cfg.KeyPrefix))
	fmt.Print(formatConfigLine("AuthType", cfg.AuthType))

	// Login Control | 登录控制
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Print(formatConfigLine("Concurrent Login", cfg.IsConcurrent))
	fmt.Print(formatConfigLine("Share Token", cfg.IsShare))
	fmt.Print(formatConfigLine("Max Login Count", formatCount(cfg.MaxLoginCount)))

	// Timeout & Activity | 超时与活跃控制
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Print(formatConfigLine("Token Timeout", formatTimeout(cfg.Timeout)))
	fmt.Print(formatConfigLine("Active Timeout", formatTimeout(cfg.ActiveTimeout)))

	// Renewal & Refresh Strategy | 续期与刷新策略
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Print(formatConfigLine("Auto Renew", cfg.AutoRenew))
	fmt.Print(formatConfigLine("Max Refresh", formatTimeout(cfg.MaxRefresh)))
	fmt.Print(formatConfigLine("Renew Interval", formatTimeout(cfg.RenewInterval)))

	// Token Read Sources (compact) | Token 读取来源（紧凑显示）
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	fmt.Print(formatConfigLine("Read From", tokenReadSources(cfg)))

	// Security & Storage | 安全与存储
	fmt.Println("├─────────────────────────────────────────────────────────┤")
	if cfg.TokenStyle == "jwt" || cfg.TokenStyle == "JWT" {
		fmt.Print(formatConfigLine("JWT Secret Key", configured))
	} else {
		fmt.Print(formatConfigLine("JWT Secret Key", "(not used)"))
	}

	fmt.Println("└─────────────────────────────────────────────────────────┘")
	fmt.Println()
}
