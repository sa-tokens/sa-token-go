// @Author daixk 2026/1/6 14:36:00
package main

import (
	"context"
	"fmt"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/storage/redis"
	"github.com/click33/sa-token-go/stputil"
	"time"
)

func init() {
	storage, err := redis.NewStorage("redis://:root@192.168.19.104:6379/0?dial_timeout=3&read_timeout=10s&max_retries=2")
	if err != nil {
		panic(err)
	}

	stputil.SetManager(
		builder.NewBuilder().
			// ========== 存储和Token ==========
			SetStorage(storage).                // 设置存储实现（默认内存，可配置Redis或自实现）
			TokenName("satoken").               // Token 名称（也是 Cookie 名称）
			Timeout(300).                       // Token 过期时间（秒）
			MaxRefresh(150).                    // 自动续期触发阈值（秒）
			RenewInterval(config.NoLimit).      // 续期的最小间隔（秒）
			ActiveTimeout(config.NoLimit).      // 最大不活跃时间（秒）
			IsConcurrent(true).                 // 是否允许并发登录
			IsShare(false).                     // 并发登录是否共享 Token
			MaxLoginCount(2).                   // 最大在线 Token 数量
			IsReadBody(false).                  // 是否从请求体读取 Token
			IsReadHeader(true).                 // 是否从 Header 读取 Token
			IsReadCookie(false).                // 是否从 Cookie 读取 Token
			TokenStyle(adapter.TokenStyleUUID). // Token 样式
			TokenSessionCheckLogin(true).       // 登录时是否校验Token会话
			AutoRenew(true).                    // 是否自动续期
			JwtSecretKey("").                   // 设置JWT密钥（JWT模式才生效）
			AuthType("auth").                   // 认证体系类型
			KeyPrefix("satoken").               // 存储键前缀

			// ========== Cookie配置 ==========
			CookieDomain("example.com").        // Cookie域名
			CookiePath("/").                    // Cookie路径
			CookieSecure(false).                // 是否启用Secure
			CookieHttpOnly(true).               // 是否启用HttpOnly
			CookieSameSite(config.SameSiteLax). // SameSite策略
			CookieMaxAge(300).                  // Cookie最大过期时间
			// CookieConfig(&config.CookieConfig{...}). // 可以直接设置完整Cookie配置

			// ========== 日志配置 ==========
			IsLog(true).                             // 是否打印操作日志
			IsPrintBanner(true).                     // 是否打印启动Banner
			LoggerPath("./logs").                    // 日志目录
			LoggerFileFormat("{Y}-{m}-{d}.log").     // 日志文件命名格式
			LoggerPrefix("[satoken]").               // 日志前缀
			LoggerLevel(adapter.LogLevelDebug).      // 最低日志级别
			LoggerTimeFormat("2006-01-02 15:04:05"). // 时间戳格式
			LoggerStdout(true).                      // 是否打印到控制台
			LoggerStdoutOnly(false).                 // 是否只打印到控制台
			LoggerQueueSize(4096).                   // 异步写入队列大小
			LoggerRotateSize(1024 * 1024 * 10).      // 滚动文件大小阈值 10MB
			LoggerRotateExpire(24 * time.Hour).      // 滚动文件时间间隔
			LoggerRotateBackupLimit(30).             // 最大备份文件数量
			LoggerRotateBackupDays(7).               // 备份文件保留天数
			// LoggerConfig(&slog.LoggerConfig{...}).   // 可以直接设置完整日志配置

			// ========== 续期池配置 ==========
			RenewPoolMinSize(10).                           // 最小协程数
			RenewPoolMaxSize(50).                           // 最大协程数
			RenewPoolScaleUpRate(0.7).                      // 扩容阈值
			RenewPoolScaleDownRate(0.3).                    // 缩容阈值
			RenewPoolCheckInterval(5 * time.Second).        // 自动扩缩容检查间隔
			RenewPoolExpiry(60 * time.Second).              // 空闲协程过期时间
			RenewPoolPrintStatusInterval(30 * time.Second). // 状态打印间隔
			RenewPoolPreAlloc(false).                       // 是否预分配内存
			RenewPoolNonBlocking(true).                     // 是否非阻塞模式
			// RenewPoolConfig(&ants.RenewPoolConfig{...}). // 可以直接设置完整续期池配置

			// ========== 自定义适配器 ==========
			// SetGenerator(generator).                  // 自定义Token生成器
			// SetCodec(codec).                          // 自定义编码器
			// SetLog(log).                              // 自定义日志
			// SetPool(pool).                            // 自定义协程池

			// ========== 自定义权限与角色 ==========
			SetCustomPermissionListFunc(func(loginID, authType string) ([]string, error) {
				if loginID == "1" {
					return []string{"admin:read", "admin:update"}, nil
				}
				return []string{"user:read"}, nil
			}).
			SetCustomRoleListFunc(func(loginID, authType string) ([]string, error) {
				if loginID == "1" {
					return []string{"admin", "guanliyuan"}, nil
				}
				return []string{"user"}, nil
			}).

			// ========== JWT模式 ==========
			// Jwt("your-secret-key").                    // 如果需要JWT模式，可直接启用

			Build(), // 构建Manager
	)
}

func main() {
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
}
