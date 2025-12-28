# 快速开始示例

这是一个最简单的 Sa-Token-Go 使用示例，展示了如何使用 `stputil` 全局工具类快速实现认证和授权功能。

## 运行示例

```bash
go run main.go
```

## 示例说明

本示例展示了以下功能：

1. **一行初始化** - 使用 Builder 模式快速配置
2. **登录认证** - 支持多种类型的用户 ID（int、string 等）
3. **检查登录** - 验证用户登录状态
4. **权限管理** - 设置和检查用户权限（支持通配符）
5. **角色管理** - 设置和检查用户角色
6. **Session 管理** - 存储和读取会话数据
7. **账号封禁** - 临时封禁和解封用户
8. **Token 信息** - 查看 Token 详细信息
9. **登出** - 清除用户登录状态

## 核心代码

```go
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
    // 一行初始化
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
    ctx := context.Background()

    // 登录
    token, _ := stputil.Login(ctx, 1000)
    fmt.Println("Token:", token)

    // 检查登录
    isLogin := stputil.IsLogin(ctx, token)
    fmt.Println("是否登录:", isLogin)

    // 获取登录ID
    loginID, _ := stputil.GetLoginID(ctx, token)
    fmt.Println("登录ID:", loginID)

    // 设置权限
    _ = stputil.SetPermissions(ctx, 1000, []string{"user:read", "user:write", "admin:*"})

    // 检查权限（支持通配符匹配）
    hasPermission := stputil.HasPermission(ctx, 1000, "user:read")
    hasAdminPerm := stputil.HasPermission(ctx, 1000, "admin:delete") // admin:* 匹配
    fmt.Println("有 user:read 权限:", hasPermission)
    fmt.Println("有 admin:delete 权限:", hasAdminPerm)

    // 设置角色
    _ = stputil.SetRoles(ctx, 1000, []string{"admin", "manager"})

    // 检查角色
    hasRole := stputil.HasRole(ctx, 1000, "admin")
    fmt.Println("有 admin 角色:", hasRole)

    // Session 管理
    sess, _ := stputil.GetSession(ctx, 1000)
    _ = sess.Set(ctx, "nickname", "张三")
    fmt.Println("昵称:", sess.GetString("nickname"))

    // 账号封禁
    _ = stputil.Disable(ctx, 1000, 1*time.Hour)
    fmt.Println("是否被封禁:", stputil.IsDisable(ctx, 1000))

    // 解封
    _ = stputil.Untie(ctx, 1000)

    // 登出
    _ = stputil.Logout(ctx, 1000)
    fmt.Println("登出后是否登录:", stputil.IsLogin(ctx, token))
}
```

## 重要说明

### Context 参数

所有 `stputil` 函数都需要 `context.Context` 作为第一个参数：

```go
ctx := context.Background()

// 正确用法
token, _ := stputil.Login(ctx, userID)
isLogin := stputil.IsLogin(ctx, token)
_ = stputil.Logout(ctx, userID)
```

### 权限通配符

支持使用 `*` 作为通配符匹配权限：

```go
// 设置权限
_ = stputil.SetPermissions(ctx, userID, []string{"admin:*"})

// admin:* 可以匹配所有 admin: 开头的权限
stputil.HasPermission(ctx, userID, "admin:read")   // true
stputil.HasPermission(ctx, userID, "admin:write")  // true
stputil.HasPermission(ctx, userID, "admin:delete") // true
stputil.HasPermission(ctx, userID, "user:read")    // false
```

## 输出示例

```
=== Sa-Token-Go 简洁使用示例 ===

1. 登录测试
   用户1000登录成功，Token: a1b2c3d4-e5f6-7890-abcd-ef1234567890
   用户user123登录成功，Token: b2c3d4e5-f6a7-8901-bcde-f12345678901

2. 检查登录
   Token1是否登录: true
   Token2是否登录: true

3. 获取登录ID
   Token1的登录ID: 1000
   Token2的登录ID: user123

4. 权限管理
   已设置权限: user:read, user:write, admin:*
   是否有user:read权限: true
   是否有user:delete权限: false
   是否有admin:delete权限(通配符): true

5. 角色管理
   已设置角色: admin, manager
   是否有admin角色: true
   是否有user角色: false

6. Session管理
   Session已设置: nickname=张三, age=25

7. 账号封禁
   用户user123已被封禁1小时
   是否被封禁: true
   剩余封禁时间: 3600秒
   已解封，是否被封禁: false

8. Token信息
   登录ID: 1000
   设备: default
   创建时间: 1703750400
   活跃时间: 1703750400

9. 登出
   用户1000已登出
   Token1是否还有效: false

=== 示例完成！ ===
```

## 常用函数速查

| 函数 | 说明 |
|------|------|
| `stputil.Login(ctx, loginID)` | 用户登录，返回 Token |
| `stputil.Logout(ctx, loginID)` | 用户登出 |
| `stputil.IsLogin(ctx, token)` | 检查是否已登录 |
| `stputil.GetLoginID(ctx, token)` | 获取登录ID |
| `stputil.SetPermissions(ctx, loginID, perms)` | 设置权限 |
| `stputil.HasPermission(ctx, loginID, perm)` | 检查权限 |
| `stputil.SetRoles(ctx, loginID, roles)` | 设置角色 |
| `stputil.HasRole(ctx, loginID, role)` | 检查角色 |
| `stputil.GetSession(ctx, loginID)` | 获取 Session |
| `stputil.Disable(ctx, loginID, duration)` | 封禁账号 |
| `stputil.Untie(ctx, loginID)` | 解封账号 |
| `stputil.Kickout(ctx, loginID)` | 踢人下线 |

## 扩展学习

- [Gin 集成示例](../../gin/gin-example) - 学习如何在 Gin 框架中使用
- [注解装饰器示例](../../annotation/annotation-example) - 学习中间件装饰器
- [事件监听示例](../../manager/listener-example) - 学习事件监听机制
