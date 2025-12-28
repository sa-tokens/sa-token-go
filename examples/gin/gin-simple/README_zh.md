# Gin 简单示例 - 只需导入一个包

此示例演示如何通过 **只导入 `integrations/gin` 包** 来使用 Sa-Token-Go 与 Gin。

## 特性

- **单一导入** - 只需要 `github.com/click33/sa-token-go/integrations/gin`
- **完整功能** - 访问所有 core 和 stputil 的功能
- **简洁 API** - 干净易用
- **Context 支持** - 所有函数都支持 `context.Context`

## 快速开始

### 1. 安装依赖

```bash
go get github.com/click33/sa-token-go/integrations/gin
go get github.com/gin-gonic/gin
```

### 2. 运行示例

```bash
cd examples/gin/gin-simple
go run main.go
```

### 3. 测试 API

**登录：**
```bash
curl -X POST http://localhost:8080/login -d 'user_id=1000'
# 响应: {"message":"登录成功","token":"xxx"}
```

**检查登录状态：**
```bash
curl -H "token: YOUR_TOKEN" http://localhost:8080/check
# 响应: {"login_id":"1000","message":"已登录"}
```

**访问受保护的 API：**
```bash
curl -H "token: YOUR_TOKEN" http://localhost:8080/api/user
# 响应: {"name":"User 1000","user_id":"1000"}
```

**登出：**
```bash
curl -X POST -H "token: YOUR_TOKEN" http://localhost:8080/logout
# 响应: {"message":"登出成功"}
```

**踢人下线：**
```bash
curl -X POST -H "token: YOUR_TOKEN" http://localhost:8080/api/kickout/1000
# 响应: {"message":"踢人成功"}
```

## 代码示例

```go
package main

import (
    "log"

    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/gin-gonic/gin"
)

func main() {
    // 创建 Builder 并构建 Manager
    mgr := sagin.NewDefaultBuild().
        TokenName("token").
        Timeout(7200).
        IsPrintBanner(true).
        Build()

    // 设置全局管理器
    sagin.SetManager(mgr)

    // 创建路由
    r := gin.Default()

    // 登录接口
    r.POST("/login", func(c *gin.Context) {
        userID := c.PostForm("user_id")
        ctx := c.Request.Context()

        token, err := sagin.Login(ctx, userID)
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }

        c.JSON(200, gin.H{
            "message": "登录成功",
            "token":   token,
        })
    })

    // 受保护的路由
    protected := r.Group("/api")
    protected.Use(sagin.CheckLoginMiddleware())
    {
        protected.GET("/user", func(c *gin.Context) {
            loginID, _ := sagin.GetLoginIDFromRequest(c)
            c.JSON(200, gin.H{"user_id": loginID})
        })
    }

    r.Run(":8080")
}
```

## 可用函数

所有 `stputil` 的函数都在 `sagin` 中重新导出，并支持 `context.Context`：

### 认证相关

```go
sagin.Login(ctx, loginID, device...)         // 登录
sagin.Logout(ctx, loginID, device...)        // 登出
sagin.LogoutByToken(ctx, token)              // 根据Token登出
sagin.IsLogin(ctx, token)                    // 检查登录状态
sagin.CheckLogin(ctx, token)                 // 检查登录（抛出错误）
sagin.GetLoginID(ctx, token)                 // 从Token获取登录ID
sagin.GetLoginIDFromRequest(c)               // 从Gin上下文获取登录ID
```

### 踢人下线 & 封禁

```go
sagin.Kickout(ctx, loginID, device...)       // 踢人下线
sagin.KickoutByToken(ctx, token)             // 根据Token踢人下线
sagin.Disable(ctx, loginID, duration)        // 封禁账号
sagin.IsDisable(ctx, loginID)                // 检查是否被封禁
sagin.Untie(ctx, loginID)                    // 解封账号
```

### 权限 & 角色

```go
sagin.SetPermissions(ctx, loginID, perms)    // 设置权限
sagin.SetRoles(ctx, loginID, roles)          // 设置角色
sagin.HasPermission(ctx, loginID, perm)      // 检查权限
sagin.HasRole(ctx, loginID, role)            // 检查角色
sagin.GetPermissions(ctx, loginID)           // 获取权限列表
sagin.GetRoles(ctx, loginID)                 // 获取角色列表
```

### Session 管理

```go
sagin.GetSession(ctx, loginID)               // 获取Session
sagin.GetSessionByToken(ctx, token)          // 根据Token获取Session
sagin.HasSession(ctx, loginID)               // 检查Session是否存在
```

### 安全特性

```go
sagin.Generate(ctx)                          // 生成随机数
sagin.Verify(ctx, nonce)                     // 验证随机数
sagin.GenerateTokenPair(ctx, loginID)        // 生成访问令牌和刷新令牌
sagin.RefreshAccessToken(ctx, refreshToken)  // 刷新访问令牌
```

### Builder & Config

```go
sagin.NewDefaultBuild()                      // 创建默认构建器
sagin.NewDefaultConfig()                     // 创建默认配置
sagin.SetManager(mgr)                        // 设置全局管理器
sagin.GetManager()                           // 获取全局管理器
```

## 中间件函数

| 中间件 | 说明 |
|--------|------|
| `CheckLoginMiddleware()` | 检查是否已登录 |
| `CheckRoleMiddleware(roles...)` | 检查是否拥有指定角色 |
| `CheckPermissionMiddleware(perms...)` | 检查是否拥有指定权限 |
| `CheckDisableMiddleware()` | 检查账号是否被封禁 |
| `IgnoreMiddleware()` | 忽略认证检查 |

## 优势

1. **更简单的依赖** - 只需要一个导入
2. **更清晰的代码** - 更少的导入语句
3. **框架专用** - 为 Gin 优化
4. **Context 支持** - 所有函数都支持 `context.Context`

## 了解更多

- [主文档](../../../README_zh.md)
- [Gin 示例](../gin-example) - 更完整的示例
- [注解示例](../../annotation/annotation-example) - 中间件用法
