# Gin 框架集成示例

本示例演示如何在 Gin 框架中使用 Sa-Token-Go。

## 快速开始

### 安装依赖

```bash
go mod download
```

### 运行示例

```bash
go run cmd/main.go
```

服务器将在 `http://localhost:8080` 启动。

## 使用方式

### 方式一：使用 Builder 构建器（推荐）

```go
package main

import (
    "github.com/gin-gonic/gin"
    sagin "github.com/click33/sa-token-go/integrations/gin"
)

func main() {
    // 使用 Builder 创建 Manager
    mgr := sagin.NewDefaultBuild().
        TokenName("Authorization").
        Timeout(7200).
        IsPrintBanner(true).
        Build()

    // 设置全局 Manager
    sagin.SetManager(mgr)

    // 设置路由
    r := gin.Default()

    // 登录接口
    r.POST("/login", func(c *gin.Context) {
        var req struct {
            UserID string `json:"userId"`
        }
        c.ShouldBindJSON(&req)

        ctx := c.Request.Context()
        token, _ := sagin.Login(ctx, req.UserID)
        c.JSON(200, gin.H{"token": token})
    })

    // 需要登录的接口
    r.GET("/user", sagin.CheckLoginMiddleware(), func(c *gin.Context) {
        loginID, _ := sagin.GetLoginIDFromRequest(c)
        c.JSON(200, gin.H{
            "loginId": loginID,
            "message": "用户信息",
        })
    })

    // 需要权限的接口
    r.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "管理员数据"})
    })

    r.Run(":8080")
}
```

### 方式二：使用路由组

```go
package main

import (
    "github.com/gin-gonic/gin"
    sagin "github.com/click33/sa-token-go/integrations/gin"
)

func main() {
    // 初始化 Manager
    mgr := sagin.NewDefaultBuild().Build()
    sagin.SetManager(mgr)

    r := gin.Default()

    // 公开接口
    r.POST("/login", loginHandler)

    // 受保护的路由组
    protected := r.Group("/api")
    protected.Use(sagin.CheckLoginMiddleware())
    {
        protected.GET("/user", userHandler)
        protected.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), adminHandler)
    }

    r.Run(":8080")
}
```

## API 端点

### 公开接口

- `POST /login` - 用户登录
  ```bash
  curl -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"userId":"1000"}'
  ```

  响应：
  ```json
  {
    "message": "登录成功",
    "token": "YOUR_TOKEN"
  }
  ```

- `GET /public` - 公开访问
  ```bash
  curl http://localhost:8080/public
  ```

### 受保护接口

- `GET /api/user` - 获取用户信息（需要登录）
  ```bash
  curl http://localhost:8080/api/user \
    -H "Authorization: YOUR_TOKEN"
  ```

  响应：
  ```json
  {
    "message": "用户信息",
    "loginId": "1000"
  }
  ```

- `GET /api/admin` - 管理员接口（需要管理员权限）
  ```bash
  curl http://localhost:8080/api/admin \
    -H "Authorization: YOUR_TOKEN"
  ```

## 中间件说明

| 中间件 | 说明 |
|--------|------|
| `CheckLoginMiddleware()` | 检查是否已登录 |
| `CheckRoleMiddleware(roles...)` | 检查是否拥有指定角色 |
| `CheckPermissionMiddleware(perms...)` | 检查是否拥有指定权限 |
| `CheckDisableMiddleware()` | 检查账号是否被封禁 |
| `IgnoreMiddleware()` | 忽略认证检查 |

## 常用函数

### 认证相关

```go
// 登录（需要 context）
token, err := sagin.Login(ctx, userID)

// 登出
err := sagin.Logout(ctx, userID)
err := sagin.LogoutByToken(ctx, token)

// 检查登录状态
isLogin := sagin.IsLogin(ctx, token)

// 获取登录ID
loginID, err := sagin.GetLoginID(ctx, token)

// 从请求中获取登录ID（Gin 专用）
loginID, err := sagin.GetLoginIDFromRequest(c)
```

### 权限和角色

```go
// 设置权限
err := sagin.SetPermissions(ctx, userID, []string{"user:read", "admin:*"})

// 设置角色
err := sagin.SetRoles(ctx, userID, []string{"admin", "user"})

// 检查权限
hasPermission := sagin.HasPermission(ctx, userID, "admin:*")

// 检查角色
hasRole := sagin.HasRole(ctx, userID, "admin")
```

### 踢人和封禁

```go
// 踢人下线
err := sagin.Kickout(ctx, userID)

// 封禁账号
err := sagin.Disable(ctx, userID, time.Hour)

// 解封账号
err := sagin.Untie(ctx, userID)
```

## 配置文件

配置文件位于 `configs/config.yaml`：

```yaml
token:
  timeout: 7200        # Token超时时间（秒）
  active_timeout: 1800 # 活跃超时时间（秒）

server:
  port: 8080           # 服务器端口
```

## 更多示例

- [简单示例](../gin-simple) - 最简单的使用方式
- [注解示例](../../annotation/annotation-example) - 中间件装饰器用法
