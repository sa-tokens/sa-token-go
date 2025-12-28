# 注解装饰器示例

本示例演示如何在 Gin 框架中使用 Sa-Token-Go 的中间件装饰器（类似 Java 的 `@SaCheckLogin`、`@SaCheckRole` 等）。

## 运行示例

```bash
go run main.go
```

服务器将在 `http://localhost:8080` 启动。

## 中间件装饰器

Sa-Token-Go 提供了类似 Java 注解的中间件函数：

### CheckLoginMiddleware - 检查登录

```go
r.GET("/user/info", sagin.CheckLoginMiddleware(), handler.GetUserInfo)
```

### CheckRoleMiddleware - 检查角色

```go
r.GET("/manager", sagin.CheckRoleMiddleware("admin"), handler.GetManagerData)
```

### CheckPermissionMiddleware - 检查权限

```go
// 单个权限
r.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), handler.GetAdminData)

// 多个权限（OR 逻辑）
r.GET("/user-or-admin",
    sagin.CheckPermissionMiddleware("user:read", "admin:*"),
    handler.GetUserOrAdmin)
```

### CheckDisableMiddleware - 检查是否被封禁

```go
r.GET("/sensitive", sagin.CheckDisableMiddleware(), handler.GetSensitiveData)
```

### IgnoreMiddleware - 忽略认证

```go
r.GET("/public", sagin.IgnoreMiddleware(), handler.GetPublic)
```

## 完整示例

```go
package main

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    sagin "github.com/click33/sa-token-go/integrations/gin"
)

func init() {
    // 初始化 Manager
    sagin.SetManager(
        sagin.NewDefaultBuild().Build(),
    )
}

// 处理器结构体
type UserHandler struct{}

// 公开访问 - 忽略认证
func (h *UserHandler) GetPublic(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "message": "这是公开接口，不需要登录",
    })
}

// 需要登录
func (h *UserHandler) GetUserInfo(c *gin.Context) {
    loginID, _ := sagin.GetLoginIDFromRequest(c)
    c.JSON(http.StatusOK, gin.H{
        "message": "用户个人信息",
        "loginId": loginID,
    })
}

// 需要管理员权限
func (h *UserHandler) GetAdminData(c *gin.Context) {
    loginID, _ := sagin.GetLoginIDFromRequest(c)
    c.JSON(http.StatusOK, gin.H{
        "message": "管理员数据",
        "loginId": loginID,
        "data":    "这是管理员专有的数据",
    })
}

// 登录接口
func loginHandler(c *gin.Context) {
    var req struct {
        UserID int `json:"userId"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
        return
    }

    ctx := c.Request.Context()

    // 登录
    token, err := sagin.Login(ctx, req.UserID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "登录失败"})
        return
    }

    // 设置权限和角色（模拟）
    if req.UserID == 1 {
        _ = sagin.SetPermissions(ctx, req.UserID, []string{"user:read", "user:write", "admin:*"})
        _ = sagin.SetRoles(ctx, req.UserID, []string{"admin", "manager"})
    } else {
        _ = sagin.SetPermissions(ctx, req.UserID, []string{"user:read", "user:write"})
        _ = sagin.SetRoles(ctx, req.UserID, []string{"user"})
    }

    c.JSON(http.StatusOK, gin.H{
        "token":   token,
        "message": "登录成功",
    })
}

// 封禁账号接口
func disableHandler(c *gin.Context) {
    var req struct {
        UserID int `json:"userId"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
        return
    }

    ctx := c.Request.Context()

    // 封禁账号1小时
    _ = sagin.Disable(ctx, req.UserID, 1*time.Hour)

    c.JSON(http.StatusOK, gin.H{
        "message": "账号已封禁1小时",
    })
}

func main() {
    r := gin.Default()

    // 登录接口（公开）
    r.POST("/login", loginHandler)

    // 封禁接口（需要管理员权限）
    r.POST("/disable", sagin.CheckPermissionMiddleware("admin:*"), disableHandler)

    // 使用装饰器模式设置路由
    handler := &UserHandler{}

    // 公开访问 - 忽略认证
    r.GET("/public", sagin.IgnoreMiddleware(), handler.GetPublic)

    // 需要登录
    r.GET("/user/info", sagin.CheckLoginMiddleware(), handler.GetUserInfo)

    // 需要管理员权限
    r.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), handler.GetAdminData)

    // 需要用户权限或管理员权限（OR逻辑）
    r.GET("/user-or-admin",
        sagin.CheckPermissionMiddleware("user:read", "admin:*"),
        handler.GetUserOrAdmin)

    // 需要管理员角色
    r.GET("/manager", sagin.CheckRoleMiddleware("admin"), handler.GetManagerData)

    // 检查账号是否被封禁
    r.GET("/sensitive", sagin.CheckDisableMiddleware(), handler.GetSensitiveData)

    // 启动服务器
    _ = r.Run(":8080")
}
```

## API 测试

### 1. 登录（用户ID=1 获得管理员权限）

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"userId": 1}'
```

响应：
```json
{
  "token": "YOUR_TOKEN",
  "message": "登录成功"
}
```

### 2. 登录（普通用户）

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"userId": 2}'
```

### 3. 访问公开接口（无需登录）

```bash
curl http://localhost:8080/public
```

响应：
```json
{
  "message": "这是公开接口，不需要登录"
}
```

### 4. 访问需要登录的接口

```bash
curl http://localhost:8080/user/info \
  -H "Authorization: YOUR_TOKEN"
```

响应：
```json
{
  "message": "用户个人信息",
  "loginId": "1"
}
```

### 5. 访问需要管理员权限的接口

```bash
curl http://localhost:8080/admin \
  -H "Authorization: YOUR_TOKEN"
```

响应（管理员）：
```json
{
  "message": "管理员数据",
  "loginId": "1",
  "data": "这是管理员专有的数据"
}
```

### 6. 访问需要角色的接口

```bash
curl http://localhost:8080/manager \
  -H "Authorization: YOUR_TOKEN"
```

### 7. 封禁账号（需要管理员权限）

```bash
curl -X POST http://localhost:8080/disable \
  -H "Content-Type: application/json" \
  -H "Authorization: YOUR_TOKEN" \
  -d '{"userId": 2}'
```

响应：
```json
{
  "message": "账号已封禁1小时"
}
```

### 8. 访问敏感数据（检查封禁状态）

```bash
curl http://localhost:8080/sensitive \
  -H "Authorization: YOUR_TOKEN"
```

## 注解对比

### Java (Sa-Token)

```java
@SaCheckLogin
@GetMapping("/user/info")
public Result getUserInfo() {
    return Result.success();
}

@SaCheckRole("admin")
@GetMapping("/admin")
public Result getAdminData() {
    return Result.success();
}

@SaCheckPermission("admin:*")
@GetMapping("/admin/data")
public Result getAdminOnlyData() {
    return Result.success();
}
```

### Go (Sa-Token-Go)

```go
r.GET("/user/info", sagin.CheckLoginMiddleware(), handler.GetUserInfo)

r.GET("/admin", sagin.CheckRoleMiddleware("admin"), handler.GetAdminData)

r.GET("/admin/data", sagin.CheckPermissionMiddleware("admin:*"), handler.GetAdminOnlyData)
```

## 中间件说明

| 中间件 | 说明 | 对应 Java 注解 |
|--------|------|----------------|
| `CheckLoginMiddleware()` | 检查是否已登录 | `@SaCheckLogin` |
| `CheckRoleMiddleware(roles...)` | 检查是否拥有指定角色 | `@SaCheckRole` |
| `CheckPermissionMiddleware(perms...)` | 检查是否拥有指定权限 | `@SaCheckPermission` |
| `CheckDisableMiddleware()` | 检查账号是否被封禁 | `@SaCheckDisable` |
| `IgnoreMiddleware()` | 忽略认证检查 | `@SaIgnore` |

## 优势

- **声明式编程** - 代码更简洁、可读性更强
- **统一验证** - 自动处理认证和授权逻辑
- **错误处理** - 自动返回标准错误响应
- **灵活组合** - 可以组合使用多个中间件
- **权限模式** - 支持通配符权限匹配（如 `admin:*`）

## 权限说明

本示例中的权限分配：

| 用户 ID | 权限 | 角色 |
|---------|------|------|
| 1 | `user:read`, `user:write`, `admin:*` | `admin`, `manager` |
| 其他 | `user:read`, `user:write` | `user` |

## 更多示例

- [快速开始](../../quick-start/simple-example) - 学习基础用法
- [Gin 集成](../../gin/gin-example) - 完整的 Gin 集成示例
