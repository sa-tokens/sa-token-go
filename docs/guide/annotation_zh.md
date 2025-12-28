# 注解使用指南

[English](annotation.md) | 中文文档

## 概述

Sa-Token-Go 提供了类似 Java 版 sa-token 的注解功能，使用装饰器模式实现。

## 支持的注解

| 注解 | Java版 | Go版 | 说明 |
|------|--------|------|------|
| 忽略认证 | `@SaIgnore` | `sagin.Ignore()` | 公开访问，不需要登录 |
| 检查登录 | `@SaCheckLogin` | `sagin.CheckLogin()` | 需要登录才能访问 |
| 检查角色 | `@SaCheckRole("admin")` | `sagin.CheckRole("admin")` | 需要指定角色 |
| 检查权限 | `@SaCheckPermission("admin:*")` | `sagin.CheckPermission("admin:*")` | 需要指定权限 |
| 检查封禁 | `@SaCheckDisable` | `sagin.CheckDisable()` | 检查账号是否被封禁 |

## 基础使用

### 1. 忽略认证 - @SaIgnore

```go
// 公开接口，不需要登录
r.GET("/public", sagin.Ignore(), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "公开访问"})
})
```

### 2. 检查登录 - @SaCheckLogin

```go
// 需要登录才能访问
r.GET("/user/info", sagin.CheckLogin(), func(c *gin.Context) {
    token := c.GetHeader("Authorization")
    loginID, _ := stputil.GetLoginID(token)
    
    c.JSON(200, gin.H{"loginId": loginID})
})
```

### 3. 检查权限 - @SaCheckPermission

```go
// 需要admin权限
r.GET("/admin", sagin.CheckPermission("admin"), adminHandler)

// 需要admin:write权限
r.POST("/admin/users", sagin.CheckPermission("admin:write"), createUserHandler)

// 需要admin开头的任意权限
r.DELETE("/admin/users/:id", sagin.CheckPermission("admin:*"), deleteUserHandler)
```

### 4. 检查角色 - @SaCheckRole

```go
// 需要admin角色
r.GET("/manager-example", sagin.CheckRole("admin"), managerHandler)

// 需要manager角色
r.GET("/reports", sagin.CheckRole("manager-example"), reportsHandler)
```

### 5. 检查封禁 - @SaCheckDisable

```go
// 检查账号是否被封禁
r.GET("/sensitive", sagin.CheckDisable(), func(c *gin.Context) {
    // 只有未被封禁的账号才能访问
    c.JSON(200, gin.H{"message": "敏感数据"})
})
```

## 高级用法

### OR逻辑（多权限/角色之一）

```go
// 拥有user:read或admin:read权限即可访问
r.GET("/data", 
    sagin.CheckPermission("user:read", "admin:read"),
    dataHandler)

// 拥有admin或manager角色即可访问
r.GET("/dashboard",
    sagin.CheckRole("admin", "manager-example"),
    dashboardHandler)
```

### 组合使用

```go
// 多个装饰器组合
r.GET("/super-admin",
    sagin.CheckLogin(),           // 先检查登录
    sagin.CheckRole("admin"),     // 再检查角色
    sagin.CheckPermission("super:*"), // 最后检查权限
    superAdminHandler)
```

### 自定义注解

```go
// 创建自定义注解
customAnnotation := &sagin.Annotation{
    CheckPermission: []string{"admin:write", "super:write"},
    CheckRole:       []string{"admin"},
}

r.POST("/custom", sagin.WithAnnotation(customAnnotation), customHandler)
```

## 完整示例

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func init() {
    stputil.SetManager(
        core.NewBuilder().
            Storage(memory.NewStorage()).
            Build(),
    )
}

func main() {
    r := gin.Default()

    // 登录接口（公开）
    r.POST("/login", loginHandler)

    // 公开访问
    r.GET("/public", sagin.Ignore(), publicHandler)

    // 需要登录
    r.GET("/user/info", sagin.CheckLogin(), userInfoHandler)

    // 需要权限
    r.GET("/admin", sagin.CheckPermission("admin:*"), adminHandler)
    r.GET("/users", sagin.CheckPermission("user:read"), listUsersHandler)
    r.POST("/users", sagin.CheckPermission("user:write"), createUserHandler)
    r.DELETE("/users/:id", sagin.CheckPermission("user:delete"), deleteUserHandler)

    // 需要角色
    r.GET("/manager-example", sagin.CheckRole("manager-example"), managerHandler)

    // 检查封禁状态
    r.GET("/sensitive", sagin.CheckDisable(), sensitiveHandler)

    // 组合使用
    r.POST("/super",
        sagin.CheckRole("admin"),
        sagin.CheckPermission("super:*"),
        superHandler)

    r.Run(":8080")
}

func loginHandler(c *gin.Context) {
    var req struct {
        UserID int `json:"userId"`
    }
    c.BindJSON(&req)

    token, _ := stputil.Login(req.UserID)
    
    // 设置权限和角色
    stputil.SetPermissions(req.UserID, []string{"user:read", "user:write"})
    stputil.SetRoles(req.UserID, []string{"admin"})

    c.JSON(200, gin.H{"token": token})
}
```

## 错误响应

当认证/授权失败时，自动返回标准错误响应：

### 未登录 (401)

```json
{
    "code": 401,
    "message": "未登录"
}
```

### 权限不足 (403)

```json
{
    "code": 403,
    "message": "权限不足"
}
```

### 角色不足 (403)

```json
{
    "code": 403,
    "message": "角色不足"
}
```

### 账号已被封禁 (403)

```json
{
    "code": 403,
    "message": "账号已被封禁"
}
```

## 测试示例

```bash
# 1. 登录
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"userId": 1000}'
# 响应: {"token": "xxx"}

# 2. 公开访问
curl http://localhost:8080/public
# 响应: {"message": "公开访问"}

# 3. 需要登录
curl http://localhost:8080/user/info \
  -H "Authorization: <token>"
# 响应: {"loginId": "1000"}

# 4. 需要权限
curl http://localhost:8080/admin \
  -H "Authorization: <token>"
# 响应: {"message": "管理员数据"}

# 5. 权限不足
curl http://localhost:8080/admin \
  -H "Authorization: <invalid-token>"
# 响应: {"code": 403, "message": "权限不足"}
```

## 下一步

- [登录认证](authentication.md)
- [角色管理](role.md)
- [框架集成](gin-integration.md)

