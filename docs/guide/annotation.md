# Annotation Usage Guide

[中文文档](annotation_zh.md) | English

## Overview

Sa-Token-Go provides annotation-like decorators for Gin framework, similar to Java's `@SaCheckLogin`, `@SaCheckRole` annotations.

## Available Annotations

- `@CheckLogin` - Check if user is logged in
- `@CheckRole` - Check if user has specified role
- `@CheckPermission` - Check if user has specified permission
- `@CheckDisable` - Check if account is disabled
- `@Ignore` - Ignore authentication

## Basic Usage

### CheckLogin

```go
import sagin "github.com/click33/sa-token-go/integrations/gin"

r := gin.Default()

// Requires login
r.GET("/user/info", sagin.CheckLogin(), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "User info"})
})
```

### CheckRole

```go
// Requires admin role
r.GET("/admin", sagin.CheckRole("admin"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Admin page"})
})

// Requires any of the roles
r.GET("/dashboard", sagin.CheckRole("admin", "manager-example"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Dashboard"})
})
```

### CheckPermission

```go
// Requires permission
r.GET("/users", sagin.CheckPermission("user:read"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "User list"})
})

// Requires any of the permissions
r.DELETE("/user/:id", sagin.CheckPermission("user:delete", "admin:*"), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "User deleted"})
})
```

### CheckDisable

```go
// Check if account is disabled
r.GET("/profile", sagin.CheckDisable(), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Profile"})
})
```

### Ignore

```go
// Ignore authentication
r.GET("/public", sagin.Ignore(), func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "Public page"})
})
```

## Complete Example

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/memory"
    sagin "github.com/click33/sa-token-go/integrations/gin"
)

func main() {
    // Initialize
    stputil.SetManager(
        core.NewBuilder().
            Storage(memory.NewStorage()).
            Build(),
    )

    r := gin.Default()

    // Public routes (no authentication)
    r.GET("/", sagin.Ignore(), indexHandler)
    r.POST("/login", loginHandler)

    // Login required
    r.GET("/user/info", sagin.CheckLogin(), userInfoHandler)

    // Role required
    r.GET("/admin", sagin.CheckRole("admin"), adminHandler)
    r.GET("/manager-example", sagin.CheckRole("admin", "manager-example"), managerHandler)

    // Permission required
    r.GET("/users", sagin.CheckPermission("user:read"), listUsersHandler)
    r.POST("/users", sagin.CheckPermission("user:create"), createUserHandler)
    r.DELETE("/users/:id", sagin.CheckPermission("user:delete"), deleteUserHandler)

    // Check disable
    r.GET("/profile", sagin.CheckDisable(), profileHandler)

    r.Run(":8080")
}
```

## Gin Integration

Annotations are currently only supported for Gin framework. For other frameworks (Echo, Fiber, Chi), use middleware instead:

```go
// Echo example
import saecho "github.com/click33/sa-token-go/integrations/echo"

e.GET("/user/info", userInfoHandler, saecho.NewPlugin(manager).AuthMiddleware())
```

## Related Documentation

- [Quick Start](../tutorial/quick-start.md)
- [Authentication Guide](authentication.md)
- [Permission Management](permission.md)
