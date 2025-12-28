# Gin Simple Example - Only Import One Package

This example demonstrates how to use Sa-Token-Go with Gin by **only importing the `integrations/gin` package**.

## Features

- **Single Import** - Only need `github.com/click33/sa-token-go/integrations/gin`
- **All Functions** - Access to all core and stputil functions
- **Simple API** - Clean and easy to use
- **Context Support** - All functions support `context.Context`

## Quick Start

### 1. Install dependencies

```bash
go get github.com/click33/sa-token-go/integrations/gin
go get github.com/gin-gonic/gin
```

### 2. Run the example

```bash
cd examples/gin/gin-simple
go run main.go
```

### 3. Test the API

**Login:**
```bash
curl -X POST http://localhost:8080/login -d 'user_id=1000'
# Response: {"message":"登录成功","token":"xxx"}
```

**Check Login Status:**
```bash
curl -H "token: YOUR_TOKEN" http://localhost:8080/check
# Response: {"login_id":"1000","message":"已登录"}
```

**Access Protected API:**
```bash
curl -H "token: YOUR_TOKEN" http://localhost:8080/api/user
# Response: {"name":"User 1000","user_id":"1000"}
```

**Logout:**
```bash
curl -X POST -H "token: YOUR_TOKEN" http://localhost:8080/logout
# Response: {"message":"登出成功"}
```

**Kickout User:**
```bash
curl -X POST -H "token: YOUR_TOKEN" http://localhost:8080/api/kickout/1000
# Response: {"message":"踢人成功"}
```

## Code Example

```go
package main

import (
    "log"

    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/gin-gonic/gin"
)

func main() {
    // Create Builder and build Manager
    mgr := sagin.NewDefaultBuild().
        TokenName("token").
        Timeout(7200).
        IsPrintBanner(true).
        Build()

    // Set global manager
    sagin.SetManager(mgr)

    // Create router
    r := gin.Default()

    // Login endpoint
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

    // Protected routes
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

## Available Functions

All functions from `stputil` are re-exported in `sagin` with `context.Context` support:

### Authentication

```go
sagin.Login(ctx, loginID, device...)         // Login
sagin.Logout(ctx, loginID, device...)        // Logout
sagin.LogoutByToken(ctx, token)              // Logout by token
sagin.IsLogin(ctx, token)                    // Check login status
sagin.CheckLogin(ctx, token)                 // Check login (throws error)
sagin.GetLoginID(ctx, token)                 // Get login ID from token
sagin.GetLoginIDFromRequest(c)               // Get login ID from Gin context
```

### Kickout & Disable

```go
sagin.Kickout(ctx, loginID, device...)       // Kickout user
sagin.KickoutByToken(ctx, token)             // Kickout by token
sagin.Disable(ctx, loginID, duration)        // Disable account
sagin.IsDisable(ctx, loginID)                // Check if disabled
sagin.Untie(ctx, loginID)                    // Re-enable account
```

### Permission & Role

```go
sagin.SetPermissions(ctx, loginID, perms)    // Set permissions
sagin.SetRoles(ctx, loginID, roles)          // Set roles
sagin.HasPermission(ctx, loginID, perm)      // Check permission
sagin.HasRole(ctx, loginID, role)            // Check role
sagin.GetPermissions(ctx, loginID)           // Get permissions
sagin.GetRoles(ctx, loginID)                 // Get roles
```

### Session

```go
sagin.GetSession(ctx, loginID)               // Get session
sagin.GetSessionByToken(ctx, token)          // Get session by token
sagin.HasSession(ctx, loginID)               // Check session exists
```

### Security Features

```go
sagin.Generate(ctx)                          // Generate nonce
sagin.Verify(ctx, nonce)                     // Verify nonce
sagin.GenerateTokenPair(ctx, loginID)        // Generate access + refresh token
sagin.RefreshAccessToken(ctx, refreshToken)  // Refresh access token
```

### Builder & Config

```go
sagin.NewDefaultBuild()                      // Create default builder
sagin.NewDefaultConfig()                     // Create default config
sagin.SetManager(mgr)                        // Set global manager
sagin.GetManager()                           // Get global manager
```

## Middleware Functions

| Middleware | Description |
|------------|-------------|
| `CheckLoginMiddleware()` | Check if user is logged in |
| `CheckRoleMiddleware(roles...)` | Check if user has specified roles |
| `CheckPermissionMiddleware(perms...)` | Check if user has specified permissions |
| `CheckDisableMiddleware()` | Check if account is disabled |
| `IgnoreMiddleware()` | Skip authentication check |

## Benefits

1. **Simpler Dependencies** - Only one import needed
2. **Cleaner Code** - Less import statements
3. **Framework-Specific** - Optimized for Gin
4. **Context Support** - All functions support `context.Context`

## Learn More

- [Main Documentation](../../../README.md)
- [Gin Example](../gin-example) - More complete example
- [Annotation Example](../../annotation/annotation-example) - Middleware usage
