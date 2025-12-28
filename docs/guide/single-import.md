# Single Import Usage Guide

**[中文文档](single-import_zh.md)**

## Overview

Starting from v0.1.0, Sa-Token-Go supports **single import mode** - you only need to import one framework integration package to access all features of core and stputil.

## Benefits

✅ **Simpler dependencies** - Import only one package  
✅ **Cleaner code** - Fewer import statements  
✅ **Better IDE support** - All functions in one namespace  
✅ **Backward compatible** - Old import method still works  

## Traditional Way vs. New Way

### Traditional Way (Multiple Imports)

```go
import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // Use core
    config := core.DefaultConfig()
    storage := memory.NewStorage()
    manager := core.NewManager(storage, config)
    
    // Use stputil
    stputil.SetManager(manager)
    token, _ := stputil.Login(1000)
    
    // Use gin integration
    plugin := gin.NewPlugin(manager)
}
```

### New Way (Single Import) ✨

```go
import (
    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // All functions in sagin package!
    config := sagin.DefaultConfig()
    storage := memory.NewStorage()
    manager := sagin.NewManager(storage, config)
    
    sagin.SetManager(manager)
    token, _ := sagin.Login(1000)
    
    plugin := sagin.NewPlugin(manager)
}
```

## Installation

### For Gin Framework

```bash
go get github.com/click33/sa-token-go/integrations/gin@v0.1.0
go get github.com/click33/sa-token-go/storage/memory@v0.1.0
```

### For Echo Framework

```bash
go get github.com/click33/sa-token-go/integrations/echo@v0.1.0
go get github.com/click33/sa-token-go/storage/memory@v0.1.0
```

### For Fiber Framework

```bash
go get github.com/click33/sa-token-go/integrations/fiber@v0.1.0
go get github.com/click33/sa-token-go/storage/memory@v0.1.0
```

### For Chi Framework

```bash
go get github.com/click33/sa-token-go/integrations/chi@v0.1.0
go get github.com/click33/sa-token-go/storage/memory@v0.1.0
```

## Complete Example (Gin)

```go
package main

import (
    "log"

    "github.com/gin-gonic/gin"
    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // 1. Initialize storage
    storage := memory.NewStorage()

    // 2. Create configuration (from sagin package)
    config := sagin.DefaultConfig()
    config.TokenName = "token"
    config.Timeout = 7200  // 2 hours
    config.IsPrint = true

    // 3. Create manager-example (from sagin package)
    manager := sagin.NewManager(storage, config)

    // 4. Set global manager-example (from sagin package)
    sagin.SetManager(manager)

    // 5. Create Gin router
    r := gin.Default()

    // 6. Login endpoint
    r.POST("/login", func(c *gin.Context) {
        userID := c.PostForm("user_id")
        if userID == "" {
            c.JSON(400, gin.H{"error": "user_id required"})
            return
        }

        // Use sagin.Login (from sagin package)
        token, err := sagin.Login(userID)
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }

        c.JSON(200, gin.H{
            "message": "Login successful",
            "token":   token,
        })
    })

    // 7. Logout endpoint
    r.POST("/logout", func(c *gin.Context) {
        token := c.GetHeader("token")
        if token == "" {
            c.JSON(400, gin.H{"error": "token required"})
            return
        }

        // Use sagin.LogoutByToken (from sagin package)
        if err := sagin.LogoutByToken(token); err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }

        c.JSON(200, gin.H{"message": "Logout successful"})
    })

    // 8. Check login status
    r.GET("/check", func(c *gin.Context) {
        token := c.GetHeader("token")
        if token == "" {
            c.JSON(400, gin.H{"error": "token required"})
            return
        }

        // Use sagin.IsLogin (from sagin package)
        isLogin := sagin.IsLogin(token)
        if !isLogin {
            c.JSON(401, gin.H{"error": "Not logged in"})
            return
        }

        // Use sagin.GetLoginID (from sagin package)
        loginID, _ := sagin.GetLoginID(token)

        c.JSON(200, gin.H{
            "message":  "Logged in",
            "login_id": loginID,
        })
    })

    // 9. Protected routes with annotations
    plugin := sagin.NewPlugin(manager)
    protected := r.Group("/api")
    protected.Use(plugin.AuthMiddleware())
    {
        protected.GET("/user", func(c *gin.Context) {
            token := c.GetHeader("token")
            loginID, _ := sagin.GetLoginID(token)

            c.JSON(200, gin.H{
                "user_id": loginID,
                "name":    "User " + loginID,
            })
        })

        // Kickout user
        protected.POST("/kickout/:user_id", func(c *gin.Context) {
            userID := c.Param("user_id")

            // Use sagin.Kickout (from sagin package)
            if err := sagin.Kickout(userID); err != nil {
                c.JSON(500, gin.H{"error": err.Error()})
                return
            }

            c.JSON(200, gin.H{"message": "Kickout successful"})
        })
    }

    // 10. Start server
    log.Println("Server starting on port: 8080")
    log.Println("Example: curl -X POST http://localhost:8080/login -d 'user_id=1000'")
    if err := r.Run(":8080"); err != nil {
        log.Fatal("Server failed to start:", err)
    }
}
```

## Available Functions

All functions from `core` and `stputil` are re-exported in framework integration packages:

### Configuration & Initialization

```go
config := sagin.DefaultConfig()           // Create log config
manager := sagin.NewManager(storage, cfg) // Create manager-example
builder := sagin.NewBuilder()             // Create builder
sagin.SetManager(manager)                 // Set global manager-example
manager := sagin.GetManager()             // Get global manager-example
```

### Authentication

```go
token, _ := sagin.Login(loginID, device...)
sagin.LoginByToken(loginID, token, device...)
sagin.Logout(loginID, device...)
sagin.LogoutByToken(token)
isLogin := sagin.IsLogin(token)
sagin.CheckLogin(token)
loginID, _ := sagin.GetLoginID(token)
tokenValue, _ := sagin.GetTokenValue(loginID, device...)
tokenInfo, _ := sagin.GetTokenInfo(token)
```

### Kickout & Disable

```go
sagin.Kickout(loginID, device...)
sagin.Disable(loginID, duration)
isDisabled := sagin.IsDisable(loginID)
sagin.CheckDisable(loginID)
remainTime, _ := sagin.GetDisableTime(loginID)
sagin.Untie(loginID)
```

### Permission & Role

```go
sagin.CheckPermission(loginID, permission)
hasPermission := sagin.HasPermission(loginID, permission)
sagin.CheckPermissionAnd(loginID, perms...)
sagin.CheckPermissionOr(loginID, perms...)
permissions := sagin.GetPermissionList(loginID)

sagin.CheckRole(loginID, role)
hasRole := sagin.HasRole(loginID, role)
sagin.CheckRoleAnd(loginID, roles...)
sagin.CheckRoleOr(loginID, roles...)
roles := sagin.GetRoleList(loginID)
```

### Session Management

```go
session, _ := sagin.GetSession(loginID)
session, _ := sagin.GetSessionByToken(token)
tokenSession, _ := sagin.GetTokenSession(token)
```

### Security Features

```go
nonce, _ := sagin.GenerateNonce()
sagin.VerifyNonce(nonce)
accessToken, refreshToken, _ := sagin.LoginWithRefreshToken(loginID, device...)
newAccessToken, newRefreshToken, _ := sagin.RefreshAccessToken(refreshToken)
sagin.RevokeRefreshToken(refreshToken)
oauth2Server := sagin.GetOAuth2Server()
```

### Token & Utilities

```go
sagin.RenewTimeout(token)
randomStr := sagin.RandomString(16)
isEmpty := sagin.IsEmpty(str)
matched := sagin.MatchPattern(pattern, str)
```

## Type Definitions

All types from `core` are also exported:

```go
type Config = sagin.Config
type Manager = sagin.Manager
type Session = sagin.Session
type TokenInfo = sagin.TokenInfo
type Storage = sagin.Storage
type EventListener = sagin.EventListener
// ... and more
```

## Constants

All constants are available:

```go
sagin.TokenStyleUUID
sagin.TokenStyleJWT
sagin.TokenStyleHash
// ... and more

sagin.EventLogin
sagin.EventLogout
sagin.EventKickout
// ... and more
```

## Framework-Specific Examples

### Echo Example

```go
import (
    saecho "github.com/click33/sa-token-go/integrations/echo"
    "github.com/labstack/echo/v4"
)

func main() {
    config := saecho.DefaultConfig()
    manager := saecho.NewManager(storage, config)
    saecho.SetManager(manager)
    
    e := echo.New()
    
    e.POST("/login", func(c echo.Context) error {
        token, _ := saecho.Login(userID)
        return c.JSON(200, map[string]string{"token": token})
    })
    
    e.Start(":8080")
}
```

### Fiber Example

```go
import (
    safiber "github.com/click33/sa-token-go/integrations/fiber"
    "github.com/gofiber/fiber/v2"
)

func main() {
    config := safiber.DefaultConfig()
    manager := safiber.NewManager(storage, config)
    safiber.SetManager(manager)
    
    app := fiber.New()
    
    app.Post("/login", func(c *fiber.Ctx) error {
        token, _ := safiber.Login(userID)
        return c.JSON(fiber.Map{"token": token})
    })
    
    app.Listen(":8080")
}
```

### Chi Example

```go
import (
    sachi "github.com/click33/sa-token-go/integrations/chi"
    "github.com/go-chi/chi/v5"
)

func main() {
    config := sachi.DefaultConfig()
    manager := sachi.NewManager(storage, config)
    sachi.SetManager(manager)
    
    r := chi.NewRouter()
    
    r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
        token, _ := sachi.Login(userID)
        json.NewEncoder(w).Encode(map[string]string{"token": token})
    })
    
    http.ListenAndServe(":8080", r)
}
```

## Migration from Old Import Method

If you have existing code using the old import method, you can migrate step by step:

### Step 1: Add new import (keep old ones)

```go
import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    sagin "github.com/click33/sa-token-go/integrations/gin"  // Add this
    "github.com/click33/sa-token-go/storage/memory"
)
```

### Step 2: Replace function calls

```go
// Old
config := core.DefaultConfig()

// New
config := sagin.DefaultConfig()
```

### Step 3: Remove old imports

```go
import (
    // Remove these
    // "github.com/click33/sa-token-go/core"
    // "github.com/click33/sa-token-go/stputil"
    
    sagin "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)
```

## FAQ

**Q: Do I still need to import core or stputil?**  
A: No, the framework integration package already includes them.

**Q: Can I mix old and new import methods?**  
A: Yes, but not recommended. Choose one method for consistency.

**Q: Does this work for all frameworks?**  
A: Yes, Gin, Echo, Fiber, and Chi all support single import.

**Q: Is there any performance impact?**  
A: No, it's just re-exporting. No additional overhead.

**Q: What if I don't use any web framework?**  
A: Then use the traditional import method with `core` and `stputil`.

## Learn More

- [Complete Example](../../examples/gin/gin-simple/)
- [Main Documentation](../../README.md)
- [API Reference](../api/api.md)

