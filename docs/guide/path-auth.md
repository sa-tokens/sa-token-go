# Path-Based Authentication

Path-based authentication allows you to configure which paths require authentication and which paths are excluded, providing flexible access control for your application.

## Features

- **Ant-style wildcard patterns** - Support for `/**`, `/*`, `*.html` patterns
- **Include/Exclude configuration** - Fine-grained control over which paths need authentication
- **Custom validators** - Optional login ID validation functions
- **Framework integration** - Works seamlessly with all supported frameworks
- **Token extraction** - Automatically extracts tokens from headers and cookies

## Pattern Matching

The path matching supports Ant-style wildcards:

- `/**` - Matches all paths
- `/api/**` - Matches all paths starting with `/api/`
- `/api/*` - Matches single-level paths under `/api/` (e.g., `/api/user`, but not `/api/user/profile`)
- `*.html` - Matches paths ending with `.html`
- `/exact` - Exact path match

### Pattern Examples

```go
// Match all paths
"/**"

// Match all API paths
"/api/**"

// Match single-level API paths
"/api/*"

// Match static files
"*.html"
"*.css"
"*.js"

// Match specific paths
"/login"
"/logout"
"/public/**"
```

## Usage

### Basic Configuration

The simplest way to use path-based authentication is through middleware:

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // Initialize manager
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenName("Authorization").
        Timeout(86400).
        Build()

    // Create path authentication configuration
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).        // Paths that require authentication
        SetExclude([]string{"/api/public/**"})   // Paths excluded from authentication

    // Create plugin and use middleware
    plugin := gin.NewPlugin(manager)
    r := gin.Default()
    
    // Apply path authentication middleware
    r.Use(plugin.PathAuthMiddleware(config))
    
    // Your routes
    r.GET("/api/user/info", getUserInfo)
    r.GET("/api/public/status", getStatus)  // This path is excluded
    
    r.Run(":8080")
}
```

### Multiple Include/Exclude Patterns

You can specify multiple patterns for more complex scenarios:

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{
        "/api/**",           // All API paths
        "/admin/**",         // All admin paths
        "/user/profile",     // Specific user profile path
    }).
    SetExclude([]string{
        "/api/public/**",    // Public API paths
        "/api/auth/login",   // Login endpoint
        "/api/auth/register", // Register endpoint
        "*.html",            // Static HTML files
        "*.css",             // CSS files
        "*.js",              // JavaScript files
    })
```

### With Custom Validator

You can add custom validation logic for login IDs:

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{"/api/public/**"}).
    SetValidator(func(loginID string) bool {
        // Custom validation logic
        // For example, check if user is banned
        if loginID == "banned_user" {
            return false
        }
        
        // Check if user account is active
        // You can query your database here
        // return isUserActive(loginID)
        
        return true
    })
```

### Complete Example with Gin

```go
package main

import (
    "net/http"
    
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/gin-gonic/gin"
)

func main() {
    // Initialize Sa-Token manager
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenName("Authorization").
        Timeout(86400).
        Build()

    // Configure path authentication
    pathAuthConfig := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{
            "/api/auth/login",
            "/api/auth/register",
            "/api/public/**",
        })

    // Create Gin router
    r := gin.Default()
    
    // Create plugin
    plugin := gin.NewPlugin(manager)
    
    // Apply path authentication middleware
    r.Use(plugin.PathAuthMiddleware(pathAuthConfig))
    
    // Public routes (excluded from auth)
    r.POST("/api/auth/login", plugin.LoginHandler)
    r.POST("/api/auth/register", registerHandler)
    r.GET("/api/public/status", getStatus)
    
    // Protected routes (require authentication)
    api := r.Group("/api")
    {
        api.GET("/user/info", getUserInfo)
        api.GET("/user/profile", getUserProfile)
        api.POST("/user/update", updateUser)
    }
    
    r.Run(":8080")
}

func getUserInfo(c *gin.Context) {
    // Get login ID from context (set by PathAuthMiddleware)
    loginID, exists := c.Get("loginID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "message": "User info retrieved",
    })
}

func getUserProfile(c *gin.Context) {
    loginID, _ := c.Get("loginID")
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "profile": "User profile data",
    })
}

func updateUser(c *gin.Context) {
    loginID, _ := c.Get("loginID")
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "message": "User updated",
    })
}

func registerHandler(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func getStatus(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
```

### Using ProcessAuth Directly

If you need more control, you can use `ProcessAuth` directly in your handlers:

```go
import "github.com/click33/sa-token-go/core"

func customHandler(c *gin.Context) {
    path := c.Request.URL.Path
    token := c.GetHeader("Authorization")
    if token == "" {
        token, _ = c.Cookie("Authorization")
    }
    
    config := core.NewPathAuthConfig().SetInclude([]string{"/api/**"})
    result := core.ProcessAuth(path, token, config, manager)
    
    if result.ShouldReject() {
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "path authentication required",
            "path": path,
        })
        c.Abort()
        return
    }
    
    // Use result.LoginID() to get the login ID
    loginID := result.LoginID()
    if loginID == "" {
        // Token is valid but loginID not available
        // You might need to get it another way
    }
    
    // Continue with your logic
    c.JSON(http.StatusOK, gin.H{"loginID": loginID})
}
```

## Framework Examples

### Gin

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/gin-gonic/gin"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := gin.NewPlugin(manager)
    r := gin.Default()
    r.Use(plugin.PathAuthMiddleware(config))
    
    r.Run(":8080")
}
```

### Echo

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/echo"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/labstack/echo/v4"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := echo.NewPlugin(manager)
    e := echo.New()
    e.Use(plugin.PathAuthMiddleware(config))
    
    e.Start(":8080")
}
```

### Fiber

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/fiber"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/gofiber/fiber/v2"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := fiber.NewPlugin(manager)
    app := fiber.New()
    app.Use(plugin.PathAuthMiddleware(config))
    
    app.Listen(":8080")
}
```

### Chi

```go
package main

import (
    "net/http"
    
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/chi"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/go-chi/chi/v5"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := chi.NewPlugin(manager)
    r := chi.NewRouter()
    r.Use(plugin.PathAuthMiddleware(config))
    
    http.ListenAndServe(":8080", r)
}
```

### GoFrame

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/gf"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/gogf/gf/v2/frame/g"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := gf.NewPlugin(manager)
    s := g.Server()
    s.Use(plugin.PathAuthMiddleware(config))
    
    s.Run()
}
```

### Kratos

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/kratos"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/go-kratos/kratos/v2"
    "github.com/go-kratos/kratos/v2/transport/http"
)

func main() {
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{"/api/public/**"})
    
    plugin := kratos.NewPlugin(manager)
    
    httpSrv := http.NewServer(
        http.Middleware(
            plugin.PathAuthMiddleware(config),
        ),
    )
    
    app := kratos.New(
        kratos.Server(httpSrv),
    )
    
    app.Run()
}
```

## Error Handling

When path authentication fails, the middleware returns a standardized error:

```go
// Error response format
{
    "code": 401,
    "message": "path authentication required",
    "error": "path authentication required: this path requires authentication",
    "path": "/api/user/info"  // Included in context
}
```

You can customize error handling:

```go
// In your error handler
if err := core.GetErrorCode(err); err == core.CodePathAuthRequired {
    // Handle path authentication error
    path, _ := err.GetContext("path")
    // Custom error response
}
```

## Best Practices

1. **Order Matters**: Place path authentication middleware before other middleware that depends on authentication
2. **Specific First**: More specific patterns should be listed before general patterns
3. **Public Paths**: Always exclude authentication endpoints (login, register) from authentication
4. **Static Files**: Exclude static file paths (CSS, JS, images) for better performance
5. **Error Handling**: Provide clear error messages to help users understand authentication requirements

## Common Scenarios

### Scenario 1: API with Public and Private Endpoints

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{
        "/api/auth/**",      // All auth endpoints
        "/api/public/**",    // Public API endpoints
    })
```

### Scenario 2: Admin Panel Protection

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/admin/**"}).
    SetExclude([]string{
        "/admin/login",
        "/admin/static/**",  // Admin static files
    })
```

### Scenario 3: Multi-Tenant Application

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{"/api/public/**"}).
    SetValidator(func(loginID string) bool {
        // Check tenant access
        return checkTenantAccess(loginID)
    })
```

## API Reference

### PathAuthConfig

- `SetInclude(patterns []string) *PathAuthConfig` - Set paths that require authentication
- `SetExclude(patterns []string) *PathAuthConfig` - Set paths excluded from authentication
- `SetValidator(validator func(loginID string) bool) *PathAuthConfig` - Set custom login ID validator
- `Check(path string) bool` - Check if a path requires authentication

### ProcessAuth

```go
func ProcessAuth(path, tokenStr string, config *PathAuthConfig, mgr *Manager) *AuthResult
```

Processes authentication for a request path and returns an `AuthResult` containing:
- `NeedAuth bool` - Whether authentication is required
- `Token string` - The extracted token
- `TokenInfo *TokenInfo` - Token information if valid
- `IsValid bool` - Whether the token is valid

### AuthResult

- `ShouldReject() bool` - Check if the request should be rejected
- `LoginID() string` - Get the login ID from token info

### Error Functions

- `NewPathAuthRequiredError(path string) *SaTokenError` - Create path authentication required error
- `NewPathNotAllowedError(path string) *SaTokenError` - Create path not allowed error
