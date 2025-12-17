# 路径鉴权

路径鉴权允许您配置哪些路径需要鉴权，哪些路径被排除，为应用程序提供灵活的访问控制。

## 特性

- **Ant风格通配符模式** - 支持 `/**`、`/*`、`*.html` 等模式
- **包含/排除配置** - 精细控制哪些路径需要鉴权
- **自定义验证器** - 可选的登录ID验证函数
- **框架集成** - 与所有支持的框架无缝协作
- **Token提取** - 自动从请求头和Cookie中提取Token

## 模式匹配

路径匹配支持Ant风格通配符：

- `/**` - 匹配所有路径
- `/api/**` - 匹配所有以 `/api/` 开头的路径
- `/api/*` - 匹配 `/api/` 下的单级路径（例如 `/api/user`，但不匹配 `/api/user/profile`）
- `*.html` - 匹配以 `.html` 结尾的路径
- `/exact` - 精确路径匹配

### 模式示例

```go
// 匹配所有路径
"/**"

// 匹配所有API路径
"/api/**"

// 匹配单级API路径
"/api/*"

// 匹配静态文件
"*.html"
"*.css"
"*.js"

// 匹配特定路径
"/login"
"/logout"
"/public/**"
```

## 使用方法

### 基本配置

使用路径鉴权最简单的方式是通过中间件：

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // 初始化管理器
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenName("Authorization").
        Timeout(86400).
        Build()

    // 创建路径鉴权配置
    config := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).        // 需要鉴权的路径
        SetExclude([]string{"/api/public/**"})  // 排除鉴权的路径

    // 创建插件并使用中间件
    plugin := gin.NewPlugin(manager)
    r := gin.Default()
    
    // 应用路径鉴权中间件
    r.Use(plugin.PathAuthMiddleware(config))
    
    // 您的路由
    r.GET("/api/user/info", getUserInfo)
    r.GET("/api/public/status", getStatus)  // 此路径被排除
    
    r.Run(":8080")
}
```

### 多个包含/排除模式

您可以指定多个模式以实现更复杂的场景：

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{
        "/api/**",           // 所有API路径
        "/admin/**",         // 所有管理路径
        "/user/profile",     // 特定用户资料路径
    }).
    SetExclude([]string{
        "/api/public/**",    // 公共API路径
        "/api/auth/login",   // 登录端点
        "/api/auth/register", // 注册端点
        "*.html",            // 静态HTML文件
        "*.css",             // CSS文件
        "*.js",              // JavaScript文件
    })
```

### 使用自定义验证器

您可以添加自定义的登录ID验证逻辑：

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{"/api/public/**"}).
    SetValidator(func(loginID string) bool {
        // 自定义验证逻辑
        // 例如，检查用户是否被封禁
        if loginID == "banned_user" {
            return false
        }
        
        // 检查用户账号是否激活
        // 您可以在这里查询数据库
        // return isUserActive(loginID)
        
        return true
    })
```

### Gin完整示例

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
    // 初始化Sa-Token管理器
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenName("Authorization").
        Timeout(86400).
        Build()

    // 配置路径鉴权
    pathAuthConfig := core.NewPathAuthConfig().
        SetInclude([]string{"/api/**"}).
        SetExclude([]string{
            "/api/auth/login",
            "/api/auth/register",
            "/api/public/**",
        })

    // 创建Gin路由器
    r := gin.Default()
    
    // 创建插件
    plugin := gin.NewPlugin(manager)
    
    // 应用路径鉴权中间件
    r.Use(plugin.PathAuthMiddleware(pathAuthConfig))
    
    // 公共路由（排除鉴权）
    r.POST("/api/auth/login", plugin.LoginHandler)
    r.POST("/api/auth/register", registerHandler)
    r.GET("/api/public/status", getStatus)
    
    // 受保护的路由（需要鉴权）
    api := r.Group("/api")
    {
        api.GET("/user/info", getUserInfo)
        api.GET("/user/profile", getUserProfile)
        api.POST("/user/update", updateUser)
    }
    
    r.Run(":8080")
}

func getUserInfo(c *gin.Context) {
    // 从上下文获取登录ID（由PathAuthMiddleware设置）
    loginID, exists := c.Get("loginID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "message": "用户信息已获取",
    })
}

func getUserProfile(c *gin.Context) {
    loginID, _ := c.Get("loginID")
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "profile": "用户资料数据",
    })
}

func updateUser(c *gin.Context) {
    loginID, _ := c.Get("loginID")
    c.JSON(http.StatusOK, gin.H{
        "loginID": loginID,
        "message": "用户已更新",
    })
}

func registerHandler(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "注册成功"})
}

func getStatus(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
```

### 直接使用 ProcessAuth

如果您需要更多控制，可以在处理器中直接使用 `ProcessAuth`：

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
            "error": "路径需要鉴权",
            "path": path,
        })
        c.Abort()
        return
    }
    
    // 使用 result.LoginID() 获取登录ID
    loginID := result.LoginID()
    if loginID == "" {
        // Token有效但登录ID不可用
        // 您可能需要通过其他方式获取
    }
    
    // 继续您的逻辑
    c.JSON(http.StatusOK, gin.H{"loginID": loginID})
}
```

## 框架示例

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

## 错误处理

当路径鉴权失败时，中间件会返回标准化的错误：

```go
// 错误响应格式
{
    "code": 401,
    "message": "path authentication required",
    "error": "path authentication required: this path requires authentication",
    "path": "/api/user/info"  // 包含在上下文中
}
```

您可以自定义错误处理：

```go
// 在您的错误处理器中
if err := core.GetErrorCode(err); err == core.CodePathAuthRequired {
    // 处理路径鉴权错误
    path, _ := err.GetContext("path")
    // 自定义错误响应
}
```

## 最佳实践

1. **顺序很重要**：将路径鉴权中间件放在其他依赖认证的中间件之前
2. **具体优先**：更具体的模式应该列在通用模式之前
3. **公共路径**：始终将认证端点（登录、注册）排除在鉴权之外
4. **静态文件**：排除静态文件路径（CSS、JS、图片）以提高性能
5. **错误处理**：提供清晰的错误消息，帮助用户理解鉴权要求

## 常见场景

### 场景1：包含公共和私有端点的API

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{
        "/api/auth/**",      // 所有认证端点
        "/api/public/**",    // 公共API端点
    })
```

### 场景2：管理面板保护

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/admin/**"}).
    SetExclude([]string{
        "/admin/login",
        "/admin/static/**",  // 管理后台静态文件
    })
```

### 场景3：多租户应用

```go
config := core.NewPathAuthConfig().
    SetInclude([]string{"/api/**"}).
    SetExclude([]string{"/api/public/**"}).
    SetValidator(func(loginID string) bool {
        // 检查租户访问权限
        return checkTenantAccess(loginID)
    })
```

## API 参考

### PathAuthConfig

- `SetInclude(patterns []string) *PathAuthConfig` - 设置需要鉴权的路径
- `SetExclude(patterns []string) *PathAuthConfig` - 设置排除鉴权的路径
- `SetValidator(validator func(loginID string) bool) *PathAuthConfig` - 设置自定义登录ID验证器
- `Check(path string) bool` - 检查路径是否需要鉴权

### ProcessAuth

```go
func ProcessAuth(path, tokenStr string, config *PathAuthConfig, mgr *Manager) *AuthResult
```

处理请求路径的鉴权，返回包含以下信息的 `AuthResult`：
- `NeedAuth bool` - 是否需要鉴权
- `Token string` - 提取的token
- `TokenInfo *TokenInfo` - 如果有效则包含token信息
- `IsValid bool` - token是否有效

### AuthResult

- `ShouldReject() bool` - 检查请求是否应该被拒绝
- `LoginID() string` - 从token信息中获取登录ID

### 错误函数

- `NewPathAuthRequiredError(path string) *SaTokenError` - 创建路径需要鉴权错误
- `NewPathNotAllowedError(path string) *SaTokenError` - 创建路径不允许访问错误
