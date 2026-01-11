# Sa-Token-Go

**中文文档** | **[English](README.md)**

[![Go Version](https://img.shields.io/badge/Go-%3E%3D1.21-blue)](https://img.shields.io)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

一个轻量级、高性能的 Go 权限认证框架，参考 [sa-token](https://github.com/dromara/sa-token) 设计。

## ✨ 核心特性

- 🔐 **登录认证** - 支持多设备登录、Token管理
- 🛡️ **权限验证** - 细粒度权限控制、通配符支持（`*`, `user:*`, `user:*:view`）
- 🛣️ **路径鉴权** - 灵活的路径鉴权、支持Ant风格通配符
- 👥 **角色管理** - 灵活的角色授权机制
- 🚫 **账号封禁** - 临时/永久封禁功能
- 👢 **踢人下线** - 强制用户下线、多端互斥登录
- 💾 **Session会话** - 完整的Session管理
- ⏰ **活跃检测** - 自动检测Token活跃度
- 🔄 **自动续期** - Token异步自动续期（性能提升400%）
- 🎨 **注解支持** - `@SaCheckLogin`、`@SaCheckRole`、`@SaCheckPermission`
- 🎧 **事件监听** - 强大的事件系统、支持优先级、异步执行
- 📦 **模块化设计** - 按需导入、最小依赖
- 🔒 **Nonce防重放** - 防止请求重放攻击、一次性令牌
- 🔄 **Refresh Token** - 刷新令牌机制、无感刷新
- 🔐 **OAuth2** - 完整的OAuth2授权码模式实现

## 🚀 快速开始

### 📥 安装

#### 方式一：简化导入（推荐）✨

**只需导入一个框架集成包，自动包含 core 和 stputil 功能！**

```bash
# 只导入框架集成包（自动包含 core + stputil）
go get github.com/click33/sa-token-go/integrations/gin@latest   # Gin框架
# 或
go get github.com/click33/sa-token-go/integrations/echo@latest  # Echo框架
# 或
go get github.com/click33/sa-token-go/integrations/fiber@latest # Fiber框架
# 或
go get github.com/click33/sa-token-go/integrations/chi@latest   # Chi框架
# 或
go get github.com/click33/sa-token-go/integrations/gf@latest    # GoFrame框架
# 或
go get github.com/click33/sa-token-go/integrations/kratos@latest# Kratos框架

# 存储模块（选一个）
go get github.com/click33/sa-token-go/storage/memory@latest # 内存存储（开发）
go get github.com/click33/sa-token-go/storage/redis@latest  # Redis存储（生产）
```

#### 方式二：分开导入

```bash
# 核心模块
go get github.com/click33/sa-token-go/core@latest 
go get github.com/click33/sa-token-go/stputil@latest 

# 存储模块（选一个）
go get github.com/click33/sa-token-go/storage/memory@latest # 内存存储（开发）
go get github.com/click33/sa-token-go/storage/redis@latest  # Redis存储（生产）

# 框架集成（可选）
go get github.com/click33/sa-token-go/integrations/gin@latest   # Gin框架
go get github.com/click33/sa-token-go/integrations/echo@latest  # Echo框架
go get github.com/click33/sa-token-go/integrations/fiber@latest # Fiber框架
go get github.com/click33/sa-token-go/integrations/chi@latest   # Chi框架
go get github.com/click33/sa-token-go/integrations/gf@latest    # GoFrame框架
go get github.com/click33/sa-token-go/integrations/kratos@latest# Kratos框架
```

### ⚡ 超简洁使用（一行初始化）

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/memory"
)

func init() {
    // 🎯 一行初始化！显示启动 Banner
    stputil.SetManager(
        core.NewBuilder().
            Storage(memory.NewStorage()).
            TokenName("Authorization").
            Timeout(86400).                      // 24小时
            TokenStyle(core.TokenStyleRandom64). // Token风格
            IsPrintBanner(true).                 // 显示启动Banner
            Build(),
    )
}
```

**启动时会显示 Banner：**

```
   _____         ______      __                  ______     
  / ___/____ _  /_  __/___  / /_____  ____      / ____/____ 
  \__ \/ __  |   / / / __ \/ //_/ _ \/ __ \_____/ / __/ __ \
 ___/ / /_/ /   / / / /_/ / ,< /  __/ / / /_____/ /_/ / /_/ /
/____/\__,_/   /_/  \____/_/|_|\___/_/ /_/      \____/\____/ 
                                                             
:: Sa-Token-Go ::                                    (v0.1.7)
:: Go Version ::                                     go1.21.0
:: GOOS/GOARCH ::                                    linux/amd64

┌─────────────────────────────────────────────────────────┐
│ Token Style     : random64                              │
│ Token Timeout   : 86400                      seconds    │
│ Auto Renew      : true                                  │
└─────────────────────────────────────────────────────────┘
```

```go
func main() {
    // 🚀 直接使用 StpUtil，无需传递manager
    token, _ := stputil.Login(1000)
    println("登录成功，Token:", token)
    
    // 设置权限
    stputil.SetPermissions(1000, []string{"user:read", "user:write"})
    
    // 检查权限
    if stputil.HasPermission(1000, "user:read") {
        println("有权限！")
    }
    
    // 登出
    stputil.Logout(1000)
}
```

## 🔧 核心API

### 🔑 登录认证

```go
// 登录（支持 int, int64, uint, string）
token, _ := stputil.Login(1000)
token, _ := stputil.Login("user123")
token, _ := stputil.Login(1000, "mobile")  // 指定设备

// 检查登录（自动异步续签）
isLogin := stputil.IsLogin(token)

// 获取登录ID
loginID, _ := stputil.GetLoginID(token)

// 登出
stputil.Logout(1000)
stputil.LogoutByToken(token)

// 踢人下线
stputil.Kickout(1000)
stputil.Kickout(1000, "mobile")
```

### 🛡️ 权限验证

```go
// 设置权限
stputil.SetPermissions(1000, []string{
    "user:read",
    "user:write",
    "admin:*",      // 通配符：匹配所有admin权限
})

// 检查权限
hasPermission := stputil.HasPermission(1000, "user:read")
hasPermission := stputil.HasPermission(1000, "admin:delete")  // 通配符匹配

// 多权限检查
hasAll := stputil.HasPermissionsAnd(1000, []string{"user:read", "user:write"})  // AND逻辑
hasAny := stputil.HasPermissionsOr(1000, []string{"admin", "super"})           // OR逻辑
```

### 👥 角色管理

```go
// 设置角色
stputil.SetRoles(1000, []string{"admin", "manager"})

// 检查角色
hasRole := stputil.HasRole(1000, "admin")

// 多角色检查
hasAll := stputil.HasRolesAnd(1000, []string{"admin", "manager"})
hasAny := stputil.HasRolesOr(1000, []string{"admin", "super"})
```

### 💾 Session管理

```go
// 获取Session
sess, _ := stputil.GetSession(1000)

// 设置数据
sess.Set("nickname", "张三")
sess.Set("age", 25)

// 读取数据
nickname := sess.GetString("nickname")
age := sess.GetInt("age")

// 删除数据
sess.Delete("nickname")

// 删除Session
stputil.DeleteSession(1000)
```

### 🚫 账号封禁

```go
// 封禁1小时
stputil.Disable(1000, 1*time.Hour)

// 永久封禁
stputil.Disable(1000, 0)

// 解封
stputil.Untie(1000)

// 检查是否被封禁
isDisabled := stputil.IsDisable(1000)

// 获取剩余封禁时间
remainingTime, _ := stputil.GetDisableTime(1000)
```

## 🌐 框架集成

### 🌟 Gin 集成（单一导入）

**新方式：只导入 `integrations/gin` 即可使用所有功能！**

```go
import (
    "github.com/gin-gonic/gin"
    sagin "github.com/click33/sa-token-go/integrations/gin"  // 只需这一个导入！
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // 初始化（所有功能都在 sagin 包中）
    storage := memory.NewStorage()
    config := sagin.DefaultConfig()  // 使用 sagin.DefaultConfig
    manager := sagin.NewManager(storage, config)  // 使用 sagin.NewManager
    sagin.SetManager(manager)  // 使用 sagin.SetManager
    
    r := gin.Default()
    
    // 登录接口
    r.POST("/login", func(c *gin.Context) {
        userID := c.PostForm("user_id")
        token, _ := sagin.Login(userID)  // 使用 sagin.Login
        c.JSON(200, gin.H{"token": token})
    })
    
    // 使用注解装饰器（类似Java）
    r.GET("/public", sagin.Ignore(), publicHandler)                  // 公开访问
    r.GET("/user", sagin.CheckLogin(), userHandler)                  // 需要登录
    r.GET("/admin", sagin.CheckPermission("admin:*"), adminHandler)  // 需要权限
    r.GET("/manager", sagin.CheckRole("manager"), managerHandler)    // 需要角色
    r.GET("/sensitive", sagin.CheckDisable(), sensitiveHandler)      // 检查封禁
    
    r.Run(":8080")
}
```

### 🎯 注解装饰器支持

**支持的注解：**

| 注解 | 说明 | 示例 |
|------|------|------|
| `@SaIgnore` | 忽略认证 | `sagin.Ignore()` |
| `@SaCheckLogin` | 检查登录 | `sagin.CheckLogin()` |
| `@SaCheckRole` | 检查角色 | `sagin.CheckRole("admin")` |
| `@SaCheckPermission` | 检查权限 | `sagin.CheckPermission("admin:*")` |
| `@SaCheckDisable` | 检查封禁 | `sagin.CheckDisable()` |

**使用示例：**

```go
import sagin "github.com/click33/sa-token-go/integrations/gin"

func main() {
    r := gin.Default()

    // 公开访问 - 忽略认证
    r.GET("/public", sagin.Ignore(), publicHandler)

    // 需要登录
    r.GET("/user/info", sagin.CheckLogin(), userInfoHandler)

    // 需要管理员权限
    r.GET("/admin", sagin.CheckPermission("admin:*"), adminHandler)

    // 需要多个权限之一（OR逻辑）
    r.GET("/user-or-admin",
        sagin.CheckPermission("user:read", "admin:*"),
        userOrAdminHandler)

    // 需要管理员角色
    r.GET("/manager", sagin.CheckRole("admin"), managerHandler)

    // 检查账号是否被封禁
    r.GET("/sensitive", sagin.CheckDisable(), sensitiveHandler)

    r.Run(":8080")
}
```

### 🌟 GoFrame 集成（单一导入）

**GoFrame 框架集成，支持完整功能！**

```go
import (
    "github.com/gogf/gf/v2/frame/g"
    "github.com/gogf/gf/v2/net/ghttp"
    sagf "github.com/click33/sa-token-go/integrations/gf"  // 只需这一个导入！
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // 初始化（sagf 包包含所有功能）
    storage := memory.NewStorage()
    config := sagf.DefaultConfig()
    manager := sagf.NewManager(storage, config)
    sagf.SetManager(manager)
    
    s := g.Server()
    
    // 登录接口
    s.BindHandler("POST:/login", func(r *ghttp.Request) {
        userID := r.Get("user_id").String()
        token, _ := sagf.Login(userID)
        r.Response.WriteJson(g.Map{"token": token})
    })
    
    // 使用注解式装饰器（类似 Java）
    s.BindHandler("GET:/public", sagf.Ignore(), publicHandler)                  // 公开访问
    s.BindHandler("GET:/user", sagf.CheckLogin(), userHandler)                  // 需要登录
    s.BindHandler("GET:/admin", sagf.CheckPermission("admin:*"), adminHandler)  // 需要权限
    s.BindHandler("GET:/manager", sagf.CheckRole("manager"), managerHandler)    // 需要角色
    s.BindHandler("GET:/sensitive", sagf.CheckDisable(), sensitiveHandler)      // 检查是否禁用
    
    s.SetPort(8080)
    s.Run()
}
```

### 🔌 其他框架集成

**Echo / Fiber / Chi / Kratos** 同样支持注解装饰器：

```go
// Echo
import saecho "github.com/click33/sa-token-go/integrations/echo"
e.GET("/user", saecho.CheckLogin(), handler)

// Fiber
import safiber "github.com/click33/sa-token-go/integrations/fiber"
app.Get("/user", safiber.CheckLogin(), handler)

// Chi
import sachi "github.com/click33/sa-token-go/integrations/chi"
r.Get("/user", sachi.CheckLogin(), handler)

// Kratos
import sakratos "github.com/click33/sa-token-go/integrations/kratos"
// 使用 Plugin.Server() 作为中间件
```

## 🎨 高级特性

### 🎨 Token 风格

Sa-Token-Go 支持 9 种 Token 生成风格：

| 风格 | 格式示例 | 长度 | 适用场景 |
|------|----------|------|----------|
| **UUID** | `550e8400-e29b-41d4-...` | 36 | 通用场景 |
| **Simple** | `aB3dE5fG7hI9jK1l` | 16 | 紧凑型Token |
| **Random32/64/128** | 随机字符串 | 32/64/128 | 高安全性 |
| **JWT** | `eyJhbGciOiJIUzI1...` | 可变 | 无状态认证 |
| **Hash** 🆕 | `a3f5d8b2c1e4f6a9...` | 64 | SHA256哈希 |
| **Timestamp** 🆕 | `1700000000123_user1000_...` | 可变 | 可追溯时间 |
| **Tik** 🆕 | `7Kx9mN2pQr4` | 11 | 短ID（类似抖音） |

**JWT Token 支持：**

```go
// 使用 JWT Token
stputil.SetManager(
    core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenStyle(core.TokenStyleJWT).          // 使用 JWT
        JwtSecretKey("your-256-bit-secret").     // JWT 密钥
        Timeout(3600).                           // 1小时过期
        Build(),
)

// 登录后获得 JWT Token
token, _ := stputil.Login(1000)
// 返回格式：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

[👉 查看 Token 风格示例](examples/token-styles/)

### 🔒 安全特性

#### 🔐 Nonce 防重放攻击

```go
// 生成nonce
nonce, _ := stputil.GenerateNonce()

// 验证nonce（一次性使用）
valid := stputil.VerifyNonce(nonce)  // true
valid = stputil.VerifyNonce(nonce)   // false（防止重放）
```

#### 🔄 Refresh Token 刷新机制

```go
// 登录获取访问令牌和刷新令牌
tokenInfo, _ := stputil.LoginWithRefreshToken(1000, "web")
fmt.Println("Access Token:", tokenInfo.AccessToken)
fmt.Println("Refresh Token:", tokenInfo.RefreshToken)

// 刷新访问令牌
newInfo, _ := stputil.RefreshAccessToken(tokenInfo.RefreshToken)
```

#### 🔑 OAuth2 授权码模式

```go
// 创建OAuth2服务器
oauth2Server := stputil.GetOAuth2Server()

// 注册客户端
oauth2Server.RegisterClient(&core.OAuth2Client{
    ClientID:     "webapp",
    ClientSecret: "secret123",
    RedirectURIs: []string{"http://localhost:8080/callback"},
    GrantTypes:   []core.OAuth2GrantType{core.GrantTypeAuthorizationCode},
    Scopes:       []string{"read", "write"},
})

// 生成授权码
authCode, _ := oauth2Server.GenerateAuthorizationCode(
    "webapp", "http://localhost:8080/callback", "user123", []string{"read"},
)

// 用授权码换取访问令牌
accessToken, _ := oauth2Server.ExchangeCodeForToken(
    authCode.Code, "webapp", "secret123", "http://localhost:8080/callback",
)
```

[👉 查看 OAuth2 完整示例](examples/oauth2-example/)

### 🎧 事件监听

监听认证和授权事件，实现审计日志、安全监控等功能：

```go
storage := memory.NewStorage()

manager := core.NewBuilder().
    Storage(storage).
    Build()

// 监听登录事件
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    fmt.Printf("[LOGIN] User: %s, Token: %s\n", data.LoginID, data.Token)
    // 记录审计日志、发送通知等
})

// 监听登出事件
manager.RegisterFunc(core.EventLogout, func(data *core.EventData) {
    fmt.Printf("[LOGOUT] User: %s\n", data.LoginID)
})

// 高级特性：优先级、同步执行
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(auditLogger),
    core.ListenerConfig{
        Priority: 100,   // 高优先级
        Async:    false, // 同步执行
    },
)

// 监听所有事件（通配符）
manager.RegisterFunc(core.EventAll, func(data *core.EventData) {
    log.Printf("[%s] %s", data.Event, data.LoginID)
})

// 可通过底层 EventManager 访问更多控制能力
manager.GetEventManager().SetPanicHandler(customPanicHandler)

// 设置全局管理器
stputil.SetManager(manager)
```

**可用事件：**

- `EventLogin` - 用户登录
- `EventLogout` - 用户登出  
- `EventKickout` - 强制下线
- `EventDisable` - 账号封禁
- `EventPermissionCheck` - 权限检查
- `EventRoleCheck` - 角色检查
- `EventAll` - 所有事件（通配符）

[→ 查看事件监听完整文档](docs/guide/listener_zh.md)

## 🏗️ 架构讨论

下面通过架构图来更直观地理解 sa-token-go 的设计思路和组件关系：

<img src="docs/IMG_3976.JPG" alt="sa-token-go 架构图" width="200px" height="300px" />

## 📦 项目结构

```
sa-token-go/
├── core/                    # 核心模块
│   ├── adapter/            # 适配器接口
│   ├── builder/            # Builder构建器
│   ├── config/             # 配置
│   ├── context/            # 上下文
│   ├── listener/           # 事件监听
│   ├── manager/            # 认证管理器
│   ├── oauth2/             # OAuth2实现 🆕
│   ├── security/           # 安全特性（Nonce、RefreshToken）🆕
│   ├── session/            # Session管理
│   ├── token/              # Token生成器
│   └── utils/              # 工具函数
│
├── stputil/                # 全局工具类
│
├── storage/                # 存储模块
│   ├── memory/             # 内存存储
│   └── redis/              # Redis存储
│
├── integrations/           # 框架集成
│   ├── gin/                # Gin集成（含注解）
│   ├── echo/               # Echo集成
│   ├── fiber/              # Fiber集成
│   ├── chi/                # Chi集成
│   └── gf/                 # GoFrame集成
│
├── examples/               # 示例项目
│   ├── quick-start/        # 快速开始
│   ├── token-styles/       # Token风格演示 🆕
│   ├── security-features/  # 安全特性演示 🆕
│   ├── oauth2-example/     # OAuth2完整示例 🆕
│   ├── annotation/         # 注解使用
│   ├── jwt-example/        # JWT示例
│   ├── redis-example/      # Redis示例
│   ├── listener-example/   # 事件监听示例
│   └── gin/echo/fiber/chi/ # 框架集成示例
│
└── docs/                   # 文档
    ├── tutorial/           # 教程
    ├── guide/              # 使用指南
    ├── api/                # API文档
    └── design/             # 设计文档
```

## 📚 文档与示例

### 📖 详细文档

- [快速开始](docs/tutorial/quick-start_zh.md) - 5分钟上手
- [登录认证](docs/guide/authentication_zh.md) - 登录认证详解
- [路径鉴权](docs/guide/path-auth_zh.md) - 路径鉴权详解
- [权限验证](docs/guide/permission_zh.md) - 权限系统详解
- [注解使用](docs/guide/annotation_zh.md) - 装饰器模式详解
- [事件监听](docs/guide/listener_zh.md) - 事件系统详解
- [JWT 使用](docs/guide/jwt_zh.md) - JWT Token 详解
- [Redis 存储](docs/guide/redis-storage_zh.md) - Redis 存储配置
- [Nonce 防重放](docs/guide/nonce_zh.md) - Nonce 防重放攻击
- [Refresh Token](docs/guide/refresh-token_zh.md) - 刷新令牌机制
- [OAuth2](docs/guide/oauth2_zh.md) - OAuth2 授权详解

### 📋 API 文档

- [StpUtil API](docs/api/stputil_zh.md) - 全局工具类完整API

### 🏗️ 设计文档

- [架构设计](docs/design/architecture_zh.md) - 系统架构、数据流转
- [自动续签设计](docs/design/auto-renew_zh.md) - 异步续签机制
- [模块化设计](docs/design/modular_zh.md) - 模块划分策略

### 💡 示例项目

| 示例 | 说明 | 路径 |
|------|------|------|
| ⚡ 快速开始 | Builder+StpUtil最简使用 | [examples/quick-start/](examples/quick-start/) |
| 🎨 Token风格 | 9种Token生成风格演示 | [examples/token-styles/](examples/token-styles/) |
| 🔒 安全特性 | Nonce/RefreshToken/OAuth2 | [examples/security-features/](examples/security-features/) |
| 🔐 OAuth2示例 | 完整OAuth2授权码流程 | [examples/oauth2-example/](examples/oauth2-example/) |
| 📝 注解使用 | 装饰器模式详解 | [examples/annotation/](examples/annotation/) |
| 🔑 JWT示例 | JWT Token使用 | [examples/jwt-example/](examples/jwt-example/) |
| 💾 Redis示例 | Redis存储配置 | [examples/redis-example/](examples/redis-example/) |
| 🎧 事件监听 | 事件系统使用 | [examples/listener-example/](examples/listener-example/) |
| 🌐 Gin集成 | Gin框架完整集成 | [examples/gin/](examples/gin/) |
| 🌐 Echo集成 | Echo框架集成 | [examples/echo/](examples/echo/) |
| 🌐 Fiber集成 | Fiber框架集成 | [examples/fiber/](examples/fiber/) |
| 🌐 Chi集成 | Chi框架集成 | [examples/chi/](examples/chi/) |
| 🌐 GoFrame集成 | GoFrame框架集成 | [examples/gf/](examples/gf/) |

### 💾 存储方案

- [Memory 存储](storage/memory/) - 用于开发环境
- [Redis 存储](storage/redis/) - 用于生产环境

## 📄 许可证

Apache License 2.0

## 🙏 致谢

参考 [sa-token](https://github.com/dromara/sa-token) 设计

### 贡献者

特别感谢以下贡献者的宝贵贡献：

- [@qprodn](https://github.com/qprodn)
- [@Zany2](https://github.com/Zany2)
- [@zyw](https://github.com/zyw)
- [@nuanxinqing123](https://github.com/nuanxinqing123)
- [@vera-byte](https://github.com/vera-byte)
- [@MoLing-Dong](https://github.com/MoLing-Dong)

## 📞 支持

- 💬 问题反馈: [GitHub Issues](https://github.com/click33/sa-token-go/issues)
- 📖 文档: [docs/](docs/)

---
