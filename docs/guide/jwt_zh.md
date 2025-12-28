# JWT Token 使用指南

[English](jwt.md) | 中文文档

## 简介

JWT（JSON Web Token）是一种无状态的 Token 方案，Token 本身包含了用户信息和过期时间，非常适合分布式系统。

Sa-Token-Go 完整支持 JWT Token，你可以通过简单的配置切换到 JWT 模式。

## JWT 优势

- ✅ **无状态**：不需要服务端存储 Session
- ✅ **分布式友好**：多个服务可以独立验证
- ✅ **信息自包含**：Token 包含用户信息
- ✅ **跨域支持**：可以跨不同域使用
- ✅ **标准化**：遵循 RFC 7519 标准

## JWT 结构

JWT 由三部分组成，用 `.` 分隔：

```
Header.Payload.Signature
```

**示例：**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbklkIjoiMTAwMCIsImRldmljZSI6IiIsImlhdCI6MTY5NzIzNDU2NywiZXhwIjoxNjk3MjM4MTY3fQ.xxx
```

### 各部分说明

- **Header（头部）**：Token 类型和加密算法
  ```json
  {
    "alg": "HS256",
    "typ": "JWT"
  }
  ```

- **Payload（载荷）**：用户数据
  ```json
  {
    "loginId": "1000",
    "device": "",
    "iat": 1697234567,  // 签发时间
    "exp": 1697238167   // 过期时间
  }
  ```

- **Signature（签名）**：使用密钥加密前两部分
  ```
  HMACSHA256(
    base64UrlEncode(header) + "." + base64UrlEncode(payload),
    secret
  )
  ```

## 基本使用

### 1. 配置 JWT

```go
import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/memory"
)

func init() {
    stputil.SetManager(
        core.NewBuilder().
            Storage(memory.NewStorage()).
            TokenStyle(core.TokenStyleJWT).                    // 使用 JWT
            JwtSecretKey("your-256-bit-secret-key-here").    // 设置密钥（必需）
            Timeout(3600).                                     // Token 过期时间（秒）
            Build(),
    )
}
```

### 2. 登录获取 JWT Token

```go
// 登录
token, err := stputil.Login(1000)
if err != nil {
    panic(err)
}

fmt.Println("JWT Token:", token)
// 输出：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. 验证 JWT Token

```go
// 验证 Token 是否有效
if stputil.IsLogin(token) {
    fmt.Println("Token 有效")
    
    // 获取登录 ID
    loginID, _ := stputil.GetLoginID(token)
    fmt.Println("登录ID:", loginID)
}
```

### 4. 解析 JWT

你可以使用 [jwt.io](https://jwt.io) 在线工具解析 JWT Token 查看内容。

**Payload 示例：**
```json
{
  "loginId": "1000",
  "device": "",
  "iat": 1697234567,
  "exp": 1697238167
}
```

## 高级配置

### 完整配置示例

```go
stputil.SetManager(
    core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenName("Authorization").             // Token 名称
        TokenStyle(core.TokenStyleJWT).         // JWT 模式
        JwtSecretKey("your-secret-key").        // JWT 密钥
        Timeout(7200).                          // 2小时过期
        AutoRenew(true).                        // 自动续期
        IsPrintBanner(true).                    // 显示启动 Banner
        IsReadHeader(true).                     // 从 Header 读取
        Build(),
)
```

### 配置项说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `TokenStyle` | Token 风格，设为 `TokenStyleJWT` | `TokenStyleUUID` |
| `JwtSecretKey` | JWT 签名密钥（必需） | `""` |
| `Timeout` | Token 过期时间（秒） | `2592000`（30天） |
| `AutoRenew` | 是否自动续期 | `true` |
| `IsReadHeader` | 是否从 Header 读取 | `true` |
| `IsReadCookie` | 是否从 Cookie 读取 | `false` |
| `IsReadBody` | 是否从 Body 读取 | `false` |

## 安全最佳实践

### 1. 使用强密钥

```go
// ❌ 弱密钥（不安全）
JwtSecretKey("secret")
JwtSecretKey("123456")

// ✅ 强密钥（推荐至少 32 字节）
JwtSecretKey("a-very-long-and-random-secret-key-at-least-256-bits")
JwtSecretKey("8f3b5d7a9c2e1f4d6b8a0c2e4f6d8a1b3c5e7f9a2c4e6d8f0a2c4e6d8f0a2c4e")
```

### 2. 从环境变量读取密钥

```go
import "os"

stputil.SetManager(
    core.NewBuilder().
        Storage(memory.NewStorage()).
        TokenStyle(core.TokenStyleJWT).
        JwtSecretKey(os.Getenv("JWT_SECRET_KEY")).  // 从环境变量读取
        Build(),
)
```

### 3. 设置合理的过期时间

```go
// 短期 Token（推荐）
Timeout(3600)   // 1小时
Timeout(7200)   // 2小时

// 长期 Token（需要配合刷新机制）
Timeout(86400)  // 24小时
Timeout(604800) // 7天
```

### 4. 使用 HTTPS

JWT Token 应该通过 HTTPS 传输，防止被中间人截获。

### 5. 不在 JWT 中存储敏感信息

JWT Payload 是 Base64 编码的，可以被解码。不要存储密码、信用卡等敏感信息。

```go
// ❌ 不要这样做
payload := map[string]interface{}{
    "loginId": 1000,
    "password": "123456",  // 危险！
}

// ✅ 只存储必要的标识信息
payload := map[string]interface{}{
    "loginId": 1000,
    "device": "mobile",
}
```

## JWT vs 普通 Token

| 特性 | JWT | UUID/Random |
|------|-----|-------------|
| 状态 | 无状态 | 有状态 |
| 服务端存储 | 不需要 | 需要 Redis/数据库 |
| Token 大小 | 较大（几百字节） | 较小（32-128字节） |
| 可撤销性 | 困难（需要黑名单） | 容易（删除存储） |
| 分布式 | 优秀（独立验证） | 需要共享存储 |
| 性能 | 高（不查数据库） | 中等（需查询） |
| 续期 | 需要刷新 Token | 直接延长过期时间 |

## 使用场景

### ✅ 适合 JWT 的场景

- **微服务架构**：各服务独立验证 Token
- **无状态 API**：RESTful API
- **跨域认证**：不同域名的服务
- **短期访问令牌**：有明确过期时间
- **移动应用**：App 端认证

### ❌ 不适合 JWT 的场景

- **需要立即撤销**：无法立即让 Token 失效
- **频繁更新权限**：权限变化不会反映到已签发的 Token
- **长期会话**：JWT 无法像 Session 那样自动续期
- **存储敏感信息**：JWT 可以被解码

## 常见问题

### Q1: JWT Token 可以被撤销吗？

A: JWT 是无状态的，签发后无法直接撤销。解决方案：

1. **设置短过期时间**：Token 很快就会自然失效
2. **使用黑名单**：将需要撤销的 Token 加入黑名单
3. **混合方案**：JWT + 服务端验证

```go
// 黑名单示例
func (m *Manager) RevokeToken(token string) {
    // 将 token 加入黑名单
    m.storage.Set("blacklist:"+token, "1", time.Hour*24)
}

func (m *Manager) IsTokenRevoked(token string) bool {
    return m.storage.Exists("blacklist:" + token)
}
```

### Q2: JWT 如何续期？

A: JWT 续期有两种方案：

**方案一：刷新 Token**
```go
// 签发新的 Token
newToken, _ := stputil.Login(loginID)
```

**方案二：双 Token 机制**
```go
// Access Token（短期）
accessToken := generateJWT(loginID, 15*time.Minute)

// Refresh Token（长期）
refreshToken := generateJWT(loginID, 7*24*time.Hour)
```

### Q3: JWT 密钥可以修改吗？

A: 可以修改，但会导致已签发的 Token 失效。建议：

1. **灰度切换**：同时支持新旧密钥
2. **计划维护**：在低峰期统一更换
3. **定期轮换**：每 3-6 个月轮换一次密钥

### Q4: JWT Token 太长怎么办？

A: JWT Token 通常 200-500 字节，解决方案：

1. **减少 Payload**：只包含必要信息
2. **使用压缩**：启用 gzip 压缩
3. **使用普通 Token**：如果 Token 长度是问题

## 完整示例

### Web API 示例

```go
package main

import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/click33/sa-token-go/integrations/gin"
    "github.com/gin-gonic/gin"
)

func main() {
    // 初始化 JWT
    stputil.SetManager(
        core.NewBuilder().
            Storage(memory.NewStorage()).
            TokenStyle(core.TokenStyleJWT).
            JwtSecretKey("your-secret-key").
            Timeout(7200).  // 2小时
            Build(),
    )

    r := gin.Default()
    
    // 注册 Sa-Token 插件
    r.Use(sagin.NewPlugin().Build())

    // 登录接口
    r.POST("/login", func(c *gin.Context) {
        username := c.PostForm("username")
        password := c.PostForm("password")
        
        // 验证用户名密码（示例）
        if username == "admin" && password == "123456" {
            token, _ := stputil.Login(1000)
            c.JSON(200, gin.H{
                "code":    0,
                "message": "登录成功",
                "token":   token,
            })
        } else {
            c.JSON(401, gin.H{
                "code":    -1,
                "message": "用户名或密码错误",
            })
        }
    })

    // 需要认证的接口
    r.GET("/user/info", func(c *gin.Context) {
        // 从 Header 获取 Token
        ctx := sagin.GetRequestContext(c)
        token := ctx.GetHeader("Authorization")
        
        // 验证登录
        if !stputil.IsLogin(token) {
            c.JSON(401, gin.H{
                "code":    -1,
                "message": "未登录",
            })
            return
        }
        
        // 获取登录 ID
        loginID, _ := stputil.GetLoginID(token)
        
        c.JSON(200, gin.H{
            "code":    0,
            "message": "success",
            "loginId": loginID,
        })
    })

    r.Run(":8080")
}
```

### 客户端使用

```bash
# 登录
curl -X POST http://localhost:8080/login \
  -d "username=admin&password=123456"

# 返回
{
  "code": 0,
  "message": "登录成功",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# 访问接口（在 Header 中携带 Token）
curl http://localhost:8080/user/info \
  -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 相关文档

- [快速开始](../tutorial/quick-start.md)
- [认证指南](authentication.md)
- [配置说明](configuration.md)
- [JWT 示例代码](../../examples/manager-example/jwt-example/)

## 在线工具

- [JWT.io](https://jwt.io) - JWT 调试工具
- [JWT Inspector](https://jwt-inspector.netlify.app/) - JWT 检查器
- [Base64 Decode](https://www.base64decode.org/) - Base64 解码

