# Redis 存储配置指南

[English](redis-storage.md) | 中文文档

## 概述

Redis 存储是生产环境推荐的存储后端。它提供高性能、数据持久化，并支持分布式部署。

## 安装

```bash
# 安装 Redis 存储模块
go get github.com/click33/sa-token-go/storage/redis

# 安装 Redis 客户端
go get github.com/redis/go-redis/v9
```

## 支持的配置方式

Sa-Token-Go 的 Redis 存储支持以下几种配置方式：

| 方式 | 函数 | 适用场景 | 灵活性 | 支持集群/哨兵 |
|-----|------|---------|-------|-------------|
| **URL** | `redis.NewStorage(url)` | 简单配置，开发环境 | ⭐ | ❌ |
| **Builder** | `redis.NewBuilder().Build()` | 链式配置，推荐 | ⭐⭐⭐ | ❌ |
| **Config** | `redis.NewStorageFromConfig(cfg)` | 结构化配置 | ⭐⭐⭐ | ❌ |
| **Client** | `redis.NewStorageFromClient(rdb)` | 自定义客户端 | ⭐⭐⭐⭐⭐ | ✅ |

**推荐：**

- 开发/测试：使用 **URL** 或 **Builder** 方式
- 生产环境（单机）：使用 **Builder** 或 **Config** 方式
- 生产环境（集群/哨兵）：使用 **Client** 方式 + `goredis.NewClusterClient` 或 `goredis.NewFailoverClient`

## 基本使用

### 1. 使用 Redis URL（最简单）

```go
package main

import (
    "fmt"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/redis"
)

func main() {
    // 使用 Redis URL
    redisStorage, err := redis.NewStorage("redis://localhost:6379/0")
    if err != nil {
        panic(err)
    }

    // 使用 Redis 存储初始化 Sa-Token
    stputil.SetManager(
        core.NewBuilder().
            Storage(redisStorage).
            TokenName("Authorization").
            Timeout(86400).        // 24小时
            KeyPrefix("satoken").  // 键前缀（自动添加冒号）
            Build(),
    )

    // 现在可以使用 Sa-Token 了
    token, _ := stputil.Login("1000")
    fmt.Println("登录成功，Token:", token)
}
```

### 2. 带密码认证

```go
// 使用 Redis URL（推荐）
redisStorage, err := redis.NewStorage("redis://:your-redis-password@localhost:6379/0")
if err != nil {
    panic(err)
}

stputil.SetManager(
    core.NewBuilder().
        Storage(redisStorage).
        KeyPrefix("satoken").  // 键前缀
        Build(),
)
```

### 3. 使用 Redis Builder（推荐）

```go
// 使用 Builder 模式配置
redisStorage, err := redis.NewBuilder().
    Host("localhost").
    Port(6379).
    Password("your-password").
    Database(0).
    PoolSize(10).
    Build()
if err != nil {
    panic(err)
}

stputil.SetManager(
    core.NewBuilder().
        Storage(redisStorage).
        KeyPrefix("satoken").
        Build(),
)
```

### 4. 使用自定义 Redis 客户端（✅ 完全支持）

**适用场景：** 需要自定义连接池、超时、重试等高级配置，或使用 Redis 集群/哨兵模式

#### 4.1 标准 Redis 单机

```go
import (
    goredis "github.com/redis/go-redis/v9"
    "github.com/click33/sa-token-go/storage/redis"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
)

// 创建自定义 Redis 客户端
rdb := goredis.NewClient(&goredis.Options{
    Addr:     "localhost:6379",
    Password: "your-password",
    DB:       0,
    PoolSize: 10,
})

// 从已有客户端创建存储（✅ 核心方法）
redisStorage := redis.NewStorageFromClient(rdb)

stputil.SetManager(
    core.NewBuilder().
        Storage(redisStorage).
        KeyPrefix("satoken").
        Build(),
)
```

#### 4.2 Redis 集群模式

```go
// 创建 Redis 集群客户端
rdb := goredis.NewClusterClient(&goredis.ClusterOptions{
    Addrs: []string{
        "localhost:7000",
        "localhost:7001",
        "localhost:7002",
    },
    Password: "your-password",
    PoolSize: 20,
})

// 从集群客户端创建存储（✅ 支持集群）
redisStorage := redis.NewStorageFromClient(rdb)

stputil.SetManager(
    core.NewBuilder().
        Storage(redisStorage).
        KeyPrefix("satoken").
        Build(),
)
```

#### 4.3 Redis 哨兵模式

```go
// 创建 Redis 哨兵客户端
rdb := goredis.NewFailoverClient(&goredis.FailoverOptions{
    MasterName:    "mymaster",
    SentinelAddrs: []string{
        "localhost:26379",
        "localhost:26380",
        "localhost:26381",
    },
    Password: "your-password",
    DB:       0,
})

// 从哨兵客户端创建存储（✅ 支持哨兵）
redisStorage := redis.NewStorageFromClient(rdb)

stputil.SetManager(
    core.NewBuilder().
        Storage(redisStorage).
        KeyPrefix("satoken").
        Build(),
)
```

## 高级配置

### 完整配置示例

```go
package main

import (
    "time"
    
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/redis"
    goredis "github.com/redis/go-redis/v9"
)

func main() {
    // Redis 客户端完整选项
    rdb := goredis.NewClient(&goredis.Options{
        Addr:         "localhost:6379",
        Password:     "",
        DB:           0,
        PoolSize:     10,              // 连接池大小
        MinIdleConns: 5,               // 最小空闲连接数
        MaxRetries:   3,               // 最大重试次数
        DialTimeout:  5 * time.Second,
        ReadTimeout:  3 * time.Second,
        WriteTimeout: 3 * time.Second,
        PoolTimeout:  4 * time.Second,
    })

    // 从自定义客户端创建存储
    redisStorage := redis.NewStorageFromClient(rdb)

    // 使用 Redis 初始化 Sa-Token（完整参数）
    stputil.SetManager(
        core.NewBuilder().
            Storage(redisStorage).
            TokenName("Authorization").      // Token 名称
            TokenStyle(core.TokenStyleJWT).  // Token 风格
            JwtSecretKey("your-secret-key"). // JWT 密钥
            Timeout(7200).                   // Token 超时时间（秒）
            IsConcurrent(true).              // 是否允许并发登录
            IsShare(false).                  // 是否共享 Token（false=每次登录新Token）
            MaxLoginCount(5).                // 最多并发登录数
            AutoRenew(true).                 // 是否自动续期
            IsReadHeader(true).              // 是否从 Header 读取 Token
            IsReadCookie(false).             // 是否从 Cookie 读取 Token
            IsReadBody(false).               // 是否从 Body 读取 Token
            KeyPrefix("satoken").            // Redis 键前缀（自动添加:）
            IsPrintBanner(true).             // 是否打印启动横幅
            IsLog(false).                    // 是否启用日志
            Build(),
    )

    // 使用 Sa-Token
    token, _ := stputil.Login("1000")
    println("Token:", token)
}
```

### 连接池配置

```go
rdb := goredis.NewClient(&goredis.Options{
    Addr:     "localhost:6379",
    
    // 连接池设置
    PoolSize:     100,              // 最大连接数
    MinIdleConns: 10,               // 最小空闲连接数
    MaxIdleConns: 50,               // 最大空闲连接数
    
    // 超时设置
    DialTimeout:  5 * time.Second,  // 连接超时
    ReadTimeout:  3 * time.Second,  // 读取超时
    WriteTimeout: 3 * time.Second,  // 写入超时
    PoolTimeout:  4 * time.Second,  // 连接池获取超时
    
    // 重试设置
    MaxRetries:      3,              // 最大重试次数
    MinRetryBackoff: 8 * time.Millisecond,
    MaxRetryBackoff: 512 * time.Millisecond,
})
```

## 环境变量

### 使用环境变量

#### 方式1: 使用 Redis URL（推荐）

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/redis"
)

func main() {
    // 从环境变量构建 Redis URL
    redisAddr := os.Getenv("REDIS_ADDR")
    if redisAddr == "" {
        redisAddr = "localhost:6379"
    }
    
    redisPassword := os.Getenv("REDIS_PASSWORD")
    redisDB := os.Getenv("REDIS_DB")
    if redisDB == "" {
        redisDB = "0"
    }
    
    // 构建 Redis URL
    redisURL := fmt.Sprintf("redis://:%s@%s/%s", redisPassword, redisAddr, redisDB)
    
    redisStorage, err := redis.NewStorage(redisURL)
    if err != nil {
        panic(err)
    }

    stputil.SetManager(
        core.NewBuilder().
            Storage(redisStorage).
            JwtSecretKey(os.Getenv("JWT_SECRET_KEY")).
            KeyPrefix("satoken").
            Build(),
    )
}
```

#### 方式2: 使用自定义客户端

```go
package main

import (
    "os"
    "strconv"
    
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/redis"
    goredis "github.com/redis/go-redis/v9"
)

func main() {
    // 从环境变量读取配置
    redisAddr := os.Getenv("REDIS_ADDR")
    if redisAddr == "" {
        redisAddr = "localhost:6379"
    }
    
    redisPassword := os.Getenv("REDIS_PASSWORD")
    redisDB, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
    
    rdb := goredis.NewClient(&goredis.Options{
        Addr:     redisAddr,
        Password: redisPassword,
        DB:       redisDB,
    })

    stputil.SetManager(
        core.NewBuilder().
            Storage(redis.NewStorageFromClient(rdb)).  // ← 使用 NewStorageFromClient
            JwtSecretKey(os.Getenv("JWT_SECRET_KEY")).
            KeyPrefix("satoken").
            Build(),
    )
}
```

### .env 文件示例

```bash
# Redis 配置
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=your-password
REDIS_DB=0

# Sa-Token 配置
JWT_SECRET_KEY=your-256-bit-secret-key
TOKEN_TIMEOUT=7200
```

## Redis 键结构

Sa-Token-Go 在 Redis 中使用以下键模式（**完全兼容 Java sa-token**）：

```
# 认证相关
satoken:token:{tokenValue}           # Token -> LoginID 映射（只存 loginID 字符串）
satoken:account:{loginID}:{device}   # Account -> Token 映射

# Session 和权限
satoken:session:{loginID}            # 用户 Session 数据（存储完整的用户对象）
satoken:login:permission:{loginID}   # 用户权限列表
satoken:login:role:{loginID}         # 用户角色列表

# 账号管理
satoken:disable:{loginID}            # 账号禁用状态
```

### 键值存储示例

```bash
# Token 键（轻量级，只存 loginID）
Key:   satoken:token:6R9twUC-OL_uL6JQFKfncyoVuK3NlDL2...
Value: 1000                          # 只是简单的字符串（4 bytes）

# Account 键（loginID -> Token）
Key:   satoken:account:1000:log
Value: 6R9twUC-OL_uL6JQFKfncyoVuK3NlDL2...

# Session 键（存储完整用户对象和自定义数据）
Key:   satoken:session:1000
Value: {
  "id": "1000",
  "createTime": 1698123456,
  "data": {
    "user": {...完整的 User 对象...},
    "loginTime": 1698123456,
    "loginIP": "192.168.1.100"
  }
}
```

### 在 Redis CLI 中查看键

```bash
# 连接到 Redis
redis-cli -h localhost -p 6379

# 列出所有 Sa-Token 键
KEYS satoken:*

# 查看 Token 映射（返回 loginID）
GET satoken:token:6R9twUC-OL_uL6JQFKfncyoVuK3NlDL2...
# 输出: "1000"

# 查看 Account 映射（返回 Token）
GET satoken:account:1000:log
# 输出: "6R9twUC-OL_uL6JQFKfncyoVuK3NlDL2..."

# 查看用户 Session（包含完整用户数据）
GET satoken:session:1000
# 输出: JSON 格式的 Session 数据

# 查看用户权限
GET satoken:login:permission:1000

# 查看用户角色
GET satoken:login:role:1000

# 查看 TTL（剩余生存时间）
TTL satoken:token:6R9twUC-OL_uL6JQFKfncyoVuK3NlDL2...
# 输出: 3600 (秒)
```

### 设计原则（兼容 Java sa-token）

1. **Token 键轻量级**：只存储 `loginID` 字符串，不存储复杂对象
2. **Session 存储完整数据**：用户对象、权限、角色等存在 Session 中
3. **键前缀统一**：Manager 层统一管理 `satoken:` 前缀
4. **过期时间自动设置**：根据 `Timeout` 配置自动设置 TTL

## 生产环境最佳实践

### 1. 连接池配置

```go
rdb := goredis.NewClient(&goredis.Options{
    Addr:         "localhost:6379",
    PoolSize:     100,  // 根据负载调整
    MinIdleConns: 10,   // 保持一些连接活跃
})
```

### 2. 错误处理

```go
rdb := goredis.NewClient(&goredis.Options{
    Addr:     "localhost:6379",
    Password: os.Getenv("REDIS_PASSWORD"),
})

// 测试连接
ctx := context.Background()
if err := rdb.Ping(ctx).Err(); err != nil {
    log.Fatalf("无法连接到 Redis: %v", err)
}
```

### 3. 高可用（哨兵模式）

```go
rdb := goredis.NewFailoverClient(&goredis.FailoverOptions{
    MasterName:    "mymaster",
    SentinelAddrs: []string{
        "sentinel1:26379",
        "sentinel2:26379",
        "sentinel3:26379",
    },
    Password: os.Getenv("REDIS_PASSWORD"),
    DB:       0,
    
    // 哨兵选项
    SentinelPassword: os.Getenv("SENTINEL_PASSWORD"),
    
    // 连接池
    PoolSize:     100,
    MinIdleConns: 10,
})
```

### 4. TLS/SSL 支持

```go
import "crypto/tls"

rdb := goredis.NewClient(&goredis.Options{
    Addr:     "localhost:6379",
    Password: os.Getenv("REDIS_PASSWORD"),
    
    // 启用 TLS
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
})
```

### 5. 优雅关闭

```go
func main() {
    rdb := goredis.NewClient(&goredis.Options{
        Addr: "localhost:6379",
    })
    
    stputil.SetManager(
        core.NewBuilder().
            Storage(redis.NewStorage(rdb)).
            Build(),
    )

    // ... 你的应用代码 ...

    // 优雅关闭
    defer func() {
        if err := rdb.Close(); err != nil {
            log.Printf("关闭 Redis 时出错: %v", err)
        }
    }()
}
```

## 性能优化

### 1. 使用管道

Sa-Token-Go 的 Redis 存储自动为批量操作使用管道。

### 2. 键过期时间

Sa-Token 会根据你的 `Timeout` 配置自动设置键的过期时间：

```go
core.NewBuilder().
    Timeout(3600).  // 键将在1小时后过期
    Build()
```

### 3. 连接复用

Redis 客户端维护连接池以获得最佳性能：

```go
rdb := goredis.NewClient(&goredis.Options{
    PoolSize:     100,  // 复用最多100个连接
    MinIdleConns: 10,   // 始终保持10个热连接
})
```

## 监控

### 检查 Redis 状态

```go
import "context"

ctx := context.Background()

// Ping
pong, err := rdb.Ping(ctx).Err()
if err != nil {
    log.Printf("Redis ping 失败: %v", err)
}

// 获取信息
info, err := rdb.Info(ctx).Result()
if err != nil {
    log.Printf("获取 Redis 信息失败: %v", err)
}
println(info)
```

### 监控键数量

```bash
# 在 Redis CLI 中
INFO keyspace

# 输出示例：
# db0:keys=1234,expires=567,avg_ttl=3600000
```

## 故障排查

### 连接被拒绝

```go
// 问题：无法连接到 Redis
// 解决方案：检查 Redis 是否运行
// 命令：redis-cli ping
```

### 认证失败

```go
// 问题：NOAUTH Authentication required
// 解决方案：设置正确的密码
rdb := goredis.NewClient(&goredis.Options{
    Addr:     "localhost:6379",
    Password: "correct-password",
})
```

### 连接数过多

```go
// 问题：ERR max number of clients reached
// 解决方案：增加 Redis 最大客户端数或减少连接池大小
// Redis 配置：maxclients 10000

rdb := goredis.NewClient(&goredis.Options{
    PoolSize: 50, // 减少连接池大小
})
```

## Docker 部署

### Docker Compose 示例

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass your-password
    volumes:
      - redis-data:/data
    restart: unless-stopped

  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=your-password
      - JWT_SECRET_KEY=your-secret-key
    depends_on:
      - redis

volumes:
  redis-data:
```

### 应用代码

```go
// 在你的 Go 应用中
func main() {
    rdb := goredis.NewClient(&goredis.Options{
        Addr:     os.Getenv("REDIS_ADDR"),     // redis:6379
        Password: os.Getenv("REDIS_PASSWORD"),
        DB:       0,
    })

    stputil.SetManager(
        core.NewBuilder().
            Storage(redis.NewStorage(rdb)).
            JwtSecretKey(os.Getenv("JWT_SECRET_KEY")).
            Build(),
    )
    
    // 启动你的 Web 服务器...
}
```

## Kubernetes 部署

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: satoken-config
data:
  REDIS_ADDR: "redis-service:6379"
  REDIS_DB: "0"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: satoken-secret
type: Opaque
stringData:
  REDIS_PASSWORD: "your-redis-password"
  JWT_SECRET_KEY: "your-jwt-secret-key"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: satoken-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        - name: REDIS_ADDR
          valueFrom:
            configMapKeyRef:
              name: satoken-config
              key: REDIS_ADDR
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: satoken-secret
              key: REDIS_PASSWORD
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: satoken-secret
              key: JWT_SECRET_KEY
```

## 对比：Memory vs Redis

| 特性 | Memory | Redis |
|------|--------|-------|
| 性能 | 优秀 | 很好 |
| 持久化 | ❌ 重启丢失 | ✅ 持久化 |
| 分布式 | ❌ 不支持 | ✅ 支持 |
| 扩展性 | 有限 | 优秀 |
| 配置 | 简单 | 需要 Redis |
| 适用场景 | 开发/测试 | 生产环境 |

## 完整示例

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/redis"
    sagin "github.com/click33/sa-token-go/integrations/gin"
    goredis "github.com/redis/go-redis/v9"
)

func main() {
    // 初始化 Redis
    rdb := goredis.NewClient(&goredis.Options{
        Addr:     os.Getenv("REDIS_ADDR"),
        Password: os.Getenv("REDIS_PASSWORD"),
        DB:       0,
        
        PoolSize:     100,
        MinIdleConns: 10,
        DialTimeout:  5 * time.Second,
        ReadTimeout:  3 * time.Second,
        WriteTimeout: 3 * time.Second,
    })

    // 测试 Redis 连接
    ctx := context.Background()
    if err := rdb.Ping(ctx).Err(); err != nil {
        log.Fatalf("无法连接到 Redis: %v", err)
    }

    // 初始化 Sa-Token
    stputil.SetManager(
        core.NewBuilder().
            Storage(redis.NewStorage(rdb)).
            TokenName("Authorization").
            TokenStyle(core.TokenStyleJWT).
            JwtSecretKey(os.Getenv("JWT_SECRET_KEY")).
            Timeout(7200).
            ActiveTimeout(1800).
            IsConcurrent(true).
            IsShare(false).
            MaxLoginCount(5).
            AutoRenew(true).
            IsReadHeader(true).
            IsPrintBanner(true).
            IsLog(true).
            Build(),
    )

    // 设置 Gin
    r := gin.Default()
    r.Use(sagin.NewPlugin(stputil.GetManager()).Build())

    // 路由
    r.POST("/login", loginHandler)
    r.GET("/user/info", sagin.CheckLogin(), userInfoHandler)
    r.GET("/admin", sagin.CheckPermission("admin"), adminHandler)

    // 启动服务器
    if err := r.Run(":8080"); err != nil {
        log.Fatal(err)
    }

    // 优雅关闭
    defer rdb.Close()
}

func loginHandler(c *gin.Context) {
    // ... 登录逻辑 ...
}

func userInfoHandler(c *gin.Context) {
    // ... 用户信息逻辑 ...
}

func adminHandler(c *gin.Context) {
    // ... 管理员逻辑 ...
}
```

## 相关文档

- [快速开始](../tutorial/quick-start.md)
- [Memory 存储](../../storage/memory/)
- [认证指南](authentication.md)
- [JWT 指南](jwt.md)

## Redis 资源

- [Redis 官方网站](https://redis.io/)
- [go-redis 文档](https://redis.uptrace.dev/)
- [Redis 命令](https://redis.io/commands/)
