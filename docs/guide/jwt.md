# JWT Token Guide

[中文文档](jwt_zh.md) | English

## Introduction

JWT (JSON Web Token) is a stateless token solution. The token itself contains user information and expiration time, making it ideal for distributed systems.

## JWT Advantages

- ✅ **Stateless**: No need for server-side session storage
- ✅ **Distributed-friendly**: Multiple services can validate independently
- ✅ **Self-contained**: Token contains user information
- ✅ **Cross-domain support**: Can be used across different domains

## JWT Structure

JWT consists of three parts separated by `.`:

```
Header.Payload.Signature
```

**Example:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbklkIjoiMTAwMCIsImRldmljZSI6IiIsImlhdCI6MTY5NzIzNDU2NywiZXhwIjoxNjk3MjM4MTY3fQ.xxx
```

## Basic Usage

### 1. Configure JWT

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
            TokenStyle(core.TokenStyleJWT).              // Use JWT
            JwtSecretKey("your-256-bit-secret-key").    // Set secret key
            Timeout(3600).                               // 1 hour
            Build(),
    )
}
```

### 2. Login with JWT

```go
// Login and get JWT token
token, _ := stputil.Login(1000)
// Returns: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Validate JWT

```go
// Validate token
if stputil.IsLogin(token) {
    fmt.Println("Token is valid")
}

// Get login ID
loginID, _ := stputil.GetLoginID(token)
```

## Security Best Practices

### 1. Use Strong Secret Key

```go
// ❌ Weak key
JwtSecretKey("secret")

// ✅ Strong key (at least 32 bytes recommended)
JwtSecretKey("a-very-long-and-random-secret-key-at-least-256-bits")
```

### 2. Set Reasonable Expiration

```go
// Short-term token (recommended)
Timeout(3600)   // 1 hour
Timeout(7200)   // 2 hours

// Long-term token (needs refresh mechanism)
Timeout(86400)  // 24 hours
```

### 3. Read from Environment Variables

```go
import "os"

JwtSecretKey(os.Getenv("JWT_SECRET_KEY"))
```

## JWT vs Regular Token

| Feature | JWT | UUID/Random |
|---------|-----|-------------|
| State | Stateless | Stateful |
| Server Storage | Not needed | Required |
| Token Size | Larger | Smaller |
| Revocability | Difficult | Easy |
| Distributed | Excellent | Needs shared storage |
| Performance | High | Medium |

## Related Documentation

- [Quick Start](../tutorial/quick-start.md)
- [Authentication Guide](authentication.md)
- [JWT Example](../../examples/manager-example/jwt-example/README.md)
