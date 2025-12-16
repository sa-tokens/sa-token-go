English | [中文文档](nonce_zh.md)

# Nonce Anti-Replay Attack

## What is a Replay Attack?

A replay attack occurs when an attacker intercepts and resends legitimate requests for malicious purposes. Examples:
- Intercepting transfer requests and resending to cause multiple debits
- Intercepting login requests to obtain multiple tokens
- Intercepting operation requests to repeat sensitive actions

## Nonce Anti-Replay Principle

**Nonce** (Number used once) is a one-time random number:
1. Server generates unique nonce
2. Client includes nonce in request
3. Server validates nonce and immediately deletes it
4. Same nonce cannot be used again

## Quick Start

### Basic Usage

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
            Build(),
    )
}

func main() {
    // 1. Generate nonce
    nonce, err := stputil.GenerateNonce()
    if err != nil {
        panic(err)
    }
    fmt.Println("Nonce:", nonce)
    // Output: 64-char hexadecimal string
    
    // 2. First verification (success)
    valid := stputil.VerifyNonce(nonce)
    fmt.Println("First verify:", valid)  // true
    
    // 3. Second verification (fail - replay prevented)
    valid = stputil.VerifyNonce(nonce)
    fmt.Println("Second verify:", valid)  // false
}
```

## Complete Workflow

### 1. API Endpoint Protection

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/click33/sa-token-go/stputil"
)

func main() {
    r := gin.Default()
    
    // Generate nonce
    r.GET("/nonce", func(c *gin.Context) {
        nonce, err := stputil.GenerateNonce()
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"nonce": nonce})
    })
    
    // Nonce-protected API
    r.POST("/transfer", func(c *gin.Context) {
        nonce := c.GetHeader("X-Nonce")
        
        // Verify nonce
        if !stputil.VerifyNonce(nonce) {
            c.JSON(401, gin.H{"error": "Invalid or expired nonce"})
            return
        }
        
        // Execute transfer logic
        amount := c.PostForm("amount")
        c.JSON(200, gin.H{
            "message": "Transfer successful",
            "amount":  amount,
        })
    })
    
    r.Run(":8080")
}
```

### 2. Client Usage

```go
// Step 1: Get nonce
resp1, _ := http.Get("http://localhost:8080/nonce")
var result map[string]string
json.NewDecoder(resp1.Body).Decode(&result)
nonce := result["nonce"]

// Step 2: Make request with nonce
req, _ := http.NewRequest("POST", "http://localhost:8080/transfer", nil)
req.Header.Set("X-Nonce", nonce)
req.PostForm = url.Values{
    "amount": []string{"100"},
}

resp2, _ := http.DefaultClient.Do(req)
// Transfer successful

// Step 3: Repeat request (will fail)
resp3, _ := http.DefaultClient.Do(req)
// Fail: Invalid or expired nonce
```

## Nonce Configuration

### Custom TTL

```go
import "time"

// Method 1: Via Manager
manager := core.NewBuilder().
    Storage(storage).
    Build()

// Get NonceManager with custom TTL
nonceManager := core.NewNonceManager(storage, 300) // 5 minutes (seconds)
```

### Default Configuration

```go
// Default TTL: 5 minutes
// Default length: 64 characters (32 bytes hex)
```

## Advanced Usage

### 1. Middleware Protection

```go
func NonceMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Skip GET requests
        if c.Request.Method == "GET" {
            c.Next()
            return
        }
        
        nonce := c.GetHeader("X-Nonce")
        
        if !stputil.VerifyNonce(nonce) {
            c.JSON(401, gin.H{"error": "Invalid or expired nonce"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// Usage
r.Use(NonceMiddleware())
```

### 2. Protect Sensitive Operations

```go
// Protect only sensitive operations
r.POST("/delete-account", NonceMiddleware(), deleteAccountHandler)
r.POST("/transfer-money", NonceMiddleware(), transferHandler)
r.POST("/change-password", NonceMiddleware(), changePasswordHandler)
```

### 3. Batch Validation

```go
func verifyMultipleNonces(nonces []string) bool {
    for _, nonce := range nonces {
        if !stputil.VerifyNonce(nonce) {
            return false
        }
    }
    return true
}
```

## Best Practices

### 1. Protect Sensitive Operations Only

```go
// ✅ Need nonce
POST /transfer       // Transfer
POST /delete         // Delete
POST /change-email   // Change email

// ❌ Don't need nonce
GET  /list           // Query
GET  /detail         // Detail
POST /search         // Search
```

### 2. Set Reasonable TTL

```go
// Quick operations (1 minute)
core.NewNonceManager(storage, 60)

// Form submissions (5 minutes, log)
core.NewNonceManager(storage, 300)

// Long processes (10 minutes)
core.NewNonceManager(storage, 600)
```

### 3. Clear Error Messages

```go
if !stputil.VerifyNonce(nonce) {
    c.JSON(401, gin.H{
        "error": "invalid_nonce",
        "message": "Request expired or duplicated, please refresh and retry",
        "code": 1001,
    })
    return
}
```

### 4. Frontend Integration

```javascript
// Frontend example (Vue/React)
async function protectedRequest(url, data) {
    // 1. Get nonce
    const nonceResp = await fetch('/nonce');
    const { nonce } = await nonceResp.json();
    
    // 2. Make request
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            'X-Nonce': nonce,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    });
    
    return resp.json();
}

// Usage
protectedRequest('/transfer', { amount: 100 })
    .then(result => console.log('Success:', result))
    .catch(err => console.error('Error:', err));
```

## Storage Key Structure

```
satoken:nonce:{nonce_value} → timestamp (TTL: 5 minutes)
```

## Performance

### 1. Nonce Generation Performance

```
Single generation: ~100ns
10000 times: ~1ms
Concurrent safe: ✅
```

### 2. Validation Performance

```
Single validation: ~50ns (Memory)
Single validation: ~1ms (Redis)
```

### 3. Memory Usage

```
Single nonce: ~100 bytes
10000 nonces: ~1MB
Auto cleanup: ✅
```

## Security Recommendations

### 1. HTTPS Transport

```
❌ HTTP  - Nonce can be intercepted
✅ HTTPS - Nonce encrypted in transit
```

### 2. Combine with Token Auth

```go
// Verify both token and nonce
token := c.GetHeader("Authorization")
nonce := c.GetHeader("X-Nonce")

if !stputil.IsLogin(token) {
    c.JSON(401, gin.H{"error": "Not logged in"})
    return
}

if !stputil.VerifyNonce(nonce) {
    c.JSON(401, gin.H{"error": "Replay attack detected"})
    return
}
```

### 3. Rate Limiting

```go
// Nonce + Rate limiting double protection
r.Use(RateLimitMiddleware())
r.Use(NonceMiddleware())
```

## FAQ

### Q: What if nonce expires?

A: Client requests the `/nonce` endpoint again to get a new nonce.

### Q: How to prevent nonce interception?

A: Must use HTTPS with token authentication for double protection.

### Q: Will nonce consume a lot of storage?

A: No, nonces auto-expire and have minimal memory footprint.

### Q: Do all APIs need nonce?

A: No, only protect sensitive write operations (POST/PUT/DELETE).

## Next Steps

- [Refresh Token Guide](refresh-token.md)
- [OAuth2 Guide](oauth2.md)
- [Security Features Example](../../examples/security-features/)

