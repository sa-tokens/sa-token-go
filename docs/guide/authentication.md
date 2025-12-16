# Authentication Guide

[中文文档](authentication_zh.md) | English

## Basic Login

### Simple Login

```go
// Login user (supports multiple types)
token, err := stputil.Login(1000)           // int
token, err := stputil.Login("user123")      // string
token, err := stputil.Login(int64(1000))    // int64
```

### Multi-Device Login

```go
// Specify device type
token, _ := stputil.Login(1000, "web")
token, _ := stputil.Login(1000, "mobile")
token, _ := stputil.Login(1000, "app")
```

## Check Login Status

```go
// Check if logged in
isLogin := stputil.IsLogin(token)

// Check login (throws error if not logged in)
err := stputil.CheckLogin(token)

// Get login ID
loginID, err := stputil.GetLoginID(token)
```

## Logout

```go
// Logout by login ID
stputil.Logout(1000)

// Logout by login ID and device
stputil.Logout(1000, "mobile")

// Logout by token
stputil.LogoutByToken(token)
```

## Kickout

```go
// Kickout user
stputil.Kickout(1000)

// Kickout specific device
stputil.Kickout(1000, "mobile")
```

## Token Management

### Get Token Value

```go
// Get token by login ID
token, err := stputil.GetTokenValue(1000)

// Get token by login ID and device
token, err := stputil.GetTokenValue(1000, "mobile")
```

### Get Token Info

```go
// Get token information
info, err := stputil.GetTokenInfo(token)

fmt.Println("Login ID:", info.LoginID)
fmt.Println("Device:", info.Device)
fmt.Println("Create Time:", info.CreateTime)
```

## Login Configuration

### Concurrent Login

```go
// Allow concurrent login (log: true)
core.NewBuilder().
    IsConcurrent(true).
    Build()
```

### Share Token

```go
// Share token for concurrent logins (log: true)
core.NewBuilder().
    IsShare(true).
    Build()
```

### Max Login Count

```go
// Maximum concurrent logins
core.NewBuilder().
    IsConcurrent(true).
    IsShare(false).
    MaxLoginCount(5).  // Max 5 devices
    Build()
```

## Related Documentation

- [Quick Start](../tutorial/quick-start.md)
- [Permission Management](permission.md)
- [JWT Guide](jwt.md)
- [Redis Storage](redis-storage.md)
