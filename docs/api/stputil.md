English | [中文文档](stputil_zh.md)

# StpUtil API Documentation

## Overview

StpUtil is the global utility class of Sa-Token-Go, providing convenient access to all core functionalities.

## Initialization

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
```

## Authentication API

### Login

Login and return token

**Signature**:
```go
func Login(loginID interface{}, device ...string) (string, error)
```

**Parameters**:
- `loginID` - Login ID, supports int/int64/uint/string
- `device` - Optional, device type, defaults to "default"

**Returns**:
- `string` - Token value
- `error` - Error information

**Example**:
```go
token, _ := stputil.Login(1000)
token, _ := stputil.Login("user123", "mobile")
```

### IsLogin

Check if token is valid

**Signature**:
```go
func IsLogin(tokenValue string) bool
```

**Parameters**:
- `tokenValue` - Token value

**Returns**:
- `bool` - true if logged in

**Notes**:
- Automatically triggers asynchronous renewal (if enabled)
- Checks active timeout (if configured)

**Example**:
```go
if stputil.IsLogin(token) {
    // Logged in
}
```

### GetLoginID

Get login ID

**Signature**:
```go
func GetLoginID(tokenValue string) (string, error)
```

**Parameters**:
- `tokenValue` - Token value

**Returns**:
- `string` - Login ID
- `error` - Error information

**Example**:
```go
loginID, err := stputil.GetLoginID(token)
```

### Logout

Logout

**Signature**:
```go
func Logout(loginID interface{}, device ...string) error
```

**Parameters**:
- `loginID` - Login ID
- `device` - Optional, device type

**Example**:
```go
stputil.Logout(1000)
stputil.Logout(1000, "mobile")
```

### Kickout

Kick user offline

**Signature**:
```go
func Kickout(loginID interface{}, device ...string) error
```

**Parameters**:
- `loginID` - Login ID
- `device` - Optional, device type

**Example**:
```go
stputil.Kickout(1000)
stputil.Kickout(1000, "mobile")
```

## Permission Verification API

### SetPermissions

Set permissions

**Signature**:
```go
func SetPermissions(loginID interface{}, permissions []string) error
```

**Parameters**:
- `loginID` - Login ID
- `permissions` - Permission list

**Example**:
```go
stputil.SetPermissions(1000, []string{
    "user:read",
    "user:write",
    "admin:*",
})
```

### HasPermission

Check if has specified permission

**Signature**:
```go
func HasPermission(loginID interface{}, permission string) bool
```

**Parameters**:
- `loginID` - Login ID
- `permission` - Permission string

**Returns**:
- `bool` - true if has permission

**Example**:
```go
if stputil.HasPermission(1000, "user:read") {
    // Has permission
}
```

### HasPermissionsAnd

Check if has all permissions (AND logic)

**Signature**:
```go
func HasPermissionsAnd(loginID interface{}, permissions []string) bool
```

**Example**:
```go
if stputil.HasPermissionsAnd(1000, []string{"user:read", "user:write"}) {
    // Has both permissions
}
```

### HasPermissionsOr

Check if has any permission (OR logic)

**Signature**:
```go
func HasPermissionsOr(loginID interface{}, permissions []string) bool
```

**Example**:
```go
if stputil.HasPermissionsOr(1000, []string{"admin", "super"}) {
    // Has admin or super permission
}
```

## Role Management API

### SetRoles

Set roles

**Signature**:
```go
func SetRoles(loginID interface{}, roles []string) error
```

**Example**:
```go
stputil.SetRoles(1000, []string{"admin", "manager-example"})
```

### HasRole

Check if has specified role

**Signature**:
```go
func HasRole(loginID interface{}, role string) bool
```

**Example**:
```go
if stputil.HasRole(1000, "admin") {
    // Has admin role
}
```

### HasRolesAnd / HasRolesOr

Multiple role check

**Example**:
```go
// AND logic
stputil.HasRolesAnd(1000, []string{"admin", "manager-example"})

// OR logic
stputil.HasRolesOr(1000, []string{"admin", "super"})
```

## Account Disable API

### Disable

Disable account

**Signature**:
```go
func Disable(loginID interface{}, duration time.Duration) error
```

**Parameters**:
- `loginID` - Login ID
- `duration` - Disable duration, 0 means permanent

**Example**:
```go
stputil.Disable(1000, 1*time.Hour)  // Disable for 1 hour
stputil.Disable(1000, 0)            // Permanent disable
```

### IsDisable

Check if disabled

**Signature**:
```go
func IsDisable(loginID interface{}) bool
```

**Example**:
```go
if stputil.IsDisable(1000) {
    // Account is disabled
}
```

### Untie

Untie (enable) account

**Signature**:
```go
func Untie(loginID interface{}) error
```

**Example**:
```go
stputil.Untie(1000)
```

### GetDisableTime

Get remaining disable time

**Signature**:
```go
func GetDisableTime(loginID interface{}) (int64, error)
```

**Returns**:
- `int64` - Remaining seconds, -2 means not disabled

**Example**:
```go
remaining, _ := stputil.GetDisableTime(1000)
fmt.Printf("Remaining disable time: %d seconds\n", remaining)
```

## Session Management API

### GetSession

Get session

**Signature**:
```go
func GetSession(loginID interface{}) (*Session, error)
```

**Example**:
```go
sess, _ := stputil.GetSession(1000)

// Set data
sess.Set("nickname", "John")
sess.Set("age", 25)

// Get data
nickname := sess.GetString("nickname")
age := sess.GetInt("age")
```

### DeleteSession

Delete session

**Signature**:
```go
func DeleteSession(loginID interface{}) error
```

**Example**:
```go
stputil.DeleteSession(1000)
```

## Advanced API

### GetTokenInfo

Get token detailed information

**Signature**:
```go
func GetTokenInfo(tokenValue string) (*TokenInfo, error)
```

**Returns**:
```go
type TokenInfo struct {
    LoginID    string
    Device     string
    CreateTime int64
    ActiveTime int64
    Tag        string
}
```

**Example**:
```go
info, _ := stputil.GetTokenInfo(token)
fmt.Printf("Login ID: %s\n", info.LoginID)
fmt.Printf("Device: %s\n", info.Device)
```

### SetTokenTag

Set token tag

**Signature**:
```go
func SetTokenTag(tokenValue, tag string) error
```

**Example**:
```go
stputil.SetTokenTag(token, "admin-panel")
```

### GetTokenValueList

Get all tokens for an account

**Signature**:
```go
func GetTokenValueList(loginID interface{}) ([]string, error)
```

**Example**:
```go
tokens, _ := stputil.GetTokenValueList(1000)
fmt.Printf("Account has %d tokens\n", len(tokens))
```

### GetSessionCount

Get session count for an account

**Signature**:
```go
func GetSessionCount(loginID interface{}) (int, error)
```

**Example**:
```go
count, _ := stputil.GetSessionCount(1000)
fmt.Printf("Account has %d sessions\n", count)
```

## Complete Method List

### Authentication
- `Login` - Login
- `LoginByToken` - Login with specified token
- `Logout` - Logout
- `LogoutByToken` - Logout by token
- `IsLogin` - Check login
- `CheckLogin` - Check login (throws error)
- `GetLoginID` - Get login ID
- `GetLoginIDNotCheck` - Get login ID (no check)
- `GetTokenValue` - Get token value
- `GetTokenInfo` - Get token information

### Kickout
- `Kickout` - Kick user offline

### Account Disable
- `Disable` - Disable account
- `Untie` - Untie account
- `IsDisable` - Check disable status
- `GetDisableTime` - Get remaining disable time

### Session Management
- `GetSession` - Get session
- `GetSessionByToken` - Get session by token
- `DeleteSession` - Delete session

### Permission Verification
- `SetPermissions` - Set permissions
- `GetPermissions` - Get permissions
- `HasPermission` - Check permission
- `HasPermissionsAnd` - AND logic
- `HasPermissionsOr` - OR logic

### Role Management
- `SetRoles` - Set roles
- `GetRoles` - Get roles
- `HasRole` - Check role
- `HasRolesAnd` - AND logic
- `HasRolesOr` - OR logic

### Token Management
- `SetTokenTag` - Set token tag
- `GetTokenTag` - Get token tag
- `GetTokenValueList` - Get all tokens
- `GetSessionCount` - Get session count

## Next Steps

- [Manager API](manager.md)
- [Session API](session.md)
- [Storage API](storage.md)
