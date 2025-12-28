[English](stputil.md) | 中文文档

# StpUtil API 文档

## 概述

StpUtil 是 Sa-Token-Go 的全局工具类，提供了所有核心功能的便捷访问。

## 初始化

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

## 登录认证 API

### Login

登录并返回Token

**签名**：
```go
func Login(loginID interface{}, device ...string) (string, error)
```

**参数**：
- `loginID` - 登录ID，支持 int/int64/uint/string
- `device` - 可选，设备类型，默认"default"

**返回**：
- `string` - Token值
- `error` - 错误信息

**示例**：
```go
token, _ := stputil.Login(1000)
token, _ := stputil.Login("user123", "mobile")
```

### IsLogin

检查Token是否有效

**签名**：
```go
func IsLogin(tokenValue string) bool
```

**参数**：
- `tokenValue` - Token值

**返回**：
- `bool` - true表示已登录

**说明**：
- 自动触发异步续签（如果开启）
- 检查活跃超时（如果配置）

**示例**：
```go
if stputil.IsLogin(token) {
    // 已登录
}
```

### GetLoginID

获取登录ID

**签名**：
```go
func GetLoginID(tokenValue string) (string, error)
```

**参数**：
- `tokenValue` - Token值

**返回**：
- `string` - 登录ID
- `error` - 错误信息

**示例**：
```go
loginID, err := stputil.GetLoginID(token)
```

### Logout

登出

**签名**：
```go
func Logout(loginID interface{}, device ...string) error
```

**参数**：
- `loginID` - 登录ID
- `device` - 可选，设备类型

**示例**：
```go
stputil.Logout(1000)
stputil.Logout(1000, "mobile")
```

### Kickout

踢人下线

**签名**：
```go
func Kickout(loginID interface{}, device ...string) error
```

**参数**：
- `loginID` - 登录ID
- `device` - 可选，设备类型

**示例**：
```go
stputil.Kickout(1000)
stputil.Kickout(1000, "mobile")
```

## 权限验证 API

### SetPermissions

设置权限

**签名**：
```go
func SetPermissions(loginID interface{}, permissions []string) error
```

**参数**：
- `loginID` - 登录ID
- `permissions` - 权限列表

**示例**：
```go
stputil.SetPermissions(1000, []string{
    "user:read",
    "user:write",
    "admin:*",
})
```

### HasPermission

检查是否有指定权限

**签名**：
```go
func HasPermission(loginID interface{}, permission string) bool
```

**参数**：
- `loginID` - 登录ID
- `permission` - 权限字符串

**返回**：
- `bool` - true表示有权限

**示例**：
```go
if stputil.HasPermission(1000, "user:read") {
    // 有权限
}
```

### HasPermissionsAnd

检查是否拥有所有权限（AND逻辑）

**签名**：
```go
func HasPermissionsAnd(loginID interface{}, permissions []string) bool
```

**示例**：
```go
if stputil.HasPermissionsAnd(1000, []string{"user:read", "user:write"}) {
    // 同时拥有两个权限
}
```

### HasPermissionsOr

检查是否拥有任一权限（OR逻辑）

**签名**：
```go
func HasPermissionsOr(loginID interface{}, permissions []string) bool
```

**示例**：
```go
if stputil.HasPermissionsOr(1000, []string{"admin", "super"}) {
    // 拥有admin或super权限之一
}
```

## 角色管理 API

### SetRoles

设置角色

**签名**：
```go
func SetRoles(loginID interface{}, roles []string) error
```

**示例**：
```go
stputil.SetRoles(1000, []string{"admin", "manager-example"})
```

### HasRole

检查是否有指定角色

**签名**：
```go
func HasRole(loginID interface{}, role string) bool
```

**示例**：
```go
if stputil.HasRole(1000, "admin") {
    // 有admin角色
}
```

### HasRolesAnd / HasRolesOr

多角色检查

**示例**：
```go
// AND逻辑
stputil.HasRolesAnd(1000, []string{"admin", "manager-example"})

// OR逻辑
stputil.HasRolesOr(1000, []string{"admin", "super"})
```

## 账号封禁 API

### Disable

封禁账号

**签名**：
```go
func Disable(loginID interface{}, duration time.Duration) error
```

**参数**：
- `loginID` - 登录ID
- `duration` - 封禁时长，0表示永久封禁

**示例**：
```go
stputil.Disable(1000, 1*time.Hour)  // 封禁1小时
stputil.Disable(1000, 0)            // 永久封禁
```

### IsDisable

检查是否被封禁

**签名**：
```go
func IsDisable(loginID interface{}) bool
```

**示例**：
```go
if stputil.IsDisable(1000) {
    // 账号已被封禁
}
```

### Untie

解封账号

**签名**：
```go
func Untie(loginID interface{}) error
```

**示例**：
```go
stputil.Untie(1000)
```

### GetDisableTime

获取剩余封禁时间

**签名**：
```go
func GetDisableTime(loginID interface{}) (int64, error)
```

**返回**：
- `int64` - 剩余秒数，-2表示未封禁

**示例**：
```go
remaining, _ := stputil.GetDisableTime(1000)
fmt.Printf("剩余封禁时间: %d秒\n", remaining)
```

## Session管理 API

### GetSession

获取Session

**签名**：
```go
func GetSession(loginID interface{}) (*Session, error)
```

**示例**：
```go
sess, _ := stputil.GetSession(1000)

// 设置数据
sess.Set("nickname", "张三")
sess.Set("age", 25)

// 读取数据
nickname := sess.GetString("nickname")
age := sess.GetInt("age")
```

### DeleteSession

删除Session

**签名**：
```go
func DeleteSession(loginID interface{}) error
```

**示例**：
```go
stputil.DeleteSession(1000)
```

## 高级 API

### GetTokenInfo

获取Token详细信息

**签名**：
```go
func GetTokenInfo(tokenValue string) (*TokenInfo, error)
```

**返回**：
```go
type TokenInfo struct {
    LoginID    string
    Device     string
    CreateTime int64
    ActiveTime int64
    Tag        string
}
```

**示例**：
```go
info, _ := stputil.GetTokenInfo(token)
fmt.Printf("登录ID: %s\n", info.LoginID)
fmt.Printf("设备: %s\n", info.Device)
```

### SetTokenTag

设置Token标签

**签名**：
```go
func SetTokenTag(tokenValue, tag string) error
```

**示例**：
```go
stputil.SetTokenTag(token, "admin-panel")
```

### GetTokenValueList

获取账号的所有Token

**签名**：
```go
func GetTokenValueList(loginID interface{}) ([]string, error)
```

**示例**：
```go
tokens, _ := stputil.GetTokenValueList(1000)
fmt.Printf("该账号有 %d 个Token\n", len(tokens))
```

### GetSessionCount

获取账号的Session数量

**签名**：
```go
func GetSessionCount(loginID interface{}) (int, error)
```

**示例**：
```go
count, _ := stputil.GetSessionCount(1000)
fmt.Printf("该账号有 %d 个Session\n", count)
```

## 完整方法列表

### 登录认证
- `Login` - 登录
- `LoginByToken` - 使用指定Token登录
- `Logout` - 登出
- `LogoutByToken` - 根据Token登出
- `IsLogin` - 检查登录
- `CheckLogin` - 检查登录（抛出错误）
- `GetLoginID` - 获取登录ID
- `GetLoginIDNotCheck` - 获取登录ID（不检查）
- `GetTokenValue` - 获取Token值
- `GetTokenInfo` - 获取Token信息

### 踢人下线
- `Kickout` - 踢人下线

### 账号封禁
- `Disable` - 封禁账号
- `Untie` - 解封账号
- `IsDisable` - 检查封禁状态
- `GetDisableTime` - 获取剩余封禁时间

### Session管理
- `GetSession` - 获取Session
- `GetSessionByToken` - 根据Token获取Session
- `DeleteSession` - 删除Session

### 权限验证
- `SetPermissions` - 设置权限
- `GetPermissions` - 获取权限
- `HasPermission` - 检查权限
- `HasPermissionsAnd` - AND逻辑
- `HasPermissionsOr` - OR逻辑

### 角色管理
- `SetRoles` - 设置角色
- `GetRoles` - 获取角色
- `HasRole` - 检查角色
- `HasRolesAnd` - AND逻辑
- `HasRolesOr` - OR逻辑

### Token管理
- `SetTokenTag` - 设置Token标签
- `GetTokenTag` - 获取Token标签
- `GetTokenValueList` - 获取所有Token
- `GetSessionCount` - 获取Session数量

## 下一步

- [Manager API](manager.md)
- [Session API](session.md)
- [Storage API](storage.md)

