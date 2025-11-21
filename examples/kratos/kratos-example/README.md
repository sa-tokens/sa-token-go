# Kratos 框架集成示例

本示例演示如何在 Kratos 框架中使用 Sa-Token-Go。

## 快速开始

### 安装依赖

```bash
go mod download
```

### 运行示例

```bash
go run cmd/main.go
```

服务器将在 `http://localhost:8000` 启动。

## 使用方式

在 Kratos 中集成 Sa-Token-Go 主要通过中间件实现。以下是核心代码示例：

```go
package main

import (
    "context"
    "fmt"
    
    v1 "github.com/click33/sa-token-go/examples/kratos/kratos-example/api/helloworld/v1"
    sakratos "github.com/click33/sa-token-go/integrations/kratos"
    "github.com/click33/sa-token-go/storage/memory"
    "github.com/click33/sa-token-go/stputil"
    "github.com/go-kratos/kratos/v2"
    "github.com/go-kratos/kratos/v2/transport/http"
)

type server struct {
	v1.UnimplementedUserServer
}

func (s server) GetUserInfo(ctx context.Context, request *v1.GetUserInfoRequest) (*v1.GetUserInfoReply, error) {
	fmt.Println("==============GetUserInfo==============")

	return &v1.GetUserInfoReply{}, nil
}

func (s server) Login(ctx context.Context, request *v1.LoginRequest) (*v1.LoginReply, error) {
	tokenInfo, _ := stputil.Login(request.LoginId)

	return &v1.LoginReply{
		Token: tokenInfo,
	}, nil
}

func main() {
    // 1. 初始化存储和 Manager
    storage := memory.NewStorage()
    config := sakratos.DefaultConfig()
    manager := sakratos.NewManager(storage, config)
    
    // 2. 创建插件并设置全局 Manager
    saPlugin := sakratos.NewPlugin(manager)
    stputil.SetManager(manager)

    // 3. 配置路由鉴权规则
    saPlugin.
        // 跳过登录接口（公开访问）
        Skip(v1.OperationUserLogin).
        // 用户信息接口需要登录，并且需要 "user:some:info" 权限
        ExactMatcher(v1.OperationUserGetUserInfo).RequireLogin().RequirePermission("user:some:info").Build().
        // 其他路径匹配 
		ExactMatcher("otherOperation1").RequireLogin().RequireRole("role1").Build().

    // 4. 创建 HTTP Server 并注入中间件
    httpSrv := http.NewServer(
        http.Address(":8000"),
        http.Middleware(
            saPlugin.Server(), // 注入 Sa-Token 中间件
        ),
    )
    
    s := &server{}
    v1.RegisterUserHTTPServer(httpSrv, s)
    
    app := kratos.New(
        kratos.Name("kratos-example"),
        kratos.Server(
            httpSrv,
        ),
    )
    
    if err := app.Run(); err != nil {
        panic(err)
    }
}
```

## API 端点

### 公开接口

- `POST /api/login` - 用户登录
  ```bash
  curl -X POST http://localhost:8000/api/login \
    -H "Content-Type: application/json" \
    -d '{"loginId":"10001"}'
  ```

### 受保护接口

- `GET /api/user/info` - 获取用户信息（需要登录及权限）
  ```bash
  curl http://localhost:8000/api/user/info \
    -H "Authorization: YOUR_TOKEN"
  ```


## 路由匹配方式介绍
- `ExactMatcher`: 精确匹配,推荐搭配生成的operation枚举值使用
  ```go
  saPlugin.ExactMatcher(v1.OperationUserGetUserInfo).RequireLogin().Build()
  ```
- `PrefixMatcher`: 前缀匹配
  ```go
  saPlugin.PrefixMatcher("/helloworld.v1.User").RequireLogin().Build()
  ```
- `SuffixMatcher`: 后缀匹配
  ```go
  saPlugin.SuffixMatcher("/GetUserInfo").RequireLogin().Build()
  ```
- `PatternMatcher`: 通配符匹配（支持 `*` 和 `?`）
  ```go
  saPlugin.PatternMatcher("/helloworld.v1.User/*").RequireLogin().Build()
  ```
- `RegexMatcher`: 正则表达式匹配
  ```go
  saPlugin.RegexMatcher("^/helloworld.v1.User/\\d+$").RequireLogin().Build()
  ```
- `ContainsMatcher`: 包含匹配
  ```go
  saPlugin.ContainsMatcher("User").RequireRole("admin").Build()
  ```
- `FuncMatcher`: 自定义函数匹配
  ```go
  saPlugin.FuncMatcher(func(op string) bool {
      return len(op) > 10
  }).RequireLogin().Build()
  ```
- `AutoMatcher`: 自动匹配（如果包含 `*` 或 `?` 则使用通配符匹配，否则使用精确匹配）
  ```go
  saPlugin.AutoMatcher("/helloworld.v1.User/*").Build()
  ```

## 鉴权规则介绍

用于给“匹配到的 Operation”配置鉴权规则，支持链式调用。


- `RequireLogin`: 需要登录
- `RequirePermission`: 需要指定权限（单个）
- `RequirePermissions`: 需要多个权限（AND）
- `RequireAnyPermission`: 任一权限即可（OR）
- `RequireRole`: 需要指定角色（单个）
- `RequireRoles`: 需要多个角色（AND）
- `RequireAnyRole`: 任一角色即可（OR）
- `CheckNotDisabled`: 校验账号未被封禁
- `CustomCheck(name, fn)`: 自定义校验函数
- `AddChecker(checker)`: 注入自定义 `Checker` 实现
- `Build()`: 构建并注册规则

示例：

```go
// 配置路由规则
saPlugin.
// 跳过指定Operation 
    Skip(v1.OperationUserLogin).
    // 命中任何规则时，是否要求默认登录 默认false
    DefaultRequireLogin(true).
    // 自定义错误处理
    SetErrorHandler(handler).
    ExactMatcher(v1.OperationUserGetUserInfo).
    // 用户信息需要登录
    RequireLogin().
    // 需要指定的一个权限code
    RequirePermission("user:some:info").
    // 需要其中一个权限code
    RequireAnyPermission("user:some:info1", "user:some:info2").
    // 需要以下全部权限code
    RequirePermissions("user:some:info3", "user:some:info4").
    // 需要指定的一个角色code
    RequireRole("role1").
    // 需要其中一个角色code
    RequireAnyRole("role1","role2").
    // 需要以下全部角色code
    RequireRoles("role1","role2").
    // 校验是否被封禁
    CheckNotDisabled().
    // 自定义检查逻辑
    CustomCheck(func(ctx context.Context, manager *core.Manager, loginID string) error {
        if loginID == "banned" {
            return errors.New("access denied for this user")
        }
        return nil
    }).
    Build()
```

