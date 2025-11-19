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

var (
	Name string
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
	// 初始化存储
	storage := memory.NewStorage()
	config := sakratos.DefaultConfig()
	manager := sakratos.NewManager(storage, config)
	// 创建 sa-token 中间件
	saPlugin := sakratos.NewPlugin(manager)
	stputil.SetManager(manager)

	// 配置路由规则
	saPlugin.
		// 跳过公开路由
		Skip(v1.OperationUserLogin).
		// 用户信息需要登录
		ExactMatcher(v1.OperationUserGetUserInfo).RequireLogin().RequirePermission("user:some:info").Build()

	httpSrv := http.NewServer(
		http.Address(":8000"),
		http.Middleware(
			saPlugin.Server(),
		),
	)
	s := &server{}
	v1.RegisterUserHTTPServer(httpSrv, s)
	app := kratos.New(
		kratos.Name(Name),
		kratos.Server(
			httpSrv,
		),
	)
	fmt.Println("Server running on port 8000")

	if err := app.Run(); err != nil {
		panic(err)
	}
}
