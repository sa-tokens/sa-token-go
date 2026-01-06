package main

import (
	"net/http"

	sagf "github.com/click33/sa-token-go/integrations/gf"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func main() {
	// redis存储实现
	storage, err := sagf.NewRedisStorage("redis://:root@192.168.19.104:6379/0?dial_timeout=3&read_timeout=10s&max_retries=2")
	if err != nil {
		panic(err)
	}
	// 内存存储实现
	//storage := sagf.NewMemoryStorage()

	// 使用 Builder 模式构建 Manager | Build Manager using Builder pattern
	manager := sagf.NewDefaultBuild().
		//SetStorage(sagf.NewMemoryStorage()). // 设置内存存储 | Set memory storage
		SetStorage(storage). // 设置内存存储 | Set memory storage
		IsLog(false).        // 开启日志 | Enable logging
		Build()

	// 注册 Manager | Register Manager
	sagf.SetManager(manager)

	s := g.Server()

	// 首页路由 | Home route
	s.BindHandler("/", func(r *ghttp.Request) {
		r.Response.WriteJson(g.Map{
			"code":    sagf.CodeSuccess,
			"message": "Welcome to Sa-Token-Go GF Example",
		})
	})

	// 公开路由 | Public route
	s.BindHandler("/public", func(r *ghttp.Request) {
		r.Response.WriteStatusExit(http.StatusOK, g.Map{
			"code":    sagf.CodeSuccess,
			"message": "公开访问 | Public access",
		})
	})

	// 登录接口 | Login API
	s.BindHandler("/login", func(r *ghttp.Request) {
		// 模拟用户ID | Simulate user ID
		loginID := r.Get("id", "10001").String()

		// 执行登录 | Perform login
		token, err := sagf.Login(r.Context(), loginID)
		if err != nil {
			r.Response.WriteStatusExit(http.StatusOK, g.Map{
				"code":    sagf.CodeServerError,
				"message": err.Error(),
			})
			return
		}

		// 角色
		if loginID == "1" {
			err = sagf.SetRoles(r.Context(), loginID, []string{"admin"})
			if err != nil {
				r.Response.WriteJson(g.Map{
					"code":    sagf.CodeServerError,
					"message": "登录失败",
					"data":    g.Array{},
				})
			}
		}
		// 权限
		if loginID == "1" {
			err = sagf.SetPermissions(r.Context(), loginID, []string{"admin:read", "admin:delete"})
			if err != nil {
				r.Response.WriteJson(g.Map{
					"code":    sagf.CodeServerError,
					"message": "登录失败",
					"data":    g.Array{},
				})
			}
		}

		r.Response.WriteJson(g.Map{
			"code":    sagf.CodeSuccess,
			"message": "登录成功 | Login successful",
			"data": g.Map{
				"token":   token,
				"loginID": loginID,
			},
		})
	})

	s.Group("/", func(group *ghttp.RouterGroup) {
		group.Middleware(sagf.AuthMiddleware(
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": err.Error(),
				})
			}),
		))
		group.GET("/logout", func(r *ghttp.Request) {
			// 从请求中获取 Token | Get token from request
			saCtx, ok := sagf.GetSaTokenContext(r)
			if !ok {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": "未登录 | Not logged in",
				})
				return
			}

			tokenValue := saCtx.GetTokenValue()
			err := sagf.LogoutByToken(r.Context(), tokenValue)
			if err != nil {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeServerError,
					"message": err.Error(),
				})
				return
			}

			r.Response.WriteJson(g.Map{
				"code":    sagf.CodeSuccess,
				"message": "登出成功 | Logout successful",
			})
		})
	})

	// 受保护的路由组 | Protected route group
	protected := s.Group("/").Middleware(
		sagf.AuthMiddleware(
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": err.Error(),
				})
			})))
	{
		// 获取用户信息 | Get user info
		protected.GET("/user", func(r *ghttp.Request) {
			saCtx, _ := sagf.GetSaTokenContext(r)
			tokenValue := saCtx.GetTokenValue()

			loginID, err := sagf.GetLoginID(r.Context(), tokenValue)
			if err != nil {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": err.Error(),
				})
				return
			}

			r.Response.WriteJson(g.Map{
				"code":    sagf.CodeSuccess,
				"message": "获取用户信息成功 | Get user info successful",
				"data": g.Map{
					"loginID": loginID,
					"token":   tokenValue,
				},
			})
		})

		// 获取 Token 信息 | Get token info
		protected.GET("/token-info", func(r *ghttp.Request) {
			saCtx, _ := sagf.GetSaTokenContext(r)
			tokenValue := saCtx.GetTokenValue()

			tokenInfo, err := sagf.GetTokenInfo(r.Context(), tokenValue)
			if err != nil {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeServerError,
					"message": err.Error(),
				})
				return
			}

			r.Response.WriteJson(g.Map{
				"code":    sagf.CodeSuccess,
				"message": "获取Token信息成功 | Get token info successful",
				"data":    tokenInfo,
			})
		})
	}

	// 需要特定权限的路由 | Routes requiring specific permissions
	permGroup := s.Group("/").Middleware(
		sagf.AuthMiddleware(
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": err.Error(),
				})
			}),
		),
		sagf.PermissionMiddleware(
			[]string{"admin:read", "admin:delete"},
			sagf.WithLogicType(sagf.LogicAnd),
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodePermissionDenied,
					"message": err.Error(),
				})
			}),
		),
	)
	{
		permGroup.GET("/dashboard", func(r *ghttp.Request) {
			r.Response.WriteJson(g.Map{
				"code":    sagf.CodeSuccess,
				"message": "管理员面板 | Admin dashboard",
			})
		})
	}

	// 需要特定角色的路由 | Routes requiring specific roles
	roleGroup := s.Group("/").Middleware(
		sagf.AuthMiddleware(
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodeNotLogin,
					"message": err.Error(),
				})
			}),
		),
		sagf.RoleMiddleware(
			[]string{"super-admin"},
			sagf.WithLogicType(sagf.LogicAnd),
			sagf.WithFailFunc(func(r *ghttp.Request, err error) {
				r.Response.WriteStatusExit(http.StatusOK, g.Map{
					"code":    sagf.CodePermissionDenied,
					"message": err.Error(),
				})
			}),
		),
	)
	{
		roleGroup.GET("/settings", func(r *ghttp.Request) {
			r.Response.WriteJson(g.Map{
				"code":    sagf.CodeSuccess,
				"message": "超级管理员设置 | Super admin settings",
			})
		})
	}

	s.SetPort(8000)
	s.Run()
}
