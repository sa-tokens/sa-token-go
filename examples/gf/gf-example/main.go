package main

import (
	"net/http"

	satoken "github.com/click33/sa-token-go/integrations/gf"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

func main() {
	// 使用 Builder 模式构建 Manager | Build Manager using Builder pattern
	manager := satoken.NewDefaultBuild().
		SetStorage(satoken.NewMemoryStorage()). // 设置内存存储 | Set memory storage
		IsLog(true).                            // 开启日志 | Enable logging
		Build()

	// 注册 Manager | Register Manager
	satoken.SetManager(manager)

	s := g.Server()

	// 首页路由 | Home route
	s.BindHandler("/", func(r *ghttp.Request) {
		r.Response.WriteJson(g.Map{
			"code":    satoken.CodeSuccess,
			"message": "Welcome to Sa-Token-Go GF Example",
		})
	})

	// 公开路由 | Public route
	s.BindHandler("/public", func(r *ghttp.Request) {
		r.Response.WriteStatusExit(http.StatusOK, g.Map{
			"code":    satoken.CodeSuccess,
			"message": "公开访问 | Public access",
		})
	})

	// 登录接口 | Login API
	s.BindHandler("/login", func(r *ghttp.Request) {
		// 模拟用户ID | Simulate user ID
		loginID := r.Get("id", "10001").String()

		// 执行登录 | Perform login
		token, err := satoken.Login(r.Context(), loginID)
		if err != nil {
			r.Response.WriteStatusExit(http.StatusInternalServerError, g.Map{
				"code":    satoken.CodeServerError,
				"message": err.Error(),
			})
			return
		}

		r.Response.WriteJson(g.Map{
			"code":    satoken.CodeSuccess,
			"message": "登录成功 | Login successful",
			"data": g.Map{
				"token":   token,
				"loginID": loginID,
			},
		})
	})

	// 登出接口 | Logout API
	s.BindHandler("/logout", func(r *ghttp.Request) {
		// 从请求中获取 Token | Get token from request
		saCtx, ok := satoken.GetSaTokenContext(r)
		if !ok {
			r.Response.WriteStatusExit(http.StatusUnauthorized, g.Map{
				"code":    satoken.CodeNotLogin,
				"message": "未登录 | Not logged in",
			})
			return
		}

		tokenValue := saCtx.GetTokenValue()
		err := satoken.LogoutByToken(r.Context(), tokenValue)
		if err != nil {
			r.Response.WriteStatusExit(http.StatusInternalServerError, g.Map{
				"code":    satoken.CodeServerError,
				"message": err.Error(),
			})
			return
		}

		r.Response.WriteJson(g.Map{
			"code":    satoken.CodeSuccess,
			"message": "登出成功 | Logout successful",
		})
	})

	// 受保护的路由组 | Protected route group
	protected := s.Group("/api").Middleware(satoken.AuthMiddleware())
	{
		// 获取用户信息 | Get user info
		protected.GET("/user", func(r *ghttp.Request) {
			saCtx, _ := satoken.GetSaTokenContext(r)
			tokenValue := saCtx.GetTokenValue()

			loginID, err := satoken.GetLoginID(r.Context(), tokenValue)
			if err != nil {
				r.Response.WriteStatusExit(http.StatusUnauthorized, g.Map{
					"code":    satoken.CodeNotLogin,
					"message": err.Error(),
				})
				return
			}

			r.Response.WriteJson(g.Map{
				"code":    satoken.CodeSuccess,
				"message": "获取用户信息成功 | Get user info successful",
				"data": g.Map{
					"loginID": loginID,
					"token":   tokenValue,
				},
			})
		})

		// 获取 Token 信息 | Get token info
		protected.GET("/token-info", func(r *ghttp.Request) {
			saCtx, _ := satoken.GetSaTokenContext(r)
			tokenValue := saCtx.GetTokenValue()

			tokenInfo, err := satoken.GetTokenInfo(r.Context(), tokenValue)
			if err != nil {
				r.Response.WriteStatusExit(http.StatusInternalServerError, g.Map{
					"code":    satoken.CodeServerError,
					"message": err.Error(),
				})
				return
			}

			r.Response.WriteJson(g.Map{
				"code":    satoken.CodeSuccess,
				"message": "获取Token信息成功 | Get token info successful",
				"data":    tokenInfo,
			})
		})
	}

	// 需要特定权限的路由 | Routes requiring specific permissions
	permGroup := s.Group("/admin").Middleware(
		satoken.AuthMiddleware(),
		satoken.PermissionMiddleware([]string{"admin:read"}, satoken.WithLogicType(satoken.LogicOr)),
	)
	{
		permGroup.GET("/dashboard", func(r *ghttp.Request) {
			r.Response.WriteJson(g.Map{
				"code":    satoken.CodeSuccess,
				"message": "管理员面板 | Admin dashboard",
			})
		})
	}

	// 需要特定角色的路由 | Routes requiring specific roles
	roleGroup := s.Group("/super").Middleware(
		satoken.AuthMiddleware(),
		satoken.RoleMiddleware([]string{"super-admin"}, satoken.WithLogicType(satoken.LogicAnd)),
	)
	{
		roleGroup.GET("/settings", func(r *ghttp.Request) {
			r.Response.WriteJson(g.Map{
				"code":    satoken.CodeSuccess,
				"message": "超级管理员设置 | Super admin settings",
			})
		})
	}

	s.SetPort(8000)
	s.Run()
}
