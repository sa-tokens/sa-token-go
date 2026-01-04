package main

import (
	"log"
	"net/http"

	saecho "github.com/click33/sa-token-go/integrations/echo"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// 使用 Builder 模式构建 Manager | Build Manager using Builder pattern
	manager := saecho.NewDefaultBuild().
		TokenName("Authorization").
		Timeout(7200).
		IsLog(true).
		IsPrintBanner(true).
		Build()

	// 设置全局管理器 | Set global manager
	saecho.SetManager(manager)

	// 创建Echo实例 | Create Echo instance
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// 登录接口 | Login endpoint
	e.POST("/login", func(c echo.Context) error {
		userID := c.FormValue("user_id")
		if userID == "" {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "user_id is required",
			})
		}

		ctx := c.Request().Context()

		// 使用 saecho 包的全局函数登录 | Use saecho package global function to login
		token, err := saecho.Login(ctx, userID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "登录成功",
			"token":   token,
		})
	})

	// 登出接口 | Logout endpoint
	e.POST("/logout", func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "token is required",
			})
		}

		ctx := c.Request().Context()

		// 使用 saecho 包的全局函数登出 | Use saecho package global function to logout
		if err := saecho.LogoutByToken(ctx, token); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "登出成功",
		})
	})

	// 公开路由 | Public route
	e.GET("/public", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "公开访问",
		})
	})

	// 检查登录状态 | Check login status
	e.GET("/check", func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "token is required",
			})
		}

		ctx := c.Request().Context()

		// 使用 saecho 包的全局函数检查登录 | Use saecho package global function to check login
		isLogin := saecho.IsLogin(ctx, token)
		if !isLogin {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{
				"error": "未登录",
			})
		}

		// 获取登录ID | Get login ID
		loginID, _ := saecho.GetLoginID(ctx, token)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":  "已登录",
			"login_id": loginID,
		})
	})

	// 受保护的路由组 | Protected route group
	api := e.Group("/api")
	api.Use(saecho.AuthMiddleware())
	{
		// 用户信息 | User info
		api.GET("/user", func(c echo.Context) error {
			token := c.Request().Header.Get("Authorization")
			ctx := c.Request().Context()
			loginID, _ := saecho.GetLoginID(ctx, token)

			return c.JSON(http.StatusOK, map[string]interface{}{
				"user_id": loginID,
				"name":    "User " + loginID,
			})
		})

		// 获取 Token 信息 | Get token info
		api.GET("/token-info", func(c echo.Context) error {
			token := c.Request().Header.Get("Authorization")
			ctx := c.Request().Context()

			tokenInfo, err := saecho.GetTokenInfo(ctx, token)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]interface{}{
					"error": err.Error(),
				})
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"code":    200,
				"message": "获取Token信息成功",
				"data":    tokenInfo,
			})
		})

		// 踢人下线 | Kickout user
		api.POST("/kickout/:user_id", func(c echo.Context) error {
			userID := c.Param("user_id")
			ctx := c.Request().Context()

			// 使用 saecho 包的全局函数踢人 | Use saecho package global function to kickout
			if err := saecho.Kickout(ctx, userID); err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]interface{}{
					"error": err.Error(),
				})
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"message": "踢人成功",
			})
		})
	}

	// 需要权限的路由组 | Routes requiring permissions
	admin := e.Group("/admin")
	admin.Use(saecho.AuthMiddleware())
	admin.Use(saecho.PermissionMiddleware([]string{"admin:read"}, saecho.WithLogicType(saecho.LogicOr)))
	{
		admin.GET("/dashboard", func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message": "管理员面板",
			})
		})
	}

	// 需要角色的路由组 | Routes requiring roles
	super := e.Group("/super")
	super.Use(saecho.AuthMiddleware())
	super.Use(saecho.RoleMiddleware([]string{"super-admin"}, saecho.WithLogicType(saecho.LogicAnd)))
	{
		super.GET("/settings", func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message": "超级管理员设置",
			})
		})
	}

	// 启动服务器 | Start server
	log.Println("服务器启动在端口: 8080")
	log.Println("示例: curl -X POST http://localhost:8080/login -d 'user_id=1000'")
	if err := e.Start(":8080"); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}
