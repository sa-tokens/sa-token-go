package main

import (
	"log"

	safiber "github.com/click33/sa-token-go/integrations/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	// 使用 Builder 模式构建 Manager | Build Manager using Builder pattern
	manager := safiber.NewDefaultBuild().
		TokenName("Authorization").
		Timeout(7200).
		IsLog(true).
		IsPrintBanner(true).
		Build()

	// 设置全局管理器 | Set global manager
	safiber.SetManager(manager)

	// 创建Fiber应用 | Create Fiber app
	app := fiber.New()
	app.Use(logger.New())
	app.Use(recover.New())

	// 登录接口 | Login endpoint
	app.Post("/login", func(c *fiber.Ctx) error {
		userID := c.FormValue("user_id")
		if userID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "user_id is required",
			})
		}

		ctx := c.Context()

		// 使用 safiber 包的全局函数登录 | Use safiber package global function to login
		token, err := safiber.Login(ctx, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"message": "登录成功",
			"token":   token,
		})
	})

	// 登出接口 | Logout endpoint
	app.Post("/logout", func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "token is required",
			})
		}

		ctx := c.Context()

		// 使用 safiber 包的全局函数登出 | Use safiber package global function to logout
		if err := safiber.LogoutByToken(ctx, token); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"message": "登出成功",
		})
	})

	// 公开路由 | Public route
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "公开访问",
		})
	})

	// 检查登录状态 | Check login status
	app.Get("/check", func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "token is required",
			})
		}

		ctx := c.Context()

		// 使用 safiber 包的全局函数检查登录 | Use safiber package global function to check login
		isLogin := safiber.IsLogin(ctx, token)
		if !isLogin {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "未登录",
			})
		}

		// 获取登录ID | Get login ID
		loginID, _ := safiber.GetLoginID(ctx, token)

		return c.JSON(fiber.Map{
			"message":  "已登录",
			"login_id": loginID,
		})
	})

	// 受保护的路由组 | Protected route group
	api := app.Group("/api")
	api.Use(safiber.AuthMiddleware())
	{
		// 用户信息 | User info
		api.Get("/user", func(c *fiber.Ctx) error {
			token := c.Get("Authorization")
			ctx := c.Context()
			loginID, _ := safiber.GetLoginID(ctx, token)

			return c.JSON(fiber.Map{
				"user_id": loginID,
				"name":    "User " + loginID,
			})
		})

		// 获取 Token 信息 | Get token info
		api.Get("/token-info", func(c *fiber.Ctx) error {
			token := c.Get("Authorization")
			ctx := c.Context()

			tokenInfo, err := safiber.GetTokenInfo(ctx, token)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			return c.JSON(fiber.Map{
				"code":    200,
				"message": "获取Token信息成功",
				"data":    tokenInfo,
			})
		})

		// 踢人下线 | Kickout user
		api.Post("/kickout/:user_id", func(c *fiber.Ctx) error {
			userID := c.Params("user_id")
			ctx := c.Context()

			// 使用 safiber 包的全局函数踢人 | Use safiber package global function to kickout
			if err := safiber.Kickout(ctx, userID); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			return c.JSON(fiber.Map{
				"message": "踢人成功",
			})
		})
	}

	// 需要权限的路由组 | Routes requiring permissions
	admin := app.Group("/admin")
	admin.Use(safiber.AuthMiddleware())
	admin.Use(safiber.PermissionMiddleware([]string{"admin:read"}, safiber.WithLogicType(safiber.LogicOr)))
	{
		admin.Get("/dashboard", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "管理员面板",
			})
		})
	}

	// 需要角色的路由组 | Routes requiring roles
	super := app.Group("/super")
	super.Use(safiber.AuthMiddleware())
	super.Use(safiber.RoleMiddleware([]string{"super-admin"}, safiber.WithLogicType(safiber.LogicAnd)))
	{
		super.Get("/settings", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "超级管理员设置",
			})
		})
	}

	// 启动服务器 | Start server
	log.Println("服务器启动在端口: 8080")
	log.Println("示例: curl -X POST http://localhost:8080/login -d 'user_id=1000'")
	if err := app.Listen(":8080"); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}
