package main

import (
	"log"

	sagin "github.com/click33/sa-token-go/integrations/gin"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func main() {
	// 加载配置
	viper.SetConfigFile("configs/config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: No config file found, using defaults: %v", err)
	}

	// 创建 Builder
	b := sagin.NewDefaultBuild().
		TokenName("Authorization").
		IsPrintBanner(true)

	// 从配置文件读取配置
	if viper.IsSet("token.timeout") {
		b.Timeout(viper.GetInt64("token.timeout"))
	}
	if viper.IsSet("token.active_timeout") {
		b.ActiveTimeout(viper.GetInt64("token.active_timeout"))
	}

	// 构建 Manager
	mgr := b.Build()

	// 设置全局 Manager
	sagin.SetManager(mgr)

	// 设置路由
	r := gin.Default()

	// 公开路由
	r.POST("/login", func(c *gin.Context) {
		var req struct {
			UserID string `json:"userId" form:"userId"`
		}
		if err := c.ShouldBind(&req); err != nil || req.UserID == "" {
			c.JSON(400, gin.H{"error": "userId is required"})
			return
		}

		ctx := c.Request.Context()
		token, err := sagin.Login(ctx, req.UserID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{
			"message": "登录成功",
			"token":   token,
		})
	})

	r.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "公开访问"})
	})

	// 受保护路由
	protected := r.Group("/api")
	protected.Use(sagin.CheckLoginMiddleware())
	{
		protected.GET("/user", func(c *gin.Context) {
			loginID, _ := sagin.GetLoginIDFromRequest(c)
			c.JSON(200, gin.H{
				"message": "用户信息",
				"loginId": loginID,
			})
		})

		protected.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), func(c *gin.Context) {
			loginID, _ := sagin.GetLoginIDFromRequest(c)
			c.JSON(200, gin.H{
				"message": "管理员数据",
				"loginId": loginID,
			})
		})
	}

	// 启动服务器
	port := "8080"
	if viper.IsSet("server.port") {
		port = viper.GetString("server.port")
	}

	log.Printf("服务器启动在端口: %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}
