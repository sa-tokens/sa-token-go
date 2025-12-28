package main

import (
	"net/http"
	"time"

	sagin "github.com/click33/sa-token-go/integrations/gin"
	"github.com/gin-gonic/gin"
)

func init() {
	// 初始化 Manager
	sagin.SetManager(
		sagin.NewDefaultBuild().Build(),
	)
}

// 处理器结构体
type UserHandler struct{}

// 公开访问 - 忽略认证
func (h *UserHandler) GetPublic(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "这是公开接口，不需要登录",
	})
}

// 需要登录
func (h *UserHandler) GetUserInfo(c *gin.Context) {
	loginID, _ := sagin.GetLoginIDFromRequest(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "用户个人信息",
		"loginId": loginID,
	})
}

// 需要管理员权限
func (h *UserHandler) GetAdminData(c *gin.Context) {
	loginID, _ := sagin.GetLoginIDFromRequest(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "管理员数据",
		"loginId": loginID,
		"data":    "这是管理员专有的数据",
	})
}

// 需要多个权限之一
func (h *UserHandler) GetUserOrAdmin(c *gin.Context) {
	loginID, _ := sagin.GetLoginIDFromRequest(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "用户或管理员都可以访问",
		"loginId": loginID,
	})
}

// 需要特定角色
func (h *UserHandler) GetManagerData(c *gin.Context) {
	loginID, _ := sagin.GetLoginIDFromRequest(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "经理数据",
		"loginId": loginID,
	})
}

// 检查账号是否被封禁
func (h *UserHandler) GetSensitiveData(c *gin.Context) {
	loginID, _ := sagin.GetLoginIDFromRequest(c)

	c.JSON(http.StatusOK, gin.H{
		"message": "敏感数据",
		"loginId": loginID,
	})
}

// 登录接口
func loginHandler(c *gin.Context) {
	var req struct {
		UserID int `json:"userId"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	ctx := c.Request.Context()

	// 登录
	token, err := sagin.Login(ctx, req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登录失败"})
		return
	}

	// 设置权限和角色（模拟）
	if req.UserID == 1 {
		_ = sagin.SetPermissions(ctx, req.UserID, []string{"user:read", "user:write", "admin:*"})
		_ = sagin.SetRoles(ctx, req.UserID, []string{"admin", "manager-example"})
	} else {
		_ = sagin.SetPermissions(ctx, req.UserID, []string{"user:read", "user:write"})
		_ = sagin.SetRoles(ctx, req.UserID, []string{"user"})
	}

	c.JSON(http.StatusOK, gin.H{
		"token":   token,
		"message": "登录成功",
	})
}

// 封禁账号接口
func disableHandler(c *gin.Context) {
	var req struct {
		UserID int `json:"userId"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	ctx := c.Request.Context()

	// 封禁账号1小时
	_ = sagin.Disable(ctx, req.UserID, 1*time.Hour)

	c.JSON(http.StatusOK, gin.H{
		"message": "账号已封禁1小时",
	})
}

func main() {
	r := gin.Default()

	// 登录接口（公开）
	r.POST("/login", loginHandler)

	// 封禁接口（需要管理员权限）
	r.POST("/disable", sagin.CheckPermissionMiddleware("admin:*"), disableHandler)

	// 使用装饰器模式设置路由
	handler := &UserHandler{}

	// 公开访问 - 忽略认证
	r.GET("/public", sagin.IgnoreMiddleware(), handler.GetPublic)

	// 需要登录
	r.GET("/user/info", sagin.CheckLoginMiddleware(), handler.GetUserInfo)

	// 需要管理员权限
	r.GET("/admin", sagin.CheckPermissionMiddleware("admin:*"), handler.GetAdminData)

	// 需要用户权限或管理员权限（OR逻辑）
	r.GET("/user-or-admin",
		sagin.CheckPermissionMiddleware("user:read", "admin:*"),
		handler.GetUserOrAdmin)

	// 需要管理员角色
	r.GET("/manager-example", sagin.CheckRoleMiddleware("admin"), handler.GetManagerData)

	// 检查账号是否被封禁
	r.GET("/sensitive", sagin.CheckDisableMiddleware(), handler.GetSensitiveData)

	// 启动服务器
	_ = r.Run(":8080")
}
