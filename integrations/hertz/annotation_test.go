package hertz

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/common/utils"
	"github.com/stretchr/testify/assert"
)

// setupTestRouter 创建测试路由器和初始化 sa-token
func setupTestRouter() *server.Hertz {
	router := server.Default()

	// 创建内存存储
	storage := memory.NewStorage()

	// 创建配置
	cfg := &config.Config{
		TokenName:     "satoken",
		Timeout:       2592000, // 30 天（秒）
		IsConcurrent:  true,
		IsShare:       true,
		MaxLoginCount: -1,
	}

	// 创建并设置全局 Manager
	mgr := manager.NewManager(storage, cfg)
	stputil.SetManager(mgr)

	return router
}

// mockLogin 模拟用户登录并返回 token
func mockLogin(loginID interface{}) string {
	token, _ := stputil.Login(loginID)
	return token
}

// mockLoginWithRole 模拟用户登录并设置角色
func mockLoginWithRole(loginID interface{}, roles []string) string {
	token, _ := stputil.Login(loginID)
	stputil.SetRoles(loginID, roles)
	return token
}

// mockLoginWithPermission 模拟用户登录并设置权限
func mockLoginWithPermission(loginID interface{}, permissions []string) string {
	token, _ := stputil.Login(loginID)
	stputil.SetPermissions(loginID, permissions)
	return token
}

// TestCheckRole_WithValidRole 测试具有有效角色的用户访问
func TestCheckRole_WithValidRole(t *testing.T) {
	router := setupTestRouter()

	// 设置路由 - 使用 CheckRole 作为中间件
	router.GET("/admin", CheckRole("Admin"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	// 创建一个具有 Admin 角色的用户
	token := mockLoginWithRole("user123", []string{"Admin"})
	fmt.Println("Debug: Token generated:", token)
	loginID, _ := stputil.GetLoginID(token)
	fmt.Println("Debug: LoginID from storage:", loginID)

	// 发送请求
	w := ut.PerformRequest(router.Engine, "GET", "/admin", nil,
		ut.Header{Key: "Authorization", Value: token})

	// 断言
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestCheckRole_WithInvalidRole 测试没有所需角色的用户访问
func TestCheckRole_WithInvalidRole(t *testing.T) {
	router := setupTestRouter()

	// 设置路由
	router.GET("/admin", CheckRole("Admin"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	// 创建一个只有 User 角色的用户
	token := mockLoginWithRole("user456", []string{"User"})

	// 发送请求
	w := ut.PerformRequest(router.Engine, "GET", "/admin", nil,
		ut.Header{Key: "Authorization", Value: token})

	// 断言
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "角色不足")
}

// TestCheckRole_MultipleRoles 测试多个角色的情况（OR 逻辑）
func TestCheckRole_MultipleRoles(t *testing.T) {
	router := setupTestRouter()

	// 设置路由 - 需要 Admin 或 SuperAdmin 角色
	router.GET("/manage", CheckRole("Admin", "SuperAdmin"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	// 测试具有 SuperAdmin 角色的用户
	token := mockLoginWithRole("superuser", []string{"SuperAdmin"})

	w := ut.PerformRequest(router.Engine, "GET", "/manage", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestCheckRole_NoToken 测试未提供 token 的情况
func TestCheckRole_NoToken(t *testing.T) {
	router := setupTestRouter()

	router.GET("/admin", CheckRole("Admin"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	w := ut.PerformRequest(router.Engine, "GET", "/admin", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "未登录")
}

// TestCheckRole_InvalidToken 测试无效 token 的情况
func TestCheckRole_InvalidToken(t *testing.T) {
	router := setupTestRouter()

	router.GET("/admin", CheckRole("Admin"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	w := ut.PerformRequest(router.Engine, "GET", "/admin", nil,
		ut.Header{Key: "Authorization", Value: "invalid-token-12345"})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "未登录")
}

// TestCheckPermission_WithValidPermission 测试具有有效权限的用户访问
func TestCheckPermission_WithValidPermission(t *testing.T) {
	router := setupTestRouter()

	router.GET("/users", CheckPermission("user.read"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	token := mockLoginWithPermission("user789", []string{"user.read"})

	w := ut.PerformRequest(router.Engine, "GET", "/users", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "success")
}

// TestCheckPermission_WithInvalidPermission 测试没有所需权限的用户访问
func TestCheckPermission_WithInvalidPermission(t *testing.T) {
	router := setupTestRouter()

	router.GET("/users", CheckPermission("user.delete"), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "success"})
	})

	token := mockLoginWithPermission("user789", []string{"user.read"})

	w := ut.PerformRequest(router.Engine, "GET", "/users", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "权限不足")
}

// TestCheckLogin_Success 测试登录检查成功
func TestCheckLogin_Success(t *testing.T) {
	router := setupTestRouter()

	router.GET("/profile", CheckLogin(), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "profile data"})
	})

	token := mockLogin("user999")

	w := ut.PerformRequest(router.Engine, "GET", "/profile", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "profile data")
}

// TestCheckLogin_Failed 测试登录检查失败
func TestCheckLogin_Failed(t *testing.T) {
	router := setupTestRouter()

	router.GET("/profile", CheckLogin(), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "profile data"})
	})

	w := ut.PerformRequest(router.Engine, "GET", "/profile", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "未登录")
}

// TestCheckDisable_NotDisabled 测试账号未被封禁的情况
func TestCheckDisable_NotDisabled(t *testing.T) {
	router := setupTestRouter()

	router.GET("/resource", CheckDisable(), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "resource data"})
	})

	token := mockLogin("user101")

	w := ut.PerformRequest(router.Engine, "GET", "/resource", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "resource data")
}

// TestCheckDisable_IsDisabled 测试账号被封禁的情况
func TestCheckDisable_IsDisabled(t *testing.T) {
	router := setupTestRouter()

	router.GET("/resource", CheckDisable(), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "resource data"})
	})

	loginID := "user102"
	token := mockLogin(loginID)

	// 封禁账号
	stputil.Disable(loginID, 3600) // 封禁 1 小时

	w := ut.PerformRequest(router.Engine, "GET", "/resource", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "账号已被封禁")
}

// TestIgnore_SkipsAuthentication 测试忽略认证装饰器
func TestIgnore_SkipsAuthentication(t *testing.T) {
	router := setupTestRouter()

	router.GET("/public", Ignore(), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "public data"})
	})

	w := ut.PerformRequest(router.Engine, "GET", "/public", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "public data")
}

// TestChainedMiddleware_CheckRoleAndHandler 测试链式中间件：CheckRole + 实际处理器
func TestChainedMiddleware_CheckRoleAndHandler(t *testing.T) {
	router := setupTestRouter()

	// 模拟用户示例代码的使用方式
	safeGroup := router.Group("/safe")
	{
		safeGroup.GET("", CheckRole("SuperAdmin"), func(c context.Context, ctx *app.RequestContext) {
			ctx.JSON(http.StatusOK, utils.H{"message": "safe settings"})
		})
	}

	// 测试具有 SuperAdmin 角色的用户
	token := mockLoginWithRole("admin123", []string{"SuperAdmin"})

	w := ut.PerformRequest(router.Engine, "GET", "/safe", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "safe settings")
}

// TestChainedMiddleware_CheckRoleAndHandler_NoRole 测试链式中间件：无角色访问
func TestChainedMiddleware_CheckRoleAndHandler_NoRole(t *testing.T) {
	router := setupTestRouter()

	safeGroup := router.Group("/safe")
	{
		safeGroup.GET("", CheckRole("SuperAdmin"), func(c context.Context, ctx *app.RequestContext) {
			ctx.JSON(http.StatusOK, utils.H{"message": "safe settings"})
		})
	}

	// 测试具有普通用户角色
	token := mockLoginWithRole("user123", []string{"User"})

	w := ut.PerformRequest(router.Engine, "GET", "/safe", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "角色不足")
}

// TestGetHandler_WithNilHandler 测试 GetHandler 在 handler 为 nil 时的行为
func TestGetHandler_WithNilHandler(t *testing.T) {
	router := setupTestRouter()

	// 直接使用 GetHandler 创建中间件
	middleware := GetHandler(nil, &Annotation{CheckRole: []string{"Admin"}})

	router.GET("/test", middleware, func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "test passed"})
	})

	token := mockLoginWithRole("testuser", []string{"Admin"})

	w := ut.PerformRequest(router.Engine, "GET", "/test", nil,
		ut.Header{Key: "Authorization", Value: token})

	// 应该能够正常执行，不会 panic
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test passed")
}

// TestMiddleware_CheckRole 测试 Middleware 函数的角色检查
func TestMiddleware_CheckRole(t *testing.T) {
	router := setupTestRouter()

	// 使用 Middleware 函数
	router.GET("/api/data", Middleware(&Annotation{CheckRole: []string{"Admin"}}), func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"data": "sensitive data"})
	})

	token := mockLoginWithRole("admin999", []string{"Admin"})

	w := ut.PerformRequest(router.Engine, "GET", "/api/data", nil,
		ut.Header{Key: "Authorization", Value: token})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sensitive data")
}

// TestParseTag 测试标签解析功能
func TestParseTag(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		expected *Annotation
	}{
		{
			name: "解析登录检查标签",
			tag:  "sa_check_login",
			expected: &Annotation{
				CheckLogin: true,
			},
		},
		{
			name: "解析角色检查标签",
			tag:  "sa_check_role=Admin|SuperAdmin",
			expected: &Annotation{
				CheckRole: []string{"Admin", "SuperAdmin"},
			},
		},
		{
			name: "解析权限检查标签",
			tag:  "sa_check_permission=user.read|user.write",
			expected: &Annotation{
				CheckPermission: []string{"user.read", "user.write"},
			},
		},
		{
			name: "解析忽略认证标签",
			tag:  "sa_ignore",
			expected: &Annotation{
				Ignore: true,
			},
		},
		{
			name: "解析封禁检查标签",
			tag:  "sa_check_disable",
			expected: &Annotation{
				CheckDisable: true,
			},
		},
		{
			name:     "空标签",
			tag:      "",
			expected: &Annotation{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseTag(tt.tag)
			assert.Equal(t, tt.expected.CheckLogin, result.CheckLogin)
			assert.Equal(t, tt.expected.CheckRole, result.CheckRole)
			assert.Equal(t, tt.expected.CheckPermission, result.CheckPermission)
			assert.Equal(t, tt.expected.CheckDisable, result.CheckDisable)
			assert.Equal(t, tt.expected.Ignore, result.Ignore)
		})
	}
}

// TestAnnotationValidate 测试注解验证功能
func TestAnnotationValidate(t *testing.T) {
	tests := []struct {
		name       string
		annotation *Annotation
		valid      bool
	}{
		{
			name: "有效的单一检查",
			annotation: &Annotation{
				CheckLogin: true,
			},
			valid: true,
		},
		{
			name: "有效的忽略标记",
			annotation: &Annotation{
				Ignore:     true,
				CheckLogin: true, // 即使有其他标记，忽略时仍然有效
			},
			valid: true,
		},
		{
			name:       "有效的空注解",
			annotation: &Annotation{},
			valid:      true,
		},
		{
			name: "无效的多重检查",
			annotation: &Annotation{
				CheckLogin: true,
				CheckRole:  []string{"Admin"},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.annotation.Validate()
			assert.Equal(t, tt.valid, result)
		})
	}
}
