package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const baseURL = "http://127.0.0.1:8000"

// Response 通用响应结构
type Response struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// LoginData 登录响应数据
type LoginData struct {
	Token   string `json:"token"`
	LoginID string `json:"loginID"`
}

// httpGet 发送 GET 请求
func httpGet(url string, token string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("satoken", token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result Response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response failed: %s, body: %s", err, string(body))
	}

	return &result, nil
}

// TestHomePage 测试首页
func TestHomePage(t *testing.T) {
	resp, err := httpGet(baseURL+"/", "")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Errorf("期望 code=200, 实际 code=%d", resp.Code)
	}

	t.Logf("首页响应: code=%d, message=%s", resp.Code, resp.Message)
}

// TestPublicRoute 测试公开路由
func TestPublicRoute(t *testing.T) {
	resp, err := httpGet(baseURL+"/public", "")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Errorf("期望 code=200, 实际 code=%d", resp.Code)
	}

	t.Logf("公开路由响应: code=%d, message=%s", resp.Code, resp.Message)
}

// TestLoginAndLogout 测试登录和登出流程
func TestLoginAndLogout(t *testing.T) {
	// 1. 登录
	t.Log("=== 步骤1: 登录 ===")
	resp, err := httpGet(baseURL+"/login?id=10001", "")
	if err != nil {
		t.Fatalf("登录请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Fatalf("登录失败: code=%d, message=%s", resp.Code, resp.Message)
	}

	var loginData LoginData
	if err := json.Unmarshal(resp.Data, &loginData); err != nil {
		t.Fatalf("解析登录数据失败: %v", err)
	}

	t.Logf("登录成功: token=%s, loginID=%s", loginData.Token, loginData.LoginID)

	// 2. 使用 token 访问受保护资源
	t.Log("=== 步骤2: 访问受保护资源 ===")
	resp, err = httpGet(baseURL+"/api/user", loginData.Token)
	if err != nil {
		t.Fatalf("获取用户信息请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Errorf("获取用户信息失败: code=%d, message=%s", resp.Code, resp.Message)
	} else {
		t.Logf("获取用户信息成功: %s", string(resp.Data))
	}

	// 3. 登出
	t.Log("=== 步骤3: 登出 ===")
	resp, err = httpGet(baseURL+"/logout", loginData.Token)
	if err != nil {
		t.Fatalf("登出请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Errorf("登出失败: code=%d, message=%s", resp.Code, resp.Message)
	} else {
		t.Logf("登出成功: message=%s", resp.Message)
	}

	// 4. 登出后再次访问受保护资源（应该失败）
	t.Log("=== 步骤4: 登出后访问受保护资源 ===")
	resp, err = httpGet(baseURL+"/api/user", loginData.Token)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}

	if resp.Code == 200 {
		t.Error("登出后不应该能访问受保护资源")
	} else {
		t.Logf("符合预期，访问被拒绝: code=%d, message=%s", resp.Code, resp.Message)
	}
}

// TestProtectedRouteWithoutToken 测试无 token 访问受保护路由
func TestProtectedRouteWithoutToken(t *testing.T) {
	resp, err := httpGet(baseURL+"/api/user", "")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}

	if resp.Code == 200 {
		t.Error("无 token 不应该能访问受保护资源")
	} else {
		t.Logf("符合预期，访问被拒绝: code=%d, message=%s", resp.Code, resp.Message)
	}
}

// TestTokenInfo 测试获取 Token 信息
func TestTokenInfo(t *testing.T) {
	// 先登录
	resp, err := httpGet(baseURL+"/login?id=20001", "")
	if err != nil {
		t.Fatalf("登录请求失败: %v", err)
	}

	var loginData LoginData
	if err := json.Unmarshal(resp.Data, &loginData); err != nil {
		t.Fatalf("解析登录数据失败: %v", err)
	}

	t.Logf("登录成功: token=%s", loginData.Token)

	// 获取 Token 信息
	resp, err = httpGet(baseURL+"/api/token-info", loginData.Token)
	if err != nil {
		t.Fatalf("获取Token信息请求失败: %v", err)
	}

	if resp.Code != 200 {
		t.Errorf("获取Token信息失败: code=%d, message=%s", resp.Code, resp.Message)
	} else {
		t.Logf("Token信息: %s", string(resp.Data))
	}
}

// TestAdminDashboard 测试管理员面板（需要权限）
func TestAdminDashboard(t *testing.T) {
	// 先登录
	resp, err := httpGet(baseURL+"/login?id=admin001", "")
	if err != nil {
		t.Fatalf("登录请求失败: %v", err)
	}

	var loginData LoginData
	if err := json.Unmarshal(resp.Data, &loginData); err != nil {
		t.Fatalf("解析登录数据失败: %v", err)
	}

	t.Logf("登录成功: token=%s", loginData.Token)

	// 访问管理员面板
	resp, err = httpGet(baseURL+"/admin/dashboard", loginData.Token)
	if err != nil {
		t.Fatalf("访问管理员面板请求失败: %v", err)
	}

	// 注意：这个测试可能会因为没有配置权限而失败，这是正常的
	t.Logf("管理员面板响应: code=%d, message=%s", resp.Code, resp.Message)
}

// TestSuperSettings 测试超级管理员设置（需要角色）
func TestSuperSettings(t *testing.T) {
	// 先登录
	resp, err := httpGet(baseURL+"/login?id=super001", "")
	if err != nil {
		t.Fatalf("登录请求失败: %v", err)
	}

	var loginData LoginData
	if err := json.Unmarshal(resp.Data, &loginData); err != nil {
		t.Fatalf("解析登录数据失败: %v", err)
	}

	t.Logf("登录成功: token=%s", loginData.Token)

	// 访问超级管理员设置
	resp, err = httpGet(baseURL+"/super/settings", loginData.Token)
	if err != nil {
		t.Fatalf("访问超级管理员设置请求失败: %v", err)
	}

	// 注意：这个测试可能会因为没有配置角色而失败，这是正常的
	t.Logf("超级管理员设置响应: code=%d, message=%s", resp.Code, resp.Message)
}

// TestInvalidToken 测试无效 Token
func TestInvalidToken(t *testing.T) {
	resp, err := httpGet(baseURL+"/api/user", "invalid-token-12345")
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}

	if resp.Code == 200 {
		t.Error("无效 token 不应该能访问受保护资源")
	} else {
		t.Logf("符合预期，无效Token被拒绝: code=%d, message=%s", resp.Code, resp.Message)
	}
}

// TestMultipleLogin 测试多次登录同一用户
func TestMultipleLogin(t *testing.T) {
	userID := "multi-user-001"

	// 第一次登录
	resp1, err := httpGet(baseURL+"/login?id="+userID, "")
	if err != nil {
		t.Fatalf("第一次登录请求失败: %v", err)
	}

	var loginData1 LoginData
	if err := json.Unmarshal(resp1.Data, &loginData1); err != nil {
		t.Fatalf("解析第一次登录数据失败: %v", err)
	}

	t.Logf("第一次登录成功: token=%s", loginData1.Token)

	// 第二次登录
	resp2, err := httpGet(baseURL+"/login?id="+userID, "")
	if err != nil {
		t.Fatalf("第二次登录请求失败: %v", err)
	}

	var loginData2 LoginData
	if err := json.Unmarshal(resp2.Data, &loginData2); err != nil {
		t.Fatalf("解析第二次登录数据失败: %v", err)
	}

	t.Logf("第二次登录成功: token=%s", loginData2.Token)

	// 检查两个 token 是否都有效
	resp, err := httpGet(baseURL+"/api/user", loginData1.Token)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	t.Logf("第一个Token访问结果: code=%d, message=%s", resp.Code, resp.Message)

	resp, err = httpGet(baseURL+"/api/user", loginData2.Token)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	t.Logf("第二个Token访问结果: code=%d, message=%s", resp.Code, resp.Message)
}

// 以下是一个完整的测试流程示例，可以直接运行
func ExampleFullFlow() {
	fmt.Println("=== Sa-Token-Go GF Example API 测试 ===")
	fmt.Println()

	// 1. 测试首页
	fmt.Println("1. 测试首页")
	resp, _ := httpGet(baseURL+"/", "")
	fmt.Printf("   响应: %s\n", resp.Message)

	// 2. 测试公开路由
	fmt.Println("2. 测试公开路由")
	resp, _ = httpGet(baseURL+"/public", "")
	fmt.Printf("   响应: %s\n", resp.Message)

	// 3. 登录
	fmt.Println("3. 登录")
	resp, _ = httpGet(baseURL+"/login?id=test001", "")
	var loginData LoginData
	json.Unmarshal(resp.Data, &loginData)
	fmt.Printf("   Token: %s\n", loginData.Token)

	// 4. 访问受保护资源
	fmt.Println("4. 访问受保护资源")
	resp, _ = httpGet(baseURL+"/api/user", loginData.Token)
	fmt.Printf("   响应: %s\n", resp.Message)

	// 5. 登出
	fmt.Println("5. 登出")
	resp, _ = httpGet(baseURL+"/logout", loginData.Token)
	fmt.Printf("   响应: %s\n", resp.Message)

	fmt.Println()
	fmt.Println("=== 测试完成 ===")
}

// BenchmarkLogin 登录性能测试
func BenchmarkLogin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		httpGet(baseURL+"/login?id=bench-user", "")
	}
}

// BenchmarkProtectedRoute 受保护路由性能测试
func BenchmarkProtectedRoute(b *testing.B) {
	// 先登录获取 token
	resp, err := httpGet(baseURL+"/login?id=bench-user", "")
	if err != nil {
		b.Fatalf("登录失败: %v", err)
	}

	var loginData LoginData
	if err := json.Unmarshal(resp.Data, &loginData); err != nil {
		b.Fatalf("解析登录数据失败: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		httpGet(baseURL+"/api/user", loginData.Token)
	}
}

// 辅助函数：打印分隔线
func printSeparator(title string) {
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("  %s\n", title)
	fmt.Println(strings.Repeat("=", 50))
}
