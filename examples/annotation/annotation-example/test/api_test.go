// @Author daixk 2026/1/4 15:57:00
package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

//
// 工具函数
//

// 简单封装 HTTP 请求
func doRequest(t *testing.T, method, url string, body any, token string) {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("创建请求错误: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("\n[%s %s] 返回结果:\n%s\n\n", method, url, b)
}

//
// 每个接口单独测试
//

// 1. 公开接口
func TestPublic(t *testing.T) {
	doRequest(t, "GET", "http://localhost:8080/public", nil, "")
}

// 2. 登录
func TestLoginUser1(t *testing.T) {
	doRequest(t, "POST", "http://localhost:8080/login", map[string]any{
		"userId": 1,
	}, "")
}

func TestLoginUser2(t *testing.T) {
	doRequest(t, "POST", "http://localhost:8080/login", map[string]any{
		"userId": 2,
	}, "")
}

// 3. 获取用户信息（需要登录）
func TestUserInfo(t *testing.T) {
	// 先登录
	token := getToken(t, 2)

	// 请求
	doRequest(t, "GET", "http://localhost:8080/user/info", nil, token)
}

// 4. 管理员接口（admin:*）
func TestAdmin(t *testing.T) {
	token := getToken(t, 1)

	doRequest(t, "GET", "http://localhost:8080/admin", nil, token)
}

// 5. 用户 or 管理员 OR 权限
func TestUserOrAdmin(t *testing.T) {
	token := getToken(t, 2)

	doRequest(t, "GET", "http://localhost:8080/user-or-admin", nil, token)
}

// 6. 测试角色：admin
func TestRoleManager(t *testing.T) {
	token := getToken(t, 1)

	doRequest(t, "GET", "http://localhost:8080/manager-example", nil, token)
}

// 7. 测试封禁接口
func TestDisable(t *testing.T) {
	token := getToken(t, 1)

	doRequest(t, "POST", "http://localhost:8080/disable", map[string]any{
		"userId": 2,
	}, token)
}

// 8. 查看是否被封禁
func TestSensitive(t *testing.T) {
	token := getToken(t, 2)

	doRequest(t, "GET", "http://localhost:8080/sensitive", nil, token)
}

// 工具：登录并返回 token
func getToken(t *testing.T, userID int) string {
	var respBody struct {
		Token string `json:"token"`
	}

	body := map[string]any{"userId": userID}

	var reqBody io.Reader
	b, _ := json.Marshal(body)
	reqBody = bytes.NewReader(b)

	req, _ := http.NewRequest("POST", "http://localhost:8080/login", reqBody)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &respBody)

	if respBody.Token == "" {
		t.Fatalf("登录返回 token 为空: %s", data)
	}

	return respBody.Token
}

//
// 最终测试：执行全部接口
//

func TestAll(t *testing.T) {
	t.Run("Public", TestPublic)

	t.Run("LoginUser1", TestLoginUser1)
	t.Run("LoginUser2", TestLoginUser2)

	t.Run("UserInfo", TestUserInfo)
	t.Run("Admin", TestAdmin)
	t.Run("UserOrAdmin", TestUserOrAdmin)
	t.Run("RoleManager", TestRoleManager)

	t.Run("Disable", TestDisable)
	t.Run("Sensitive", TestSensitive)
}
