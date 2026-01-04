package main

import (
	"encoding/json"
	"log"
	"net/http"

	sachi "github.com/click33/sa-token-go/integrations/chi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	// 使用 Builder 模式构建 Manager | Build Manager using Builder pattern
	manager := sachi.NewDefaultBuild().
		TokenName("Authorization").
		Timeout(7200).
		IsLog(true).
		IsPrintBanner(true).
		Build()

	// 设置全局管理器 | Set global manager
	sachi.SetManager(manager)

	// 创建路由 | Create router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// 登录接口 | Login endpoint
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		if userID == "" {
			http.Error(w, `{"error": "user_id is required"}`, http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		// 使用 sachi 包的全局函数登录 | Use sachi package global function to login
		token, err := sachi.Login(ctx, userID)
		if err != nil {
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "登录成功", "token": "` + token + `"}`))
	})

	// 登出接口 | Logout endpoint
	r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"error": "token is required"}`, http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		// 使用 sachi 包的全局函数登出 | Use sachi package global function to logout
		if err := sachi.LogoutByToken(ctx, token); err != nil {
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "登出成功"}`))
	})

	// 公开路由 | Public route
	r.Get("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "公开访问"}`))
	})

	// 检查登录状态 | Check login status
	r.Get("/check", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"error": "token is required"}`, http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		// 使用 sachi 包的全局函数检查登录 | Use sachi package global function to check login
		isLogin := sachi.IsLogin(ctx, token)
		if !isLogin {
			http.Error(w, `{"error": "未登录"}`, http.StatusUnauthorized)
			return
		}

		// 获取登录ID | Get login ID
		loginID, _ := sachi.GetLoginID(ctx, token)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "已登录", "login_id": "` + loginID + `"}`))
	})

	// 受保护的路由组 | Protected route group
	r.Group(func(r chi.Router) {
		r.Use(sachi.AuthMiddleware())

		// 用户信息 | User info
		r.Get("/api/user", func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			ctx := r.Context()
			loginID, _ := sachi.GetLoginID(ctx, token)

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"user_id": "` + loginID + `", "name": "User ` + loginID + `"}`))
		})

		// 获取 Token 信息 | Get token info
		r.Get("/api/token-info", func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			ctx := r.Context()

			tokenInfo, err := sachi.GetTokenInfo(ctx, token)
			if err != nil {
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{
				"code":    200,
				"message": "获取Token信息成功",
				"data": map[string]interface{}{
					"authType":   tokenInfo.AuthType,
					"loginId":    tokenInfo.LoginID,
					"device":     tokenInfo.Device,
					"createTime": tokenInfo.CreateTime,
					"activeTime": tokenInfo.ActiveTime,
				},
			}
			json.NewEncoder(w).Encode(response)
		})

		// 踢人下线 | Kickout user
		r.Post("/api/kickout/{user_id}", func(w http.ResponseWriter, r *http.Request) {
			userID := chi.URLParam(r, "user_id")
			ctx := r.Context()

			// 使用 sachi 包的全局函数踢人 | Use sachi package global function to kickout
			if err := sachi.Kickout(ctx, userID); err != nil {
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message": "踢人成功"}`))
		})
	})

	// 需要权限的路由组 | Routes requiring permissions
	r.Group(func(r chi.Router) {
		r.Use(sachi.AuthMiddleware())
		r.Use(sachi.PermissionMiddleware([]string{"admin:read"}, sachi.WithLogicType(sachi.LogicOr)))

		r.Get("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message": "管理员面板"}`))
		})
	})

	// 需要角色的路由组 | Routes requiring roles
	r.Group(func(r chi.Router) {
		r.Use(sachi.AuthMiddleware())
		r.Use(sachi.RoleMiddleware([]string{"super-admin"}, sachi.WithLogicType(sachi.LogicAnd)))

		r.Get("/super/settings", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message": "超级管理员设置"}`))
		})
	})

	// 启动服务器 | Start server
	log.Println("服务器启动在端口: 8080")
	log.Println("示例: curl -X POST http://localhost:8080/login -d 'user_id=1000'")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}
