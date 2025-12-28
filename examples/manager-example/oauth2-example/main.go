package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/click33/sa-token-go/core/oauth2"
	"github.com/gin-gonic/gin"
)

var oauth2Server *oauth2.OAuth2Server

func main() {
	// 创建 OAuth2 服务器
	// 参数：authType, prefix, storage, serializer
	oauth2Server = oauth2.NewOAuth2Server("login", "sa:", nil, nil)

	// 注册客户端
	registerClients()

	r := gin.Default()

	// OAuth2 端点
	r.GET("/oauth/authorize", authorizeHandler)
	r.POST("/oauth/token", tokenHandler)
	r.GET("/oauth/userinfo", userinfoHandler)
	r.POST("/oauth/revoke", revokeHandler)

	fmt.Println("OAuth2 Server running on http://localhost:8080")
	fmt.Println("\nOAuth2 Flow:")
	fmt.Println("1. GET  /oauth/authorize?client_id=webapp&redirect_uri=http://localhost:8080/callback&response_type=code&state=xyz")
	fmt.Println("2. POST /oauth/token (grant_type=authorization_code&code=...&client_id=webapp&client_secret=secret123&redirect_uri=...)")
	fmt.Println("3. GET  /oauth/userinfo (Authorization: Bearer <token>)")
	fmt.Println("4. POST /oauth/revoke (token=<token>)")

	_ = r.Run(":8080")
}

func registerClients() {
	// 注册 Web 应用客户端
	webClient := &oauth2.Client{
		ClientID:     "webapp",
		ClientSecret: "secret123",
		RedirectURIs: []string{
			"http://localhost:8080/callback",
			"http://localhost:3000/callback",
		},
		GrantTypes: []oauth2.GrantType{
			oauth2.GrantTypeAuthorizationCode,
			oauth2.GrantTypeRefreshToken,
		},
		Scopes: []string{"read", "write", "profile"},
	}
	_ = oauth2Server.RegisterClient(webClient)

	// 注册移动应用客户端
	mobileClient := &oauth2.Client{
		ClientID:     "mobile-app",
		ClientSecret: "mobile-secret-456",
		RedirectURIs: []string{
			"myapp://oauth/callback",
		},
		GrantTypes: []oauth2.GrantType{
			oauth2.GrantTypeAuthorizationCode,
			oauth2.GrantTypeRefreshToken,
		},
		Scopes: []string{"read", "write"},
	}
	_ = oauth2Server.RegisterClient(mobileClient)

	// 注册服务端客户端（客户端凭证模式）
	serviceClient := &oauth2.Client{
		ClientID:     "service-app",
		ClientSecret: "service-secret-789",
		RedirectURIs: []string{},
		GrantTypes: []oauth2.GrantType{
			oauth2.GrantTypeClientCredentials,
		},
		Scopes: []string{"api:read", "api:write"},
	}
	_ = oauth2Server.RegisterClient(serviceClient)

	fmt.Println("✅ OAuth2 Clients registered:")
	fmt.Println("  - webapp (client_id: webapp, secret: secret123)")
	fmt.Println("  - mobile-app (client_id: mobile-app, secret: mobile-secret-456)")
	fmt.Println("  - service-app (client_id: service-app, secret: service-secret-789)")
}

// 授权端点 - 生成授权码
func authorizeHandler(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	state := c.Query("state")
	scope := c.Query("scope")

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type"})
		return
	}

	scopes := []string{"read", "write"}
	if scope != "" {
		scopes = []string{scope}
	}

	// 模拟已登录用户
	userID := "user123"

	ctx := c.Request.Context()

	// 生成授权码
	// 参数顺序：ctx, clientID, userID, redirectURI, scopes
	authCode, err := oauth2Server.GenerateAuthorizationCode(
		ctx,
		clientID,
		userID,
		redirectURI,
		scopes,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode.Code, state)
	c.JSON(http.StatusOK, gin.H{
		"message":      "Authorization code generated",
		"code":         authCode.Code,
		"redirect_url": redirectURL,
		"user_id":      userID,
		"scopes":       scopes,
	})
}

// 令牌端点 - 根据授权类型处理
func tokenHandler(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	ctx := c.Request.Context()

	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(ctx, c)
	case "refresh_token":
		handleRefreshTokenGrant(ctx, c)
	case "client_credentials":
		handleClientCredentialsGrant(ctx, c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

// 授权码模式
func handleAuthorizationCodeGrant(ctx context.Context, c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")

	accessToken, err := oauth2Server.ExchangeCodeForToken(
		ctx,
		code,
		clientID,
		clientSecret,
		redirectURI,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken.Token,
		"token_type":    accessToken.TokenType,
		"expires_in":    accessToken.ExpiresIn,
		"refresh_token": accessToken.RefreshToken,
		"scope":         accessToken.Scopes,
	})
}

// 刷新令牌模式
func handleRefreshTokenGrant(ctx context.Context, c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	accessToken, err := oauth2Server.RefreshAccessToken(
		ctx,
		clientID,
		refreshToken,
		clientSecret,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken.Token,
		"token_type":    accessToken.TokenType,
		"expires_in":    accessToken.ExpiresIn,
		"refresh_token": accessToken.RefreshToken,
		"scope":         accessToken.Scopes,
	})
}

// 客户端凭证模式
func handleClientCredentialsGrant(ctx context.Context, c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	scope := c.PostForm("scope")

	var scopes []string
	if scope != "" {
		scopes = []string{scope}
	}

	accessToken, err := oauth2Server.ClientCredentialsToken(
		ctx,
		clientID,
		clientSecret,
		scopes,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken.Token,
		"token_type":   accessToken.TokenType,
		"expires_in":   accessToken.ExpiresIn,
		"scope":        accessToken.Scopes,
	})
}

// 用户信息端点
func userinfoHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		return
	}

	var token string
	_, _ = fmt.Sscanf(authHeader, "Bearer %s", &token)

	ctx := c.Request.Context()

	// 验证访问令牌并获取信息
	accessToken, err := oauth2Server.ValidateAccessTokenAndGetInfo(ctx, token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    accessToken.UserID,
		"client_id":  accessToken.ClientID,
		"scopes":     accessToken.Scopes,
		"expires_in": accessToken.ExpiresIn,
	})
}

// 撤销令牌端点
func revokeHandler(c *gin.Context) {
	token := c.PostForm("token")
	ctx := c.Request.Context()

	if err := oauth2Server.RevokeToken(ctx, token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token revoked successfully"})
}
