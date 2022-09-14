package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc"
	gin_oidc "github.com/dakario/gin-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Initialize session cookie
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	// gin OIDC middleware preparation
	issuerUrl, _ := url.Parse("https://cloudsso.cisco.com")
	clientUrl, _ := url.Parse("http://localhost:8080/")
	logoutUrl, _ := url.Parse("https://wwww.cisco.com/")

	initParams := gin_oidc.InitParams{
		Router:       router,
		ClientId:     "",
		ClientSecret: "",
		Issuer:       *issuerUrl,
		ClientUrl:    *clientUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		ErrorHandler: func(c *gin.Context) {
			message := c.Errors.Last().Error()
			c.IndentedJSON(http.StatusInternalServerError, message)
		},
		PostLogoutUrl: *logoutUrl, // Mind you, the gin-oidc code assumes the Idp _ALWAYS_ uses /protocol/openid-connect/logout to log out. This is not the case... .
		// If your Idp doesn't, logging out will crash your code. Relevant code is at https://github.com/dakario/gin-oidc/blob/master/ginoidc.go#L75
	}

	// To protect all endpoints
	// router.Use(gin_oidc.Init(initParams))

	// or... protect a individual endpoints
	protectMiddleware := gin_oidc.Init(initParams)

	router.GET("/secret", protectMiddleware, getProtected)
	router.GET("/public", getPublic)

	router.Run("0.0.0.0:8080")
}

func getPublic(ctx *gin.Context) {
	ctx.IndentedJSON(http.StatusOK, "public")
}

func getProtected(ctx *gin.Context) {
	// Get the Claims we're returning
	serverSession := sessions.Default(ctx)
	claims := serverSession.Get("oidcClaims")

	if claims != nil {
		// claims is an Interface, cast it to []byte so we can JSON Unmarshal it
		ss := map[string]string{}
		json.Unmarshal([]byte(claims.(string)), &ss)

		username := ss["sub"]
		message := fmt.Sprintf("Protected Endpoint! User %v is Authorized!", username)

		ctx.IndentedJSON(http.StatusOK, message)
	}
}
