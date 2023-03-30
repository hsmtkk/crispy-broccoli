package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	AUTHORIZATION_REQUEST_URL = "https://www.amazon.com/ap/oa"
	ACCESS_TOKEN_REQUEST_URL  = "https://api.amazon.com/auth/o2/token"
	PROFILE_URL               = "https://api.amazon.com/user/profile"
)

func main() {
	portStr := loadEnvVar("PORT")
	lwaClientID := loadEnvVar("LWA_CLIENT_ID")
	lwaClientSecret := loadEnvVar("LWA_CLIENT_SECRET")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("failed to parse %s as int: %s", portStr, err.Error())
	}

	handler := newHandler(lwaClientID, lwaClientSecret)

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/login", handler.loginHandler)
	e.GET("/redirect", handler.redirectHandler)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))
}

type handler struct {
	lwaClientID     string
	lwaClientSecret string
}

func newHandler(lwaClientID, lwaClientSecret string) *handler {
	return &handler{lwaClientID, lwaClientSecret}
}

func (h *handler) loginHandler(ectx echo.Context) error {
	fmt.Println("loginHandler")
	dumpHTTPRequest(ectx.Request(), false)
	redirectURI := fmt.Sprintf("https://%s/redirect", ectx.Request().Host)
	queries := map[string]string{
		"client_id":     h.lwaClientID,
		"scope":         "profile",
		"response_type": "code",
		"redirect_uri":  redirectURI,
	}
	url, err := makeURL(AUTHORIZATION_REQUEST_URL, queries)
	if err != nil {
		return err
	}
	return ectx.Redirect(http.StatusFound, url)
}

func (h *handler) redirectHandler(ectx echo.Context) error {
	fmt.Println("redirectHandler")
	dumpHTTPRequest(ectx.Request(), false)
	code := ectx.Request().URL.Query().Get("code")
	redirectURI := fmt.Sprintf("https://%s/redirect", ectx.Request().Host)
	accessToken, err := h.getAccessToken(ectx.Request().Context(), code, redirectURI)
	if err != nil {
		return err
	}
	profile, err := getProfile(accessToken)
	if err != nil {
		return err
	}
	return ectx.JSON(http.StatusOK, profile)
}

type accessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func (h *handler) getAccessToken(ctx context.Context, code, redirectURI string) (string, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("redirect_uri", redirectURI)
	values.Set("client_id", h.lwaClientID)
	values.Set("client_secret", h.lwaClientSecret)
	req, err := http.NewRequest(
		http.MethodPost,
		ACCESS_TOKEN_REQUEST_URL,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to make new HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	respBytes, err := sendHTTPRequest(req)
	if err != nil {
		return "", err
	}
	schema := accessTokenResponse{}
	if err := json.Unmarshal(respBytes, &schema); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return schema.AccessToken, nil
}

func dumpHTTPRequest(req *http.Request, dumpBody bool) {
	reqBytes, err := httputil.DumpRequest(req, dumpBody)
	if err != nil {
		fmt.Printf("failed to dump HTTP request: %s", err.Error())
	}
	fmt.Println("dump HTTP request")
	fmt.Println(string(reqBytes))
}

func dumpHTTPResponse(resp *http.Response, dumpBody bool) {
	respBytes, err := httputil.DumpResponse(resp, dumpBody)
	if err != nil {
		fmt.Printf("failed to dump HTTP response: %s", err.Error())
	}
	fmt.Println("dump HTTP response")
	fmt.Println(string(respBytes))
}

type profileResponse struct {
	EMail  string `json:"email"`
	Name   string `json:"name"`
	UserID string `json:"user_id"`
}

func getProfile(accessToken string) (profileResponse, error) {
	profile := profileResponse{}
	req, err := http.NewRequest(http.MethodGet, PROFILE_URL, nil)
	if err != nil {
		return profile, fmt.Errorf("failed to make new HTTP request: %w", err)
	}
	req.Header.Add("x-amz-access-token", accessToken)
	respBytes, err := sendHTTPRequest(req)
	if err != nil {
		return profile, err
	}
	if err := json.Unmarshal(respBytes, &profile); err != nil {
		return profile, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return profile, nil
}

func makeURL(baseURL string, queries map[string]string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %s: %w", baseURL, err)
	}
	q := u.Query()
	for k, v := range queries {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func sendHTTPRequest(req *http.Request) ([]byte, error) {
	dumpHTTPRequest(req, false)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()
	dumpHTTPResponse(resp, false)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("got HTTP error code: %d: %s", resp.StatusCode, resp.Status)
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %w", err)
	}
	return respBytes, nil
}

func loadEnvVar(name string) string {
	val := os.Getenv(name)
	if val == "" {
		log.Fatalf("env var %s is not defined", name)
	}
	return val
}
