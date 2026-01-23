//go:build ignore

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TokenResponse from Harbor's token service
type TokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at"`
}

func main() {
	// Configuration - set these via environment variables
	registry := getEnv("HARBOR_REGISTRY", "harbor.osso.io")
	repo := getEnv("HARBOR_REPO", "slash2/craft-fpm")
	tag := getEnv("HARBOR_TAG", "8.3-slim")
	username := os.Getenv("HARBOR_USERNAME")
	password := os.Getenv("HARBOR_PASSWORD")

	if username == "" || password == "" {
		fmt.Println("Please set HARBOR_USERNAME and HARBOR_PASSWORD environment variables")
		os.Exit(1)
	}

	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repo, tag)
	fmt.Printf("Target: %s\n", manifestURL)
	fmt.Printf("Username: %s\n\n", username)

	// Test 1: Single request
	fmt.Println("=== Test 1: Single Request ===")
	if err := testSingleRequest(manifestURL, registry, username, password); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}

	// Test 2: Sequential requests (reusing token)
	fmt.Println("\n=== Test 2: Sequential Requests (reuse token) ===")
	if err := testSequentialRequests(manifestURL, registry, username, password, 5); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}

	// Test 3: Concurrent requests (each gets own token)
	fmt.Println("\n=== Test 3: Concurrent Requests (separate tokens) ===")
	testConcurrentRequests(manifestURL, registry, username, password, 10)

	// Test 4: Concurrent requests with shared token
	fmt.Println("\n=== Test 4: Concurrent Requests (shared token) ===")
	testConcurrentSharedToken(manifestURL, registry, username, password, 10)
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// testSingleRequest does a single auth + HEAD request
func testSingleRequest(manifestURL, registry, username, password string) error {
	token, err := getToken(registry, username, password, manifestURL)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}
	fmt.Printf("Got token: %s...\n", token[:min(50, len(token))])

	status, err := doHeadRequest(manifestURL, token)
	if err != nil {
		return fmt.Errorf("HEAD request: %w", err)
	}
	fmt.Printf("HEAD response: %d\n", status)
	return nil
}

// testSequentialRequests gets one token and reuses it
func testSequentialRequests(manifestURL, registry, username, password string, count int) error {
	token, err := getToken(registry, username, password, manifestURL)
	if err != nil {
		return fmt.Errorf("get token: %w", err)
	}
	fmt.Printf("Got token: %s...\n", token[:min(50, len(token))])

	for i := 0; i < count; i++ {
		status, err := doHeadRequest(manifestURL, token)
		if err != nil {
			fmt.Printf("  Request %d: ERROR - %v\n", i+1, err)
		} else {
			fmt.Printf("  Request %d: %d\n", i+1, status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// testConcurrentRequests - each goroutine gets its own token
func testConcurrentRequests(manifestURL, registry, username, password string, count int) {
	var wg sync.WaitGroup
	results := make(chan string, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each request gets its own token
			token, err := getToken(registry, username, password, manifestURL)
			if err != nil {
				results <- fmt.Sprintf("  Request %d: TOKEN ERROR - %v", id, err)
				return
			}

			status, err := doHeadRequest(manifestURL, token)
			if err != nil {
				results <- fmt.Sprintf("  Request %d: HEAD ERROR - %v", id, err)
				return
			}
			results <- fmt.Sprintf("  Request %d: %d", id, status)
		}(i + 1)
	}

	wg.Wait()
	close(results)

	for r := range results {
		fmt.Println(r)
	}
}

// testConcurrentSharedToken - all goroutines share one token
func testConcurrentSharedToken(manifestURL, registry, username, password string, count int) {
	token, err := getToken(registry, username, password, manifestURL)
	if err != nil {
		fmt.Printf("ERROR getting token: %v\n", err)
		return
	}
	fmt.Printf("Got shared token: %s...\n", token[:min(50, len(token))])

	var wg sync.WaitGroup
	results := make(chan string, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			status, err := doHeadRequest(manifestURL, token)
			if err != nil {
				results <- fmt.Sprintf("  Request %d: ERROR - %v", id, err)
				return
			}
			results <- fmt.Sprintf("  Request %d: %d", id, status)
		}(i + 1)
	}

	wg.Wait()
	close(results)

	for r := range results {
		fmt.Println(r)
	}
}

// getToken fetches a bearer token from Harbor's token service
func getToken(registry, username, password, manifestURL string) (string, error) {
	// Step 1: Make unauthenticated request to get WWW-Authenticate header
	client := &http.Client{Timeout: 30 * time.Second}

	req, _ := http.NewRequest("HEAD", manifestURL, nil)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("initial request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Step 2: Parse WWW-Authenticate header
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("no WWW-Authenticate header")
	}

	realm, service, scope, err := parseWWWAuthenticate(wwwAuth)
	if err != nil {
		return "", fmt.Errorf("parse WWW-Authenticate: %w", err)
	}

	fmt.Printf("  Token service: %s\n", realm)
	fmt.Printf("  Service: %s, Scope: %s\n", service, scope)

	// Step 3: Request token from token service
	tokenURL := fmt.Sprintf("%s?service=%s&scope=%s",
		realm,
		url.QueryEscape(service),
		url.QueryEscape(scope))

	tokenReq, _ := http.NewRequest("GET", tokenURL, nil)

	// Add Basic Auth
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	tokenReq.Header.Set("Authorization", "Basic "+auth)

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		return "", fmt.Errorf("token service returned %d: %s", tokenResp.StatusCode, string(body))
	}

	var tokenData TokenResponse
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	// Harbor returns "token", Docker Hub returns "access_token"
	token := tokenData.Token
	if token == "" {
		token = tokenData.AccessToken
	}

	return token, nil
}

// parseWWWAuthenticate extracts realm, service, and scope from WWW-Authenticate header
func parseWWWAuthenticate(header string) (realm, service, scope string, err error) {
	// Example: Bearer realm="https://harbor.osso.io/service/token",service="harbor-registry",scope="repository:slash2/craft-fpm:pull"

	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", "", fmt.Errorf("not Bearer auth: %s", header)
	}

	realmRe := regexp.MustCompile(`realm="([^"]+)"`)
	serviceRe := regexp.MustCompile(`service="([^"]+)"`)
	scopeRe := regexp.MustCompile(`scope="([^"]+)"`)

	if m := realmRe.FindStringSubmatch(header); m != nil {
		realm = m[1]
	}
	if m := serviceRe.FindStringSubmatch(header); m != nil {
		service = m[1]
	}
	if m := scopeRe.FindStringSubmatch(header); m != nil {
		scope = m[1]
	}

	if realm == "" {
		return "", "", "", fmt.Errorf("no realm in header")
	}

	return realm, service, scope, nil
}

// doHeadRequest performs a HEAD request with Bearer token
func doHeadRequest(manifestURL, token string) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, _ := http.NewRequest("HEAD", manifestURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}
