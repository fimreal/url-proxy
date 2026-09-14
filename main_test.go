package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeTargetURL(t *testing.T) {
	tests := []struct {
		name       string
		rawURI     string
		urlPath    string
		expectURL  string
		expectFail bool
	}{
		{
			name:      "Standard HTTPS",
			rawURI:    "/https://github.com/torvalds/linux",
			urlPath:   "/https:/github.com/torvalds/linux",
			expectURL: "https://github.com/torvalds/linux",
		},
		{
			name:      "Standard HTTP",
			rawURI:    "/http://example.com/index.html",
			urlPath:   "/http:/example.com/index.html",
			expectURL: "http://example.com/index.html",
		},
		{
			name:      "Reverse Proxy Slash Collapsed (https:/)",
			rawURI:    "/https:/github.com/torvalds/linux/releases",
			urlPath:   "/https:/github.com/torvalds/linux/releases",
			expectURL: "https://github.com/torvalds/linux/releases",
		},
		{
			name:      "Reverse Proxy Slash Collapsed (http:/)",
			rawURI:    "/http:/example.com/api",
			urlPath:   "/http:/example.com/api",
			expectURL: "http://example.com/api",
		},
		{
			name:      "URL Encoded Scheme (%3A%2F%2F)",
			rawURI:    "/https%3A%2F%2Fgithub.com%2Ftorvalds",
			urlPath:   "/https%3A%2F%2Fgithub.com%2Ftorvalds",
			expectURL: "https://github.com/torvalds",
		},
		{
			name:      "URL Encoded Scheme Single Slash (%3A%2F)",
			rawURI:    "/https%3A%2Fgithub.com%2Ftorvalds",
			urlPath:   "/https%3A%2Fgithub.com%2Ftorvalds",
			expectURL: "https://github.com/torvalds",
		},
		{
			name:      "URL Encoded Scheme Lowercase (%3a%2f%2f)",
			rawURI:    "/https%3a%2f%2fgithub.com%2farchive.tar.gz",
			urlPath:   "/https%3a%2f%2fgithub.com%2farchive.tar.gz",
			expectURL: "https://github.com/archive.tar.gz",
		},
		{
			name:      "Missing Scheme (Default to HTTPS)",
			rawURI:    "/github.com/torvalds/linux",
			urlPath:   "/github.com/torvalds/linux",
			expectURL: "https://github.com/torvalds/linux",
		},
		{
			name:      "Preserve Query String",
			rawURI:    "/https://api.github.com/repos?state=open&sort=created",
			urlPath:   "/https:/api.github.com/repos",
			expectURL: "https://api.github.com/repos?state=open&sort=created",
		},
		{
			name:      "Preserve Port",
			rawURI:    "/http://example.com:8443/test",
			urlPath:   "/http:/example.com:8443/test",
			expectURL: "http://example.com:8443/test",
		},
		{
			name:      "Multiple leading slashes",
			rawURI:    "///https://github.com/test",
			urlPath:   "/https:/github.com/test",
			expectURL: "https://github.com/test",
		},
		{
			name:       "Empty target",
			rawURI:     "/",
			urlPath:    "/",
			expectFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, err := NormalizeTargetURL(tt.rawURI, tt.urlPath)
			if tt.expectFail {
				if err == nil {
					t.Errorf("expected failure, got URL: %v", gotURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotURL.String() != tt.expectURL {
				t.Errorf("expected %q, got %q", tt.expectURL, gotURL.String())
			}
		})
	}
}

func TestSecurityManager_SSRF(t *testing.T) {
	cfg := &Config{
		BlockPrivateIPs: true,
	}
	sm := NewSecurityManager(cfg)

	privateIPs := []string{
		"127.0.0.1",
		"10.0.0.1",
		"10.255.255.254",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254", // Cloud metadata
		"0.0.0.0",
		"::1",
		"fc00::1",
		"fe80::1",
	}

	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		if !sm.IsPrivateOrBlockedIP(ip) {
			t.Errorf("expected IP %s to be recognized as private/blocked", ipStr)
		}
		err := sm.ValidateTargetHost(ipStr)
		if err == nil {
			t.Errorf("expected ValidateTargetHost to reject private IP %s", ipStr)
		}
	}

	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"140.82.121.3", // GitHub IP
	}

	for _, ipStr := range publicIPs {
		ip := net.ParseIP(ipStr)
		if sm.IsPrivateOrBlockedIP(ip) {
			t.Errorf("expected public IP %s to not be blocked", ipStr)
		}
		if err := sm.ValidateTargetHost(ipStr); err != nil {
			t.Errorf("expected ValidateTargetHost to allow public IP %s, got: %v", ipStr, err)
		}
	}
}

func TestSecurityManager_DomainAllowAndBlock(t *testing.T) {
	cfg := &Config{
		AllowDomains:    []string{"*.github.com", "github.com", "objects.githubusercontent.com"},
		BlockDomains:    []string{"malicious.github.com"},
		BlockPrivateIPs: true,
	}
	sm := NewSecurityManager(cfg)

	allowed := []string{
		"github.com",
		"api.github.com",
		"raw.github.com",
		"objects.githubusercontent.com",
	}
	for _, h := range allowed {
		if err := sm.ValidateTargetHost(h); err != nil {
			t.Errorf("expected %s to be allowed, got error: %v", h, err)
		}
	}

	blocked := []string{
		"malicious.github.com", // in BlockDomains
		"google.com",           // not in AllowDomains
		"gitlab.com",           // not in AllowDomains
	}
	for _, h := range blocked {
		if err := sm.ValidateTargetHost(h); err == nil {
			t.Errorf("expected %s to be blocked, but was allowed", h)
		}
	}
}

func TestSecurityManager_WildcardAllDomains(t *testing.T) {
	cfg := &Config{
		AllowDomains:    []string{"*"},
		BlockDomains:    []string{"blocked-evil.com"},
		BlockPrivateIPs: true,
	}
	sm := NewSecurityManager(cfg)

	// All public domains should be allowed
	publicDomains := []string{
		"github.com",
		"gitlab.com",
		"huggingface.co",
		"raw.githubusercontent.com",
		"google.com",
		"sub.anydomain.org",
	}
	for _, h := range publicDomains {
		if err := sm.ValidateTargetHost(h); err != nil {
			t.Errorf("expected %s to be allowed when ALLOW_DOMAINS=*, got error: %v", h, err)
		}
	}

	// BlockDomains should still be enforced
	if err := sm.ValidateTargetHost("blocked-evil.com"); err == nil {
		t.Errorf("expected blocked-evil.com to be blocked even when ALLOW_DOMAINS=*")
	}

	// Private IPs should still be blocked (SSRF defense)
	if err := sm.ValidateTargetHost("127.0.0.1"); err == nil {
		t.Errorf("expected 127.0.0.1 to be blocked by SSRF even when ALLOW_DOMAINS=*")
	}
	if err := sm.ValidateTargetHost("169.254.169.254"); err == nil {
		t.Errorf("expected 169.254.169.254 to be blocked by SSRF even when ALLOW_DOMAINS=*")
	}
}

func TestProxyServer_RedirectAndHeaders(t *testing.T) {
	// Setup mock upstream server
	upstreamMux := http.NewServeMux()

	// Endpoint 1: 302 Redirect to /final-asset
	upstreamMux.HandleFunc("/download/app.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final-asset", http.StatusFound)
	})

	// Endpoint 2: Target with headers and body
	upstreamMux.HandleFunc("/final-asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="app.tar.gz"`)
		w.Header().Set("X-Custom-Upstream", "Present")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Asset Content v1.0.0"))
	})

	upstreamServer := httptest.NewServer(upstreamMux)
	defer upstreamServer.Close()

	// Create ProxyServer instance with private IP blocking disabled for test server (127.0.0.1)
	cfg := &Config{
		Port:            ":8080",
		BlockPrivateIPs: false, // allow 127.0.0.1 httptest server
		MaxRedirects:    10,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	// Send request through proxy
	targetReqPath := fmt.Sprintf("/%s/download/app.tar.gz", upstreamServer.URL)
	req := httptest.NewRequest("GET", targetReqPath, nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after following redirect, got %d", res.StatusCode)
	}

	if cd := res.Header.Get("Content-Disposition"); cd != `attachment; filename="app.tar.gz"` {
		t.Errorf("Content-Disposition header mismatch, got %q", cd)
	}

	if ct := res.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type header mismatch, got %q", ct)
	}

	body, _ := io.ReadAll(res.Body)
	if string(body) != "Asset Content v1.0.0" {
		t.Errorf("body mismatch, got %q", string(body))
	}
}

func TestProxyServer_RangePartialContent(t *testing.T) {
	// Setup mock upstream server supporting Range
	fullContent := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "bytes=0-9" {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Range", "bytes 0-9/36")
			w.WriteHeader(http.StatusPartialContent)
			w.Write([]byte(fullContent[0:10]))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fullContent))
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    10,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	targetReqPath := fmt.Sprintf("/%s/data.txt", upstreamServer.URL)
	req := httptest.NewRequest("GET", targetReqPath, nil)
	req.Header.Set("Range", "bytes=0-9")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("expected 206 Partial Content, got %d", res.StatusCode)
	}

	if cr := res.Header.Get("Content-Range"); cr != "bytes 0-9/36" {
		t.Errorf("expected Content-Range 'bytes 0-9/36', got %q", cr)
	}

	body, _ := io.ReadAll(res.Body)
	if string(body) != "0123456789" {
		t.Errorf("body mismatch: got %q, expected '0123456789'", string(body))
	}
}

func TestProxyServer_HealthCheck(t *testing.T) {
	cfg := &Config{
		Port:            ":8080",
		AllowDomains:    []string{"github.com"},
		BlockPrivateIPs: true,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("expected health check json, got %s", string(body))
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("ALLOW_DOMAINS", "github.com,*.github.com")
	t.Setenv("BLOCK_DOMAINS", "bad.com")
	t.Setenv("BLOCK_PRIVATE_IPS", "false")
	t.Setenv("MAX_REDIRECTS", "5")
	t.Setenv("BUFFER_SIZE_KB", "64")

	cfg := LoadConfig()
	if cfg.Port != ":9090" {
		t.Errorf("expected port :9090, got %s", cfg.Port)
	}
	if len(cfg.AllowDomains) != 2 || cfg.AllowDomains[0] != "github.com" {
		t.Errorf("unexpected allow domains: %v", cfg.AllowDomains)
	}
	if len(cfg.BlockDomains) != 1 || cfg.BlockDomains[0] != "bad.com" {
		t.Errorf("unexpected block domains: %v", cfg.BlockDomains)
	}
	if cfg.BlockPrivateIPs != false {
		t.Errorf("expected block private ips false, got true")
	}
	if cfg.MaxRedirects != 5 {
		t.Errorf("expected max redirects 5, got %d", cfg.MaxRedirects)
	}
	if cfg.BufferSizeKB != 64 {
		t.Errorf("expected buffer size 64, got %d", cfg.BufferSizeKB)
	}
	if cfg.HideClientIP {
		t.Errorf("expected HideClientIP to be false by default")
	}
}

func TestNormalizeTargetURL_MoreCases(t *testing.T) {
	// Query with %3F
	u, err := NormalizeTargetURL("/https://example.com/search%3Fq=test", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.RawQuery != "q=test" {
		t.Errorf("expected query 'q=test', got %q", u.RawQuery)
	}

	// Unsupported scheme
	_, err = NormalizeTargetURL("/ftp://ftp.example.com/file", "")
	if err == nil {
		t.Errorf("expected error for ftp scheme, got nil")
	}
}

func TestProxyServer_ForbiddenAndErrors(t *testing.T) {
	cfg := &Config{
		AllowDomains:    []string{"allowed.com"},
		BlockDomains:    []string{"blocked.com"},
		BlockPrivateIPs: true,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	// 1. Blocked domain
	req := httptest.NewRequest("GET", "/http://blocked.com/foo", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked domain, got %d", rec.Code)
	}

	// 2. Non-allowed domain
	req = httptest.NewRequest("GET", "/http://other.com/foo", nil)
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-allowed domain, got %d", rec.Code)
	}

	// 3. SSRF direct private IP
	req = httptest.NewRequest("GET", "/http://127.0.0.1:80/secret", nil)
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SSRF private IP, got %d", rec.Code)
	}

	// 4. Bad request (empty target)
	req = httptest.NewRequest("GET", "/bad-url-without-host", nil)
	// Wait, bad-url-without-host defaults to https://bad-url-without-host, which isn't allowed
	// Try empty target:
	req = httptest.NewRequest("GET", "/://invalid", nil)
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
		t.Errorf("expected 400 or 403, got %d", rec.Code)
	}
}

func TestProxyServer_RootUsagePage(t *testing.T) {
	cfg := &Config{
		Port: ":8080",
	}
	proxy := NewProxyServer(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for root, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "极轻量通用 URL 转发服务") {
		t.Errorf("expected usage page HTML")
	}
}

func TestProxyServer_PostStreamBody(t *testing.T) {
	var receivedBody string
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.Header().Set("X-Echo", "OK")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Created Successfully"))
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	postData := "name=firefly&action=deploy"
	req := httptest.NewRequest("POST", "/"+upstreamServer.URL+"/api/resource", strings.NewReader(postData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}
	if receivedBody != postData {
		t.Errorf("upstream did not receive correct POST body: got %q, expected %q", receivedBody, postData)
	}
}

func TestProxyServer_NoRedirectWhenMaxZero(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/target", http.StatusFound)
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    0, // Do not follow redirects
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/redirect", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found when MaxRedirects=0, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/target" {
		t.Errorf("expected Location header 'https://example.com/target', got %q", loc)
	}
}

func TestProxyServer_SSEStreamingChatCompletion(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Verify headers
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer sk-test-123456" {
			t.Errorf("expected Authorization header 'Bearer sk-test-123456', got %q", auth)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}

		// 2. Verify body
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"stream":true`) {
			t.Errorf("expected body to contain stream:true, got %s", string(body))
		}

		// 3. Respond with SSE stream
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		chunks := []string{
			"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":\" OpenAI\"}}]}\n\n",
			"data: [DONE]\n\n",
		}
		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			if ok {
				flusher.Flush()
			}
		}
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	payload := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/"+upstreamServer.URL+"/v1/chat/completions", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer sk-test-123456")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	respBody, _ := io.ReadAll(res.Body)
	expectedContent := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" OpenAI\"}}]}\n\ndata: [DONE]\n\n"
	if string(respBody) != expectedContent {
		t.Errorf("streamed body mismatch: got %q, expected %q", string(respBody), expectedContent)
	}
}

func TestLoadConfig_HideClientIP(t *testing.T) {
	// 1. Default when no env set: HideClientIP should be false (transparent IP passthrough)
	t.Setenv("HIDE_CLIENT_IP", "")
	t.Setenv("FORWARD_CLIENT_IP", "")
	cfg := LoadConfig()
	if cfg.HideClientIP != false {
		t.Errorf("expected default HideClientIP false, got %v", cfg.HideClientIP)
	}

	// 2. Explicit HIDE_CLIENT_IP=false
	t.Setenv("HIDE_CLIENT_IP", "false")
	t.Setenv("FORWARD_CLIENT_IP", "")
	cfg = LoadConfig()
	if cfg.HideClientIP != false {
		t.Errorf("expected HideClientIP false when HIDE_CLIENT_IP=false")
	}

	// 3. FORWARD_CLIENT_IP=true
	t.Setenv("HIDE_CLIENT_IP", "")
	t.Setenv("FORWARD_CLIENT_IP", "true")
	cfg = LoadConfig()
	if cfg.HideClientIP != false {
		t.Errorf("expected HideClientIP false when FORWARD_CLIENT_IP=true")
	}

	// 4. HIDE_CLIENT_IP=true
	t.Setenv("HIDE_CLIENT_IP", "true")
	t.Setenv("FORWARD_CLIENT_IP", "true") // HIDE_CLIENT_IP takes precedence
	cfg = LoadConfig()
	if cfg.HideClientIP != true {
		t.Errorf("expected HideClientIP true when HIDE_CLIENT_IP=true")
	}
}

func TestProxyServer_HideClientIP(t *testing.T) {
	var receivedHeaders http.Header
	var mu sync.Mutex

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstreamServer.Close()

	// Case 1: HideClientIP is true (High anonymity mode)
	{
		cfg := &Config{
			BlockPrivateIPs: false,
			MaxRedirects:    5,
			BufferSizeKB:    32,
			HideClientIP:    true,
		}
		proxy := NewProxyServer(cfg)

		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.RemoteAddr = "198.51.100.10:54321"
		req.Header.Set("Authorization", "Bearer test-secret")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.Header.Set("X-Real-IP", "203.0.113.1")
		req.Header.Set("X-Client-IP", "203.0.113.1")
		req.Header.Set("CF-Connecting-IP", "203.0.113.1")
		req.Header.Set("True-Client-IP", "203.0.113.1")
		req.Header.Set("Forwarded", "for=203.0.113.1")
		req.Header.Set("User-Agent", "my-client/1.0")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Verify standard headers are preserved
		if headers.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("expected Authorization to be preserved, got %q", headers.Get("Authorization"))
		}
		if headers.Get("User-Agent") != "my-client/1.0" {
			t.Errorf("expected User-Agent to be preserved, got %q", headers.Get("User-Agent"))
		}

		// Verify all client identifying headers and proxy info headers are stripped
		disallowed := []string{
			"X-Forwarded-For",
			"X-Forwarded-Proto",
			"X-Real-Ip",
			"X-Client-Ip",
			"Cf-Connecting-Ip",
			"True-Client-Ip",
			"Forwarded",
		}
		for _, h := range disallowed {
			if val := headers.Get(h); val != "" {
				t.Errorf("expected header %s to be stripped in HideClientIP mode, got %q", h, val)
			}
		}
	}

	// Case 2: HideClientIP is false (Transparent forwarding mode - default)
	{
		cfg := &Config{
			BlockPrivateIPs: false,
			MaxRedirects:    5,
			BufferSizeKB:    32,
			HideClientIP:    false,
		}
		proxy := NewProxyServer(cfg)

		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.RemoteAddr = "198.51.100.10:54321"
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("Via", "1.1 other-proxy")
		req.Header.Set("Forwarded", "for=1.1.1.1")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// In transparent mode, X-Forwarded-For should append client IP
		xff := headers.Get("X-Forwarded-For")
		if !strings.Contains(xff, "198.51.100.10") {
			t.Errorf("expected X-Forwarded-For to contain client remote addr, got %q", xff)
		}
		// Proxy information headers must NOT be sent to upstream
		if val := headers.Get("X-Forwarded-Proto"); val != "" {
			t.Errorf("expected no X-Forwarded-Proto in upstream request, got %q", val)
		}
		if val := headers.Get("Via"); val != "" {
			t.Errorf("expected no Via header in upstream request, got %q", val)
		}
		if val := headers.Get("Forwarded"); val != "" {
			t.Errorf("expected no Forwarded header in upstream request, got %q", val)
		}
	}
}

func TestProxyServer_ClientChoice_Header(t *testing.T) {
	var receivedHeaders http.Header
	var mu sync.Mutex

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamServer.Close()

	// Default server has HideClientIP: true
	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		HideClientIP:    true,
	}
	proxy := NewProxyServer(cfg)

	// Case 1: Client sends X-Forward-Client-IP: true
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		req.Header.Set("X-Forward-Client-IP", "true")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Control header must be stripped
		if headers.Get("X-Forward-Client-IP") != "" {
			t.Errorf("expected X-Forward-Client-IP to be stripped from upstream, got %q", headers.Get("X-Forward-Client-IP"))
		}
		// X-Forwarded-For and X-Real-IP should contain client IP
		if !strings.Contains(headers.Get("X-Forwarded-For"), "198.51.100.20") {
			t.Errorf("expected X-Forwarded-For to contain client IP, got %q", headers.Get("X-Forwarded-For"))
		}
		if headers.Get("X-Real-IP") != "198.51.100.20" {
			t.Errorf("expected X-Real-IP to be 198.51.100.20, got %q", headers.Get("X-Real-IP"))
		}
	}

	// Case 2: Client sends X-Forward-Client-IP: false
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		req.Header.Set("X-Forward-Client-IP", "false")

		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		if headers.Get("X-Forwarded-For") != "" {
			t.Errorf("expected no X-Forwarded-For, got %q", headers.Get("X-Forwarded-For"))
		}
	}

	// Case 3: Server has HideClientIP: false (transparent), but client sends X-Hide-Client-IP: true
	{
		transparentCfg := &Config{
			BlockPrivateIPs: false,
			MaxRedirects:    5,
			BufferSizeKB:    32,
			HideClientIP:    false,
		}
		transparentProxy := NewProxyServer(transparentCfg)

		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		req.Header.Set("X-Hide-Client-IP", "true")

		rec := httptest.NewRecorder()
		transparentProxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		if headers.Get("X-Forwarded-For") != "" {
			t.Errorf("expected no X-Forwarded-For when client requested hide, got %q", headers.Get("X-Forwarded-For"))
		}
	}
}

func TestProxyServer_QueryPreservedUntouched(t *testing.T) {
	var receivedURL string
	var mu sync.Mutex

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedURL = r.URL.String()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		HideClientIP:    true,
	}
	proxy := NewProxyServer(cfg)

	// Verify query string is 100% untouched and preserved
	rawTarget := "/api?foo=bar&b=2&a=1"
	req := httptest.NewRequest("GET", "/"+upstreamServer.URL+rawTarget, nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	mu.Lock()
	u := receivedURL
	mu.Unlock()

	if u != rawTarget {
		t.Errorf("expected URL query to be 100%% untouched %q, got %q", rawTarget, u)
	}
}

func TestLoadConfig_Auth(t *testing.T) {
	// Case 1: BASIC_AUTH env
	t.Setenv("BASIC_AUTH", "myuser:mypass123")
	t.Setenv("BEARER_TOKEN", "")
	cfg := LoadConfig()
	if cfg.BasicAuthUser != "myuser" || cfg.BasicAuthPass != "mypass123" {
		t.Errorf("expected basic auth user myuser pass mypass123, got %s:%s", cfg.BasicAuthUser, cfg.BasicAuthPass)
	}
	if !cfg.AuthEnabled() {
		t.Errorf("expected AuthEnabled to be true")
	}

	// Case 2: BASIC_AUTH_USER and BASIC_AUTH_PASS env
	t.Setenv("BASIC_AUTH", "")
	t.Setenv("BASIC_AUTH_USER", "admin")
	t.Setenv("BASIC_AUTH_PASS", "secret888")
	cfg = LoadConfig()
	if cfg.BasicAuthUser != "admin" || cfg.BasicAuthPass != "secret888" {
		t.Errorf("expected basic auth admin:secret888, got %s:%s", cfg.BasicAuthUser, cfg.BasicAuthPass)
	}

	// Case 3: BEARER_TOKEN env (comma-separated)
	t.Setenv("BASIC_AUTH_USER", "")
	t.Setenv("BASIC_AUTH_PASS", "")
	t.Setenv("BEARER_TOKEN", "token1, token2, token3")
	cfg = LoadConfig()
	if len(cfg.BearerTokens) != 3 || cfg.BearerTokens[0] != "token1" || cfg.BearerTokens[1] != "token2" || cfg.BearerTokens[2] != "token3" {
		t.Errorf("unexpected bearer tokens: %v", cfg.BearerTokens)
	}
	if !cfg.AuthEnabled() {
		t.Errorf("expected AuthEnabled to be true")
	}

	// Case 4: CLI flags override
	t.Setenv("BASIC_AUTH", "")
	t.Setenv("BEARER_TOKEN", "")
	cfg = LoadConfig("-basic-auth", "flaguser:flagpass", "-token", "tokA,tokB")
	if cfg.BasicAuthUser != "flaguser" || cfg.BasicAuthPass != "flagpass" {
		t.Errorf("expected flaguser:flagpass, got %s:%s", cfg.BasicAuthUser, cfg.BasicAuthPass)
	}
	if len(cfg.BearerTokens) != 2 || cfg.BearerTokens[0] != "tokA" || cfg.BearerTokens[1] != "tokB" {
		t.Errorf("expected [tokA tokB], got %v", cfg.BearerTokens)
	}
	if !cfg.AuthEnabled() {
		t.Errorf("expected AuthEnabled to be true")
	}
}

func TestProxyServer_BasicAuth(t *testing.T) {
	var receivedHeaders http.Header
	var mu sync.Mutex

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-ok"))
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		BasicAuthUser:   "admin",
		BasicAuthPass:   "supersecret",
	}
	proxy := NewProxyServer(cfg)

	// 1. Unauthenticated request -> 401 Unauthorized
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
			t.Errorf("expected WWW-Authenticate: Basic header, got %q", rec.Header().Get("WWW-Authenticate"))
		}
	}

	// 2. Invalid credentials -> 401 Unauthorized
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		badCred := base64.StdEncoding.EncodeToString([]byte("admin:wrongpass"))
		req.Header.Set("Authorization", "Basic "+badCred)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for bad credentials, got %d", rec.Code)
		}
	}

	// 3. Valid credentials via Authorization header -> 200 OK
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		validCred := base64.StdEncoding.EncodeToString([]byte("admin:supersecret"))
		req.Header.Set("Authorization", "Basic "+validCred)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Verify proxy credentials are NOT forwarded to upstream!
		if headers.Get("Authorization") != "" {
			t.Errorf("expected Authorization header to be stripped from upstream, got %q", headers.Get("Authorization"))
		}
	}

	// 4. Valid credentials via Proxy-Authorization header, with custom Authorization for upstream
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		validCred := base64.StdEncoding.EncodeToString([]byte("admin:supersecret"))
		req.Header.Set("Proxy-Authorization", "Basic "+validCred)
		req.Header.Set("Authorization", "Bearer upstream-token-12345")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Upstream should receive its own Authorization, and NOT Proxy-Authorization
		if headers.Get("Authorization") != "Bearer upstream-token-12345" {
			t.Errorf("expected upstream Authorization preserved, got %q", headers.Get("Authorization"))
		}
		if headers.Get("Proxy-Authorization") != "" {
			t.Errorf("expected Proxy-Authorization stripped, got %q", headers.Get("Proxy-Authorization"))
		}
	}
}

func TestProxyServer_BearerAuth(t *testing.T) {
	var receivedHeaders http.Header
	var mu sync.Mutex

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-ok"))
	}))
	defer upstreamServer.Close()

	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		BearerTokens:    []string{"token-alpha", "token-beta"},
	}
	proxy := NewProxyServer(cfg)

	// 1. Unauthenticated request -> 401 Unauthorized
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("expected WWW-Authenticate: Bearer header, got %q", rec.Header().Get("WWW-Authenticate"))
		}
	}

	// 2. Invalid token -> 401 Unauthorized
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	}

	// 3. Valid token in Authorization header -> 200 OK
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.Header.Set("Authorization", "Bearer token-alpha")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Proxy token stripped from upstream
		if headers.Get("Authorization") != "" {
			t.Errorf("expected Authorization stripped from upstream, got %q", headers.Get("Authorization"))
		}
	}

	// 4. Valid token in Proxy-Authorization header
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.Header.Set("Proxy-Authorization", "Bearer token-beta")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	}

	// 5. Valid token in X-Proxy-Token header, with upstream Authorization
	{
		req := httptest.NewRequest("GET", "/"+upstreamServer.URL+"/test", nil)
		req.Header.Set("X-Proxy-Token", "token-alpha")
		req.Header.Set("Authorization", "Bearer sk-target-api-key")
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		mu.Lock()
		headers := receivedHeaders.Clone()
		mu.Unlock()

		// Upstream receives target Authorization, X-Proxy-Token is stripped
		if headers.Get("Authorization") != "Bearer sk-target-api-key" {
			t.Errorf("expected target Authorization preserved, got %q", headers.Get("Authorization"))
		}
		if headers.Get("X-Proxy-Token") != "" {
			t.Errorf("expected X-Proxy-Token stripped from upstream, got %q", headers.Get("X-Proxy-Token"))
		}
	}
}

func TestProxyServer_HealthCheck_NoAuthRequired(t *testing.T) {
	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		BasicAuthUser:   "admin",
		BasicAuthPass:   "pass123",
		BearerTokens:    []string{"token-xyz"},
	}
	proxy := NewProxyServer(cfg)

	// Healthcheck must succeed without credentials
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /healthz, got %d", rec.Code)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if data["auth_enabled"] != true {
		t.Errorf("expected auth_enabled true in healthz, got %v", data["auth_enabled"])
	}
}

func TestProxyServer_HelpEndpoint(t *testing.T) {
	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	// 1. GET /help
	req := httptest.NewRequest("GET", "/help", nil)
	req.Host = "10.0.0.10:18080"
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /help, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain; charset=utf-8, got %q", ct)
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Universal URL Proxy (url-proxy)",
		"USAGE:",
		"Proxy-Authorization",
		"X-Proxy-Token",
		"X-Forward-Client-IP",
		"10.0.0.10:18080",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected /help body to contain %q", expected)
		}
	}

	// 2. GET /help/
	req2 := httptest.NewRequest("GET", "/help/", nil)
	rec2 := httptest.NewRecorder()
	proxy.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /help/, got %d", rec2.Code)
	}

	// 3. GET /?help
	req3 := httptest.NewRequest("GET", "/?help", nil)
	rec3 := httptest.NewRecorder()
	proxy.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /?help, got %d", rec3.Code)
	}
}

func TestProxyServer_HelpEndpoint_NoAuthRequired(t *testing.T) {
	// Help page must be accessible without credentials even when authentication is turned on
	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
		BasicAuthUser:   "admin",
		BasicAuthPass:   "pass123",
		BearerTokens:    []string{"token-xyz"},
	}
	proxy := NewProxyServer(cfg)

	req := httptest.NewRequest("GET", "/help", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /help without credentials, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Universal URL Proxy") {
		t.Errorf("expected /help content in unauthenticated response")
	}
}

func TestProxyServer_RootEndpoint_CommandLineVsBrowser(t *testing.T) {
	cfg := &Config{
		BlockPrivateIPs: false,
		MaxRedirects:    5,
		BufferSizeKB:    32,
	}
	proxy := NewProxyServer(cfg)

	// 1. curl client requesting "/" should get plain text help
	reqCurl := httptest.NewRequest("GET", "/", nil)
	reqCurl.Header.Set("User-Agent", "curl/7.81.0")
	recCurl := httptest.NewRecorder()
	proxy.ServeHTTP(recCurl, reqCurl)

	if recCurl.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for curl /, got %d", recCurl.Code)
	}
	if ct := recCurl.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain for curl, got %q", ct)
	}
	if !strings.Contains(recCurl.Body.String(), "Universal URL Proxy") {
		t.Errorf("expected help text for curl /")
	}

	// 2. wget client requesting "/" should get plain text help
	reqWget := httptest.NewRequest("GET", "/", nil)
	reqWget.Header.Set("User-Agent", "Wget/1.21.2")
	recWget := httptest.NewRecorder()
	proxy.ServeHTTP(recWget, reqWget)
	if recWget.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for wget /, got %d", recWget.Code)
	}
	if ct := recWget.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain for wget, got %q", ct)
	}

	// 3. Browser requesting "/" should get HTML
	reqBrowser := httptest.NewRequest("GET", "/", nil)
	reqBrowser.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	recBrowser := httptest.NewRecorder()
	proxy.ServeHTTP(recBrowser, reqBrowser)

	if recBrowser.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for browser /, got %d", recBrowser.Code)
	}
	if ct := recBrowser.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html for browser, got %q", ct)
	}
	if !strings.Contains(recBrowser.Body.String(), "<!DOCTYPE html>") {
		t.Errorf("expected HTML content for browser /")
	}
}

func TestIsCommandLineClient(t *testing.T) {
	tests := []struct {
		ua       string
		expected bool
	}{
		{"curl/7.81.0", true},
		{"curl/8.4.0", true},
		{"Wget/1.21.2", true},
		{"wget/1.20", true},
		{"HTTPie/3.2.1", true},
		{"httpie/2.4.0", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"Go-http-client/1.1", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isCommandLineClient(tt.ua)
		if got != tt.expected {
			t.Errorf("isCommandLineClient(%q) = %v; want %v", tt.ua, got, tt.expected)
		}
	}
}




