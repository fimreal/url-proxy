package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
