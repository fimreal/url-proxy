package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config stores the runtime configuration loaded from environment variables.
type Config struct {
	Port            string
	AllowDomains    []string
	BlockDomains    []string
	BlockPrivateIPs bool
	MaxRedirects    int
	BufferSizeKB    int
}

// LoadConfig initializes configuration from environment variables.
func LoadConfig() *Config {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	allowDomainsStr := os.Getenv("ALLOW_DOMAINS")
	var allowDomains []string
	if strings.TrimSpace(allowDomainsStr) != "" {
		for _, d := range strings.Split(allowDomainsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				allowDomains = append(allowDomains, strings.ToLower(d))
			}
		}
	}

	blockDomainsStr := os.Getenv("BLOCK_DOMAINS")
	var blockDomains []string
	if strings.TrimSpace(blockDomainsStr) != "" {
		for _, d := range strings.Split(blockDomainsStr, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				blockDomains = append(blockDomains, strings.ToLower(d))
			}
		}
	}

	blockPrivateIPs := true
	if val := os.Getenv("BLOCK_PRIVATE_IPS"); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			blockPrivateIPs = b
		}
	}

	maxRedirects := 10
	if val := os.Getenv("MAX_REDIRECTS"); val != "" {
		if mr, err := strconv.Atoi(val); err == nil && mr >= 0 {
			maxRedirects = mr
		}
	}

	bufferSizeKB := 32
	if val := os.Getenv("BUFFER_SIZE_KB"); val != "" {
		if bs, err := strconv.Atoi(val); err == nil && bs > 0 {
			bufferSizeKB = bs
		}
	}

	return &Config{
		Port:            port,
		AllowDomains:    allowDomains,
		BlockDomains:    blockDomains,
		BlockPrivateIPs: blockPrivateIPs,
		MaxRedirects:    maxRedirects,
		BufferSizeKB:    bufferSizeKB,
	}
}

// SecurityManager handles SSRF protection and domain allow/block lists.
type SecurityManager struct {
	AllowDomains      []string
	BlockDomains      []string
	BlockPrivateIPs   bool
	privateIPv4Blocks []*net.IPNet
	privateIPv6Blocks []*net.IPNet
}

func NewSecurityManager(cfg *Config) *SecurityManager {
	sm := &SecurityManager{
		AllowDomains:    cfg.AllowDomains,
		BlockDomains:    cfg.BlockDomains,
		BlockPrivateIPs: cfg.BlockPrivateIPs,
	}
	sm.initPrivateIPBlocks()
	return sm
}

func (sm *SecurityManager) initPrivateIPBlocks() {
	var ipv4CIDRs = []string{
		"0.0.0.0/8",          // Current network
		"10.0.0.0/8",         // Private network RFC 1918
		"100.64.0.0/10",      // Shared Address Space RFC 6598 (Carrier-Grade NAT)
		"127.0.0.0/8",        // Loopback RFC 1122
		"169.254.0.0/16",     // Link Local RFC 3927 (Cloud Metadata 169.254.169.254)
		"172.16.0.0/12",      // Private network RFC 1918
		"192.0.0.0/24",       // IETF Protocol Assignments RFC 6890
		"192.0.2.0/24",       // Documentation RFC 5737
		"192.168.0.0/16",     // Private network RFC 1918
		"198.18.0.0/15",      // Benchmarking RFC 2544
		"198.51.100.0/24",    // Documentation RFC 5737
		"203.0.113.0/24",     // Documentation RFC 5737
		"224.0.0.0/4",        // Multicast RFC 5771
		"240.0.0.0/4",        // Reserved RFC 1112
		"255.255.255.255/32", // Limited Broadcast RFC 919
	}
	var ipv6CIDRs = []string{
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"fc00::/7",      // Unique local address (ULA)
		"fe80::/10",     // Link local address
		"ff00::/8",      // Multicast
		"2001:db8::/32", // Documentation
	}

	for _, cidr := range ipv4CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			sm.privateIPv4Blocks = append(sm.privateIPv4Blocks, ipNet)
		}
	}
	for _, cidr := range ipv6CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			sm.privateIPv6Blocks = append(sm.privateIPv6Blocks, ipNet)
		}
	}
}

// IsPrivateOrBlockedIP checks if an IP is in the private/reserved range.
func (sm *SecurityManager) IsPrivateOrBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Check IPv4 addresses (including IPv4-mapped IPv6)
	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range sm.privateIPv4Blocks {
			if block.Contains(ip4) {
				return true
			}
		}
		return false
	}
	// Pure IPv6 addresses
	for _, block := range sm.privateIPv6Blocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// matchDomainPattern matches a hostname against a pattern (e.g. *.github.com).
func matchDomainPattern(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	if pattern == "*" || pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. .github.com
		if strings.HasSuffix(host, suffix) {
			return true
		}
		// Also allow *.github.com to match github.com
		if host == pattern[2:] {
			return true
		}
	}
	return false
}

// ValidateTargetHost checks if the target hostname is permitted by Allow/Block lists and SSRF rules.
func (sm *SecurityManager) ValidateTargetHost(hostname string) error {
	hostname = strings.TrimSpace(strings.ToLower(hostname))
	if hostname == "" {
		return fmt.Errorf("target host is empty")
	}

	// 1. If hostname is an IP literal, check SSRF immediately
	parsedIP := net.ParseIP(hostname)
	if parsedIP != nil && sm.BlockPrivateIPs {
		if sm.IsPrivateOrBlockedIP(parsedIP) {
			return fmt.Errorf("forbidden: IP address %s is private or reserved (SSRF protection)", hostname)
		}
	}

	// 2. Check BlockDomains
	for _, blockPattern := range sm.BlockDomains {
		if matchDomainPattern(blockPattern, hostname) {
			return fmt.Errorf("forbidden: domain %s is blocked by rule '%s'", hostname, blockPattern)
		}
	}

	// 3. Check AllowDomains (if configured)
	if len(sm.AllowDomains) > 0 {
		matched := false
		for _, allowPattern := range sm.AllowDomains {
			if matchDomainPattern(allowPattern, hostname) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("forbidden: domain %s is not in ALLOW_DOMAINS list", hostname)
		}
	}

	return nil
}

// Hop-by-hop headers according to RFC 2616 section 13.5.1
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// NormalizeTargetURL extracts and repairs target URL from request paths.
// It handles slash collapsing (e.g. /https:/domain.com), percent encoding (%3A, %2F),
// and missing schemes.
func NormalizeTargetURL(rawURI, urlPath string) (*url.URL, error) {
	candidate := strings.TrimSpace(rawURI)
	if candidate == "" {
		candidate = strings.TrimSpace(urlPath)
	}

	// Remove leading slashes
	candidate = strings.TrimLeft(candidate, "/")
	if candidate == "" {
		return nil, fmt.Errorf("empty target path")
	}

	// Step 1: Decode scheme and path delimiters if percent-encoded (%3A -> :, %2F -> /)
	// This restores the scheme, host, and path structure even if encoded by clients.
	candidate = strings.ReplaceAll(candidate, "%3A", ":")
	candidate = strings.ReplaceAll(candidate, "%3a", ":")
	candidate = strings.ReplaceAll(candidate, "%2F", "/")
	candidate = strings.ReplaceAll(candidate, "%2f", "/")

	// If query delimiter ? is encoded and no unencoded ? exists, decode the first %3F
	if !strings.Contains(candidate, "?") {
		if idx := strings.Index(strings.ToLower(candidate), "%3f"); idx != -1 {
			candidate = candidate[:idx] + "?" + candidate[idx+3:]
		}
	}

	// Step 2: Handle scheme prefix and reverse proxy slash collapsing
	// Variants:
	// https:/domain  -> https://domain
	// https:///domain -> https://domain
	// http:/domain   -> http://domain
	// domain/path    -> https://domain/path (default scheme)
	lowerCand := strings.ToLower(candidate)
	if strings.HasPrefix(lowerCand, "https:") {
		rest := strings.TrimLeft(candidate[6:], "/")
		candidate = "https://" + rest
	} else if strings.HasPrefix(lowerCand, "http:") {
		rest := strings.TrimLeft(candidate[5:], "/")
		candidate = "http://" + rest
	} else if idx := strings.Index(lowerCand, "://"); idx != -1 {
		return nil, fmt.Errorf("unsupported URL scheme: %s (only http and https supported)", candidate[:idx])
	} else {
		// Missing scheme completely, default to https
		rest := strings.TrimLeft(candidate, "/")
		candidate = "https://" + rest
	}

	// Step 3: Parse standard URL
	targetURL, err := url.Parse(candidate)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if targetURL.Host == "" {
		return nil, fmt.Errorf("target URL missing host")
	}

	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s (only http and https supported)", targetURL.Scheme)
	}

	// Ensure targetURL has a path (at least "/")
	if targetURL.Path == "" {
		targetURL.Path = "/"
	}

	return targetURL, nil
}

// ProxyServer encapsulates the proxy routing, security and streaming client.
type ProxyServer struct {
	cfg        *Config
	sec        *SecurityManager
	httpClient *http.Client
}

func NewProxyServer(cfg *Config) *ProxyServer {
	sec := NewSecurityManager(cfg)

	// Create custom dialer with SSRF and DNS Rebinding protection
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return nil
		},
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// If SSRF protection is enabled, resolve and inspect IPs
			if sec.BlockPrivateIPs {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
				}
				if len(ips) == 0 {
					return nil, fmt.Errorf("no IP address found for host %s", host)
				}

				// Check each resolved IP address
				for _, ip := range ips {
					if sec.IsPrivateOrBlockedIP(ip) {
						return nil, fmt.Errorf("SSRF protection: destination %s resolves to private/reserved IP %s", host, ip.String())
					}
				}

				// Connect to the first safe IP
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			}

			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // Unlimited request timeout to allow large file streaming
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.MaxRedirects == 0 {
				return http.ErrUseLastResponse
			}
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("stopped after reaching max redirects limit (%d)", cfg.MaxRedirects)
			}
			// Security validation on redirect destination
			if err := sec.ValidateTargetHost(req.URL.Hostname()); err != nil {
				return fmt.Errorf("redirect target blocked: %w", err)
			}
			// Retain Range header across redirects if present
			if len(via) > 0 {
				if r := via[0].Header.Get("Range"); r != "" {
					req.Header.Set("Range", r)
				}
			}
			return nil
		},
	}

	return &ProxyServer{
		cfg:        cfg,
		sec:        sec,
		httpClient: client,
	}
}

// ServeHTTP handles incoming requests, validates security, and streams responses.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Health check endpoint
	if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"allow_domains":    p.cfg.AllowDomains,
			"block_domains":    p.cfg.BlockDomains,
			"block_private_ips": p.cfg.BlockPrivateIPs,
			"max_redirects":     p.cfg.MaxRedirects,
		})
		return
	}

	// 2. Root usage page
	if r.URL.Path == "/" || r.URL.Path == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Universal URL Proxy Service</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; line-height: 1.6; color: #333; max-width: 800px; }
h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 8px; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
pre { background: #f8f9fa; padding: 12px; border-radius: 6px; border-left: 4px solid #3498db; overflow-x: auto; }
.card { background: #fdfdfd; border: 1px solid #e1e8ed; border-radius: 6px; padding: 16px; margin: 16px 0; }
</style>
</head>
<body>
<h1>极轻量通用 URL 转发服务 (URL Proxy)</h1>
<p>基于 Go 标准库实现的极轻量通用 URL Path 代理服务，支持智能路径容错、301/302 重定向跟随、全双工无缓冲流式传输与 SSRF 防护。</p>

<div class="card">
<h3>使用方式</h3>
<p>在当前服务地址后直接追加完整目标 URL：</p>
<pre>http://%s/https://github.com/torvalds/linux/archive/refs/tags/v6.0.tar.gz</pre>
</div>

<div class="card">
<h3>核心特性</h3>
<ul>
<li><strong>路径容错：</strong>自动识别并修复反向代理（如 Nginx）合并后的 <code>/https:/domain</code> 路径及 URL 编码。</li>
<li><strong>流式转发：</strong>流式传输大文件（如 Releases / Binaries），零内存缓冲，杜绝 OOM。</li>
<li><strong>断点续传：</strong>完整透传 <code>Range</code> 请求头与 <code>206 Partial Content</code> 响应头。</li>
<li><strong>安全防护：</strong>支持 <code>ALLOW_DOMAINS</code> / <code>BLOCK_DOMAINS</code> 白黑名单，默认防范内网 SSRF 与 DNS 重绑定。</li>
</ul>
</div>

<p><small>Health Check: <a href="/healthz">/healthz</a></small></p>
</body>
</html>`, r.Host)
		return
	}

	// 3. Extract and normalize target URL
	targetURL, err := NormalizeTargetURL(r.RequestURI, r.URL.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: %v", err), http.StatusBadRequest)
		return
	}

	// 4. Validate hostname security rules
	if err := p.sec.ValidateTargetHost(targetURL.Hostname()); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 5. Construct upstream request
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	// 6. Copy headers from client request (excluding hop-by-hop)
	for key, values := range r.Header {
		if hopByHopHeaders[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Set target Host header and forwarding headers
	upstreamReq.Host = targetURL.Host

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		upstreamReq.Header.Set("X-Forwarded-For", clientIP)
	}
	if r.TLS != nil {
		upstreamReq.Header.Set("X-Forwarded-Proto", "https")
	} else {
		upstreamReq.Header.Set("X-Forwarded-Proto", "http")
	}

	// 7. Execute request via http.Client (follows redirects)
	upstreamResp, err := p.httpClient.Do(upstreamReq)
	if err != nil {
		log.Printf("[Proxy Error] %s %s -> %v", r.Method, targetURL.String(), err)
		http.Error(w, fmt.Sprintf("Bad Gateway: %v", err), http.StatusBadGateway)
		return
	}
	defer upstreamResp.Body.Close()

	// 8. Copy response headers back to client
	destHeader := w.Header()
	for key, values := range upstreamResp.Header {
		if hopByHopHeaders[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, value := range values {
			destHeader.Add(key, value)
		}
	}

	// 9. Write response status code
	w.WriteHeader(upstreamResp.StatusCode)

	// 10. Stream response body to client with real-time flushing (supports SSE & LLM streaming)
	flusher, canFlush := w.(http.Flusher)
	bufSize := p.cfg.BufferSizeKB * 1024
	buf := make([]byte, bufSize)
	for {
		n, readErr := upstreamResp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				break
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				log.Printf("[Stream Error] %s %s -> %v", r.Method, targetURL.String(), readErr)
			}
			break
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		port = strings.TrimPrefix(port, ":")
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/healthz", port))
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	cfg := LoadConfig()
	server := NewProxyServer(cfg)

	log.Printf("Starting Universal URL Proxy on %s ...", cfg.Port)
	log.Printf("Config: AllowDomains=%v, BlockDomains=%v, BlockPrivateIPs=%v, MaxRedirects=%d, BufferSizeKB=%d",
		cfg.AllowDomains, cfg.BlockDomains, cfg.BlockPrivateIPs, cfg.MaxRedirects, cfg.BufferSizeKB)

	httpServer := &http.Server{
		Addr:         cfg.Port,
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		IdleTimeout:  120 * time.Second,
		WriteTimeout: 0, // Disable write timeout for unbounded streaming responses
	}

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
