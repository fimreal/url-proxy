package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
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

var (
	Version   = "dev"
	CommitSHA = "none"
	BuildDate = "unknown"
)

// Config stores the runtime configuration loaded from environment variables and CLI flags.
type Config struct {
	Host            string
	Port            string // Final listen address (e.g. ":8080" or "127.0.0.1:8080")
	TLSCertFile     string
	TLSKeyFile      string
	InsecureSkipTLS bool
	AllowDomains    []string
	BlockDomains    []string
	BlockPrivateIPs bool
	MaxRedirects    int
	BufferSizeKB    int
	HideClientIP    bool
	HelpRequested   bool

	// Authentication configuration
	BasicAuthUser string
	BasicAuthPass string
	BearerTokens  []string
}

// AuthEnabled returns true if Basic Auth or Bearer Auth is configured.
func (c *Config) AuthEnabled() bool {
	return (c.BasicAuthUser != "" && c.BasicAuthPass != "") || len(c.BearerTokens) > 0
}

// TLSEnabled returns true if both TLS cert and key are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// resolveListenAddr normalizes host, port, bind, and addr settings into a valid net.Listen address.
func resolveListenAddr(host, port, bind, addr string) string {
	target := strings.TrimSpace(bind)
	if target == "" {
		target = strings.TrimSpace(addr)
	}

	// 1. If explicit bind/addr is given:
	if target != "" {
		if strings.Contains(target, ":") {
			return target
		}
		p := strings.TrimSpace(port)
		if p == "" {
			p = "8080"
		}
		p = strings.TrimPrefix(p, ":")
		return net.JoinHostPort(target, p)
	}

	// 2. If host is given:
	h := strings.TrimSpace(host)
	p := strings.TrimSpace(port)
	if p == "" {
		p = "8080"
	}

	if h != "" {
		if strings.Contains(p, ":") && !strings.HasPrefix(p, ":") {
			return p
		}
		p = strings.TrimPrefix(p, ":")
		return net.JoinHostPort(h, p)
	}

	// 3. Only port is given:
	if strings.HasPrefix(p, ":") {
		return p
	}
	if strings.Contains(p, ":") {
		return p
	}
	return ":" + p
}

// LoadConfig initializes configuration from environment variables and optional CLI flags.
func LoadConfig(args ...string) *Config {
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	bind := os.Getenv("BIND")
	if bind == "" {
		bind = os.Getenv("ADDR")
	}
	if bind == "" {
		bind = os.Getenv("LISTEN_ADDR")
	}

	tlsCert := os.Getenv("TLS_CERT_FILE")
	if tlsCert == "" {
		tlsCert = os.Getenv("TLS_CERT")
	}
	tlsKey := os.Getenv("TLS_KEY_FILE")
	if tlsKey == "" {
		tlsKey = os.Getenv("TLS_KEY")
	}

	insecureSkipTLS := false
	if val := os.Getenv("INSECURE_SKIP_VERIFY"); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			insecureSkipTLS = b
		}
	} else if val := os.Getenv("TLS_INSECURE_SKIP_VERIFY"); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			insecureSkipTLS = b
		}
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

	hideClientIP := true
	if val := os.Getenv("HIDE_CLIENT_IP"); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			hideClientIP = b
		}
	} else if val := os.Getenv("FORWARD_CLIENT_IP"); val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			hideClientIP = !b
		}
	}

	// Basic Auth from env
	basicAuthUser := os.Getenv("BASIC_AUTH_USER")
	basicAuthPass := os.Getenv("BASIC_AUTH_PASS")
	if basicAuthPass == "" {
		basicAuthPass = os.Getenv("BASIC_AUTH_PASSWORD")
	}
	if val := os.Getenv("BASIC_AUTH"); val != "" {
		if parts := strings.SplitN(val, ":", 2); len(parts) == 2 {
			basicAuthUser = strings.TrimSpace(parts[0])
			basicAuthPass = strings.TrimSpace(parts[1])
		}
	}

	// Bearer Token(s) from env
	var bearerTokens []string
	bearerTokensStr := os.Getenv("BEARER_TOKEN")
	if bearerTokensStr == "" {
		bearerTokensStr = os.Getenv("BEARER_AUTH")
	}
	if bearerTokensStr == "" {
		bearerTokensStr = os.Getenv("AUTH_TOKEN")
	}
	if bearerTokensStr == "" {
		bearerTokensStr = os.Getenv("TOKEN")
	}
	if strings.TrimSpace(bearerTokensStr) != "" {
		for _, t := range strings.Split(bearerTokensStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				bearerTokens = append(bearerTokens, t)
			}
		}
	}

	helpRequested := false

	// CLI flags override / augment
	if len(args) > 0 {
		fs := flag.NewFlagSet("url-proxy", flag.ContinueOnError)
		fs.SetOutput(io.Discard)

		hostFlag := fs.String("host", "", "Host/IP interface to bind to (e.g. 127.0.0.1)")
		portFlag := fs.String("port", "", "Service listen port or address (e.g. 8080 or 127.0.0.1:8080)")
		bindFlag := fs.String("bind", "", "Alias for listen address (e.g. 127.0.0.1:8080)")
		addrFlag := fs.String("addr", "", "Alias for listen address (e.g. 127.0.0.1:8080)")
		tlsCertFlag := fs.String("tls-cert", "", "Path to TLS cert file")
		tlsKeyFlag := fs.String("tls-key", "", "Path to TLS key file")
		insecureFlag := fs.Bool("insecure", false, "Skip upstream TLS certificate verification")
		allowDomainsFlag := fs.String("allow-domains", "", "Allowed domains comma-separated")
		blockDomainsFlag := fs.String("block-domains", "", "Blocked domains comma-separated")
		blockPrivateIPsFlag := fs.String("block-private-ips", "", "Block private IPs (true/false)")
		maxRedirectsFlag := fs.Int("max-redirects", -1, "Maximum redirects to follow")
		bufferSizeKBFlag := fs.Int("buffer-size-kb", -1, "Buffer size in KB")
		hideClientIPFlag := fs.String("hide-client-ip", "", "Hide client real IP (true/false)")
		basicAuthFlag := fs.String("basic-auth", "", "Basic auth credentials in user:password format")
		basicUserFlag := fs.String("basic-user", "", "Basic auth username")
		basicPassFlag := fs.String("basic-pass", "", "Basic auth password")
		bearerTokenFlag := fs.String("bearer-token", "", "Bearer token(s), comma-separated")
		bearerAuthFlag := fs.String("bearer-auth", "", "Bearer token(s), comma-separated")
		tokenFlag := fs.String("token", "", "Bearer token(s), comma-separated")

		err := fs.Parse(args)
		if err == flag.ErrHelp {
			helpRequested = true
		}

		if *hostFlag != "" {
			host = *hostFlag
		}
		if *portFlag != "" {
			port = *portFlag
		}
		if *bindFlag != "" {
			bind = *bindFlag
		}
		if *addrFlag != "" {
			bind = *addrFlag
		}
		if *tlsCertFlag != "" {
			tlsCert = *tlsCertFlag
		}
		if *tlsKeyFlag != "" {
			tlsKey = *tlsKeyFlag
		}
		if *insecureFlag {
			insecureSkipTLS = true
		}
		if *allowDomainsFlag != "" {
			allowDomains = nil
			for _, d := range strings.Split(*allowDomainsFlag, ",") {
				d = strings.TrimSpace(d)
				if d != "" {
					allowDomains = append(allowDomains, strings.ToLower(d))
				}
			}
		}
		if *blockDomainsFlag != "" {
			blockDomains = nil
			for _, d := range strings.Split(*blockDomainsFlag, ",") {
				d = strings.TrimSpace(d)
				if d != "" {
					blockDomains = append(blockDomains, strings.ToLower(d))
				}
			}
		}
		if *blockPrivateIPsFlag != "" {
			if b, err := strconv.ParseBool(*blockPrivateIPsFlag); err == nil {
				blockPrivateIPs = b
			}
		}
		if *maxRedirectsFlag >= 0 {
			maxRedirects = *maxRedirectsFlag
		}
		if *bufferSizeKBFlag > 0 {
			bufferSizeKB = *bufferSizeKBFlag
		}
		if *hideClientIPFlag != "" {
			if b, err := strconv.ParseBool(*hideClientIPFlag); err == nil {
				hideClientIP = b
			}
		}
		if *basicAuthFlag != "" {
			if parts := strings.SplitN(*basicAuthFlag, ":", 2); len(parts) == 2 {
				basicAuthUser = strings.TrimSpace(parts[0])
				basicAuthPass = strings.TrimSpace(parts[1])
			}
		}
		if *basicUserFlag != "" {
			basicAuthUser = strings.TrimSpace(*basicUserFlag)
		}
		if *basicPassFlag != "" {
			basicAuthPass = strings.TrimSpace(*basicPassFlag)
		}
		btStr := *bearerTokenFlag
		if btStr == "" {
			btStr = *bearerAuthFlag
		}
		if btStr == "" {
			btStr = *tokenFlag
		}
		if btStr != "" {
			bearerTokens = nil
			for _, t := range strings.Split(btStr, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					bearerTokens = append(bearerTokens, t)
				}
			}
		}
	}

	finalAddr := resolveListenAddr(host, port, bind, "")

	return &Config{
		Host:            host,
		Port:            finalAddr,
		TLSCertFile:     tlsCert,
		TLSKeyFile:      tlsKey,
		InsecureSkipTLS: insecureSkipTLS,
		AllowDomains:    allowDomains,
		BlockDomains:    blockDomains,
		BlockPrivateIPs: blockPrivateIPs,
		MaxRedirects:    maxRedirects,
		BufferSizeKB:    bufferSizeKB,
		HideClientIP:    hideClientIP,
		HelpRequested:   helpRequested,
		BasicAuthUser:   basicAuthUser,
		BasicAuthPass:   basicAuthPass,
		BearerTokens:    bearerTokens,
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

// Client IP identifying headers stripped when HideClientIP is enabled (high-anonymity proxy mode)
var clientIPHeaders = map[string]bool{
	http.CanonicalHeaderKey("X-Forwarded-For"):     true,
	http.CanonicalHeaderKey("X-Real-IP"):           true,
	http.CanonicalHeaderKey("X-Client-IP"):         true,
	http.CanonicalHeaderKey("CF-Connecting-IP"):    true,
	http.CanonicalHeaderKey("True-Client-IP"):      true,
	http.CanonicalHeaderKey("Fastly-Client-IP"):    true,
	http.CanonicalHeaderKey("X-Cluster-Client-IP"): true,
}

// Proxy control headers stripped from upstream requests to prevent leaking proxy instructions
var proxyControlHeaders = map[string]bool{
	http.CanonicalHeaderKey("X-Forward-Client-IP"): true,
	http.CanonicalHeaderKey("X-Forward-IP"):        true,
	http.CanonicalHeaderKey("X-Hide-Client-IP"):   true,
	http.CanonicalHeaderKey("X-Hide-IP"):          true,
	http.CanonicalHeaderKey("X-Proxy-Token"):       true,
	http.CanonicalHeaderKey("X-Proxy-Auth"):        true,
	http.CanonicalHeaderKey("X-Token"):             true,
}

// Proxy information headers stripped from upstream requests to avoid leaking proxy traces.
// The proxy forwards client IP transparently without appending proxy-specific protocol or server headers.
var proxyInfoHeaders = map[string]bool{
	http.CanonicalHeaderKey("X-Forwarded-Proto"):  true,
	http.CanonicalHeaderKey("X-Forwarded-Host"):   true,
	http.CanonicalHeaderKey("X-Forwarded-Port"):   true,
	http.CanonicalHeaderKey("X-Forwarded-Server"): true,
	http.CanonicalHeaderKey("Forwarded"):          true,
	http.CanonicalHeaderKey("Via"):                true,
	http.CanonicalHeaderKey("Proxy-Connection"):   true,
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
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS,
		},
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

// determineRequestScheme detects if the incoming request was made over HTTPS
// either directly (TLS) or via a reverse proxy (X-Forwarded-Proto).
func determineRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		parts := strings.Split(proto, ",")
		p := strings.ToLower(strings.TrimSpace(parts[0]))
		if p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}

// ServeHTTP handles incoming requests, validates security, and streams responses.
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Health check endpoint (always unauthenticated for orchestrator liveness/readiness probes)
	if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"version":           Version,
			"host":              p.cfg.Host,
			"port":              p.cfg.Port,
			"tls_enabled":       p.cfg.TLSEnabled(),
			"allow_domains":    p.cfg.AllowDomains,
			"block_domains":    p.cfg.BlockDomains,
			"block_private_ips": p.cfg.BlockPrivateIPs,
			"max_redirects":     p.cfg.MaxRedirects,
			"hide_client_ip":    p.cfg.HideClientIP,
			"auth_enabled":      p.cfg.AuthEnabled(),
		})
		return
	}

	scheme := determineRequestScheme(r)

	// 2. Help manual endpoint (always unauthenticated plain-text guide for curl / CLI)
	if r.URL.Path == "/help" || r.URL.Path == "/help/" || r.URL.Query().Has("help") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(HelpText(r.Host, scheme)))
		return
	}

	// 3. Root usage page (for curl/wget, returns plain text help; for browsers, returns HTML)
	if r.URL.Path == "/" || r.URL.Path == "" {
		if isCommandLineClient(r.UserAgent()) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(HelpText(r.Host, scheme)))
			return
		}

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
<pre>%s://%s/https://github.com/torvalds/linux/archive/refs/tags/v6.0.tar.gz</pre>
</div>

<div class="card">
<h3>命令行手册 (curl /help)</h3>
<p>在终端直接执行 curl 命令即可查看包含所有认证与控制标头的英文帮助手册：</p>
<pre>curl %s://%s/help</pre>
</div>

<div class="card">
<h3>核心特性</h3>
<ul>
<li><strong>路径容错：</strong>自动识别并修复反向代理（如 Nginx）合并后的 <code>/https:/domain</code> 路径及 URL 编码。</li>
<li><strong>流式转发：</strong>流式传输大文件（如 Releases / Binaries），零内存缓冲，杜绝 OOM。</li>
<li><strong>断点续传：</strong>完整透传 <code>Range</code> 请求头与 <code>206 Partial Content</code> 响应头。</li>
<li><strong>安全认证：</strong>支持 Basic Auth 与 Bearer Auth，通过 <code>Proxy-Authorization</code> 或 <code>X-Proxy-Token</code> 鉴权并透传上游 Token。</li>
<li><strong>高匿代理：</strong>默认隐藏客户端 IP，支持 <code>X-Forward-Client-IP</code> 动态控制。</li>
<li><strong>安全防护：</strong>支持 <code>ALLOW_DOMAINS</code> / <code>BLOCK_DOMAINS</code> 白黑名单，默认防范内网 SSRF 与 DNS 重绑定。</li>
</ul>
</div>

<p><small>Health Check: <a href="/healthz">/healthz</a> | Text Help: <a href="/help">/help</a></small></p>
</body>
</html>`, scheme, r.Host, scheme, r.Host)
		return
	}

	// 4. Authentication verification (Basic Auth / Bearer Token)
	if !p.authenticate(r) {
		p.rejectUnauthorized(w)
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

	// 5. Determine client IP forwarding preference (default: hide IP, override via header)
	hideClientIP := p.cfg.HideClientIP

	// Per-request override via HTTP headers:
	// X-Forward-Client-IP: true/1/false/0
	// X-Hide-Client-IP: true/1/false/0
	if val := r.Header.Get("X-Forward-Client-IP"); val != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			hideClientIP = !b
		}
	} else if val := r.Header.Get("X-Forward-IP"); val != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			hideClientIP = !b
		}
	} else if val := r.Header.Get("X-Hide-Client-IP"); val != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			hideClientIP = b
		}
	} else if val := r.Header.Get("X-Hide-IP"); val != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
			hideClientIP = b
		}
	}

	// 6. Construct upstream request
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	// 7. Copy headers from client request (excluding hop-by-hop, proxy control headers, and client IP identifying headers if hideClientIP is enabled)
	// If Authorization was used to authenticate to the proxy itself (and no dedicated Proxy-Authorization/X-Proxy-Token was used),
	// strip Authorization so we don't leak the proxy's credentials to the upstream server!
	consumedAuthHeader := false
	if p.cfg.AuthEnabled() {
		if auth := r.Header.Get("Authorization"); auth != "" && p.checkAuthHeader(auth) {
			hasDedicatedProxyAuth := r.Header.Get("Proxy-Authorization") != "" ||
				r.Header.Get("X-Proxy-Token") != "" ||
				r.Header.Get("X-Proxy-Auth") != "" ||
				r.Header.Get("X-Token") != ""
			if !hasDedicatedProxyAuth {
				consumedAuthHeader = true
			}
		}
	}

	for key, values := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(key)
		if hopByHopHeaders[canonicalKey] || proxyControlHeaders[canonicalKey] || proxyInfoHeaders[canonicalKey] {
			continue
		}
		if hideClientIP && clientIPHeaders[canonicalKey] {
			continue
		}
		if consumedAuthHeader && canonicalKey == "Authorization" {
			continue
		}
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Set target Host header
	upstreamReq.Host = targetURL.Host

	// Forward client IP if hideClientIP is disabled (default).
	// Proxy information headers (X-Forwarded-Proto, Via, Forwarded, etc.) are NOT attached to upstream.
	if !hideClientIP {
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteIP = r.RemoteAddr
		}
		if remoteIP != "" {
			clientRealIP := remoteIP
			// If incoming request is from local loopback (e.g. reverse proxy on 127.0.0.1),
			// inspect X-Real-IP or X-Forwarded-For passed from the reverse proxy.
			if remoteIP == "127.0.0.1" || remoteIP == "::1" {
				if xri := r.Header.Get("X-Real-IP"); xri != "" {
					clientRealIP = strings.TrimSpace(xri)
				} else if xffPrior := r.Header.Get("X-Forwarded-For"); xffPrior != "" {
					parts := strings.Split(xffPrior, ",")
					clientRealIP = strings.TrimSpace(parts[0])
				}
			}

			xff := clientRealIP
			if prior := r.Header.Get("X-Forwarded-For"); prior != "" && remoteIP != "127.0.0.1" && remoteIP != "::1" {
				xff = prior + ", " + remoteIP
			}
			upstreamReq.Header.Set("X-Forwarded-For", xff)
			if upstreamReq.Header.Get("X-Real-IP") == "" {
				upstreamReq.Header.Set("X-Real-IP", clientRealIP)
			}
		}
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

// authenticate checks if the request has valid credentials matching configured Basic Auth or Bearer tokens.
func (p *ProxyServer) authenticate(r *http.Request) bool {
	if !p.cfg.AuthEnabled() {
		return true
	}

	// 1. Check Proxy-Authorization header (RFC 7235 / RFC 2617 for proxies)
	if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" {
		if p.checkAuthHeader(proxyAuth) {
			return true
		}
	}

	// 2. Check dedicated X-Proxy-Token / X-Proxy-Auth / X-Token headers
	// (allows clients to authenticate to proxy while reserving Authorization for upstream targets)
	if token := r.Header.Get("X-Proxy-Token"); token != "" {
		if p.checkBearerToken(token) {
			return true
		}
	}
	if token := r.Header.Get("X-Proxy-Auth"); token != "" {
		if p.checkAuthHeader(token) || p.checkBearerToken(token) {
			return true
		}
	}
	if token := r.Header.Get("X-Token"); token != "" {
		if p.checkBearerToken(token) {
			return true
		}
	}

	// 3. Check standard Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if p.checkAuthHeader(auth) {
			return true
		}
	}

	return false
}

func (p *ProxyServer) checkAuthHeader(auth string) bool {
	parts := strings.SplitN(strings.TrimSpace(auth), " ", 2)
	if len(parts) != 2 {
		return false
	}
	authType := strings.ToLower(parts[0])
	authPayload := strings.TrimSpace(parts[1])

	switch authType {
	case "basic":
		if p.cfg.BasicAuthUser == "" || p.cfg.BasicAuthPass == "" {
			return false
		}
		decoded, err := base64.StdEncoding.DecodeString(authPayload)
		if err != nil {
			return false
		}
		cred := strings.SplitN(string(decoded), ":", 2)
		if len(cred) != 2 {
			return false
		}
		userMatch := subtle.ConstantTimeCompare([]byte(cred[0]), []byte(p.cfg.BasicAuthUser)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(cred[1]), []byte(p.cfg.BasicAuthPass)) == 1
		return userMatch && passMatch

	case "bearer":
		return p.checkBearerToken(authPayload)
	}

	return false
}

func (p *ProxyServer) checkBearerToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" || len(p.cfg.BearerTokens) == 0 {
		return false
	}
	for _, expected := range p.cfg.BearerTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func (p *ProxyServer) rejectUnauthorized(w http.ResponseWriter) {
	if p.cfg.BasicAuthUser != "" && p.cfg.BasicAuthPass != "" {
		w.Header().Add("WWW-Authenticate", `Basic realm="url-proxy"`)
	}
	if len(p.cfg.BearerTokens) > 0 {
		w.Header().Add("WWW-Authenticate", `Bearer realm="url-proxy"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": "Authentication required. See /help for supported headers and usage examples.",
	})
}

// isCommandLineClient returns true if the User-Agent indicates a CLI tool like curl, wget, or httpie.
func isCommandLineClient(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	return strings.HasPrefix(ua, "curl") ||
		strings.HasPrefix(ua, "wget") ||
		strings.HasPrefix(ua, "httpie")
}

// HelpText returns a formatted plain-text user manual for terminal/CLI users.
func HelpText(host string, schemeOpt ...string) string {
	scheme := "http"
	if len(schemeOpt) > 0 && schemeOpt[0] != "" {
		scheme = schemeOpt[0]
	}
	if host == "" {
		host = "10.0.0.10:18080"
	}
	return fmt.Sprintf(`===============================================================================
                       Universal URL Proxy (url-proxy)
===============================================================================

USAGE:
  curl [OPTIONS] %s://%s/<target-url>

BASIC EXAMPLES:
  # 1. Download a GitHub Release asset or raw file
  curl -LO %s://%s/https://github.com/torvalds/linux/archive/refs/tags/v6.0.tar.gz

  # 2. Resumable download / Range request (HTTP 206 Partial Content)
  curl -H "Range: bytes=0-1023" %s://%s/https://example.com/largefile.zip

  # 3. Model API forwarding (OpenAI / Claude / Groq streaming or non-streaming)
  curl -X POST %s://%s/https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer sk-your-api-key" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello!"}]}'

-------------------------------------------------------------------------------
AUTHENTICATION HEADERS (When Basic Auth or Bearer Token is enabled):
-------------------------------------------------------------------------------
  If the proxy server requires authentication, pass credentials using any of:

  Option A: RFC 7235 Standard Proxy Header (Recommended for upstream auth separation)
    - Basic Auth:
        curl -H "Proxy-Authorization: Basic <base64(username:password)>" ...
    - Bearer Token:
        curl -H "Proxy-Authorization: Bearer <proxy-token>" ...
    * Benefit: The proxy consumes Proxy-Authorization. Any target
      "Authorization" header (e.g. sk-...) is 100%% preserved for the upstream!

  Option B: Dedicated Proxy Token Header (Recommended for LLM APIs)
    - Token:
        curl -H "X-Proxy-Token: <proxy-token>" ...
        curl -H "X-Proxy-Auth:  <proxy-token>" ...
    * Benefit: Dedicated header eliminates collision with upstream Authorization.

  Option C: Standard Authorization Header (Single-tier proxy usage)
    - Basic Auth:
        curl -u user:pass %s://%s/<target-url>
    - Bearer Token:
        curl -H "Authorization: Bearer <proxy-token>" %s://%s/<target-url>
    * Security: If used to authenticate to the proxy alone, this header is
      automatically stripped before forwarding to prevent credential leakage.

-------------------------------------------------------------------------------
CLIENT IP & PRIVACY HEADERS (High-Anonymity by default):
-------------------------------------------------------------------------------
  By default, the proxy operates in high-anonymity mode (HIDE_CLIENT_IP=true).
  All client identifying headers (X-Forwarded-For, X-Real-IP, etc.) and proxy
  metadata (X-Forwarded-Proto, Via) are stripped. The upstream server only sees
  the proxy's IP.

  Per-request header controls:
  - Forward client real IP to upstream:
      curl -H "X-Forward-Client-IP: true" %s://%s/<target-url>

  - Hide client real IP (default behavior):
      curl %s://%s/<target-url>

-------------------------------------------------------------------------------
UTILITY ENDPOINTS:
-------------------------------------------------------------------------------
  GET /help     - Plain-text usage manual (this help page)
  GET /healthz  - Health check & runtime status (JSON, always unauthenticated)

===============================================================================
`, scheme, host, scheme, host, scheme, host, scheme, host, scheme, host, scheme, host, scheme, host, scheme, host)
}

// PrintCLIHelp outputs the command-line flags and environment variables manual.
func PrintCLIHelp(w io.Writer) {
	fmt.Fprintf(w, `Universal URL Proxy (url-proxy) - Lightweight URL Path Forwarding Service

USAGE:
  url-proxy [OPTIONS]

LISTEN & ADDRESS OPTIONS:
  -host string
        Host or IP interface to bind to (e.g. "127.0.0.1", "0.0.0.0")
        [env: HOST]
  -port string
        Port or address to listen on (e.g. "8080", ":8080", "127.0.0.1:8080") (default ":8080")
        [env: PORT]
  -bind string, -addr string
        Alias for listen address (e.g. "127.0.0.1:8080", "127.0.0.1")
        [env: BIND, ADDR, LISTEN_ADDR]

TLS / HTTPS OPTIONS:
  -tls-cert string
        Path to TLS certificate file (enables HTTPS server)
        [env: TLS_CERT_FILE, TLS_CERT]
  -tls-key string
        Path to TLS private key file (enables HTTPS server)
        [env: TLS_KEY_FILE, TLS_KEY]
  -insecure
        Skip TLS certificate verification for upstream HTTPS targets (default false)
        [env: INSECURE_SKIP_VERIFY, TLS_INSECURE_SKIP_VERIFY]

ACCESS CONTROL & SSRF PROTECTION:
  -allow-domains string
        Comma-separated list of allowed target domains (supports wildcards, e.g. "*.github.com")
        [env: ALLOW_DOMAINS] (default: allow all if empty or "*")
  -block-domains string
        Comma-separated list of blocked target domains
        [env: BLOCK_DOMAINS]
  -block-private-ips
        Block private/internal IP ranges to prevent SSRF and DNS rebinding (default true)
        [env: BLOCK_PRIVATE_IPS]

AUTHENTICATION OPTIONS:
  -basic-auth string
        Basic Auth credentials in "username:password" format
        [env: BASIC_AUTH]
  -basic-user string
        Basic Auth username [env: BASIC_AUTH_USER]
  -basic-pass string
        Basic Auth password [env: BASIC_AUTH_PASS, BASIC_AUTH_PASSWORD]
  -bearer-token string, -token string
        Bearer token(s), comma-separated for multiple tokens
        [env: BEARER_TOKEN, BEARER_AUTH, AUTH_TOKEN, TOKEN]

PROXY & STREAMING OPTIONS:
  -hide-client-ip
        Hide client real IP & strip proxy metadata (high-anonymity mode) (default true)
        [env: HIDE_CLIENT_IP]
  -max-redirects int
        Maximum HTTP 301/302 redirects to follow (0 = do not follow) (default 10)
        [env: MAX_REDIRECTS]
  -buffer-size-kb int
        Streaming buffer size in kilobytes (default 32)
        [env: BUFFER_SIZE_KB]

UTILITIES & INFO:
  -h, -help, --help
        Show this help message and exit
  -v, -version, --version
        Show version information and exit
  -healthcheck
        Execute a local health check against the running server and exit (0 = ok, 1 = fail)

EXAMPLES:
  # 1. Listen on all interfaces on port 8080 (default)
  url-proxy

  # 2. Listen on 127.0.0.1:8080 (for reverse proxy frontend like Nginx/Caddy)
  url-proxy -host 127.0.0.1 -port 8080
  # Or via environment variables:
  HOST=127.0.0.1 PORT=8080 url-proxy

  # 3. Direct TLS / HTTPS server
  url-proxy -port :8443 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
  # Or via environment variables:
  PORT=8443 TLS_CERT_FILE=/path/to/cert.pem TLS_KEY_FILE=/path/to/key.pem url-proxy

  # 4. Behind an Nginx reverse proxy with TLS (listening on 127.0.0.1)
  # Nginx upstream config snippet:
  #   server {
  #       listen 443 ssl;
  #       server_name proxy.example.com;
  #       ssl_certificate /path/to/cert.pem;
  #       ssl_certificate_key /path/to/key.pem;
  #       location / {
  #           proxy_pass http://127.0.0.1:8080;
  #           proxy_set_header Host $host;
  #           proxy_set_header X-Real-IP $remote_addr;
  #           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  #           proxy_set_header X-Forwarded-Proto $scheme;
  #       }
  #   }
`)
}

func main() {
	// Intercept help flags immediately
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			PrintCLIHelp(os.Stdout)
			os.Exit(0)
		}
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version", "-v":
			fmt.Printf("url-proxy %s (commit: %s, built: %s)\n", Version, CommitSHA, BuildDate)
			os.Exit(0)
		case "-healthcheck":
			cfg := LoadConfig(os.Args[1:]...)
			healthURL := "http://127.0.0.1:8080/healthz"
			if cfg.Port != "" {
				addr := cfg.Port
				if strings.HasPrefix(addr, ":") {
					addr = "127.0.0.1" + addr
				}
				scheme := "http"
				if cfg.TLSEnabled() {
					scheme = "https"
				}
				healthURL = fmt.Sprintf("%s://%s/healthz", scheme, addr)
			}
			client := &http.Client{Timeout: 5 * time.Second}
			if strings.HasPrefix(healthURL, "https") {
				client.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}
			resp, err := client.Get(healthURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	cfg := LoadConfig(os.Args[1:]...)
	if cfg.HelpRequested {
		PrintCLIHelp(os.Stdout)
		os.Exit(0)
	}

	if (cfg.TLSCertFile != "" && cfg.TLSKeyFile == "") || (cfg.TLSCertFile == "" && cfg.TLSKeyFile != "") {
		log.Fatalf("Fatal: both -tls-cert and -tls-key (or TLS_CERT_FILE and TLS_KEY_FILE) must be specified to enable TLS")
	}

	server := NewProxyServer(cfg)

	proto := "http"
	if cfg.TLSEnabled() {
		proto = "https"
	}
	log.Printf("Starting Universal URL Proxy on %s://%s ...", proto, cfg.Port)
	log.Printf("Config: Host=%q, Port=%q, TLSEnabled=%v, AllowDomains=%v, BlockDomains=%v, BlockPrivateIPs=%v, MaxRedirects=%d, BufferSizeKB=%d, HideClientIP=%v, AuthEnabled=%v, InsecureSkipTLS=%v",
		cfg.Host, cfg.Port, cfg.TLSEnabled(), cfg.AllowDomains, cfg.BlockDomains, cfg.BlockPrivateIPs, cfg.MaxRedirects, cfg.BufferSizeKB, cfg.HideClientIP, cfg.AuthEnabled(), cfg.InsecureSkipTLS)

	httpServer := &http.Server{
		Addr:         cfg.Port,
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		IdleTimeout:  120 * time.Second,
		WriteTimeout: 0, // Disable write timeout for unbounded streaming responses
	}

	if cfg.TLSEnabled() {
		log.Printf("TLS enabled. Listening HTTPS on %s (cert: %s, key: %s)", cfg.Port, cfg.TLSCertFile, cfg.TLSKeyFile)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("TLS Server failed: %v", err)
		}
	} else {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
