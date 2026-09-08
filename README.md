# 极轻量通用 URL Path 转发服务 (URL Proxy)

一个极轻量、高性能、开箱即用的通用 HTTP/HTTPS URL 转发与反向代理服务（类似 `ghproxy` 的体验，但不局限在 GitHub，支持任意允许的 URL）。

本项目基于 **Go 1.18+ 标准库** 原生开发，**零外部第三方依赖**，编译后静态二进制体积仅 **4.5MB**，制作的 Docker 镜像仅 **14.7MB**，待机内存占用仅约 **10MB**，天然支持高并发流式转发与断点续传。

---

## 目录

- [核心特性与解决痛点](#核心特性与解决痛点)
- [技术选型与架构设计](#技术选型与架构设计)
- [核心机制深度剖析](#核心机制深度剖析)
  - [1. 路由解析与 Path 容错算法](#1-路由解析与-path-容错算法)
  - [2. 301/302 重定向跟随与零缓冲流式传输](#2-301302-重定向跟随与零缓冲流式传输)
  - [3. SSRF 防护与 DNS 重绑定防御体系](#3-ssrf-防护与-dns-重绑定防御体系)
- [环境变量配置参考](#环境变量配置参考)
- [快速开始与部署场景](#快速开始与部署场景)
  - [场景一：本地直接运行](#场景一本地直接运行)
  - [场景二：Docker 容器化运行（白名单模式）](#场景二docker-容器化运行白名单模式)
  - [场景三：上游挂载 HTTP / SOCKS5 出网代理](#场景三上游挂载-http--socks5-出网代理)
  - [场景四：配合 Nginx / 网关反向代理配置](#场景四配合-nginx--网关反向代理配置)
- [API 与接口测试示例](#api-与接口测试示例)
- [测试覆盖与质量报告](#测试覆盖与质量报告)

---

## 核心特性与解决痛点

在容器部署、边缘网关拉取外部依赖（如 GitHub Releases、HF 权重、Docker 资产等）时，常面临以下痛点：
1. **反向代理斜杠合并问题**：前端或前置反代（如 Nginx、Envoy、API Gateway）在处理 `http://proxy/https://github.com/...` 时，会将协议双斜杠 `//` 规范化为单斜杠 `/`，导致后端收到 `/https:/github.com/...` 并报错 404/400。
2. **URL Encode 字符兼容**：部分客户端或前端在传递 URL 时会执行 `encodeURIComponent`，将 `:` 与 `/` 转义为 `%3A` 与 `%2F`。
3. **大文件下载 OOM（内存爆仓）**：常规反代若将上游响应缓存到内存或临时文件，并发下载几 GB 的 Release 包或镜像时极易引发服务器 OOM。
4. **重定向穿透**：很多下载源（如 GitHub Release 资产）会 `302 Found` 跳转到 AWS S3 / `objects.githubusercontent.com`。若代理直接向受限客户端返回 302，客户端直连仍然会超时失败。
5. **SSRF 安全风险**：开放式代理极易沦为攻击者探测内网私有 IP（如 `127.0.0.1`、`10.0.0.0/8`、AWS/GCP 云元数据 `169.254.169.254`）的跳板。

本项目针对上述痛点进行了针对性架构设计，做到**全自动容错、透明跟随、全双工流式转发与企业级 SSRF 防御**。

---

## 技术选型与架构设计

### 选型对比

| 维度 | Go (本项目选用) | Python (FastAPI/Tornado) | Node.js (Express/Fastify) | Nginx (Lua / OpenResty) |
| :--- | :--- | :--- | :--- | :--- |
| **依赖与打包** | **单二进制文件，零依赖** | 需 Python 运行环境及 pip 包 | 需 Node.js 运行时与 node_modules | 需 OpenResty 二进制及动态模块 |
| **镜像体积** | **~14.7 MB** (Alpine) / **~8MB** (Scratch) | 80MB ~ 200MB | 100MB ~ 250MB | 50MB ~ 120MB |
| **启动速度** | **< 10ms** | 1s ~ 3s | 500ms ~ 1.5s | 100ms |
| **内存底噪** | **~ 10MB** | ~ 50MB | ~ 40MB | ~ 20MB |
| **并发流式模型** | **Goroutine + io.CopyBuffer，零 GC 压力** | asyncio 流式控制复杂，易漏关连接 | Stream Pipe 处理相对繁琐 | 需通过 Lua 协程处理，调试成本高 |

### 架构流程图

```
客户端请求 (curl / wget / browser / git)
    │
    │  GET /https://github.com/... 或 /https:/github.com/...
    ▼
┌────────────────────────────────────────────────────────┐
│              URL Proxy (Go 原生 HTTP 代理)             │
│                                                        │
│  1. NormalizeTargetURL: 恢复反代折叠斜杠、解码 %3A/%2F │
│  2. ValidateTargetHost: ALLOW/BLOCK 域名黑白名单校验   │
│  3. SSRF Defense: 拦截私网 IP / 云元数据 / DNS 重绑定  │
│  4. HTTP Client: 跟随 301/302 重定向 (继承 Range 头)   │
│  5. Stream Engine: 32KB 块双向流式拷贝，透传 HTTP 206  │
└────────────────────────────────────────────────────────┘
    │
    ▼ (透明代理/出网代理 HTTP_PROXY)
目标上游服务器 (GitHub, S3, GitLab, HF, etc.)
```

---

## 核心机制深度剖析

### 1. 路由解析与 Path 容错算法

服务通过 `NormalizeTargetURL(rawURI, urlPath string)` 进行三级智能识别与恢复：

1. **原始 URI 提取**：优先从 `r.RequestURI` 读取（该字段保留客户端原始未清洗的请求行，避免被 Go 内部 `path.Clean` 预清洗）。
2. **协议与路径分隔符解码**：
   - 将 URL 编码的 scheme 冒号及斜杠（`%3A`/`%3a` -> `:`，`%2F`/`%2f` -> `/`）精准还原。
   - 保留路径内用户真实需要的百分号编码（如 `%20` 空格、文件名中文等），防止过度解码造成二次错误。
   - 若查询参数的分隔符 `?` 被转义为 `%3F`/`%3f` 且无显式 `?`，精准恢复首个查询符。
3. **反向代理斜杠合并恢复**：
   - 识别 `https:/domain/path` -> 修复为 `https://domain/path`。
   - 识别 `http:/domain/path` -> 修复为 `http://domain/path`。
   - 识别 `domain/path`（未显式声明协议）-> 自动补齐默认协议 `https://`。

### 2. 301/302 重定向跟随与零缓冲流式传输

- **重定向透传跟随**：
  - 默认 `MAX_REDIRECTS=10`。在 `CheckRedirect` 钩子中，对每一跳重定向的新地址强制执行安全策略校验（防止上游恶意跳转至内网 IP）。
  - 在重定向跨域跳转时，保留客户端关键的 `Range` 标头，保证跳转至真实 CDN/S3 资产后断点续传依然生效。
- **零缓冲流式传输（Streaming）**：
  - 采用 `io.CopyBuffer(w, upstreamResp.Body, buf)`，缓冲区设定为 32KB（可通过 `BUFFER_SIZE_KB` 调节）。
  - 数据边从上游读取边写入下游 Socket，内存中永远仅保留几十 KB 临时块，**哪怕拉取 100GB 的镜像文件也不会消耗更多内存**。
  - 剔除 RFC 2616 定义的 Hop-by-hop 标头（`Connection`, `Keep-Alive`, `Transfer-Encoding` 等），完整透传 `Content-Type`、`Content-Length`、`Content-Disposition`、`Content-Range`、`Accept-Ranges`。

### 3. SSRF 防护与 DNS 重绑定防御体系

为了彻底避免成为内网 SSRF 攻击跳板，服务实现了纵深防御：
1. **静态目标校验**：
   - 支持 `ALLOW_DOMAINS`（白名单，支持 `*.github.com` 等通配符）。
   - 支持 `BLOCK_DOMAINS`（黑名单）。
2. **私网 IP 全网段拦截**：
   - 覆盖所有私有与保留网段：
     - `127.0.0.0/8` (Loopback 本地环回)
     - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 私网)
     - `169.254.0.0/16` (RFC 3927 链路本地，防御 AWS/GCP/Azure 机器元数据凭据泄露)
     - `100.64.0.0/10` (运营商级 NAT)
     - `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`
     - IPv6：`::1/128`, `fc00::/7` (ULA), `fe80::/10` (Link-Local)
3. **DNS 重绑定（DNS Rebinding）防御**：
   - 攻击者可将域名首次解析为公网 IP，在连接拨号时通过快速 TTL 切换为 `127.0.0.1`。
   - 本项目在 `http.Transport.DialContext` 中执行拦截：在真正建立 TCP 连接前解析 DNS，对目标地址所指向的所有实际 IP 进行私网校验。若发现私网 IP 则立即断开拨号，从网络底层彻底杜绝 DNS 重绑定隐患。

---

## 环境变量配置参考

所有行为均通过标准环境变量配置，无需任何复杂的配置文件：

| 环境变量 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `PORT` | String | `8080` | 服务监听端口（如 `8080` 或 `:8080`） |
| `ALLOW_DOMAINS` | String | 空或 `*`（默认放通所有公网） | 允许代理的目标域名列表，英文逗号分隔。支持通配符（如 `*.github.com,github.com`）或直接配置为 `*` 放通所有公网域名（仍受内网 SSRF 防护） |
| `BLOCK_DOMAINS` | String | 空 | 阻断的目标域名列表，英文逗号分隔 |
| `BLOCK_PRIVATE_IPS` | Boolean | `true` | 是否拦截私有网段/环回地址/云元数据（SSRF 防御） |
| `MAX_REDIRECTS` | Int | `10` | 允许跟随的最大 301/302 重定向次数。设为 `0` 则不跟随重定向，直接返回 302 |
| `BUFFER_SIZE_KB` | Int | `32` | 流式传输缓冲区大小（单位 KB） |
| `HTTP_PROXY` | String | 系统默认 | 上游代理配置（支持 HTTP 代理） |
| `HTTPS_PROXY` | String | 系统默认 | 上游 HTTPS 代理配置 |
| `ALL_PROXY` | String | 系统默认 | 上游全局代理（支持 `socks5://user:pass@host:port`） |
| `NO_PROXY` | String | 系统默认 | 绕过上游代理的目标列表 |

---

## 快速开始与部署场景

### 场景一：本地直接运行

```bash
# 1. 编译二进制
go build -ldflags="-s -w" -o url-proxy .

# 2. 启动服务（默认监听 8080）
./url-proxy

# 3. 访问测试
curl -i http://localhost:8080/healthz
```

### 场景二：Docker 容器化运行（白名单模式）

限制仅允许代理 GitHub 相关生态资源：

```bash
docker run -d \
  --name url-proxy \
  --restart unless-stopped \
  -p 8080:8080 \
  -e ALLOW_DOMAINS="*.github.com,github.com,*.githubusercontent.com" \
  -e MAX_REDIRECTS=10 \
  url-proxy:latest
```

使用 Docker Compose 部署示例：

```yaml
version: '3.8'

services:
  url-proxy:
    image: url-proxy:latest
    container_name: url-proxy
    restart: always
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - ALLOW_DOMAINS=*.github.com,github.com,*.githubusercontent.com,*.gitlab.com
      - BLOCK_PRIVATE_IPS=true
      - MAX_REDIRECTS=10
      - BUFFER_SIZE_KB=32
    healthcheck:
      test: ["CMD", "/app/url-proxy", "-healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
```

### 场景三：上游挂载 HTTP / SOCKS5 出网代理

若代理服务器位于内网或受限网络，需经由上游代理（如本地 SOCKS5 或代理池）访问目标：

```bash
docker run -d \
  --name url-proxy \
  -p 8080:8080 \
  -e ALL_PROXY="socks5://192.168.1.100:1080" \
  -e ALLOW_DOMAINS="*.github.com,github.com,*.githubusercontent.com" \
  url-proxy:latest
```

### 场景四：配合 Nginx / 网关反向代理配置

当 `url-proxy` 作为前置 Nginx 的后端时，需确保 Nginx **不折叠双斜杠**（或者关闭 merge_slashes），或借助本服务的自动容错功能：

```nginx
server {
    listen 80;
    server_name gh.example.com;

    # 关键配置：避免 Nginx 自动将 // 合并为 /
    merge_slashes off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        
        # 透传客户端真实信息
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 禁用 Nginx 缓冲区以保证即时流式下载
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_http_version 1.1;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
```

> **注**：即使用户的 Nginx 开启了 `merge_slashes on`，导致传入 `/https:/github.com/...`，本服务的容错算法也会自动识别并精准修复。

---

## API 与接口测试示例

### 1. 基础下载转发
```bash
curl -LO http://localhost:8080/https://github.com/torvalds/linux/archive/refs/tags/v6.0.tar.gz
```

### 2. 容错路径转发（反代合并后的非标路径）
```bash
curl -LO http://localhost:8080/https:/github.com/torvalds/linux/archive/refs/tags/v6.0.tar.gz
```

### 3. URL 编码格式转发
```bash
curl -LO http://localhost:8080/https%3A%2F%2Fgithub.com%2Ftorvalds%2Flinux%2Farchive%2Frefs%2Ftags%2Fv6.0.tar.gz
```

### 4. 断点续传（Range 标头透传）
```bash
# 断点拉取前 1024 字节
curl -H "Range: bytes=0-1023" -i http://localhost:8080/https://raw.githubusercontent.com/octocat/Hello-World/master/README
```
返回：
```http
HTTP/1.1 206 Partial Content
Accept-Ranges: bytes
Content-Range: bytes 0-1023/1234
Content-Type: text/plain; charset=utf-8
...
```

### 5. 健康检查
```bash
curl -s http://localhost:8080/healthz | jq .
```
返回示例：
```json
{
  "status": "ok",
  "allow_domains": ["*.github.com", "github.com", "*.githubusercontent.com"],
  "block_domains": null,
  "block_private_ips": true,
  "max_redirects": 10
}
```

---

## 测试覆盖与质量报告

服务内置完备的单元测试与集成测试，覆盖率近 80%，并通过 Go Race 竞争检测无任何竞态隐患。

执行测试命令：
```bash
go test -v -race -coverprofile=coverage.out .
```

测试覆盖的关键用例列表：
- [x] **URL 路径规范化**：标准 HTTPS/HTTP、反代合并单斜杠 (`https:/`)、三斜杠、URL 编码 (`%3A%2F%2F`, `%3A%2F`)、大小写混合编码、未声明协议默认补齐、Query 参数无损保留、端口号保留。
- [x] **SSRF 拦截**：全网段私有 IPv4/IPv6、链路本地/云元数据 (`169.254.169.254`)、本地回环 (`127.0.0.1`, `::1`)。
- [x] **域名控制**：白名单通配符匹配 (`*.github.com` 匹配 `raw.github.com` 及根域)、黑名单精确拦截、未授权域 403 阻断。
- [x] **301/302 重定向**：真实 HTTP 模拟服务跳转跟随、跨跳转 `Range` 标头保留、`MaxRedirects=0` 原样返回跳转。
- [x] **流式与断点续传**：大响应流式透传无内存缓存、HTTP 206 Partial Content 及 Content-Range 透传。
- [x] **健康检查与自检**：`-healthcheck` 原生自检旗标测试、Web 端图形化使用说明首页。
