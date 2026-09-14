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
  - [4. 高匿代理与客户端 IP 隐藏机制](#4-高匿代理与客户端-ip-隐藏机制)
  - [5. 访问认证安全体系（Basic Auth & Bearer Auth）](#5-访问认证安全体系basic-auth--bearer-auth)
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

### 4. 客户端 IP 透传与无代理痕迹机制

默认情况下，本项目**默认开启客户端真实 IP 透传（Transparent IP Passthrough）**，同时**绝不向上游后端附加代理痕迹信息**：
- **默认透传 IP**（`HIDE_CLIENT_IP=false`）：
  - 自动向目标上游传递客户端真实 IP（`X-Forwarded-For: <client_ip>` 与 `X-Real-IP: <client_ip>`）。
  - **绝不添加 proxy 痕迹信息**：自动剥离并杜绝向后端发送 `X-Forwarded-Proto`、`X-Forwarded-Host`、`X-Forwarded-Port`、`X-Forwarded-Server`、`Forwarded`、`Via` 等代理标识头，使上游目标端收到的请求干净纯粹，避免触发重定向循环或代理风控。
- **高匿模式**：若需要完全隐藏客户端真实 IP，可通过配置环境变量 `HIDE_CLIENT_IP=true`（或 `FORWARD_CLIENT_IP=false`）开启高匿代理，此时目标端仅能看到代理服务器自身的出网 IP。

#### 客户端自主选择（通过 HTTP 请求头动态切换）

除了服务端全局环境变量配置外，**客户端亦可在发起请求时按需自主决定是否隐藏真实 IP**。为保障目标 URL 的绝对纯净（避免破坏 AWS S3 等对象的预签名 URL 校验），本项目**仅通过 HTTP 请求头**提供控制，绝不侵入或修改目标 URL 的 Query 参数：

- **隐藏真实客户端 IP（高匿模式）**：在请求头中加入 `X-Hide-Client-IP: true`
  ```bash
  curl -H "X-Hide-Client-IP: true" http://10.0.0.10:18080/https://httpbin.org/ip
  # 目标端响应仅展示代理出口 IP
  ```
- **携带真实客户端 IP（默认行为）**：默认请求无需任何参数，或显式传入 `X-Forward-Client-IP: true`
  ```bash
  curl http://10.0.0.10:18080/https://httpbin.org/ip
  # 目标端响应包含客户端真实 IP
  ```

> **安全与零侵入保证**：
> 1. 代理服务在向上游转发时会自动剥离所有内部控制头（`X-Forward-Client-IP`、`X-Hide-Client-IP` 等），绝不向目标服务端泄露任何内部标记。
> 2. 目标 URL 路径与 Query 参数保持 100% 原始字节透传，完全不改变字符编码与参数顺序，兼容所有严格签名校验接口。

### 5. 访问认证安全体系（Basic Auth & Bearer Auth）

为了在公网或受限内网环境中保护代理服务不被滥用，服务原生支持 **Basic Auth（用户名/密码）** 与 **Bearer Auth（Token 令牌）** 双认证体系：

- **默认状态**：未配置认证信息时，认证处于关闭状态（`auth_enabled: false`），开箱即用，免密访问。
- **双通道配置**：同时支持环境变量（Docker 容器推荐）与启动参数命令行 Flag（本地二进制推荐）。
- **上游目标凭证解耦与防泄漏**：
  - 在转发 OpenAI、GitHub 私有 API 等场景中，上游目标服务器本身需要传递 `Authorization: Bearer sk-...`。
  - 客户端使用标准代理头 `Proxy-Authorization` 或专用网关头 `X-Proxy-Token` / `X-Proxy-Auth` 进行代理鉴权时，代理将仅消费自己的鉴权头，并将目标所需的 `Authorization` **100% 完整原样透传给上游**。
  - 若客户端直接使用 `Authorization` 认证代理，代理在转发时会**自动剥离该标头**，绝不将代理的内部凭证泄漏给外部目标服务器。
- **常量时间防计时攻击**：底层采用 `crypto/subtle.ConstantTimeCompare` 进行凭据对比，防止侧信道计时分析（Timing Attack）。
- **探针健康检查免认证**：`/healthz` 与 `/health` 探针接口始终保持公开访问，并在响应 JSON 中包含 `"auth_enabled": true/false`，确保 Kubernetes / Docker Compose 健康检查永不被 401 阻断。

---

## 环境变量与启动参数配置参考

所有行为均支持通过环境变量（推荐容器环境）或 CLI 启动参数（推荐本地命令行）进行配置，CLI 启动参数优先级高于环境变量：

| 环境变量 | CLI 启动参数 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `PORT` | `-port` | String | `8080` | 服务监听端口（如 `8080` 或 `:8080`） |
| `BASIC_AUTH` | `-basic-auth` | String | 空 | Basic Auth 认证凭证，格式为 `username:password` |
| `BASIC_AUTH_USER` | `-basic-user` | String | 空 | Basic Auth 用户名（可与 `BASIC_AUTH_PASS` 搭配） |
| `BASIC_AUTH_PASS` | `-basic-pass` | String | 空 | Basic Auth 密码 |
| `BEARER_TOKEN` | `-bearer-token` / `-token` | String | 空 | Bearer Token 凭据，支持逗号分隔配置多个 Token（如 `token1,token2`） |
| `ALLOW_DOMAINS` | `-allow-domains` | String | 空或 `*` | 允许代理的目标域名列表，英文逗号分隔。支持通配符（如 `*.github.com,github.com`）或 `*` 放通所有合法公网域名 |
| `BLOCK_DOMAINS` | `-block-domains` | String | 空 | 阻断的目标域名列表，英文逗号分隔 |
| `BLOCK_PRIVATE_IPS` | `-block-private-ips` | Boolean | `true` | 是否拦截私有网段/环回地址/云元数据（SSRF 防御） |
| `HIDE_CLIENT_IP` | `-hide-client-ip` | Boolean | `false` | **高匿代理模式**：是否隐藏客户端真实 IP（默认 `false`，即默认透传真实 IP 且不附加任何 proxy 标记信息） |
| `FORWARD_CLIENT_IP` | - | Boolean | `true` | 与 `HIDE_CLIENT_IP` 语义相反，默认 `true` 透传客户端 IP |
| `MAX_REDIRECTS` | `-max-redirects` | Int | `10` | 允许跟随的最大 301/302 重定向次数。设为 `0` 则不跟随重定向，直接返回 302 |
| `BUFFER_SIZE_KB` | `-buffer-size-kb` | Int | `32` | 流式传输缓冲区大小（单位 KB） |
| `HTTP_PROXY` | - | String | 系统默认 | 上游代理配置（支持 HTTP 代理） |
| `HTTPS_PROXY` | - | String | 系统默认 | 上游 HTTPS 代理配置 |
| `ALL_PROXY` | - | String | 系统默认 | 上游全局代理（支持 `socks5://user:pass@host:port`） |
| `NO_PROXY` | - | String | 系统默认 | 绕过上游代理的目标列表 |

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

### 场景二：Docker 容器化运行（使用官方多架构镜像）

已发布包含 **x86_64 (amd64)** 与 **ARM64** 的官方多架构镜像 `epurs/url-proxy:latest`，开箱即用：

```bash
# 全放通模式（默认放通所有合法公网域名，内置私网与云元数据 SSRF 防护）
docker run -d \
  --name url-proxy \
  --restart unless-stopped \
  -p 8080:8080 \
  -e ALLOW_DOMAINS="*" \
  -e MAX_REDIRECTS=10 \
  epurs/url-proxy:latest
```

或仅放行 GitHub 生态域名（白名单模式）：

```bash
docker run -d \
  --name url-proxy \
  --restart unless-stopped \
  -p 8080:8080 \
  -e ALLOW_DOMAINS="*.github.com,github.com,*.githubusercontent.com" \
  -e MAX_REDIRECTS=10 \
  epurs/url-proxy:latest
```

使用 Docker Compose 部署示例：

```yaml
version: '3.8'

services:
  url-proxy:
    image: epurs/url-proxy:latest
    container_name: url-proxy
    restart: always
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - ALLOW_DOMAINS=*
      - BLOCK_PRIVATE_IPS=true
      - MAX_REDIRECTS=10
      - BUFFER_SIZE_KB=32
    healthcheck:
      test: ["CMD", "/app/url-proxy", "-healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
```

---

### CI/CD 自动化构建与 Release 发布（兼容 GitHub Actions 与 Gitea Actions）

项目配置了完整的自动化流水线，兼顾容器化与轻量二进制分发场景：

#### 1. Docker 镜像自动化发布（`.github/workflows/docker.yaml` 与 `.gitea/workflows/docker.yaml`）
- **触发时机**：代码 Push 至 `main` 分支或推送版本 Tag（如 `v1.0.0`），或在界面手动触发（`workflow_dispatch`）。
- **多平台矩阵**：基于 Docker Buildx 原生交叉编译输出 `linux/amd64` (x86_64) 与 `linux/arm64` 镜像。
- **凭据要求**：在 GitHub / Gitea 仓库的 `Settings` -> `Actions` -> `Secrets` 中配置：
  - `DOCKER_USERNAME`: Docker Hub 用户名（默认兜底为 `epurs`）
  - `DOCKER_PASSWORD`: Docker Hub 访问 Token 或密码
- **健壮性降级**：若未配置 `DOCKER_PASSWORD`，流水线自动降级为多架构编译校验（`push: false`）并给出 Warning 提示，避免流程暴红。

#### 2. 多平台独立二进制 Release 自动化发布（`.github/workflows/release.yaml` 与 `.gitea/workflows/release.yaml`）
- **触发时机**：推送版本 Tag（如 `git push origin v1.0.0`），或在 Actions 界面手动触发（`workflow_dispatch` 输入 Tag 名称）。
- **跨平台全架构覆盖**：
  - **Linux**：`linux/amd64`, `linux/arm64`, `linux/arm` (ARMv7)
  - **macOS (Darwin)**：`darwin/amd64` (Intel Mac), `darwin/arm64` (Apple Silicon M系列芯片)
  - **Windows**：`windows/amd64.exe`, `windows/arm64.exe`
- **自动归档与校验**：各架构分别打包为 `.tar.gz` 或 `.zip`，内置 `README.md`，并自动生成包含全量哈希的 `checksums.txt`，自动发布至 GitHub Releases。
- **本地一键打包**：开发者在本地任意环境亦可直接执行脚本构建全量发布包：
  ```bash
  ./scripts/build-release.sh v1.0.0
  ```

---

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

### 场景五：iptables 主机防火墙访问控制（限定单 IP 或网段访问）

由于 Docker 容器默认绕过系统 `INPUT` 链直接经由 `FORWARD` 链进行 DNAT 路由，对容器外部端口进行访问控制时，推荐在 `DOCKER-USER` 链中配置规则：

```bash
# 仅允许指定来源 IP (例如 10.0.0.98) 访问宿主机上的 18080 端口
iptables -I DOCKER-USER 1 -i enp0s6 -s 10.0.0.98 -p tcp -m conntrack --ctorigdstport 18080 -j ACCEPT
iptables -I DOCKER-USER 2 -i enp0s6 -p tcp -m conntrack --ctorigdstport 18080 -j REJECT --reject-with tcp-reset

# 保存规则以便重启持久生效 (Ubuntu/Debian)
netfilter-persistent save
```

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

### 5. 访问认证请求示例（开启 Basic Auth 或 Bearer Auth 时）

```bash
# 方式 A：标准 Basic Auth 请求
curl -u admin:secret http://localhost:8080/https://api.github.com/user

# 方式 B：标准 Bearer Token 请求
curl -H "Authorization: Bearer my-secret-token" http://localhost:8080/https://api.github.com/user

# 方式 C：使用 Proxy-Authorization 认证代理，同时携带目标 API 的 Authorization
# （代理消费 Proxy-Authorization，并将 Authorization: Bearer sk-... 纯净透传给上游）
curl -H "Proxy-Authorization: Bearer my-proxy-token" \
     -H "Authorization: Bearer sk-openai-actual-key" \
     http://localhost:8080/https://api.openai.com/v1/chat/completions

# 方式 D：使用 X-Proxy-Token 专用标头认证代理
curl -H "X-Proxy-Token: my-proxy-token" \
     -H "Authorization: Bearer sk-openai-actual-key" \
     http://localhost:8080/https://api.openai.com/v1/chat/completions
```

### 6. 健康检查（始终免认证）
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
  "max_redirects": 10,
  "hide_client_ip": true,
  "auth_enabled": true
}
```

### 7. 终端命令行快速帮助手册（curl /help）

无需查阅网页文档，任何时候在终端执行 `curl /help`（或使用 curl 直接访问根路径 `/`）即可即时输出完整的英文格式化使用指南与标头说明：

```bash
curl http://localhost:8080/help
# 或直接
curl http://localhost:8080/
```

终端将即时打印格式化好的 USAGE、认证 Header（Basic/Bearer/Proxy-Authorization/X-Proxy-Token）、高匿与真实 IP 控制 Header 等所有选项及示例。

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
- [x] **高匿模式与客户端自主选择**：默认隐藏客户端 IP、`X-Forward-Client-IP` 按需透传、Query 参数无损不侵入。
- [x] **访问认证体系**：Basic Auth 环境变量与 CLI 参数加载、Bearer Token 多令牌比对、常量时间对比防计时攻击、上游目标凭据解耦透传、未授权 401 阻断与 WWW-Authenticate 标头、`/healthz` 探针免密放行。
- [x] **命令行即时手册**：`/help` 纯文本格式化输出、CLI（curl/wget/httpie）智能探测、未认证访问豁免保障。
- [x] **健康检查与自检**：`-healthcheck` 原生自检旗标测试、Web 端图形化使用说明首页。
