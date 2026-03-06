# Noise 基础握手模式扩展实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将当前仅支持 `XX` 的 Noise 握手流程扩展为支持所有基础握手模式，并按模式动态校验静态密钥依赖。

**Architecture:** C 侧把固定三次握手改为通用 action 驱动，首包仍承载 6 字节协商头；Go 示例客户端同步改为表驱动 pattern 解析与通用握手流程；server/proxy 两侧按 pattern 判断本端私钥和对端公钥是否必需。

**Tech Stack:** Nginx module C, Noise-C, Go, github.com/flynn/noise

---

### Task 1: 扩展协议能力表

**Files:**
- Modify: `ngx_noise_protocol.h`
- Modify: `ngx_noise_protocol.c`
- Modify: `example/noise_http_client/main.go`

**Step 1: 新增基础握手模式表**

- 列出所有基础模式及其 `pattern_id`。
- 明确排除 `fallback` 和 `psk` 变体。

**Step 2: 增加模式能力查询函数**

- 查询 initiator 是否需要本端静态私钥。
- 查询 responder 是否需要本端静态私钥。
- 查询 initiator 是否需要对端静态公钥。
- 查询 responder 是否需要对端静态公钥。

**Step 3: 放开 C/Go 两侧 pattern 解析**

- `ngx_noise_protocol_parse()`
- `parseNoisePattern()`

### Task 2: 改造 C 侧握手驱动

**Files:**
- Modify: `ngx_nsoc_handler.h`
- Modify: `ngx_nsoc_handler.c`

**Step 1: 增加首包协商状态字段**

- 记录首包协商头是否已发送。
- 记录首包协商头是否已接收。

**Step 2: 移除按 `msg_num` 推动的三次握手流程**

- 改为只看 `noise_handshakestate_get_action()`。
- 首包 negotiation data 为 6 字节，非首包为 0。

**Step 3: 保留错误协商响应路径**

- 继续支持 3 字节错误响应。
- 继续拒绝 fallback。

**Step 4: 清理旧的 `XX` 专用判断**

- 删除或收敛 `NGX_NSOC_1MSG/2MSG/3MSG` 相关依赖。

### Task 3: 改造 server/proxy 配置校验

**Files:**
- Modify: `ngx_nsoc_noiseserver_module.c`
- Modify: `ngx_nsoc_proxy_module.c`

**Step 1: responder 按模式校验密钥依赖**

- 需要本端静态私钥时校验 `server_private_key_file`。
- 需要对端静态公钥时校验 `client_public_key_file`。

**Step 2: initiator 按模式校验密钥依赖**

- 需要本端静态私钥时校验 `client_private_key_file`。
- 需要对端静态公钥时校验 `server_public_key_file`。

**Step 3: 仅在需要时加载密钥**

- 不需要的密钥文件允许为空。
- 密钥长度仍按当前 DH 推导。

### Task 4: 改造 Go 示例客户端

**Files:**
- Modify: `example/noise_http_client/main.go`

**Step 1: 新增 `-server-public-key` 参数**

- 仅在模式要求 initiator 预置 responder 静态公钥时强制。

**Step 2: 改造握手配置校验**

- 按模式判断是否需要 `-key`。
- 按模式判断是否需要 `-server-public-key`。

**Step 3: 改造通用握手循环**

- 取消固定三帧。
- 首包附带协商头。
- 后续帧 negotiation data 长度为 0。

### Task 5: 更新文档

**Files:**
- Modify: `README.md`

**Step 1: 更新支持范围描述**

- 改为“支持所有基础握手模式”。

**Step 2: 更新密钥要求说明**

- 改为“是否必填由模式决定”。

**Step 3: 更新示例客户端说明**

- 补充 `-server-public-key`。

### Task 6: 验证

**Files:**
- No file changes expected

**Step 1: 格式化**

Run: `gofmt -w example/noise_http_client/main.go`

**Step 2: 运行 Go 测试**

Run: `go test ./...`

**Step 3: 运行 diff 检查**

Run: `git diff --check`

**Step 4: 汇总未覆盖项**

- 说明是否缺少完整 Nginx + Noise-C 联调验证。
