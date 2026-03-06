# Noise Protocol Config Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 nginx noise 模块增加 `Noise_NK_25519_*_*` 协议串配置和可配置 `prologue`，并同步更新示例客户端与文档。

**Architecture:** 在 Noise 协议层增加协议规格解析与动态 prologue 构造；在连接层改为维护连接级握手快照，消除服务端共享可变 `prologue`；在代理端和服务端新增配置指令并按 `NK` 做密钥校验。

**Tech Stack:** C / nginx module API / noise-c / Go example client

---

### Task 1: 协议规格与最小测试

**Files:**
- Create: `docs/plans/2026-03-06-noise-protocol-config-design.md`
- Create: `example/noise_http_client/main_test.go`
- Modify: `example/noise_http_client/main.go`

**Step 1: Write the failing test**

为 Go 示例补最小单测，覆盖：
- 解析 `Noise_NK_25519_AESGCM_SHA256`
- 拒绝 `Noise_XX_25519_AESGCM_BLAKE2b`
- 使用配置化 `prologue` 构造握手前缀

**Step 2: Run test to verify it fails**

Run: `go test ./example/noise_http_client -run 'Test(ParseNoiseProtocol|BuildNoisePrologue)'`

Expected: FAIL，提示协议解析函数或配置化 `prologue` 能力不存在。

**Step 3: Write minimal implementation**

在 Go 示例中补：
- 协议串解析
- `NK` 协议到 `flynn/noise` 的映射
- 可配置 `prologue`

**Step 4: Run test to verify it passes**

Run: `go test ./example/noise_http_client -run 'Test(ParseNoiseProtocol|BuildNoisePrologue)'`

Expected: PASS

### Task 2: nginx 配置层

**Files:**
- Modify: `ngx_nsoc_proxy_module.c`
- Modify: `ngx_nsoc_noiseserver_module.c`
- Modify: `ngx_nsoc_noiseserver_module.h`
- Modify: `ngx_nsoc_handler.h`
- Modify: `ngx_noise_protocol.h`

**Step 1: Write the failing test**

补 Go 侧单测用例，约束 `NK` 的密钥要求：
- 代理端需要 `server_public_key_file`
- 服务端需要 `server_private_key_file`

**Step 2: Run test to verify it fails**

Run: `go test ./example/noise_http_client -run 'TestNoiseProtocolNKRequirements'`

Expected: FAIL，说明当前规则仍是旧的固定密钥模型。

**Step 3: Write minimal implementation**

在 nginx 配置层增加：
- `proxy_noise_protocol`
- `proxy_noise_prologue`
- `noise_protocol`
- `noise_prologue`

并把必填校验改成按 `NK` 规则执行。

**Step 4: Run test to verify it passes**

Run: `go test ./example/noise_http_client -run 'TestNoiseProtocolNKRequirements'`

Expected: PASS

### Task 3: 连接级握手快照与服务端严格校验

**Files:**
- Modify: `ngx_nsoc_handler.c`
- Modify: `ngx_nsoc_handler.h`
- Modify: `ngx_noise_protocol.c`
- Modify: `ngx_noise_protocol.h`

**Step 1: Write the failing test**

为 Go 示例补用例，验证：
- 首包 negotiation header 必须与配置协议一致
- `prologue` 由 `prologue text + header_len + header` 组成

**Step 2: Run test to verify it fails**

Run: `go test ./example/noise_http_client -run 'TestNegotiationHeaderMatchesConfiguredProtocol'`

Expected: FAIL，说明现有逻辑仍依赖硬编码或不做严格匹配。

**Step 3: Write minimal implementation**

在 C 侧实现：
- 连接级握手数据快照
- 首包协议严格校验
- 动态 prologue buffer 传递给 `noise_handshakestate_set_prologue()`

**Step 4: Run test to verify it passes**

Run: `go test ./example/noise_http_client -run 'TestNegotiationHeaderMatchesConfiguredProtocol'`

Expected: PASS

### Task 4: 文档、示例与最终验证

**Files:**
- Modify: `README.md`
- Modify: `ci/nginx_configs/nginx-noise-lb-int.conf`
- Modify: `ci/nginx_configs/nginx-noise-backend-int.conf`
- Modify: `example/noise_http_client/main.go`
- Test: `example/noise_http_client/main_test.go`

**Step 1: Run focused tests**

Run: `go test ./example/noise_http_client`

Expected: PASS

**Step 2: Run broader verification**

Run: `go test ./...`

Expected: 若仓库 Go 侧仅示例目录可测试，则至少示例目录通过；如 `./...` 不可运行，记录真实失败原因。

**Step 3: Update docs**

补 README 与 CI 配置示例，明确支持：
- `Noise_NK_25519_{AESGCM|ChaChaPoly}_{SHA256|SHA512|BLAKE2b|BLAKE2s}`
- `noise_prologue` / `proxy_noise_prologue`

**Step 4: Final verification**

Run: `git diff --stat`

Expected: 仅包含本次协议配置化相关变更。
