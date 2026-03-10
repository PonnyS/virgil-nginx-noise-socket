# Noise 握手错误契约 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 noise C 模块和 Go 示例客户端建立稳定的握手错误契约，让客户端获得明确类别，服务端日志保留详细根因。

**Architecture:** 沿用现有第二条协商数据 3 字节格式，只重定义 `status` 语义，不修改握手帧结构。服务端将配置期问题前移到 `merge_conf`，运行时仅返回有限错误类别；代理端和 Go 客户端只消费通用错误码。

**Tech Stack:** C / nginx module API / noise-c / Go

---

### Task 1: 定义新的握手状态码

**Files:**
- Modify: `ngx_nsoc_handler.h`

**Step 1: 添加 on-wire 状态码常量**

补 `OK / VERSION_MISMATCH / NEGOTIATION_MISMATCH / MALFORMED_NEGOTIATION / MALFORMED_HANDSHAKE / PEER_VERIFICATION_FAILED / INTERNAL_ERROR`。

**Step 2: 为连接对象增加状态字段**

给 `ngx_noise_connection_t` 增加当前握手状态字段，供服务端发送拒绝帧和代理端记录上游状态使用。

### Task 2: 重构服务端握手拒绝路径

**Files:**
- Modify: `ngx_nsoc_handler.c`
- Modify: `ngx_noise_protocol.h`
- Modify: `ngx_noise_protocol.c`

**Step 1: 抽统一错误帧发送助手**

复用当前第二条协商错误帧写入逻辑，不再硬编码 `0xFF/0x01`。

**Step 2: 细分首包 negotiation 失败**

- version 不匹配返回 `VERSION_MISMATCH`
- 其余 header 字段不匹配返回 `NEGOTIATION_MISMATCH`
- negotiation 长度异常返回 `MALFORMED_NEGOTIATION`

**Step 3: 细分握手消息失败**

- 握手帧长度超过上限返回 `MALFORMED_HANDSHAKE`
- `noise_handshakestate_read_message()` 失败返回 `PEER_VERIFICATION_FAILED`
- 运行时无法归类的内部异常返回 `INTERNAL_ERROR`

### Task 3: 前移服务端配置校验

**Files:**
- Modify: `ngx_nsoc_noiseserver_module.c`

**Step 1: 在 merge_conf 完成协议和 key 校验**

把 `noise_protocol`、`server_private_key_file`、`client_public_key_file` 的必填与文件加载前移到 `merge_conf`。

**Step 2: 精简运行时 handler**

移除连接期的 key 加载逻辑，只保留握手入口。

### Task 4: 让代理端识别上游错误码

**Files:**
- Modify: `ngx_nsoc_handler.c`
- Modify: `ngx_nsoc_proxy_module.c`

**Step 1: 解析第二条协商错误码**

让 initiator 在读到上游状态帧时记录状态码，而不是只得到通用 `NGX_ERROR`。

**Step 2: 改善代理端日志**

在上游握手失败时输出稳定错误类别。

### Task 5: 同步 Go 示例客户端

**Files:**
- Modify: `example/noise_http_client/main.go`

**Step 1: 改造状态码解析**

把 `validateSecondNegotiationData()` 从旧的 `0x01/0xFF` 语义改成新的 6 类错误码。

**Step 2: 保留未知状态兜底**

未识别状态仍输出 `unexpected handshake status: 0x..`。

### Task 6: 文档与验证

**Files:**
- Create: `docs/plans/2026-03-10-noise-handshake-error-contract-design.md`
- Modify: `README.md`

**Step 1: 更新 README**

说明握手错误码只返回通用类别，不透出内部细节。

**Step 2: 运行验证**

Run: `git diff --check`
Expected: 无 patch 格式错误

Run: `go test ./...`
Expected: Go 示例客户端可完成编译验证

Run: `clang -fsyntax-only ...`
Expected: 若环境具备 nginx 头文件则通过；否则记录真实失败原因
