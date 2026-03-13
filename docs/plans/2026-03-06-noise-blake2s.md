# Noise BLAKE2s Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在现有可配置 Noise 实现上新增 `BLAKE2s` hash 支持。

**Architecture:** 仅扩展 C 侧与 Go 示例客户端的 hash 白名单和映射关系，不改握手流程、配置指令或默认值。同步更新文档中的支持范围，确保实现与说明一致。

**Tech Stack:** Nginx module C, Noise-C, Go, github.com/flynn/noise

---

### Task 1: 扩展 C 侧 hash 白名单

**Files:**
- Modify: `ngx_noise_protocol.c`

**Step 1: 扩展 hash 解析白名单**

- 在 `ngx_noise_protocol_parse()` 中接受 `NOISE_HASH_BLAKE2s`。

**Step 2: 保持其他行为不变**

- 不改默认协议名。
- 不改握手状态机。

### Task 2: 扩展 Go demo hash 映射

**Files:**
- Modify: `example/noise_http_client/main.go`

**Step 1: 扩展 `parseNoiseHash()`**

- 增加 `BLAKE2s -> noise.HashBLAKE2s`。
- 使用与 Noise-C 一致的协商头 hash id。

### Task 3: 更新文档

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-03-06-noise-configurable-design.md`

**Step 1: 更新支持范围说明**

- 将支持的 hash 集合补为 `BLAKE2s / BLAKE2b / SHA256 / SHA512`。

### Task 4: 最小验证

**Files:**
- No file changes expected

**Step 1: 格式化 Go 文件**

Run: `gofmt -w example/noise_http_client/main.go`

**Step 2: 运行 Go 最小检查**

Run: `go test ./...`

Expected: `noise_http_client` 包通过，无测试文件也应成功退出。
