# Example Go Modules Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 `example/noise_http_client` 与 `example/noise_http_server` 补齐独立 `go.mod`，使两个示例可在各自目录单独执行 Go 命令。

**Architecture:** 保持仓库根目录继续作为非 Go 模块的 nginx/C 工程，只把两个 Go 示例目录声明为独立模块。每个模块只声明自身直接依赖，并通过 `go mod tidy` 生成或整理对应 `go.sum`。

**Tech Stack:** Go modules、`github.com/flynn/noise`、`github.com/gorilla/websocket`

---

### Task 1: 为客户端示例补齐模块声明

**Files:**
- Create: `example/noise_http_client/go.mod`
- Verify: `example/noise_http_client/go.sum`

**Step 1: 写入最小 go.mod**

```go
module github.com/VirgilSecurity/virgil-nginx-noise-socket/example/noise_http_client

go 1.20

require github.com/flynn/noise v1.1.0
```

**Step 2: 整理模块依赖**

Run: `go mod tidy`
Expected: 成功生成或更新 `go.sum`，不需要 `replace`、`exclude` 或本地模块依赖

**Step 3: 验证基础编译**

Run: `go test ./...`
Expected: 当前目录无测试也应能完成编译检查并返回 PASS

### Task 2: 为服务端示例补齐模块声明

**Files:**
- Create: `example/noise_http_server/go.mod`
- Verify: `example/noise_http_server/go.sum`

**Step 1: 写入最小 go.mod**

```go
module github.com/VirgilSecurity/virgil-nginx-noise-socket/example/noise_http_server

go 1.20

require github.com/gorilla/websocket v1.5.3
```

**Step 2: 整理模块依赖**

Run: `go mod tidy`
Expected: 成功生成或更新 `go.sum`

**Step 3: 验证基础编译**

Run: `go test ./...`
Expected: 当前目录无测试也应能完成编译检查并返回 PASS
