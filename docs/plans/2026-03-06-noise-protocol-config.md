# Noise 多模式协议支持实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标：** 为 nginx noise 模块增加 12 个交互模式的协议串配置与按模式 key 校验，并同步更新 Go 示例客户端与文档。

**架构：** 在协议层引入模式元数据表统一描述 pattern id 和双端 key 需求；代理端和服务端只按 `spec` 做校验与加载；Go 示例客户端改成模式驱动并支持 2 消息、3 消息握手。

**技术栈：** C / nginx module API / noise-c / Go / flynn-noise

---

### Task 1：补红 Go 单测并锁定模式矩阵

**Files:**
- Modify: `example/noise_http_client/main_test.go`
- Modify: `example/noise_http_client/main.go`

**Step 1: 写失败用例**

覆盖：

- 12 个交互模式协议串解析
- 拒绝 `N/K/X`
- 不同模式对 initiator static / responder static 的 key 需求
- `XX` 三消息握手可以走通

**Step 2: 跑红**

Run: `go test ./... -run 'Test(ParseNoiseProtocol|BuildInitiatorHandshakeConfig|PerformNoiseHandshakeSupportsThreeMessagePatterns)'`

Expected: FAIL，暴露当前仅支持 `NK` 和固定 2 消息握手的问题。

**Step 3: 最小实现**

在 Go 示例中增加：

- 模式表
- initiator 本地 static 私钥构造
- responder 远端 static 公钥按需加载
- 通用 initiator 握手循环

**Step 4: 跑绿**

Run: `go test ./... -run 'Test(ParseNoiseProtocol|BuildInitiatorHandshakeConfig|PerformNoiseHandshakeSupportsThreeMessagePatterns)'`

Expected: PASS

### Task 2：扩展 C 侧协议规格

**Files:**
- Modify: `ngx_noise_protocol.h`
- Modify: `ngx_noise_protocol.c`

**Step 1: 修改协议规格结构**

在 `ngx_noise_protocol_spec_t` 中补：

- client 是否需要 local private
- client 是否需要 remote public
- server 是否需要 local private
- server 是否需要 remote public

**Step 2: 改协议解析**

把 `ngx_noise_protocol_parse_name()` 从只识别 `NK` 改成按模式表识别：

- `NN/KN/NK/KK/NX/KX/XN/IN/XK/IK/XX/IX`
- 拒绝 `N/K/X`

**Step 3: 改需求判断**

让 `ngx_noise_protocol_needs_local_private_key()` / `ngx_noise_protocol_needs_remote_public_key()` 直接读取 `spec`，不再写死 `NK`。

**Step 4: 最小校验**

Run: `clang -fsyntax-only ...` 或环境允许范围内的等价语法检查。

Expected: 无新增语法错误；若环境缺 nginx 头文件，记录真实失败原因。

### Task 3：让 nginx 配置层按模式加载 key

**Files:**
- Modify: `ngx_nsoc_proxy_module.c`
- Modify: `ngx_nsoc_noiseserver_module.c`

**Step 1: 修改代理端**

在 `ngx_nsoc_proxy_set_noiselink()` 中：

- initiator 需要 remote static 时要求 `server_public_key_file`
- initiator 需要 local static 时要求 `client_private_key_file`
- 多余 key 指令直接报错

**Step 2: 修改服务端**

在 `ngx_nsoc_noiseserver_handler()` 中：

- responder 需要 local static 时要求 `server_private_key_file`
- responder 需要 remote static 时要求 `client_public_key_file`
- 多余 key 指令直接报错

**Step 3: 保持握手循环不扩分支**

继续复用现有 action 驱动握手循环，不新增每模式专用分支。

**Step 4: 人工核对**

检查 `NN`、`NK`、`XX`、`KX` 四类代表性模式的 key 规则是否与设计矩阵一致。

### Task 4：同步文档与示例

**Files:**
- Modify: `README.md`
- Modify: `docs/plans/2026-03-06-noise-protocol-config-design.md`
- Modify: `docs/plans/2026-03-06-noise-protocol-config.md`
- Modify: `example/noise_http_client/main.go`

**Step 1: 更新 README**

明确：

- 支持的 12 个交互模式
- 不支持 `N/K/X`
- `client-priv` / `server-pub` 的模式依赖关系

**Step 2: 更新设计文档**

把原来“只支持 `NK`”的描述替换为多模式版本。

**Step 3: 更新实施计划**

保证计划和代码现状一致。

**Step 4: 最终验证**

Run:

- `go test ./...`
- `git diff --check`
- `git diff --stat`

Expected:

- Go 单测通过
- diff 无空白错误
- 变更集中在协议多模式支持相关文件
