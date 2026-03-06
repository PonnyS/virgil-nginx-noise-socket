# Noise Configurable Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 Nginx noise 模块与示例客户端从固定 `Noise_XX_25519_AESGCM_BLAKE2b` 和固定 `NoiseSocketInit1` 改为可配置，并让服务端按配置强校验握手参数。

**Architecture:** C 侧新增 suite/prologue 配置结构、解析逻辑与动态 prologue 构造逻辑，替换当前固定结构和共享 `prologue` 写法。Go 示例客户端复用同样的配置语义，将命令行参数映射到 Noise 协商头和 `flynn/noise` 的握手配置。

**Tech Stack:** Nginx module C, Noise-C, Go, github.com/flynn/noise

---

### Task 1: 落地 C 侧配置模型

**Files:**
- Modify: `ngx_noise_protocol.h`
- Modify: `ngx_noise_protocol.c`
- Modify: `ngx_nsoc_handler.h`

**Step 1: 定义 suite 配置结构**

- 增加可表达 `version_id/dh_id/cipher_id/hash_id/pattern_id` 的结构体。
- 增加动态 prologue 缓冲区字段，替代固定 `noise_prologue_data_t` 直接挂载的用法。

**Step 2: 增加 suite 解析与校验函数**

- 从完整字符串解析 `Noise_XX_25519_AESGCM_BLAKE2b`。
- 输出 C 侧内部字段和值。
- 对不支持的 pattern/dh/cipher/hash 返回错误。

**Step 3: 增加 DH 到密钥长度的映射函数**

- `25519 -> 32`
- `448 -> 56`

**Step 4: 增加动态 prologue 构造函数**

- 输入 `prologue_text` 与 suite 配置。
- 输出连续字节串和长度。

**Step 5: 调整握手初始化接口**

- 让 `ngx_noise_protocol_init_handshake` 接收动态 prologue 数据与长度，而不是固定结构。

### Task 2: 改造连接对象与服务端握手

**Files:**
- Modify: `ngx_nsoc_handler.h`
- Modify: `ngx_nsoc_handler.c`

**Step 1: 为连接对象增加私有 prologue 缓冲区字段**

- 保存当前连接构造出的 prologue bytes。
- 保存长度，纳入连接池生命周期管理。

**Step 2: 删除连接直接引用共享 `noise->prologue` 的逻辑**

- 创建连接时改为复制配置基线，而不是引用共享地址。

**Step 3: 服务端握手前读取并校验首包协商头**

- 校验 `version/dh/cipher/hash/pattern` 是否与配置一致。
- 不一致直接失败。

**Step 4: 服务端按当前连接配置生成 prologue**

- 调用动态构造函数生成当前连接私有 prologue。
- 用该快照初始化握手状态。

**Step 5: 清理旧的共享状态写回逻辑**

- 删除把客户端首包写回共享 `noise->prologue` 的代码。

### Task 3: 改造 noiseserver 配置入口

**Files:**
- Modify: `ngx_nsoc_noiseserver_module.h`
- Modify: `ngx_nsoc_noiseserver_module.c`

**Step 1: 增加配置字段**

- `noise_protocol`
- `noise_prologue`

**Step 2: 增加 nginx directive**

- 定义 `noise_protocol`
- 定义 `noise_prologue`

**Step 3: 在 create/merge 阶段设置默认值**

- suite 默认 `Noise_XX_25519_AESGCM_BLAKE2b`
- prologue 默认 `NoiseSocketInit1`

**Step 4: merge 阶段完成解析和预校验**

- 解析 suite
- 校验 `prologue`
- 将结果写入内部配置基线

**Step 5: 加载密钥时按 DH 长度读取**

- 服务端私钥
- 可选客户端公钥

### Task 4: 改造 proxy 配置入口

**Files:**
- Modify: `ngx_nsoc_proxy_module.c`

**Step 1: 增加配置字段**

- `proxy_noise_protocol`
- `proxy_noise_prologue`

**Step 2: 增加 nginx directive**

- 定义 `proxy_noise_protocol`
- 定义 `proxy_noise_prologue`

**Step 3: 设置默认值并做解析**

- merge 阶段完成 suite/prologue 默认值填充和合法性校验。

**Step 4: 改造 `ngx_nsoc_proxy_set_noiselink`**

- 不再写死 `NoiseSocketInit1`
- 不再写死 `XX/25519/AESGCM/BLAKE2b`
- 按配置加载密钥长度和生成连接基线

### Task 5: 改造 Go 示例客户端

**Files:**
- Modify: `example/noise_http_client/main.go`

**Step 1: 增加配置结构**

- 表达协议头字段
- 表达 prologue 文本
- 表达 `flynn/noise` 所需对象

**Step 2: 增加命令行参数**

- `-noise-protocol`
- `-noise-prologue`

**Step 3: 增加 suite 解析逻辑**

- 从完整字符串映射到 `DH/Cipher/Hash/Pattern`
- 当前不支持的组合直接报错

**Step 4: 将握手构造改为读取配置**

- `buildNoisePrologue`
- `buildFirstNegotiationData`
- `noise.NewHandshakeState`

**Step 5: 按 DH 长度加载和校验私钥**

- 当前至少支持 `25519`
- 对暂不支持的 DH 明确报错

### Task 6: 更新文档与示例配置

**Files:**
- Modify: `README.md`
- Modify: `example/nginx.conf`
- Modify: `example/nginx.noise.4430.conf`
- Modify: `ci/nginx_configs/nginx-noise-backend-int.conf`
- Modify: `ci/nginx_configs/nginx-noise-lb-int.conf`

**Step 1: 更新功能说明**

- 删除“只支持固定 suite”的描述。

**Step 2: 更新指令文档**

- 补充 `noise_protocol`
- 补充 `noise_prologue`
- 补充 `proxy_noise_protocol`
- 补充 `proxy_noise_prologue`

**Step 3: 更新示例配置**

- 显式展示服务端与代理端配置方式。

**Step 4: 更新示例客户端使用说明**

- 展示新参数和默认行为。

### Task 7: 验证

**Files:**
- No file changes expected

**Step 1: 代码格式化**

Run: `gofmt -w example/noise_http_client/main.go`

**Step 2: 编译或最小化验证 Go 示例客户端**

Run: `go test ./example/noise_http_client/...`

**Step 3: 验证仓库可编译性或至少验证关键命令**

- 根据仓库现状运行可用的构建/检查命令。
- 若缺少可直接运行的自动化验证，明确记录原因。

**Step 4: 人工核对配置示例与 README**

- 检查新增 directive 名称与默认值一致。

### Task 8: 收尾

**Files:**
- No file changes expected

**Step 1: 汇总改动与验证结果**

- 说明哪些路径完成了 suite/prologue 配置化。

**Step 2: 询问是否继续补充单测**

- 按仓库约定在编码完成后再询问。
