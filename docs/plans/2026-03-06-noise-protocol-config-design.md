# Noise 协议配置化设计

## 背景

当前模块在代理端和服务端都将 Noise 协议写死为 `Noise_XX_25519_AESGCM_BLAKE2b`，同时将 `prologue` 固定为 `NoiseSocketInit1`。握手状态机虽然会在服务端读取首包 negotiation header，但配置层没有任何协议约束，且服务端会直接修改共享的 `prologue` 配置对象。

本次目标是在不考虑兼容性的前提下，把协议和 `prologue` 改成显式配置，并将正式支持范围收敛到 `Noise_NK_25519_{AESGCM|ChaChaPoly}_{SHA256|SHA512|BLAKE2b|BLAKE2s}`。

## 目标

- 支持通过 nginx 指令配置 Noise 协议串。
- 支持通过 nginx 指令配置 `prologue` 文本。
- 正式支持 `NK` 握手模式。
- 支持如下算法组合：
  - DH：`25519`
  - Cipher：`AESGCM`、`ChaChaPoly`
  - Hash：`SHA256`、`SHA512`、`BLAKE2b`、`BLAKE2s`
- 服务端对首包 negotiation 做严格校验，不再接受与配置不一致的协议。
- 同步更新示例客户端和 README。

## 非目标

- 本次不开放 `XX`、`IK` 等其他握手模式给配置层。
- 本次不做协议自动降级、fallback、兼容迁移。
- 本次不引入完整的 nginx 模块集成测试框架。

## 现状问题

### 1. 协议和 prologue 写死

- 代理端在 `ngx_nsoc_proxy_module.c` 中固定写入 `NoiseSocketInit1`、`AESGCM`、`25519`、`BLAKE2b`、`XX`。
- 服务端在 `ngx_nsoc_noiseserver_module.c` 中固定写入 `NoiseSocketInit1`，其余字段在握手时由客户端首包覆盖。

### 2. 服务端存在共享可变状态

服务端在握手开始阶段会将首包协商头覆盖到 `nc->prologue->header`。`nc->prologue` 实际指向的是配置级 `noise->prologue`，这意味着不同连接会修改共享对象，存在竞态和串扰风险。

### 3. 密钥必填规则与握手模式耦合错误

当前代理侧强制要求 `client_private_key_file`。这与 `NK` 的真实语义不一致：`NK` 发起方只需要对端静态公钥，不需要本地静态私钥。

## 决策

### 配置接口

代理侧新增：

```nginx
proxy_noise_protocol Noise_NK_25519_AESGCM_SHA256;
proxy_noise_prologue "NoiseSocketInit1";
```

服务端新增：

```nginx
noise_protocol Noise_NK_25519_AESGCM_SHA256;
noise_prologue "NoiseSocketInit1";
```

约束如下：

- `noise_protocol` / `proxy_noise_protocol` 为启用 Noise 时的必填项。
- `noise_prologue` / `proxy_noise_prologue` 为可选项，默认值为 `NoiseSocketInit1`。
- 协议串语法固定为 `Noise_<PATTERN>_25519_<CIPHER>_<HASH>`。
- 当前仅接受 `PATTERN=NK`。

### 协议支持范围

允许的协议集合为：

- `Noise_NK_25519_AESGCM_SHA256`
- `Noise_NK_25519_AESGCM_SHA512`
- `Noise_NK_25519_AESGCM_BLAKE2b`
- `Noise_NK_25519_AESGCM_BLAKE2s`
- `Noise_NK_25519_ChaChaPoly_SHA256`
- `Noise_NK_25519_ChaChaPoly_SHA512`
- `Noise_NK_25519_ChaChaPoly_BLAKE2b`
- `Noise_NK_25519_ChaChaPoly_BLAKE2s`

### 密钥规则

基于 `NK` 的角色语义，密钥要求调整为：

- 代理侧（initiator）：
  - 必填：`server_public_key_file`
  - 非必填：`client_private_key_file`
  - 若仍配置 `client_private_key_file`，可保留读取逻辑但不作为 `NK` 必需项
- 服务端（responder）：
  - 必填：`server_private_key_file`
  - 非法：`client_public_key_file`

这样做的原因是避免对外暴露“看似支持 NK，实则仍按 XX/IK 规则要求密钥”的伪配置能力。

## 实现方案

### 1. 新增协议规格对象

在 Noise 协议层新增“协议规格”抽象，负责保存：

- `pattern_id`
- `dh_id`
- `cipher_id`
- `hash_id`
- `protocol_name`

并提供以下能力：

- 解析 `Noise_NK_25519_AESGCM_SHA256` 这类协议串
- 校验协议是否在允许集合内
- 根据规格构造 negotiation header
- 根据 `prologue` 文本和 negotiation header 生成握手所需的完整 prologue 字节序列

这层逻辑尽量不依赖 nginx 运行态和 libnoise 对象，便于最小化测试。

### 2. 连接级握手数据快照

`ngx_noise_t` 保留配置级协议规格和 `prologue` 文本，但不再存放可被连接修改的握手头。

`ngx_noise_connection_t` 在连接初始化时生成自己的握手快照，包含：

- 当前连接使用的 negotiation header
- 当前连接的完整 prologue buffer

服务端读取首包后，对照配置做严格比对：

- 一致：继续握手
- 不一致：返回现有错误状态 `0xFF`

不再将首包内容回写到配置级对象。

### 3. 写首包时显式序列化

当前 `NGX_NSOC_1MSG` 发送路径依赖固定结构体布局和 `memcpy`。改造后首包 negotiation data 由显式序列化函数构造，避免对固定长度 `noise_prologue_data_t` 的内存布局耦合。

### 4. libnoise 初始化

`ngx_noise_protocol_init_handshake()` 改为接收连接级协议规格和动态 prologue buffer，而不是依赖固定结构体：

- 使用规格中的 `pattern_id` / `dh_id` / `cipher_id` / `hash_id` 组装 `NoiseProtocolId`
- 使用动态 prologue buffer 调用 `noise_handshakestate_set_prologue()`

### 5. 示例客户端同步

Go 示例客户端改成支持：

- 通过参数或常量选择协议串
- 通过参数或常量选择 `prologue`
- 使用 `HandshakeNK`
- 在 `NK` 下要求服务端公钥，移除对客户端静态私钥的强依赖

## 测试策略

仓库当前没有现成测试框架，且本地环境不保证存在 nginx 与 noise-c 的完整构建依赖。本次先采用“两层验证”：

1. 为协议串解析 / negotiation header 构造 / prologue 构造新增最小可执行测试，确保配置协议层规则可回归。
2. 对示例客户端执行编译级或单测级验证，确认 `NK` 配置路径正确。

对 nginx C 侧的完整握手集成测试，本次作为残留风险记录，不在本次范围内补齐框架。

## 其他握手模式评估

### XX

消息循环层面兼容，但会重新引入发起方静态私钥、服务端对远端静态公钥是否必需等差异化规则。改动量中等，测试面明显扩大。

### IK

也可复用现有握手状态机，但需要额外处理 initiator 本地静态私钥与 responder 静态公钥的联合校验，配置规则会进一步复杂化。改动量中等偏上。

### 结论

本次只正式开放 `NK`。内部设计会尽量保留未来扩 `XX/IK` 的空间，但不在配置层对外宣称支持，避免引出额外 bug 面。

## 风险与缓解

- 风险：当前握手消息编号逻辑与 `XX` 的三次消息强绑定。
  - 缓解：在 `NK` 路径上重新核对 `msg_num` 的推进与 `NOISE_ACTION_SPLIT` 行为，必要时按 action 驱动而不是按旧编号假设。
- 风险：代理和服务端配置不一致时，现网表现可能变成握手直接失败。
  - 缓解：这是本次明确选择，不考虑兼容。
- 风险：缺少完整集成测试。
  - 缓解：先为协议配置层补最小测试，并在最终验证阶段执行编译/静态检查类命令。
