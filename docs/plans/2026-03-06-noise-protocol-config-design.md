# Noise 多模式协议配置化设计

## 背景

当前模块已经从写死 `Noise_XX_25519_AESGCM_BLAKE2b` 演进到“协议串 + prologue 可配置”，但设计文档仍停留在“只开放 `NK`”的假设上。

本次需求进一步明确为：

- `prologue` 继续支持配置
- DH 仅支持 `25519`
- Cipher 支持 `AESGCM`、`ChaChaPoly`
- Hash 支持 `SHA256`、`SHA512`、`BLAKE2b`、`BLAKE2s`
- 交互模式支持：
  - `NN`、`KN`、`NK`、`KK`
  - `NX`、`KX`
  - `XN`、`IN`
  - `XK`、`IK`
  - `XX`、`IX`
- one-way 模式 `N`、`K`、`X` 不支持

不考虑兼容性，可以直接以新配置语义收敛实现。

## 目标

- 通过 nginx 指令显式配置 Noise 协议串和 `prologue`
- 服务端对首包 negotiation 做严格匹配，不接受与配置不一致的协议
- 代理端和服务端按握手模式校验 key 文件
- Go 示例客户端按模式驱动握手，而不是继续把所有协议都当成 `NK`

## 非目标

- 不支持 one-way 模式 `N`、`K`、`X`
- 不支持 fallback、deferred、psk 变体
- 不做协议自动降级或多协议端口自动协商
- 不引入新的 C 侧完整集成测试框架

## 关键结论

### 1. 保持单端点单协议

每个 `server` / `proxy` 仍然只配置一个明确协议，例如：

```nginx
noise_protocol Noise_XX_25519_AESGCM_SHA256;
noise_prologue NoiseSocketInit1;
```

不做一个端口同时接受多协议。这样可以把变更收敛在协议解析、key 规则和示例客户端，不把错误处理和配置语义扩散到握手阶段。

### 2. 只开放交互模式

`NN/KN/NK/KK/NX/KX/XN/IN/XK/IK/XX/IX` 都属于交互模式，握手后可以继续进入双向 transport。

`N/K/X` 属于 one-way pattern，不适用于当前请求/响应的双向 noise socket，因此本次明确拒绝。

### 3. 用模式元数据表驱动 key 规则

当前握手循环已经主要按 libnoise action 驱动，2 消息和 3 消息模式都可以复用。真正需要模式化的是：

- 协议串解析
- initiator / responder 的 key 必填规则
- Go 示例客户端如何构造 `flynn/noise` 握手配置

因此引入一张模式元数据表，比到处写 `switch` 更稳。

## 配置接口

服务端：

```nginx
noise_protocol Noise_XX_25519_AESGCM_SHA256;
noise_prologue NoiseSocketInit1;
server_private_key_file /etc/noise/server_key_25519;
client_public_key_file /etc/noise/client_pub_25519;
```

代理端：

```nginx
proxy_noise_protocol Noise_XX_25519_AESGCM_SHA256;
proxy_noise_prologue NoiseSocketInit1;
client_private_key_file /etc/noise/client_key_25519;
server_public_key_file /etc/noise/server_pub_25519;
```

约束：

- `noise_protocol` / `proxy_noise_protocol` 为必填
- `noise_prologue` / `proxy_noise_prologue` 默认 `NoiseSocketInit1`
- 协议串语法固定为 `Noise_<PATTERN>_25519_<CIPHER>_<HASH>`
- `PATTERN` 仅允许上述 12 个交互模式

## 模式与 key 规则

按字段语义：

- 代理端
  - `client_private_key_file` = initiator 本地 static
  - `server_public_key_file` = responder 远端 static
- 服务端
  - `server_private_key_file` = responder 本地 static
  - `client_public_key_file` = initiator 远端 static

模式矩阵：

- `NN`：四个 key 都不需要
- `KN`：代理需要 `client_private_key_file`；服务端需要 `client_public_key_file`
- `NK`：代理需要 `server_public_key_file`；服务端需要 `server_private_key_file`
- `KK`：四个 key 都需要
- `NX`：服务端需要 `server_private_key_file`
- `KX`：代理需要 `client_private_key_file`；服务端需要 `server_private_key_file` 和 `client_public_key_file`
- `XN`、`IN`：代理需要 `client_private_key_file`
- `XK`、`IK`：代理需要 `client_private_key_file` 和 `server_public_key_file`；服务端需要 `server_private_key_file`
- `XX`、`IX`：代理需要 `client_private_key_file`；服务端需要 `server_private_key_file`

本次选择“仅校验必填 key，未使用的 key 配置直接忽略”，避免协议切换时因为历史配置残留导致握手前失败。

## 实现方案

### 1. 协议规格对象扩展

在 `ngx_noise_protocol_spec_t` 中补齐模式相关元数据：

- `pattern_id`
- client 是否需要 local private
- client 是否需要 remote public
- server 是否需要 local private
- server 是否需要 remote public

`ngx_noise_protocol_parse_name()` 改成从模式表查找，而不是只认 `NK`。

### 2. 连接级握手快照保持不变

本轮继续保留已经完成的连接级协议快照和动态 prologue 设计：

- 配置级对象保存协议和 `prologue` 文本
- 连接握手只读取，不回写共享状态
- 服务端继续严格比对首包 negotiation header

### 3. 代理端与服务端按模式加载 key

代理端 `merge_conf`：

- 解析协议
- 构造 prologue
- 按 initiator 规则加载 `client_private_key_file` / `server_public_key_file`
- 当前模式不需要的额外 key 配置直接忽略

服务端运行时初始化：

- 按 responder 规则加载 `server_private_key_file` / `client_public_key_file`
- 不需要 static 的模式不再强制读文件，多余 key 配置直接忽略

### 4. Go 示例客户端改成模式驱动

Go 客户端不再把所有协议都映射成 `HandshakeNK`。

需要补的能力：

- 12 个模式到 `flynn/noise` `HandshakePattern` 的映射
- initiator 本地 static 私钥按模式按需加载
- responder 远端 static 公钥按模式按需加载
- 握手收发循环支持 2 消息和 3 消息模式

## 测试策略

仓库缺少现成的 C 侧单测框架，因此本次继续采用“两层验证”：

1. Go 单测锁定模式矩阵
   - 协议串解析
   - initiator key 需求
   - 3 消息模式握手循环
2. 命令级验证
   - `go test ./...`
   - `git diff --check`
   - C 侧做语法级或环境允许范围内的编译校验

## 风险

- 风险：Go 示例客户端虽然支持更多模式，但 `server-pub` 仍只接受 32 字节原始二进制公钥
  - 缓解：文档明确说明；后续如有需要再补 noise-c 文本公钥解析
- 风险：C 侧没有完整握手回归测试
  - 缓解：把模式表和 key 规则尽量做成纯解析层，减少散落分支
- 风险：用户沿用旧的 `NK` 认知配置 `XX/IK` 等模式时容易漏 key
  - 缓解：未使用或缺失的 key 统一在配置期/初始化期报错
