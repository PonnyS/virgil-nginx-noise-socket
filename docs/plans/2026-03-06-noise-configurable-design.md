# Noise 协议与 Prologue 可配置设计

## 背景

当前仓库只实现了固定的 `Noise_XX_25519_AESGCM_BLAKE2b`，并且 `prologue` 也被硬编码为 `NoiseSocketInit1`。

现状存在几个问题：

- 服务端和代理端在配置阶段直接写死 suite 与 prologue。
- 示例客户端在握手配置和协议头构造时也写死 suite 与 prologue。
- 服务端握手时会把客户端首包里的协商头写回共享的 `noise->prologue`，存在连接间共享状态被覆盖的问题。
- C 侧 `prologue` 数据结构将前缀文本固定为 16 字节，不支持可变长度。

本次改造不考虑兼容旧实现，目标是直接将 suite 与 prologue 改为显式配置项。

## 目标

- 支持在服务端配置 responder 使用的 Noise suite 与 prologue。
- 支持在代理端配置 initiator 使用的 Noise suite 与 prologue。
- 支持示例客户端通过参数配置 Noise suite 与 prologue。
- 服务端严格校验客户端首包协商头，配置不一致直接握手失败。
- prologue 支持任意长度，不再限制为 16 字节。

## 非目标

- 不支持服务端配置多套候选 suite。
- 不保留旧的固定 16 字节 prologue 结构兼容层。
- 本轮不优先补齐完整单测体系，编码完成后再询问是否继续补充。

## 配置设计

### 服务端

在 `noise_socket server` 上新增：

- `noise_protocol Noise_XX_25519_AESGCM_BLAKE2b;`
- `noise_prologue arbitrary bytes text;`

语义：

- `noise_protocol` 指定 responder 允许使用的唯一 suite。
- `noise_prologue` 指定握手 `prologue` 文本。
- 未配置时仍沿用当前默认值：
  - `Noise_XX_25519_AESGCM_BLAKE2b`
  - `NoiseSocketInit1`

### 代理端

在 `noise_socket server` 的 proxy 配置上新增：

- `proxy_noise_protocol Noise_XX_25519_AESGCM_BLAKE2b;`
- `proxy_noise_prologue arbitrary bytes text;`

语义：

- `proxy_noise_protocol` 指定 initiator 连接上游时使用的 suite。
- `proxy_noise_prologue` 指定 initiator 连接上游时使用的 prologue。

保留现有：

- `proxy_noise`
- `client_private_key_file`
- `server_public_key_file`

### 示例客户端

新增命令行参数：

- `-noise-protocol`
- `-noise-prologue`

默认值与 Nginx 端默认值保持一致。

## 协议与内存模型设计

### Suite 表示

内部引入一个统一的配置结构，表达 suite 的 5 个维度：

- `version_id`
- `dh_id`
- `cipher_id`
- `hash_id`
- `pattern_id`

并补充以下能力：

- 从完整字符串解析出上述字段
- 基于字段回写首包协商头
- 基于字段推导密钥长度
- 在 Go 客户端中映射到 `flynn/noise` 的 `CipherSuite` 与 `HandshakePattern`

第一阶段仅承诺支持当前实际可用组合：

- `XX`
- `25519`
- `AESGCM` / `ChaChaPoly`
- `BLAKE2s` / `BLAKE2b` / `SHA256` / `SHA512`

如果配置了当前实现不支持的组合，直接在加载/启动时返回明确错误。

### Prologue 表示

放弃当前定长结构：

- 不再依赖 `strPrologue[16]`
- 不再依赖 `sizeof(noise_prologue_data_t)` 作为 prologue 长度

改为运行时动态拼装：

`prologue_bytes = prologue_text + uint16(header_len) + first_header`

其中：

- `prologue_text` 为可变长度字节串
- `header_len` 仍表示首个协商头长度，当前固定为 6
- `first_header` 仍为 `version/dh/cipher/hash/pattern`

`NoisePrologue` 与 `NoisePrologueLen` 直接引用这块动态内存。

### 每连接快照

连接建立时不再把 `nc->prologue` 指向共享的 `noise->prologue`。

改为：

- 配置对象持有“基线配置”
- 每个连接初始化时基于基线配置生成自己的 `prologue` 字节快照
- 握手流程只读取当前连接快照，不改共享配置

这样可以避免不同连接之间互相覆盖协商字段。

## 握手流程设计

### 服务端

服务端握手流程调整为：

1. 读取客户端首包协商头。
2. 校验 `version_id` 与服务端配置是否一致。
3. 校验 `dh/cipher/hash/pattern` 与服务端配置是否一致。
4. 不一致则返回握手失败。
5. 一致则使用当前连接的配置快照生成 `NoisePrologue`，初始化握手状态。

服务端不再接受“客户端随意指定 suite，服务端被动跟随”的行为。

### 代理端

代理端不读取远端协商头来决定本地配置，而是：

1. 直接根据 `proxy_noise_protocol` 和 `proxy_noise_prologue` 生成首包。
2. 使用该配置初始化 initiator 握手状态。
3. 若上游 responder 配置不一致，由握手失败暴露。

### 示例客户端

示例客户端流程与代理端保持一致：

1. 解析 `-noise-protocol`。
2. 解析 `-noise-prologue`。
3. 构造首包协商头。
4. 基于配置创建 `noise.Config`。

## 密钥长度设计

当前 C 侧和 Go 侧都默认使用 25519 的 32 字节私钥。

为支持 suite 可配置，需要将密钥长度改为由 `dh` 推导：

- `25519` -> 32
- `448` -> 56

如果示例客户端配置了暂不支持的 DH，直接在启动时报错。
如果 Nginx 侧配置的 DH 与密钥文件长度不匹配，在加载密钥时返回错误。

## 代码改动范围

### C 侧

主要涉及：

- `ngx_noise_protocol.h`
- `ngx_noise_protocol.c`
- `ngx_nsoc_handler.h`
- `ngx_nsoc_handler.c`
- `ngx_nsoc_noiseserver_module.h`
- `ngx_nsoc_noiseserver_module.c`
- `ngx_nsoc_proxy_module.c`

重点改动：

- 定义 Noise suite 配置结构与解析函数。
- 定义动态 prologue 构造函数。
- 将连接对象改为持有私有 prologue 缓冲区和长度。
- 服务端握手增加 suite 强校验。
- 代理端使用显式配置而不是写死常量。

### Go 侧

主要涉及：

- `example/noise_http_client/main.go`

重点改动：

- 增加 suite/prologue 参数解析。
- 将固定常量改为基于配置生成。
- 将 DH、Cipher、Hash、Pattern 映射到 `flynn/noise` 对象。

### 文档与示例

主要涉及：

- `README.md`
- `example/nginx.conf`
- `example/nginx.noise.4430.conf`
- 可能涉及 `ci/nginx_configs/*.conf`

重点改动：

- 更新功能说明，不再声明只支持固定 suite。
- 为示例配置补充 `noise_protocol` / `noise_prologue` / `proxy_noise_protocol` / `proxy_noise_prologue`。
- 更新示例客户端用法说明。

## 错误处理

新增或强化以下错误：

- Noise suite 字符串格式非法
- 配置了当前未支持的 pattern/dh/cipher/hash
- 密钥文件长度与 DH 不匹配
- 服务端收到的首包协商头与配置不一致
- prologue 为空或包含 Nginx 配置解析后不可接受的值时返回明确错误

错误应尽量在配置加载阶段暴露，避免拖到运行时握手阶段。

## 验证方案

至少验证：

1. 默认配置下原有示例链路仍可工作。
2. 服务端与客户端显式配置相同 suite/prologue 时握手成功。
3. suite 不一致时握手失败。
4. prologue 不一致时握手失败。
5. 代理端到上游的 Noise 握手使用显式配置生效。

## 风险

- 现有 C 侧固定结构较深，改为动态 prologue 后需要谨慎处理内存生命周期。
- suite 解析表需要保证 C 侧和 Go 侧映射一致。
- 如果后续要支持更多 DH，示例客户端的密钥构造逻辑还需要继续扩展。

## 实施建议

先完成 Nginx 模块和示例客户端的配置化，再更新示例与文档。编码完成后再确认是否继续补充单测。
