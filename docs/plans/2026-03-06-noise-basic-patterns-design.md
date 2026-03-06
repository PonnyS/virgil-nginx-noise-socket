# Noise 基础握手模式扩展设计

## 背景

当前仓库虽然已经支持 `noise_protocol` 与 `noise_prologue` 配置，但握手流程仍然按 `XX` 模式硬编码：

- C 侧依赖 `msg_num=1/2/3` 驱动三次握手。
- Go 示例客户端也固定发送三帧握手消息。
- `pattern` 解析仅接受 `XX`。
- server/proxy 两侧对静态密钥的要求没有按握手模式动态收敛。

这会导致除 `XX` 之外的基础握手模式即使能被配置解析，也无法正确执行。

## 目标

- 支持所有基础握手模式：
  - `N`
  - `K`
  - `X`
  - `NN`
  - `KN`
  - `NK`
  - `KK`
  - `NX`
  - `KX`
  - `XN`
  - `IN`
  - `XK`
  - `IK`
  - `XX`
  - `IX`
- 不支持 `fallback` 和 `psk` 变体。
- responder 与 initiator 都按当前配置的唯一 suite 执行握手，不做多套候选回退。
- 按握手模式动态校验本端静态私钥和对端静态公钥是否必需。

## 非目标

- 不支持 `fallback`。
- 不支持 `psk0/psk1/...` 等 PSK 扩展模式。
- 不新增额外 responder 示例程序。
- 本轮不承诺补齐 Nginx + Noise-C 端到端自动化联调。

## 设计原则

- 握手消息轮次不再由本项目手写推断，而是完全跟随 Noise 状态机 action 前进。
- 协商头只在首包出现一次，后续握手帧不再携带常规协商数据。
- 模式差异只体现在：
  - 首轮由谁发送。
  - 是否要求本端静态私钥。
  - 是否要求预置对端静态公钥。
- 配置校验尽量前置到加载阶段或握手初始化阶段，避免拖到中途才因缺钥失败。

## 协议设计

### 首包协商头

保持当前协议约定不变：

- 首个握手帧 negotiation data 长度固定为 6。
- 内容仍为 `version_id/dh_id/cipher_id/hash_id/pattern_id`。
- 首包由 initiator 发送。
- responder 在初始化握手前先读取并校验首包协商头。

后续规则：

- 非首包 negotiation data 长度固定为 0。
- 现有错误协商数据 3 字节返回格式继续保留。
- 收到 `fallback` 响应仍直接失败。

### Pattern 映射

内部将基础握手模式显式建表，表项至少包含：

- 模式名
- Noise-C `pattern_id`
- Go `flynn/noise` 的 `HandshakePattern`
- initiator 是否需要本端静态私钥
- responder 是否需要本端静态私钥
- initiator 是否需要对端静态公钥
- responder 是否需要对端静态公钥

不采用“允许任意 Noise-C 识别字符串”的策略，原因是：

- 需要明确排除 `fallback` 和 `psk`。
- 需要为 Go 示例客户端同步维护一套一致的依赖判断。
- 显式表驱动更适合做配置校验和错误信息。

## C 侧设计

### 通用握手驱动

`ngx_nsoc_handler.c` 中现有基于 `msg_num` 的流程改为通用驱动：

1. responder 首次进入握手时，先读取并校验首包协商头。
2. initiator 首次写握手消息时，在首包附带协商头。
3. 后续每轮只读取 `noise_handshakestate_get_action()`：
   - `NOISE_ACTION_WRITE_MESSAGE`：写握手帧
   - `NOISE_ACTION_READ_MESSAGE`：读握手帧
   - `NOISE_ACTION_SPLIT`：握手完成
4. 不再通过 `msg_num` 推断下一步该读还是写。

连接态新增最小状态：

- `first_negotiation_sent`
- `first_negotiation_received`

这两个标记只用于控制“首包带协商头，后续为 0”的约束。

### Pattern 校验与密钥依赖

`ngx_noise_protocol.c` 增加基础模式能力表，并提供：

- 判断协议名是否属于支持的基础模式。
- 查询指定模式在 initiator / responder 角色下：
  - 是否需要本端静态私钥
  - 是否需要对端静态公钥

server/proxy 配置加载时根据当前 `noise_protocol` 做校验：

- responder 需要本端静态私钥时，`server_private_key_file` 必填。
- responder 需要对端静态公钥时，`client_public_key_file` 必填。
- initiator 需要本端静态私钥时，`client_private_key_file` 必填。
- initiator 需要对端静态公钥时，`server_public_key_file` 必填。

如果当前模式不需要某类密钥，则对应配置可为空。

### 连接对象

现有 `msg_num` 字段不再承担握手流程控制职责。

优先方案：

- 删除所有依赖 `msg_num` 的决策逻辑。
- 若保留字段也仅用于调试日志，不参与状态推进。

## Go 示例客户端设计

### Pattern 解析

`parseNoisePattern()` 改为支持所有基础握手模式，并显式拒绝：

- `fallback`
- `psk` 变体

### 静态密钥依赖

客户端新增：

- `-server-public-key`

规则：

- 模式要求 initiator 预置 responder 静态公钥时，缺少 `-server-public-key` 直接启动报错。
- 模式要求 initiator 提供本端静态私钥时，缺少 `-key` 直接启动报错。
- 模式不需要时，对应参数可为空。

### 通用握手循环

示例客户端握手流程改为：

1. 构造协商头。
2. 用当前 pattern 初始化 `noise.HandshakeState`。
3. 在循环中根据当前回合是否为首包决定 negotiation data 是否为 6 字节。
4. 按实际发送和接收消息推进，直到拿到发送/接收 cipher state。

这里仍保留“initiator 先发”的协议假设，但不再写死只有 3 帧。

## 文档与示例

README 需要同步调整：

- 删除“当前只支持 `XX`”的描述。
- 说明当前支持“所有基础握手模式，不含 fallback/psk”。
- 说明静态密钥文件是否必填由握手模式决定。
- 示例客户端说明补充 `-server-public-key`。

## 验证策略

最小验证分三层：

1. Go 侧格式化与测试：
   - `gofmt -w example/noise_http_client/main.go`
   - `go test ./...`
2. 静态检查：
   - `git diff --check`
3. 人工核对关键模式：
   - `XX`
   - `N`
   - `IK` 或 `KK`

如果当前环境缺少完整 C 侧编译或联调条件，需要在结果中明确说明。
