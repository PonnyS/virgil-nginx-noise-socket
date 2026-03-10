# Noise 握手错误契约设计

## 背景

当前 noise C 模块对客户端暴露的握手错误信息过于粗糙：

- 服务端 negotiation header 不匹配时，只会回一个通用 `0xFF`
- 其他大部分握手失败只写日志然后断开连接，客户端通常只能看到 `timeout`、`EOF` 或 `connection reset`
- 一些明显的服务端内部问题，例如 key 缺失或 key 文件打不开，还会拖到连接期才暴露

这不符合“客户端只拿到稳定、可行动的错误类别，服务端日志保留详细根因”的实践。

## 目标

- 为握手失败定义少量稳定的对外错误码
- 服务端仅向客户端返回通用可行动错误，不泄露内部配置和文件细节
- 详细根因只写服务端日志
- 将服务端可确定的配置问题前移到 `merge_conf`
- 同步修改 Go 示例客户端，对新错误码给出清晰报错

## 非目标

- 不修改握手帧结构，仍沿用第二条协商数据 3 字节格式
- 不兼容旧的 `0xFF/0x01` 语义
- 不引入新的 C 侧完整单测框架
- 不改变 transport 阶段的错误处理

## 对外错误契约

第二条协商数据的 `status` 字节定义为：

- `0x00` `OK`
- `0x01` `VERSION_MISMATCH`
- `0x02` `NEGOTIATION_MISMATCH`
- `0x03` `MALFORMED_NEGOTIATION`
- `0x04` `MALFORMED_HANDSHAKE`
- `0x05` `PEER_VERIFICATION_FAILED`
- `0x06` `INTERNAL_ERROR`

边界：

- `timeout`、`EOF`、`connection reset` 继续作为客户端本地 I/O 错误，不映射为服务端握手状态
- 客户端不直接看到 nginx 配置项、文件路径、权限错误、libnoise 内部文本
- 如果连接在服务端发出状态帧前就断开，客户端看到的仍然是本地 I/O 错误

## C 模块设计

### 1. 服务端配置错误前移

在 `ngx_nsoc_noiseserver_merge_conf()` 中完成：

- `noise_protocol` 必填校验
- 协议解析与 `prologue` 初始化
- 按模式加载 `server_private_key_file` / `client_public_key_file`
- key 缺失、文件打不开、内存分配失败直接让配置失败

这样这些内部问题不会再进入运行时握手路径，也不需要向客户端返回 `INTERNAL_ERROR`。

### 2. 统一握手拒绝帧

在 `ngx_nsoc_handler.c` 中抽统一助手，负责发送第二条协商错误帧：

- 只写 negotiation 长度、version、status、空握手消息长度
- 支持在部分发送时继续沿用现有 event/timer 机制

### 3. 服务端错误分类

服务端按以下策略向客户端返回状态码：

- 首包 version 不匹配：`VERSION_MISMATCH`
- 首包 `pattern/dh/cipher/hash` 不匹配：`NEGOTIATION_MISMATCH`
- negotiation 长度或结构异常：`MALFORMED_NEGOTIATION`
- 握手消息长度超过上限或帧格式明显异常：`MALFORMED_HANDSHAKE`
- `noise_handshakestate_read_message()` 失败：`PEER_VERIFICATION_FAILED`
- 本地无法归类且仍发生在连接期的异常：`INTERNAL_ERROR`

### 4. 日志策略

- 配置期错误继续保留详细日志
- 运行时握手拒绝记录“通用错误码 + 详细根因”
- 不记录私钥原文；公钥只保留现有文件级信息，不扩散完整内容

### 5. 代理端

代理端作为 initiator 连接上游时：

- 解析上游返回的第二条协商错误码
- 在本地日志中输出稳定错误类别
- 不把上游内部根因透给下游

## Go 示例客户端设计

更新 `validateSecondNegotiationData()`：

- 识别新的 6 类错误码
- 输出明确错误文案，例如 `server rejected handshake: NEGOTIATION_MISMATCH`
- 未知状态码仍保留兜底 `unexpected handshake status`

## 验证

- `git diff --check`
- `go test ./...`
- C 侧做语法级或环境允许范围内的编译校验
- 若环境缺 nginx 头文件或 noise-c 头文件，记录真实失败原因
