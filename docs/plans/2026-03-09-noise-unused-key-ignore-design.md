# Noise 多余 Key 忽略设计

## 背景

当前 nginx noise 配置层除了校验必填 key，还会对当前模式不使用的 key 指令直接报错。

这会让运维在切换协议模式时必须同步删掉所有不再使用的 key 指令，否则握手会在建立前失败。对示例和实际部署来说，这个约束过严，也不符合“只校验必填项”的配置直觉。

## 目标

- 代理端和服务端都只校验当前协议必填的 key 指令
- 当前协议不需要的 key 指令如果被配置，直接忽略
- 不改 Noise 协议矩阵，不改握手流程，不新增配置开关

## 非目标

- 不调整 `NN/KN/NK/KK/NX/KX/XN/IN/XK/IK/XX/IX` 的 key 需求矩阵
- 不新增 debug、warn 或 info 日志
- 不修改 Go 示例客户端的参数语义

## 设计

### 代理端

在 `ngx_nsoc_proxy_set_noiselink()` 中保留两类必填校验：

- initiator 需要 remote static 时，`server_public_key_file` 仍然必填
- initiator 需要 local static 时，`client_private_key_file` 仍然必填

如果当前协议不需要对应 key，但配置里传了值，不再报错，也不写日志，直接跳过加载逻辑。

### 服务端

在 `ngx_nsoc_noiseserver_handler()` 中保留两类必填校验：

- responder 需要 local static 时，`server_private_key_file` 仍然必填
- responder 需要 remote static 时，`client_public_key_file` 仍然必填

如果当前协议不需要对应 key，但配置里传了值，不再报错，也不写日志，直接跳过加载逻辑。

### 文档

同步更新 README 和已有设计/实施计划文档，把“多余 key 直接报错”改成“仅校验必填，多余配置忽略”。

## 影响

- `NK` 这类不需要 `client_public_key_file` 的模式，服务端即使保留该指令也不会提前失败
- `NN` 这类不需要任何 static key 的模式，可以保留历史 key 配置而不影响握手
- 必填 key 缺失时的报错行为保持不变

## 验证

- 人工检查代理端和服务端四个分支，确认只移除了“多余 key 报错”逻辑
- 尝试执行语法/构建级验证；若环境缺少 nginx 头文件或构建上下文，记录真实失败原因
