# Noise 多余 Key 忽略 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 调整 nginx Noise key 配置校验策略，只校验必填 key，多余配置直接忽略。

**Architecture:** 保持协议层的模式矩阵与 `needs_*` 判断不变，只修改代理端和服务端的配置加载分支。文档同步更新为“仅校验必填，多余配置忽略”，避免代码与说明不一致。

**Tech Stack:** C / nginx module API / 文档

---

### Task 1: 调整代理端 key 校验

**Files:**
- Modify: `ngx_nsoc_proxy_module.c`

**Step 1: 删除多余 server public key 的报错分支**

保留必填时报错与实际加载逻辑，删除：

```c
} else if (pscf->server_public_key_file.len != 0) {
    ...
    return NGX_ERROR;
}
```

**Step 2: 删除多余 client private key 的报错分支**

保留必填时报错与实际加载逻辑，删除：

```c
} else if (pscf->client_private_key_file.len != 0) {
    ...
    return NGX_ERROR;
}
```

**Step 3: 人工核对**

确认 `server_public_key_file` / `client_private_key_file` 仍然只在必需时加载进 `pscf->noise->ctx`。

### Task 2: 调整服务端 key 校验

**Files:**
- Modify: `ngx_nsoc_noiseserver_module.c`

**Step 1: 删除多余 server private key 的报错分支**

保留 responder 需要 local static 时的必填与加载逻辑。

**Step 2: 删除多余 client public key 的报错分支**

保留 responder 需要 remote static 时的必填与加载逻辑。

**Step 3: 人工核对**

确认 `noisecf->noise->ctx->private_keys` / `public_keys` 只在当前模式需要时才被填充。

### Task 3: 同步文档

**Files:**
- Create: `docs/plans/2026-03-09-noise-unused-key-ignore-design.md`
- Modify: `docs/plans/2026-03-06-noise-protocol-config-design.md`
- Modify: `docs/plans/2026-03-06-noise-protocol-config.md`
- Modify: `README.md`

**Step 1: 更新设计文档**

把“未使用的 key 指令直接报错”改成“仅校验必填，多余配置忽略”。

**Step 2: 更新 README**

在四个 key 指令说明里补充：当当前模式不需要该指令时，会忽略该配置。

### Task 4: 验证

**Files:**
- Verify: `ngx_nsoc_proxy_module.c`
- Verify: `ngx_nsoc_noiseserver_module.c`

**Step 1: 运行 diff 级检查**

Run: `git diff --check`
Expected: 无 patch 格式错误

**Step 2: 尝试语法级验证**

Run: `clang -fsyntax-only ngx_nsoc_proxy_module.c ngx_nsoc_noiseserver_module.c`
Expected: 若环境具备 nginx 头文件则通过；若不具备，记录真实失败原因
