# Claude Switcher

Claude Switcher 是一个 macOS 桌面工具，用来管理多个本机 Claude Code 账号。它可以保存账号快照、切换 OAuth 凭据、按账号隔离 Claude Code 本地痕迹，并把每个账号绑定到 Clash Verge 的 `Auto-Claude` 节点。

项目基于 Tauri 2、React、TypeScript 和 Rust 构建。

English documentation is available below: [English](#english)

## 功能

- 保存和切换本机 Claude Code 账号快照。
- 从 macOS Keychain 读取 Claude Code OAuth，并在本地加密保存。
- 切换以下账号材料：
  - `~/.claude.json`
  - `~/.claude/settings.json`
  - macOS Keychain 项 `Claude Code-credentials`
- 按账号隔离 Claude Code 本地状态：
  - `~/.claude/projects`
  - `~/.claude/telemetry`
  - `~/.claude/file-history`
  - `~/.claude/config.json`
- 为每个账号绑定 Clash Verge 的 `Auto-Claude` 节点。
- 提供“一键新号”向导：
  - 结束正在运行的 Claude Code CLI 进程
  - 保存当前账号状态
  - 把 Clash 切到指定节点
  - 确认节点已选中、alive，并能连到 `api.anthropic.com`
  - 清理当前 OAuth 状态
  - 为新号创建干净的本地 Claude 状态
  - 不自动打开浏览器或 `claude`；确认 IP 后由用户手动授权
- 显示 Claude 用量：
  - 额度百分比来自官方 Claude OAuth usage 接口
  - token 趋势来自本地 Claude Code 日志估算
- 自动保障 `~/.claude/settings.json` 中包含：

```json
{
  "permissions": {
    "defaultMode": "bypassPermissions"
  }
}
```

已有的 `permissions` 字段会保留，例如 `deny`。

## 会切换什么

Claude Switcher 管理这些本机账号面：

```text
~/.claude.json
~/.claude/settings.json
macOS Keychain: Claude Code-credentials
~/.claude/projects
~/.claude/telemetry
~/.claude/file-history
~/.claude/config.json
Clash Verge group: Auto-Claude
```

每个账号自己的 Claude 本地状态保存在：

```text
~/.claude-switcher/session-profiles/<profile-id>/
```

运行中的 `~/.claude/...` 路径会按需符号链接到当前账号的隔离目录。

## 私密数据

账号快照只保存在本机：

```text
~/.claude-switcher/store.private.json
~/.claude-switcher/backups/
~/.claude-switcher/session-profiles/
~/.claude-switcher/session-backups/
```

Keychain OAuth 内容写入本地 store 前会加密。Token 不会显示在 UI，也不会提交到仓库。

## 环境要求

- macOS
- Node.js 20+
- Rust stable
- 已安装 Claude Code CLI，并能通过 `claude` 命令启动
- 如果使用 Clash 节点绑定，需要本机运行 Clash Verge Rev

## 开发

安装依赖：

```bash
npm ci
```

启动开发版：

```bash
npm run tauri dev
```

前端构建：

```bash
npm run build
```

Rust 检查：

```bash
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 构建

构建 macOS `.app` 和 `.dmg`：

```bash
npm run tauri build
```

输出位置：

```text
src-tauri/target/release/bundle/macos/Claude Switcher.app
src-tauri/target/release/bundle/dmg/
```

## GitHub Actions

仓库包含两个 workflow：

- `CI`：push / pull request 时自动运行 TypeScript 构建、Rust fmt、clippy、test 和 Tauri build。
- `macOS Build`：手动触发，构建 macOS app 并上传 `.app` / `.dmg` artifacts。

这些 workflow 只构建源码，不会访问本机 Keychain、Claude 账号快照或 `~/.claude-switcher` 数据。

## 安全提示

- 普通切号前建议退出正在运行的 Claude Code；“一键新号”流程会自动结束 Claude Code CLI 进程。
- 不建议把旧账号 JSONL session 手动复制到新账号 profile，除非你明确希望新账号看到旧会话历史。
- 如果启用 Clash 绑定，Claude 相关域名应继续路由到 `Auto-Claude` 组；本工具负责切换该组里的具体节点。

---

## English

Claude Switcher is a macOS desktop utility for managing multiple local Claude Code accounts. It saves account snapshots, switches OAuth credentials, isolates local Claude Code traces per profile, and can bind each profile to a Clash Verge `Auto-Claude` node.

The app is built with Tauri 2, React, TypeScript, and Rust.

## Features

- Save and switch local Claude Code account snapshots.
- Store OAuth blobs from the macOS Keychain in an encrypted local store.
- Switch these account surfaces:
  - `~/.claude.json`
  - `~/.claude/settings.json`
  - macOS Keychain item `Claude Code-credentials`
- Isolate account-local Claude Code state:
  - `~/.claude/projects`
  - `~/.claude/telemetry`
  - `~/.claude/file-history`
  - `~/.claude/config.json`
- Bind each account to a Clash Verge `Auto-Claude` node.
- Guided new-account onboarding:
  - kill running Claude Code CLI processes
  - save the current profile state
  - switch Clash to the selected node
  - clean current OAuth state
  - create clean local Claude state for the new profile
  - open a clean `claude` login shell
- Show Claude usage from the official OAuth usage endpoint, with local log estimates for token trends.
- Keep `~/.claude/settings.json` hardened with:

```json
{
  "permissions": {
    "defaultMode": "bypassPermissions"
  }
}
```

Existing `permissions` fields such as `deny` are preserved.

## What Gets Switched

Claude Switcher manages these local account surfaces:

```text
~/.claude.json
~/.claude/settings.json
macOS Keychain: Claude Code-credentials
~/.claude/projects
~/.claude/telemetry
~/.claude/file-history
~/.claude/config.json
Clash Verge group: Auto-Claude
```

Per-profile local Claude state is stored under:

```text
~/.claude-switcher/session-profiles/<profile-id>/
```

The live `~/.claude/...` paths are symlinked to the active profile's isolated directory where appropriate.

## Private Data

Local account snapshots are stored only on the user's machine:

```text
~/.claude-switcher/store.private.json
~/.claude-switcher/backups/
~/.claude-switcher/session-profiles/
~/.claude-switcher/session-backups/
```

Sensitive Keychain OAuth material is encrypted before being written into the local store. Tokens are not printed in the UI and are not committed to the repo.

## Requirements

- macOS
- Node.js 20+
- Rust stable
- Claude Code CLI installed and available as `claude`
- Clash Verge Rev running locally if Clash node binding is used

## Development

```bash
npm ci
npm run tauri dev
npm run build
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Build

```bash
npm run tauri build
```

Build outputs:

```text
src-tauri/target/release/bundle/macos/Claude Switcher.app
src-tauri/target/release/bundle/dmg/
```

## GitHub Actions

- `CI`: runs TypeScript build, Rust fmt, clippy, tests, and a Tauri build on push and pull requests.
- `macOS Build`: manual workflow that builds the macOS app and uploads bundle artifacts.

The workflows build source code only. They do not access local Keychain data, Claude account snapshots, or `~/.claude-switcher` data.

## Safety Notes

- Quit active Claude Code work before switching accounts unless using the guided new-account flow, which kills Claude Code CLI processes before cleaning state.
- Do not manually copy old JSONL sessions into a new account profile unless you intentionally want that account to see the old session history.
- If Clash binding is enabled, Claude-related domains should keep routing to the `Auto-Claude` group; the app switches the selected node inside that group.
