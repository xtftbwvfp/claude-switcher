# Claude Switcher

Claude Switcher is a macOS desktop utility for managing multiple local Claude Code
accounts. It saves account snapshots, switches OAuth credentials, isolates local
Claude Code traces per profile, and can bind each profile to a Clash Verge
`Auto-Claude` node.

The app is built with Tauri 2, React, TypeScript, and Rust.

## Features

- Save and switch local Claude Code account snapshots.
- Store OAuth blobs from the macOS Keychain in an encrypted local store.
- Switch `~/.claude.json`, `~/.claude/settings.json`, and the Keychain item
  `Claude Code-credentials`.
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
- Show Claude usage from the official OAuth usage endpoint, with local log
  estimates for token trends.
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

The live `~/.claude/...` paths are symlinked to the active profile's isolated
directory where appropriate.

## Private Data

Local account snapshots are stored only on the user's machine:

```text
~/.claude-switcher/store.private.json
~/.claude-switcher/backups/
~/.claude-switcher/session-profiles/
~/.claude-switcher/session-backups/
```

Sensitive Keychain OAuth material is encrypted before being written into the
local store. Tokens are not printed in the UI and are not committed to the repo.

## Requirements

- macOS
- Node.js 20+
- Rust stable
- Claude Code CLI installed and available as `claude`
- Clash Verge Rev running locally if Clash node binding is used

## Development

Install dependencies:

```bash
npm ci
```

Run the Vite/Tauri dev app:

```bash
npm run tauri dev
```

Run frontend build:

```bash
npm run build
```

Run Rust checks:

```bash
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Build

Build the macOS app bundle and DMG:

```bash
npm run tauri build
```

Build outputs:

```text
src-tauri/target/release/bundle/macos/Claude Switcher.app
src-tauri/target/release/bundle/dmg/
```

## GitHub Actions

This repo includes two workflows:

- `CI`: runs TypeScript build, Rust fmt, clippy, tests, and a Tauri build on
  push and pull requests.
- `macOS Build`: manual workflow that builds the macOS app and uploads bundle
  artifacts.

The workflows build source code only. They do not access local Keychain data,
Claude account snapshots, or `~/.claude-switcher` data.

## Safety Notes

- Quit active Claude Code work before switching accounts unless using the guided
  new-account flow, which kills Claude Code CLI processes before cleaning state.
- Do not manually copy old JSONL sessions into a new account profile unless you
  intentionally want that account to see the old session history.
- If Clash binding is enabled, Claude-related domains should keep routing to the
  `Auto-Claude` group; the app switches the selected node inside that group.
