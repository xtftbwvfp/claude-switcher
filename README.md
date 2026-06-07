# Claude Switcher

Claude Switcher is a small macOS desktop tool for saving and switching local Claude Code account snapshots.

## What It Switches

- `~/.claude.json`
- `~/.claude/settings.json`
- macOS Keychain item `Claude Code-credentials`

The app shows only redacted account metadata in the UI. Tokens are not printed in the interface.

## Current Scope

This first version does not manage IP, Clash, or proxy nodes. It only switches the local Claude Code account state.

## Development

```bash
npm install
npm run tauri dev
```

## Build

```bash
npm run tauri build
```

Build outputs are generated under:

```text
src-tauri/target/release/bundle/
```

## Private Data

Local account snapshots are stored on the user's machine at:

```text
~/.claude-switcher/store.private.json
~/.claude-switcher/backups/
```

These files are not part of the repository.

