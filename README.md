# WireGuardTray

A small macOS menu bar app that keeps an eye on your WireGuard connection. It sits in the tray and lets you connect/disconnect without opening a terminal.

## Features

- Lock icon in the menu bar shows whether you're connected or not
- Toggle your tunnel on and off from the menu
- Polls status every 5 seconds
- Works with both `scutil` (Network Extension) tunnels and `wg-quick` configs
- Prompts for admin credentials when needed
- Remembers which tunnel you last connected to

## Getting started

Run it directly during development:

```bash
swift run
```

Or build a standalone `.app` bundle:

```bash
chmod +x scripts/build_app.sh
./scripts/build_app.sh
open dist/WireGuardTray.app
```

## How it detects tunnels

1. Checks `wg show interfaces` for any active WireGuard interfaces
2. Checks `scutil --nc list` for VPN services with WireGuard in the name

When connecting, it tries `scutil --nc start` first, then falls back to `wg-quick up`. If permissions are insufficient it'll show a macOS admin prompt and retry.

## Requirements

- macOS
- WireGuard installed (via Homebrew or the App Store app)
- For `wg-quick`: bash 4+ recommended (the bundled macOS bash is v3 and can cause issues)
