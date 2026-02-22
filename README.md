# WireGuardTray

Minimal macOS menu bar app that shows WireGuard connection state.

## What it does

- Shows a tray icon (`lock.shield.fill` when connected, `lock.shield` when disconnected)
- Checks status every 5 seconds
- Menu actions: Turn On/Turn Off, Refresh, Open WireGuard, Quit
- `Turn On` tries `scutil --nc start` for WireGuard VPN services, then `wg-quick up`
- `Turn Off` tries `scutil --nc stop` for connected WireGuard VPN services, then `wg-quick down`
- If macOS reports only `utun*` interfaces, the app maps to your WireGuard config name when possible (for example `wg0`)
- When direct `wg-quick` fails due permissions, the app retries via macOS admin prompt
- `wg-quick` actions prefer Homebrew bash (bash 4+) to avoid macOS bash 3 compatibility issues

## Run in development

```bash
swift run
```

## Build a `.app`

```bash
chmod +x scripts/build_app.sh
./scripts/build_app.sh
open dist/WireGuardTray.app
```

## Detection logic

The app checks, in order:

1. `wg show interfaces` (common install locations and PATH)
2. `scutil --nc list` for connected VPN services with names matching WireGuard
