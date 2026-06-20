# Suggested Commands

- Follow AGENTS.md: prefix shell commands with `rtk`; use `rtk proxy` for PowerShell-native commands.
- Install deps on Windows: `rtk proxy powershell -NoProfile -Command npm.cmd install`.
- Frontend build/typecheck: `rtk proxy powershell -NoProfile -Command npm.cmd run build`.
- Tauri dev: `rtk proxy powershell -NoProfile -Command npm.cmd run tauri:dev`.
- Tauri package: `rtk proxy powershell -NoProfile -Command npm.cmd run tauri:build`.
- Rust check only: `rtk cargo check --manifest-path src-tauri/Cargo.toml`.
- Directory listing on Windows: prefer `rtk proxy powershell -NoProfile -Command Get-ChildItem ...`; raw `rtk ls` may fail in this shell.