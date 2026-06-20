# Task Completion

- For frontend/Rust changes, run `rtk proxy powershell -NoProfile -Command npm.cmd run build` after dependencies are installed.
- For backend-only changes, also run `rtk cargo check --manifest-path src-tauri/Cargo.toml` when possible.
- If dependency install/build needs network or writes blocked by sandbox, rerun with escalation per environment rules.
- For app runtime work, verify at least the Tauri command surface compiles; full LAN behavior needs two running app instances on separate machines or network namespaces.