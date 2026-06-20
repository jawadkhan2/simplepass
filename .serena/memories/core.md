# Core

- Greenfield SimplePass desktop app: Tauri shell with React/TypeScript frontend and Rust backend under `src-tauri/`.
- User-facing goal: Windows/macOS LAN app for AirDrop-style peer tiles, pair-once trust, 1:1 chat, link drop/open, file drop/save-to-Downloads/open.
- Frontend source in `src/`; Tauri command bridge in `src/tauri.ts`; shared TS models in `src/types.ts`.
- Read `mem:tech_stack` for build/runtime stack, `mem:conventions` for local code patterns, `mem:suggested_commands` for Windows command forms, and `mem:task_completion` before finishing tasks.