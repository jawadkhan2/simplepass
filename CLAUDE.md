# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SimplePass is a Tauri 2 desktop app (Windows/macOS) for AirDrop-style sharing of links, files, and 1:1 chat between trusted computers on the same LAN. React/TypeScript frontend, Rust backend. All networking, crypto, persistence, and OS integration live in Rust; the frontend is a thin UI over Tauri commands and events.

## Commands

Use `npm.cmd` on Windows (the README uses `npm.cmd`; plain `npm` also works).

```powershell
npm install                                          # install JS deps
npm run dev                                           # vite dev server only (port 1420)
npm run tauri:dev                                     # full app in dev (spawns vite via beforeDevCommand)
npm run build                                          # tsc typecheck + vite build -> dist/
npm run tauri:build                                   # production installers
cargo check --manifest-path src-tauri/Cargo.toml      # Rust typecheck
cargo test --manifest-path src-tauri/Cargo.toml       # Rust tests (inline #[test] in lib.rs)
```

There is no JS linter or JS test runner configured. `npm run build` runs `tsc` as the typecheck gate.

## Architecture

### Backend (`src-tauri/src/lib.rs`)

Nearly all logic is in this single ~1300-line file (`main.rs` just calls `simplepass_lib::run()`). Key flow:

- **`run()`** builds the Tauri app: registers plugins (notification, process, autostart, updater on desktop), loads persisted state, sets up the tray, manages `AppState`, and calls `start_transport()`. The `invoke_handler!` list is the complete set of frontend-callable commands.
- **`AppState`** holds the persisted state behind a `Mutex<PersistedState>` plus an `incoming_files` map for in-progress transfers. Acquire the lock via the `lock_err` helper; never hold it across network I/O.
- **Two background threads** (`start_transport`): `run_tcp_listener` (port `TRANSPORT_PORT` 45938) accepts connections; `run_discovery` (port `DISCOVERY_PORT` 45937) does UDP LAN announce/listen. Each accepted TCP connection gets its own thread (`handle_stream`).
- **Peer lifecycle**: UDP `DiscoveryPacket`s (validated by `DISCOVERY_MAGIC`) populate the peer list; peers go offline after `PEER_OFFLINE_AFTER_MS`. State changes are pushed to the UI by `emit`ing events.

### Wire protocol

- Every TCP message is a newline-delimited JSON `TransportEnvelope` (`Plain` or `Encrypted`). One connection can carry many envelopes in order (used for chunked files), so `handle_stream` loops over lines on a single thread.
- The inner `WireMessage` enum is the actual payload: `PairRequest`/`PairAccepted`, `Chat`, `Link`, and the file trio `FileStart`/`FileChunk`/`FileEnd`. Files stream in `FILE_CHUNK_SIZE` (64 KiB) base64 chunks.
- `handle_message` dispatches by variant and emits the matching frontend event.

### Crypto

- Each device has an X25519 identity keypair persisted in state. `derive_shared_secret` does X25519 between our secret and the peer's public key.
- Paired-peer traffic is encrypted with ChaCha20-Poly1305 (`encrypt_message`/`decrypt_envelope`). **The peer_id used as associated data is the *sender's* device id** — see the `encryption_round_trip_uses_sender_peer_id` test; preserve this when touching crypto.
- Pairing is X25519 key exchange gated by an explicit accept/deny flow (`pair_peer` → `pairing-request` event → `accept_pairing`/`deny_pairing`).

### Commands ↔ events contract

`src/tauri.ts` is the single typed bridge: `api.*` wraps `invoke` calls and `events.*` wraps `listen`. When you add or rename a Rust `#[tauri::command]` or an `emit`ted event, update `src/tauri.ts` and the shared shapes in `src/types.ts` to match — these three must stay in sync.

### Frontend (`src/App.tsx`)

Single-component app. Gates on `setup.configured`: shows `FirstRun` (device naming) until configured, then the peer grid / chat / settings. Subscribes to all four `events.*` on mount and merges transfer progress with `mergeTransfers`. Native file drops use `getCurrentWebview().onDragDropEvent` to get real OS paths (Tauri `dragDropEnabled` is set in `tauri.conf.json`), which are passed to `send_files`.

### OTA updates (`src/updater.ts`)

`startAutoUpdate()` (called once from `App.tsx`) checks at launch and every 12 hours, auto-installs from GitHub Releases, and relaunches. Settings exposes a manual check. The updater endpoint and minisign `pubkey` live in `tauri.conf.json` under `plugins.updater`; `createUpdaterArtifacts: true` produces the signed `latest.json`. Release/signing-key details are in the README "Over-the-Air Updates" section.

## Conventions

- Rust↔JS field names cross the boundary as **camelCase** (serde `rename_all = "camelCase"` on wire/command types); keep TypeScript interfaces camelCase to match.
- Persisted state lives in the OS app-data dir (`app_data_file`), loaded leniently by `load_state` (a missing/corrupt file falls back to defaults) and written by `save_state`.
- `AppResult`/`AppError` (thiserror) is the backend error type; commands return `AppResult<T>` which serializes the error string to the frontend.

## Notes

- `AGENTS.md` is unrelated tooling config, not project documentation — ignore it.
- The app is unsigned; installers trip SmartScreen (Windows) and Gatekeeper (macOS). See README for the install workaround.
