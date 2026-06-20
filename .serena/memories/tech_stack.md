# Tech Stack

- Desktop: Tauri 2.x.
- Frontend: React 18 + TypeScript + Vite.
- UI icons: `lucide-react`.
- Native/backend: Rust 2021 in `src-tauri/`.
- Package manager: npm, but on Windows use `npm.cmd` because PowerShell execution policy can block `npm.ps1`.
- Local persistence: Rust-managed JSON state in app data directory; SQLite can be added when history/query needs harden.
- Peer security: X25519 key agreement with ChaCha20-Poly1305 encrypted trusted peer traffic; UDP discovery remains plaintext.