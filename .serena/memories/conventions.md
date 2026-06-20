# Conventions

- Keep UI dense and app-like, not landing-page-like; main screen is the usable AirDrop-style workspace.
- Frontend commands go through `src/tauri.ts`; avoid direct Tauri `invoke` scattered through components.
- Shared frontend models live in `src/types.ts` and should mirror Rust serde structs.
- Use ASCII in source unless an existing file clearly requires otherwise.
- Prefer conservative, scoped edits; preserve user-facing MVP behavior from the product plan.