# SimplePass

SimplePass is a Windows/macOS desktop app for sending links, files, and 1:1 chat messages between trusted computers on the same local network.

## Download & Install

Grab the latest installer: **[github.com/jawadkhan2/simplepass/releases/latest](https://github.com/jawadkhan2/simplepass/releases/latest)**

| OS | File to download |
|----|------------------|
| Windows | `SimplePass_<version>_x64-setup.exe` |
| Mac (Apple Silicon — M1/M2/M3+) | `SimplePass_<version>_aarch64.dmg` |
| Mac (Intel) | `SimplePass_<version>_x64.dmg` |

The app is not yet code-signed, so the OS shows a one-time warning on first run:

- **Windows:** SmartScreen popup → click **More info** → **Run anyway**.
- **Mac:** open the `.dmg`, drag SimplePass into Applications, then **right-click the app → Open → Open**. If macOS still refuses ("damaged" / "can't be opened"), clear the quarantine flag once:

  ```bash
  xattr -dr com.apple.quarantine "/Applications/SimplePass.app"
  ```

After the first install, SimplePass updates itself automatically — no need to download again.

## Current Features

- Tauri desktop app with React/TypeScript UI.
- First-launch device naming.
- System tray/menu-bar entry.
- Start-at-login enabled by default and toggleable in Settings.
- UDP LAN discovery for other SimplePass instances.
- Online/offline peer state based on recent LAN announcements.
- TCP peer transport for pairing, chat, links, and files.
- X25519-derived shared keys for paired devices and ChaCha20-Poly1305 encryption for trusted peer traffic.
- Accept/deny pairing request flow.
- AirDrop-style nearby computer tiles.
- Drag a URL onto one or more paired devices to open it remotely.
- Drag files onto one or more paired devices to send them remotely using Tauri native file-drop paths.
- Received links open in Chrome when available, otherwise in the default browser.
- Received files save into the OS Downloads folder, auto-rename conflicts, then open with the default app.
- 1:1 chat with local history.
- Toast notifications for received chat messages only.
- Per-destination transfer progress rows.
- Local persisted state in the app data directory.

## Development

Install dependencies:

```powershell
npm.cmd install
```

Run frontend build:

```powershell
npm.cmd run build
```

Run Rust check:

```powershell
cargo check --manifest-path src-tauri/Cargo.toml
```

Run Tauri dev:

```powershell
npm.cmd run tauri:dev
```

Build installers:

```powershell
npm.cmd run tauri:build
```

Windows artifacts are generated at:

- `src-tauri/target/release/bundle/msi/SimplePass_0.1.0_x64_en-US.msi`
- `src-tauri/target/release/bundle/nsis/SimplePass_0.1.0_x64-setup.exe`

## Over-the-Air Updates

SimplePass updates itself from GitHub Releases. It checks at launch and every 12
hours, installs in the background, and relaunches into the new version. Users can
also trigger a check via **Settings > Check for updates**.

### One-time setup (before the first release)

1. Create the GitHub repo and push this project:

   ```powershell
   git init
   git add .
   git commit -m "Initial commit"
   gh repo create simplepass --private --source=. --push
   ```

2. Replace the two placeholders in `src-tauri/tauri.conf.json`:
   - `OWNER/REPO` in `plugins.updater.endpoints` → your `owner/repo`.
   - `pubkey` → the public key generated in the next step.

3. Generate the updater signing keypair:

   ```powershell
   npm.cmd run tauri signer generate -- -w "$env:USERPROFILE\.simplepass-updater.key"
   ```

   - Paste the printed **public key** into `plugins.updater.pubkey`.
   - Keep the **private key** file and its password secret. Do not commit them.

4. Add the private key + password as GitHub Actions repository secrets
   (Settings > Secrets and variables > Actions):
   - `TAURI_SIGNING_PRIVATE_KEY` — contents of the private key file.
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password chosen above.

The very first installer must be installed by hand; auto-update applies from the
*next* release onward.

### Cutting a release

1. Bump the version in `package.json`, `src-tauri/tauri.conf.json`, and
   `src-tauri/Cargo.toml` (keep them identical).
2. Tag and push:

   ```powershell
   git commit -am "Release v0.1.1"
   git tag v0.1.1
   git push --follow-tags
   ```

`.github/workflows/release.yml` then builds Windows + macOS installers, signs
them, and publishes a GitHub Release with `latest.json`. Running apps update
within 12 hours.

### Note on OS code signing

Updater signing (above) is separate from OS code signing. Without an Apple
Developer certificate / Windows code-signing certificate, users see SmartScreen
(Windows) or Gatekeeper (macOS) warnings on install. Auto-update still works.
Add OS certificates later to remove those warnings.

## Verification Notes

- Windows frontend, Rust, and installer builds pass on this machine.
- Full LAN behavior requires two computers running SimplePass on the same network.
- macOS packaging must be run on macOS with the same Tauri project.
- Pairing and discovery still need real two-machine LAN testing across Windows/macOS firewalls.
