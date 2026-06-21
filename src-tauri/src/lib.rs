use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::NotificationExt;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

type AppResult<T> = Result<T, String>;
const DISCOVERY_PORT: u16 = 45937;
const TRANSPORT_PORT: u16 = 45938;
const DISCOVERY_MAGIC: &str = "simplepass:v1";
const PEER_OFFLINE_AFTER_MS: i64 = 9_000;
const FILE_CHUNK_SIZE: usize = 64 * 1024;
/// Largest declared size accepted for an incoming file. Caps a malicious peer's
/// ability to fill the disk by declaring/streaming an enormous transfer.
const MAX_INCOMING_FILE_SIZE: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB
/// Largest single newline-delimited envelope read off a connection. Bounds
/// memory so a peer cannot OOM us with a multi-gigabyte line that never ends.
const MAX_LINE_BYTES: u64 = 1024 * 1024; // 1 MiB
/// Largest avatar data URL stored/forwarded. Keeps a peer from spamming huge
/// blobs into persisted state.
const MAX_AVATAR_LEN: usize = 256 * 1024; // 256 KiB
/// Cap on persisted transfer history so `state.json` cannot grow without bound.
const MAX_PERSISTED_TRANSFERS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupState {
    configured: bool,
    device_id: String,
    #[serde(default = "new_identity_secret")]
    identity_secret: String,
    device_name: String,
    start_at_login: bool,
    #[serde(default)]
    avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupResponse {
    configured: bool,
    device_id: String,
    device_name: String,
    start_at_login: bool,
    avatar: Option<String>,
    /// Our own X25519 public key (base64), so the UI can show a verification
    /// fingerprint the user can read out-of-band when approving a pairing.
    public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerDevice {
    id: String,
    name: String,
    host: String,
    port: u16,
    #[serde(default)]
    public_key: Option<String>,
    os: String,
    status: String,
    trust_state: String,
    #[serde(default)]
    shared_secret: Option<String>,
    #[serde(default)]
    avatar: Option<String>,
    last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatMessage {
    id: String,
    peer_id: String,
    direction: String,
    text: String,
    created_at: i64,
    #[serde(default = "default_message_kind")]
    kind: String,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    file_size: Option<u64>,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

fn default_message_kind() -> String {
    "text".to_string()
}

fn make_chat_message(peer_id: String, direction: &str, kind: &str, text: String) -> ChatMessage {
    ChatMessage {
        id: Uuid::new_v4().to_string(),
        peer_id,
        direction: direction.to_string(),
        text,
        created_at: now_ms(),
        kind: kind.to_string(),
        file_name: None,
        file_size: None,
        file_path: None,
        url: None,
    }
}

fn record_chat_message(app: &AppHandle, state: &State<AppState>, message: ChatMessage) -> AppResult<()> {
    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.messages.push(message.clone());
        save_state(&state.path, &persisted)?;
    }
    app.emit("chat-message", message).map_err(|err| err.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransferProgress {
    id: String,
    peer_id: String,
    peer_name: String,
    label: String,
    kind: String,
    progress: u8,
    state: String,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedState {
    setup: SetupState,
    peers: Vec<PeerDevice>,
    messages: Vec<ChatMessage>,
    transfers: Vec<TransferProgress>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            setup: SetupState {
                configured: false,
                device_id: Uuid::new_v4().to_string(),
                identity_secret: new_identity_secret(),
                device_name: String::new(),
                start_at_login: true,
                avatar: None,
            },
            peers: Vec::new(),
            messages: Vec::new(),
            transfers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryPacket {
    magic: String,
    device_id: String,
    device_name: String,
    public_key: String,
    os: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum WireMessage {
    PairRequest { device: DiscoveryPacket },
    PairAccepted { device: DiscoveryPacket },
    Chat { peer_id: String, text: String },
    Link { peer_id: String, url: String },
    FileStart { peer_id: String, transfer_id: String, file_name: String, total_size: u64 },
    FileChunk { peer_id: String, transfer_id: String, data: String },
    FileEnd { peer_id: String, transfer_id: String },
    Typing { peer_id: String, is_typing: bool },
    Profile { peer_id: String, avatar: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum TransportEnvelope {
    Plain { message: WireMessage },
    Encrypted { peer_id: String, nonce: String, body: String },
}

struct AppState {
    path: PathBuf,
    inner: Mutex<PersistedState>,
    incoming_files: Mutex<HashMap<String, IncomingFile>>,
    /// Per-transfer cancel flags, keyed by transfer_id. Set by `cancel_file_send`,
    /// polled by the streaming thread in `send_files`.
    cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

/// One open TCP connection to a target peer for an in-flight outgoing file.
struct PeerConn {
    peer_id: String,
    peer_name: String,
    stream: TcpStream,
    secret: String,
    failed: bool,
}

#[derive(Debug)]
struct IncomingFile {
    path: PathBuf,
    /// Append handle kept open for the whole transfer so each chunk is a single
    /// write instead of reopening the file 64 KiB at a time.
    file: fs::File,
    expected_size: u64,
    received_size: u64,
    peer_name: String,
    file_name: String,
}

#[tauri::command]
fn get_setup_state(state: State<AppState>) -> AppResult<SetupResponse> {
    Ok(setup_response(&state.inner.lock().map_err(lock_err)?.setup))
}

#[tauri::command]
fn save_setup(
    app: AppHandle,
    state: State<AppState>,
    device_name: String,
    start_at_login: bool,
) -> AppResult<SetupResponse> {
    let cleaned = device_name.trim();
    if cleaned.is_empty() {
        return Err("Device name is required.".to_string());
    }

    let setup = SetupState {
        configured: true,
        device_id: existing_device_id(&state)?,
        identity_secret: existing_identity_secret(&state)?,
        device_name: cleaned.to_string(),
        start_at_login,
        avatar: state.inner.lock().map_err(lock_err)?.setup.avatar.clone(),
    };

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.setup = setup.clone();
        save_state(&state.path, &persisted)?;
    }

    configure_autostart(&app, start_at_login)?;
    Ok(setup_response(&setup))
}

#[tauri::command]
fn list_peers(state: State<AppState>) -> AppResult<Vec<PeerDevice>> {
    Ok(state.inner.lock().map_err(lock_err)?.peers.clone())
}

#[tauri::command]
fn pair_peer(app: AppHandle, state: State<AppState>, peer_id: String) -> AppResult<()> {
    let (peers, peer) = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        let peer = persisted
            .peers
            .iter_mut()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| "Peer not found.".to_string())?;
        peer.trust_state = "pending".to_string();
        peer.last_seen = now_ms();
        let peer_clone = peer.clone();
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        (peers, peer_clone)
    };
    let packet = local_discovery_packet(&state)?;
    if let Err(err) = send_plain_wire(&peer, WireMessage::PairRequest { device: packet }) {
        // The request never left; don't strand the tile on "Pending". Revert and
        // surface the failure so the user can retry.
        let reverted = {
            let mut persisted = state.inner.lock().map_err(lock_err)?;
            if let Some(peer) = persisted.peers.iter_mut().find(|peer| peer.id == peer_id) {
                peer.trust_state = "unpaired".to_string();
            }
            let reverted = persisted.peers.clone();
            save_state(&state.path, &persisted)?;
            reverted
        };
        let _ = app.emit("peers-changed", reverted);
        return Err(err);
    }
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

#[tauri::command]
fn accept_pairing(app: AppHandle, state: State<AppState>, peer_id: String) -> AppResult<()> {
    let shared_secret = {
        let persisted = state.inner.lock().map_err(lock_err)?;
        let peer_public_key = peer_public_key(&persisted.peers, &peer_id)?;
        derive_shared_secret(&persisted.setup.identity_secret, &peer_public_key)?
    };
    let (peers, peer) = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        let peer = persisted
            .peers
            .iter_mut()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| "Peer not found.".to_string())?;
        peer.trust_state = "paired".to_string();
        peer.shared_secret = Some(shared_secret.clone());
        peer.last_seen = now_ms();
        let peer_clone = peer.clone();
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        (peers, peer_clone)
    };
    let packet = local_discovery_packet(&state)?;
    let _ = send_plain_wire(&peer, WireMessage::PairAccepted { device: packet });
    send_profile_to_peer(&state, &peer_id);
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

/// Pushes our current profile (avatar) to a single paired peer. Best-effort.
fn send_profile_to_peer(state: &State<AppState>, peer_id: &str) {
    let (local_id, avatar) = match state.inner.lock() {
        Ok(persisted) => (persisted.setup.device_id.clone(), persisted.setup.avatar.clone()),
        Err(_) => return,
    };
    if let Ok(peer) = get_peer(state, peer_id) {
        if peer.trust_state == "paired" {
            let _ = send_wire(&peer, WireMessage::Profile { peer_id: local_id, avatar });
        }
    }
}

#[tauri::command]
fn deny_pairing(app: AppHandle, state: State<AppState>, peer_id: String) -> AppResult<()> {
    let peers = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        if let Some(peer) = persisted.peers.iter_mut().find(|peer| peer.id == peer_id) {
            peer.trust_state = "unpaired".to_string();
        }
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        peers
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

#[tauri::command]
fn revoke_peer(app: AppHandle, state: State<AppState>, peer_id: String) -> AppResult<()> {
    let peers = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        if let Some(peer) = persisted.peers.iter_mut().find(|peer| peer.id == peer_id) {
            peer.trust_state = "unpaired".to_string();
            peer.shared_secret = None;
        }
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        peers
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

#[tauri::command]
fn list_messages(state: State<AppState>, peer_id: String) -> AppResult<Vec<ChatMessage>> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    Ok(persisted
        .messages
        .iter()
        .filter(|message| message.peer_id == peer_id)
        .cloned()
        .collect())
}

#[tauri::command]
fn send_message(app: AppHandle, state: State<AppState>, peer_id: String, text: String) -> AppResult<()> {
    ensure_paired(&state, &peer_id)?;
    let peer = get_peer(&state, &peer_id)?;
    let local_id = existing_device_id(&state)?;
    send_wire(&peer, WireMessage::Chat { peer_id: local_id, text: text.clone() })?;
    let message = make_chat_message(peer_id, "sent", "text", text);
    record_chat_message(&app, &state, message)
}

// Records a chat message received from a paired peer. Internal only (called from
// `handle_message`), not a Tauri command.
fn receive_message(app: &AppHandle, state: &State<AppState>, peer_id: String, text: String) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    let message = make_chat_message(peer_id, "received", "text", text);

    // Only toast when the window is hidden (minimized to the tray). If it's open,
    // the message lands in the chat in view — no notification needed.
    let window_hidden = app
        .get_webview_window("main")
        .and_then(|window| window.is_visible().ok())
        .map(|visible| !visible)
        .unwrap_or(true);
    if window_hidden {
        let _ = app
            .notification()
            .builder()
            .title("SimplePass")
            .body("New chat message")
            .show();
    }
    record_chat_message(app, state, message)
}

// Records a link received from a paired peer. Internal only (called from
// `handle_message`), not a Tauri command — the frontend never injects links.
// The link is *not* auto-opened: a malicious/spoofed peer must not be able to
// force-open arbitrary URLs. Non-http(s) links are dropped entirely. The user
// opens a recorded link by clicking its bubble (`open_link`).
fn receive_link(app: &AppHandle, state: &State<AppState>, peer_id: String, url: String) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    if !is_http_url(&url) {
        return Ok(());
    }
    let mut message = make_chat_message(peer_id, "received", "link", url.clone());
    message.url = Some(url);
    record_chat_message(app, state, message)
}

#[tauri::command]
fn send_link(
    app: AppHandle,
    state: State<AppState>,
    peer_ids: Vec<String>,
    url: String,
) -> AppResult<Vec<TransferProgress>> {
    if peer_ids.is_empty() {
        return Ok(Vec::new());
    }
    if !is_http_url(&url) {
        return Err("Only http(s) links can be shared.".to_string());
    }

    let local_id = existing_device_id(&state)?;
    let mut transfers = make_transfers(&state, &peer_ids, &url, "link")?;
    for transfer in &mut transfers {
        transfer.progress = 0;
        transfer.state = "queued".to_string();
        emit_transfer(&app, transfer.clone())?;
        transfer.progress = 35;
        transfer.state = "sending".to_string();
        emit_transfer(&app, transfer.clone())?;
        let peer = get_peer(&state, &transfer.peer_id)?;
        match send_wire(&peer, WireMessage::Link { peer_id: local_id.clone(), url: url.clone() }) {
            Ok(()) => {
                transfer.progress = 100;
                transfer.state = "complete".to_string();
                transfer.error = None;
                let mut message = make_chat_message(transfer.peer_id.clone(), "sent", "link", url.clone());
                message.url = Some(url.clone());
                let _ = record_chat_message(&app, &state, message);
            }
            Err(err) => {
                transfer.state = "failed".to_string();
                transfer.error = Some(err);
            }
        }
        emit_transfer(&app, transfer.clone())?;
    }

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.transfers.extend(transfers.clone());
        trim_transfers(&mut persisted);
        save_state(&state.path, &persisted)?;
    }

    Ok(transfers)
}

fn transfer_row_id(transfer_id: &str, peer_id: &str) -> String {
    format!("{transfer_id}:{peer_id}")
}

/// Streams one or more files (read from disk) to every paired target. Runs on a
/// background thread so the command returns immediately; progress and completion
/// are reported through `transfer-progress` events. Each file gets its own
/// `transfer_id` and a cancel flag that `cancel_file_send` can trip.
#[tauri::command]
fn send_files(
    app: AppHandle,
    state: State<AppState>,
    peer_ids: Vec<String>,
    paths: Vec<String>,
) -> AppResult<()> {
    if peer_ids.is_empty() {
        return Err("No target devices.".to_string());
    }
    if paths.is_empty() {
        return Ok(());
    }
    let local_id = existing_device_id(&state)?;

    // Resolve + validate targets once, up front, so obvious problems surface
    // synchronously instead of disappearing into the worker thread.
    let mut targets = Vec::new();
    for peer_id in &peer_ids {
        let peer = get_peer(&state, peer_id)?;
        if peer.trust_state != "paired" {
            return Err(format!("{} is not paired.", peer.name));
        }
        if peer.host.trim().is_empty() {
            return Err(format!("{} does not have a network address yet.", peer.name));
        }
        let secret = peer
            .shared_secret
            .clone()
            .ok_or_else(|| format!("{} does not have a shared secret yet.", peer.name))?;
        targets.push((peer, secret));
    }

    thread::spawn(move || {
        for path in paths {
            send_one_file(&app, &local_id, &targets, &path);
        }
    });
    Ok(())
}

/// Connect to every target, stream a single file in chunks, and record the sent
/// message. Best-effort: a per-peer failure marks only that row failed; a cancel
/// stops the stream and skips the chat record.
fn send_one_file(app: &AppHandle, local_id: &str, targets: &[(PeerDevice, String)], path: &str) {
    let state = app.state::<AppState>();
    let transfer_id = Uuid::new_v4().to_string();
    let source = Path::new(path);
    let file_name = source
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    let mut file = match fs::File::open(source) {
        Ok(file) => file,
        Err(err) => {
            for (peer, _) in targets {
                let _ = emit_transfer(
                    app,
                    file_row(&transfer_id, peer, &file_name, 0, "failed", Some(err.to_string())),
                );
            }
            return;
        }
    };
    let total = file.metadata().map(|meta| meta.len()).unwrap_or(0);

    // Register a cancel flag for the lifetime of this transfer.
    let cancel = Arc::new(AtomicBool::new(false));
    if let Ok(mut cancels) = state.cancels.lock() {
        cancels.insert(transfer_id.clone(), cancel.clone());
    }

    // Open one connection per target and announce the file.
    let mut conns: Vec<PeerConn> = Vec::new();
    for (peer, secret) in targets {
        match TcpStream::connect((peer.host.as_str(), peer.port)) {
            Ok(mut stream) => {
                let started = write_encrypted_line(
                    &mut stream,
                    local_id,
                    secret,
                    &WireMessage::FileStart {
                        peer_id: local_id.to_string(),
                        transfer_id: transfer_id.clone(),
                        file_name: file_name.clone(),
                        total_size: total,
                    },
                );
                let failed = started.is_err();
                let _ = emit_transfer(
                    app,
                    file_row(
                        &transfer_id,
                        peer,
                        &file_name,
                        0,
                        if failed { "failed" } else { "sending" },
                        started.err(),
                    ),
                );
                conns.push(PeerConn {
                    peer_id: peer.id.clone(),
                    peer_name: peer.name.clone(),
                    stream,
                    secret: secret.clone(),
                    failed,
                });
            }
            Err(err) => {
                let _ = emit_transfer(
                    app,
                    file_row(&transfer_id, peer, &file_name, 0, "failed", Some(err.to_string())),
                );
            }
        }
    }

    // Stream the file in chunks to every live connection.
    let mut sent: u64 = 0;
    let mut buffer = vec![0_u8; FILE_CHUNK_SIZE];
    let mut cancelled = false;
    let mut read_failed = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => {
                read_failed = true;
                break;
            }
        };
        let data = BASE64.encode(&buffer[..read]);
        sent += read as u64;
        let progress = (((sent as f64) / (total.max(1) as f64)) * 100.0)
            .round()
            .min(100.0) as u8;
        for conn in conns.iter_mut() {
            if conn.failed {
                continue;
            }
            let result = write_encrypted_line(
                &mut conn.stream,
                local_id,
                &conn.secret,
                &WireMessage::FileChunk {
                    peer_id: local_id.to_string(),
                    transfer_id: transfer_id.clone(),
                    data: data.clone(),
                },
            );
            if let Err(err) = result {
                conn.failed = true;
                let _ = emit_transfer(
                    app,
                    peer_row(&transfer_id, &conn.peer_id, &conn.peer_name, &file_name, progress, "failed", Some(err)),
                );
            }
        }
        for conn in conns.iter().filter(|conn| !conn.failed) {
            let _ = emit_transfer(
                app,
                peer_row(&transfer_id, &conn.peer_id, &conn.peer_name, &file_name, progress, "sending", None),
            );
        }
    }

    // Send the end marker only on a clean finish.
    if !cancelled && !read_failed {
        for conn in conns.iter_mut().filter(|conn| !conn.failed) {
            let _ = write_encrypted_line(
                &mut conn.stream,
                local_id,
                &conn.secret,
                &WireMessage::FileEnd {
                    peer_id: local_id.to_string(),
                    transfer_id: transfer_id.clone(),
                },
            );
            let _ = conn.stream.flush();
        }
    }

    if let Ok(mut cancels) = state.cancels.lock() {
        cancels.remove(&transfer_id);
    }

    // Emit terminal rows, persist them, and record the sent chat message.
    for conn in &conns {
        let (terminal, error) = if cancelled {
            ("cancelled", None)
        } else if read_failed {
            ("failed", Some("Could not read the file.".to_string()))
        } else if conn.failed {
            ("failed", None)
        } else {
            ("complete", None)
        };
        let row = peer_row(&transfer_id, &conn.peer_id, &conn.peer_name, &file_name, 100, terminal, error);
        if let Ok(mut persisted) = state.inner.lock() {
            persisted.transfers.push(row.clone());
            trim_transfers(&mut persisted);
            let _ = save_state(&state.path, &persisted);
        }
        let _ = emit_transfer(app, row);

        if !cancelled && !read_failed && !conn.failed {
            let mut message = make_chat_message(conn.peer_id.clone(), "sent", "file", file_name.clone());
            message.file_name = Some(file_name.clone());
            message.file_size = Some(total);
            message.file_path = Some(path.to_string());
            let _ = record_chat_message(app, &state, message);
        }
    }
}

fn file_row(
    transfer_id: &str,
    peer: &PeerDevice,
    file_name: &str,
    progress: u8,
    state_str: &str,
    error: Option<String>,
) -> TransferProgress {
    peer_row(transfer_id, &peer.id, &peer.name, file_name, progress, state_str, error)
}

fn peer_row(
    transfer_id: &str,
    peer_id: &str,
    peer_name: &str,
    file_name: &str,
    progress: u8,
    state_str: &str,
    error: Option<String>,
) -> TransferProgress {
    TransferProgress {
        id: transfer_row_id(transfer_id, peer_id),
        peer_id: peer_id.to_string(),
        peer_name: peer_name.to_string(),
        label: file_name.to_string(),
        kind: "file".to_string(),
        progress,
        state: state_str.to_string(),
        error,
    }
}

/// Trips the cancel flag for an in-flight transfer; the streaming thread stops at
/// the next chunk boundary.
#[tauri::command]
fn cancel_file_send(state: State<AppState>, transfer_id: String) -> AppResult<()> {
    if let Some(flag) = state.cancels.lock().map_err(lock_err)?.get(&transfer_id) {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[tauri::command]
fn send_typing(state: State<AppState>, peer_id: String, is_typing: bool) -> AppResult<()> {
    let local_id = existing_device_id(&state)?;
    if let Ok(peer) = get_peer(&state, &peer_id) {
        if peer.trust_state == "paired" {
            let _ = send_wire(&peer, WireMessage::Typing { peer_id: local_id, is_typing });
        }
    }
    Ok(())
}

#[tauri::command]
fn clear_messages(state: State<AppState>) -> AppResult<()> {
    let mut persisted = state.inner.lock().map_err(lock_err)?;
    persisted.messages.clear();
    save_state(&state.path, &persisted)
}

#[tauri::command]
fn clear_transfers(state: State<AppState>) -> AppResult<()> {
    let mut persisted = state.inner.lock().map_err(lock_err)?;
    persisted.transfers.clear();
    save_state(&state.path, &persisted)
}

#[tauri::command]
fn open_path(path: String) -> AppResult<()> {
    open::that(path).map_err(|err| err.to_string())
}

#[tauri::command]
fn set_avatar(app: AppHandle, state: State<AppState>, avatar: Option<String>) -> AppResult<SetupResponse> {
    if let Some(value) = &avatar {
        if value.len() > MAX_AVATAR_LEN {
            return Err("That image is too large.".to_string());
        }
    }
    let (response, paired) = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.setup.avatar = avatar;
        save_state(&state.path, &persisted)?;
        let response = setup_response(&persisted.setup);
        let paired = persisted
            .peers
            .iter()
            .filter(|peer| peer.trust_state == "paired")
            .cloned()
            .collect::<Vec<_>>();
        (response, paired)
    };
    let local_id = response.device_id.clone();
    for peer in paired {
        let _ = send_wire(
            &peer,
            WireMessage::Profile {
                peer_id: local_id.clone(),
                avatar: response.avatar.clone(),
            },
        );
    }
    let _ = app.emit("setup-changed", response.clone());
    Ok(response)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .setup(|app| {
            #[cfg(desktop)]
            app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
            let path = app_data_file(app.handle())?;
            let persisted = load_state(&path);
            let _ = configure_autostart(app.handle(), persisted.setup.start_at_login);
            app.manage(AppState {
                path,
                inner: Mutex::new(persisted),
                incoming_files: Mutex::new(HashMap::new()),
                cancels: Mutex::new(HashMap::new()),
            });
            build_tray(app.handle())?;
            start_transport(app.handle().clone());
            Ok(())
        })
        // Keep the app alive in the tray: closing the window hides it instead of quitting.
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_setup_state,
            save_setup,
            list_peers,
            pair_peer,
            accept_pairing,
            deny_pairing,
            revoke_peer,
            list_messages,
            send_message,
            send_link,
            send_files,
            cancel_file_send,
            send_typing,
            clear_messages,
            clear_transfers,
            set_avatar,
            open_path,
            open_link
        ])
        .run(tauri::generate_context!())
        .expect("error while running SimplePass");
}

fn start_transport(app: AppHandle) {
    let listener_app = app.clone();
    thread::spawn(move || run_tcp_listener(listener_app));
    let discovery_app = app.clone();
    thread::spawn(move || run_discovery(discovery_app));
}

fn run_tcp_listener(app: AppHandle) {
    let listener = match TcpListener::bind(("0.0.0.0", TRANSPORT_PORT)) {
        Ok(listener) => listener,
        Err(err) => {
            let _ = app.emit(
                "transport-error",
                format!("Could not start the transport listener on port {TRANSPORT_PORT}: {err}"),
            );
            return;
        }
    };
    for stream in listener.incoming().flatten() {
        let app = app.clone();
        thread::spawn(move || {
            let _ = handle_stream(app, stream);
        });
    }
}

fn handle_stream(app: AppHandle, stream: TcpStream) -> AppResult<()> {
    let remote_addr = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);
    // A single connection may carry multiple newline-delimited envelopes (notably
    // for chunked file transfers). Processing them on one thread keeps chunks in order.
    loop {
        let mut body = String::new();
        // Cap each line so a peer can't OOM us with one endless line. A line that
        // hits the cap is almost certainly hostile/garbage; drop the connection.
        let read = (&mut reader)
            .take(MAX_LINE_BYTES)
            .read_line(&mut body)
            .map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        if read as u64 >= MAX_LINE_BYTES && !body.ends_with('\n') {
            return Err("Incoming message exceeded the size limit.".to_string());
        }
        let trimmed = body.trim();
        if trimmed.is_empty() {
            continue;
        }
        let state = app.state::<AppState>();
        let envelope: TransportEnvelope = serde_json::from_str(trimmed).map_err(|err| err.to_string())?;
        let message = decrypt_envelope(&state, envelope)?;
        handle_message(&app, &state, message, remote_addr)?;
    }
    Ok(())
}

fn handle_message(
    app: &AppHandle,
    state: &State<AppState>,
    message: WireMessage,
    remote_addr: Option<SocketAddr>,
) -> AppResult<()> {
    match message {
        WireMessage::PairRequest { device } => {
            let peer = upsert_discovered_peer(app, state, device, "pending", remote_addr, None)?;
            app.emit("pairing-request", peer).map_err(|err| err.to_string())?;
        }
        WireMessage::PairAccepted { device } => {
            let device_id = device.device_id.clone();
            // Only honor a PairAccepted that answers a PairRequest *we* sent: the
            // peer must already exist locally in the "pending" state. Without this
            // check an unsolicited PairAccepted would silently mark any LAN device
            // as a trusted peer with no user approval.
            let shared_secret = {
                let persisted = state.inner.lock().map_err(lock_err)?;
                let pending = persisted
                    .peers
                    .iter()
                    .any(|peer| peer.id == device_id && peer.trust_state == "pending");
                if !pending {
                    return Ok(());
                }
                derive_shared_secret(&persisted.setup.identity_secret, &device.public_key)?
            };
            upsert_discovered_peer(app, state, device, "paired", remote_addr, Some(shared_secret))?;
            send_profile_to_peer(state, &device_id);
        }
        WireMessage::Chat { peer_id, text } => {
            receive_message(app, state, peer_id, text)?;
        }
        WireMessage::Link { peer_id, url } => {
            receive_link(app, state, peer_id, url)?;
        }
        WireMessage::Typing { peer_id, is_typing } => {
            app.emit(
                "peer-typing",
                serde_json::json!({ "peerId": peer_id, "isTyping": is_typing }),
            )
            .map_err(|err| err.to_string())?;
        }
        WireMessage::Profile { peer_id, avatar } => {
            // Drop oversized avatars rather than persisting a peer-controlled blob.
            let avatar = avatar.filter(|value| value.len() <= MAX_AVATAR_LEN);
            let peers = {
                let mut persisted = state.inner.lock().map_err(lock_err)?;
                if let Some(peer) = persisted.peers.iter_mut().find(|peer| peer.id == peer_id) {
                    peer.avatar = avatar;
                }
                let peers = persisted.peers.clone();
                save_state(&state.path, &persisted)?;
                peers
            };
            app.emit("peers-changed", peers).map_err(|err| err.to_string())?;
        }
        WireMessage::FileStart {
            peer_id,
            transfer_id,
            file_name,
            total_size,
        } => {
            receive_file_start(app, state, peer_id, transfer_id, file_name, total_size)?;
        }
        WireMessage::FileChunk {
            peer_id,
            transfer_id,
            data,
        } => {
            receive_file_chunk(app, state, peer_id, transfer_id, data)?;
        }
        WireMessage::FileEnd { peer_id, transfer_id } => {
            receive_file_end(app, state, peer_id, transfer_id)?;
        }
    }
    Ok(())
}

fn run_discovery(app: AppHandle) {
    let socket = match UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)) {
        Ok(socket) => socket,
        Err(err) => {
            let _ = app.emit(
                "transport-error",
                format!("Could not start LAN discovery on port {DISCOVERY_PORT}: {err}"),
            );
            return;
        }
    };
    let _ = socket.set_broadcast(true);
    let _ = socket.set_nonblocking(true);
    let mut buffer = [0_u8; 2048];
    let mut last_broadcast = 0;
    let mut last_stale_check = 0;

    loop {
        let now = now_ms();
        if now - last_broadcast > 2500 {
            if let Some(packet) = app.try_state::<AppState>().and_then(|state| local_discovery_packet(&state).ok()) {
                if let Ok(body) = serde_json::to_vec(&packet) {
                    let _ = socket.send_to(&body, SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT)));
                }
            }
            last_broadcast = now;
        }

        if now - last_stale_check > 1_500 {
            if let Some(state) = app.try_state::<AppState>() {
                let _ = mark_stale_peers_offline(&app, &state, now);
            }
            last_stale_check = now;
        }

        match socket.recv_from(&mut buffer) {
            Ok((size, addr)) => {
                if let Ok(mut packet) = serde_json::from_slice::<DiscoveryPacket>(&buffer[..size]) {
                    if packet.magic == DISCOVERY_MAGIC {
                        packet.port = if packet.port == 0 { TRANSPORT_PORT } else { packet.port };
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Ok(local_id) = existing_device_id(&state) {
                                if packet.device_id != local_id {
                                    let mut packet_with_host = packet;
                                    let _ = upsert_peer_from_addr(&app, &state, &mut packet_with_host, addr);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => thread::sleep(std::time::Duration::from_millis(120)),
        }
    }
}

fn upsert_peer_from_addr(
    app: &AppHandle,
    state: &State<AppState>,
    packet: &mut DiscoveryPacket,
    addr: SocketAddr,
) -> AppResult<()> {
    let host = addr.ip().to_string();
    let peers = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        match persisted.peers.iter_mut().find(|peer| peer.id == packet.device_id) {
            Some(peer) => {
                peer.name = packet.device_name.clone();
                peer.host = host.clone();
                peer.port = packet.port;
                peer.public_key = Some(packet.public_key.clone());
                peer.os = packet.os.clone();
                peer.status = "online".to_string();
                peer.last_seen = now_ms();
            }
            None => persisted.peers.push(PeerDevice {
                id: packet.device_id.clone(),
                name: packet.device_name.clone(),
                host: host.clone(),
                port: packet.port,
                public_key: Some(packet.public_key.clone()),
                os: packet.os.clone(),
                status: "online".to_string(),
                trust_state: "unpaired".to_string(),
                shared_secret: None,
                avatar: None,
                last_seen: now_ms(),
            }),
        }
        prune_offline_host_duplicates(&mut persisted, &packet.device_id, &host);
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        peers
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

fn mark_stale_peers_offline(app: &AppHandle, state: &State<AppState>, now: i64) -> AppResult<()> {
    let maybe_peers = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        let changed = apply_stale_peer_status(&mut persisted, now);
        if changed {
            let peers = persisted.peers.clone();
            save_state(&state.path, &persisted)?;
            Some(peers)
        } else {
            None
        }
    };

    if let Some(peers) = maybe_peers {
        app.emit("peers-changed", peers).map_err(|err| err.to_string())?;
    }
    Ok(())
}

/// Drops stale duplicate identities of the same physical machine. On a LAN each
/// device owns one IP, so an *offline* peer sharing `host` with a different,
/// currently-seen `keep_id` is a dead prior identity (e.g. the peer reinstalled
/// and regenerated its device id). Returns whether anything was removed.
fn prune_offline_host_duplicates(state: &mut PersistedState, keep_id: &str, host: &str) -> bool {
    if host.trim().is_empty() {
        return false;
    }
    let before = state.peers.len();
    state
        .peers
        .retain(|peer| !(peer.id != keep_id && peer.host == host && peer.status == "offline"));
    state.peers.len() != before
}

fn apply_stale_peer_status(state: &mut PersistedState, now: i64) -> bool {
    let mut changed = false;
    for peer in &mut state.peers {
        if peer.status == "online" && now - peer.last_seen > PEER_OFFLINE_AFTER_MS {
            peer.status = "offline".to_string();
            changed = true;
        }
    }
    changed
}

fn upsert_discovered_peer(
    app: &AppHandle,
    state: &State<AppState>,
    packet: DiscoveryPacket,
    trust_state: &str,
    remote_addr: Option<SocketAddr>,
    shared_secret: Option<String>,
) -> AppResult<PeerDevice> {
    let host = remote_addr.map(|addr| addr.ip().to_string()).unwrap_or_default();
    let (peers, changed_peer) = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        let changed_peer = match persisted.peers.iter_mut().find(|peer| peer.id == packet.device_id) {
            Some(peer) => {
                peer.name = packet.device_name.clone();
                if !host.is_empty() {
                    peer.host = host.clone();
                }
                peer.port = packet.port;
                peer.public_key = Some(packet.public_key.clone());
                peer.os = packet.os.clone();
                peer.status = "online".to_string();
                peer.trust_state = trust_state.to_string();
                if shared_secret.is_some() {
                    peer.shared_secret = shared_secret.clone();
                }
                peer.last_seen = now_ms();
                peer.clone()
            }
            None => {
                let peer = PeerDevice {
                    id: packet.device_id,
                    name: packet.device_name,
                    host,
                    port: packet.port,
                    public_key: Some(packet.public_key),
                    os: packet.os,
                    status: "online".to_string(),
                    trust_state: trust_state.to_string(),
                    shared_secret,
                    avatar: None,
                    last_seen: now_ms(),
                };
                persisted.peers.push(peer);
                persisted.peers.last().cloned().ok_or_else(|| "Peer not found.".to_string())?
            }
        };
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        (peers, changed_peer)
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())?;
    Ok(changed_peer)
}

fn send_plain_wire(peer: &PeerDevice, message: WireMessage) -> AppResult<()> {
    if peer.host.trim().is_empty() {
        return Err(format!("{} does not have a network address yet.", peer.name));
    }
    let mut stream = TcpStream::connect((peer.host.as_str(), peer.port)).map_err(|err| err.to_string())?;
    let body = serde_json::to_string(&TransportEnvelope::Plain { message }).map_err(|err| err.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|err| err.to_string())?;
    stream.write_all(b"\n").map_err(|err| err.to_string())
}

fn send_wire(peer: &PeerDevice, message: WireMessage) -> AppResult<()> {
    if peer.host.trim().is_empty() {
        return Err(format!("{} does not have a network address yet.", peer.name));
    }
    let secret = peer
        .shared_secret
        .as_deref()
        .ok_or_else(|| format!("{} does not have a shared secret yet.", peer.name))?;
    let peer_id = envelope_peer_id(&message)?.to_string();
    let mut stream = TcpStream::connect((peer.host.as_str(), peer.port)).map_err(|err| err.to_string())?;
    write_encrypted_line(&mut stream, &peer_id, secret, &message)?;
    stream.flush().map_err(|err| err.to_string())
}

fn write_encrypted_line(
    stream: &mut TcpStream,
    peer_id: &str,
    secret: &str,
    message: &WireMessage,
) -> AppResult<()> {
    let envelope = encrypt_message(peer_id, secret, message)?;
    let body = serde_json::to_string(&envelope).map_err(|err| err.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|err| err.to_string())?;
    stream.write_all(b"\n").map_err(|err| err.to_string())
}

fn encrypt_message(peer_id: &str, secret: &str, message: &WireMessage) -> AppResult<TransportEnvelope> {
    let key = decode_secret(secret)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|err| err.to_string())?;
    let mut nonce_bytes = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let plaintext = serde_json::to_vec(message).map_err(|err| err.to_string())?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|err| err.to_string())?;
    Ok(TransportEnvelope::Encrypted {
        peer_id: peer_id.to_string(),
        nonce: BASE64.encode(nonce_bytes),
        body: BASE64.encode(ciphertext),
    })
}

fn envelope_peer_id(message: &WireMessage) -> AppResult<&str> {
    match message {
        WireMessage::Chat { peer_id, .. }
        | WireMessage::Link { peer_id, .. }
        | WireMessage::FileStart { peer_id, .. }
        | WireMessage::FileChunk { peer_id, .. }
        | WireMessage::FileEnd { peer_id, .. }
        | WireMessage::Typing { peer_id, .. }
        | WireMessage::Profile { peer_id, .. } => Ok(peer_id),
        WireMessage::PairRequest { .. } | WireMessage::PairAccepted { .. } => {
            Err("Pairing messages must be sent without encryption.".to_string())
        }
    }
}

fn setup_response(setup: &SetupState) -> SetupResponse {
    SetupResponse {
        configured: setup.configured,
        device_id: setup.device_id.clone(),
        device_name: setup.device_name.clone(),
        start_at_login: setup.start_at_login,
        avatar: setup.avatar.clone(),
        public_key: derive_public_key(&setup.identity_secret).ok(),
    }
}

fn decrypt_envelope(state: &State<AppState>, envelope: TransportEnvelope) -> AppResult<WireMessage> {
    match envelope {
        TransportEnvelope::Plain { message } => Ok(message),
        TransportEnvelope::Encrypted { peer_id, nonce, body } => {
            let peer = get_peer(state, &peer_id)?;
            let secret = peer
                .shared_secret
                .as_deref()
                .ok_or_else(|| format!("{} does not have a shared secret yet.", peer.name))?;
            let key = decode_secret(secret)?;
            let nonce = BASE64.decode(nonce).map_err(|err| err.to_string())?;
            let body = BASE64.decode(body).map_err(|err| err.to_string())?;
            let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|err| err.to_string())?;
            let plaintext = cipher
                .decrypt(Nonce::from_slice(&nonce), body.as_ref())
                .map_err(|err| err.to_string())?;
            serde_json::from_slice(&plaintext).map_err(|err| err.to_string())
        }
    }
}

fn new_shared_secret() -> String {
    let mut key = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    BASE64.encode(key)
}

fn new_identity_secret() -> String {
    new_shared_secret()
}

fn derive_public_key(identity_secret: &str) -> AppResult<String> {
    let secret = StaticSecret::from(secret_array(identity_secret)?);
    let public = PublicKey::from(&secret);
    Ok(BASE64.encode(public.as_bytes()))
}

fn derive_shared_secret(identity_secret: &str, peer_public_key: &str) -> AppResult<String> {
    let secret = StaticSecret::from(secret_array(identity_secret)?);
    let public = PublicKey::from(public_key_array(peer_public_key)?);
    let shared = secret.diffie_hellman(&public);
    let digest = Sha256::digest(shared.as_bytes());
    Ok(BASE64.encode(digest))
}

fn decode_secret(secret: &str) -> AppResult<Vec<u8>> {
    let decoded = BASE64.decode(secret).map_err(|err| err.to_string())?;
    if decoded.len() == 32 {
        Ok(decoded)
    } else {
        Err("Shared secret has an invalid length.".to_string())
    }
}

fn secret_array(secret: &str) -> AppResult<[u8; 32]> {
    decode_secret(secret)?
        .try_into()
        .map_err(|_| "Secret has an invalid length.".to_string())
}

fn public_key_array(public_key: &str) -> AppResult<[u8; 32]> {
    BASE64
        .decode(public_key)
        .map_err(|err| err.to_string())?
        .try_into()
        .map_err(|_| "Public key has an invalid length.".to_string())
}

fn local_discovery_packet(state: &State<AppState>) -> AppResult<DiscoveryPacket> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    Ok(DiscoveryPacket {
        magic: DISCOVERY_MAGIC.to_string(),
        device_id: persisted.setup.device_id.clone(),
        device_name: if persisted.setup.device_name.is_empty() {
            "SimplePass Device".to_string()
        } else {
            persisted.setup.device_name.clone()
        },
        public_key: derive_public_key(&persisted.setup.identity_secret)?,
        os: std::env::consts::OS.to_string(),
        port: TRANSPORT_PORT,
    })
}

fn existing_device_id(state: &State<AppState>) -> AppResult<String> {
    Ok(state.inner.lock().map_err(lock_err)?.setup.device_id.clone())
}

fn existing_identity_secret(state: &State<AppState>) -> AppResult<String> {
    Ok(state.inner.lock().map_err(lock_err)?.setup.identity_secret.clone())
}

fn peer_public_key(peers: &[PeerDevice], peer_id: &str) -> AppResult<String> {
    peers
        .iter()
        .find(|peer| peer.id == peer_id)
        .and_then(|peer| peer.public_key.clone())
        .ok_or_else(|| "Peer public key is missing.".to_string())
}

fn get_peer(state: &State<AppState>, peer_id: &str) -> AppResult<PeerDevice> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    persisted
        .peers
        .iter()
        .find(|peer| peer.id == peer_id)
        .cloned()
        .ok_or_else(|| "Peer not found.".to_string())
}

fn make_transfers(
    state: &State<AppState>,
    peer_ids: &[String],
    label: &str,
    kind: &str,
) -> AppResult<Vec<TransferProgress>> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    peer_ids
        .iter()
        .map(|peer_id| {
            let peer = persisted
                .peers
                .iter()
                .find(|peer| peer.id == *peer_id)
                .ok_or_else(|| format!("Peer not found: {peer_id}"))?;
            if peer.trust_state != "paired" {
                return Err(format!("{} is not paired.", peer.name));
            }
            Ok(TransferProgress {
                id: Uuid::new_v4().to_string(),
                peer_id: peer.id.clone(),
                peer_name: peer.name.clone(),
                label: label.to_string(),
                kind: kind.to_string(),
                progress: 100,
                state: "complete".to_string(),
                error: None,
            })
        })
        .collect()
}

fn ensure_paired(state: &State<AppState>, peer_id: &str) -> AppResult<()> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    let peer = persisted
        .peers
        .iter()
        .find(|peer| peer.id == peer_id)
        .ok_or_else(|| "Peer not found.".to_string())?;
    if peer.trust_state == "paired" {
        Ok(())
    } else {
        Err(format!("{} is not paired.", peer.name))
    }
}

fn emit_transfer(app: &AppHandle, transfer: TransferProgress) -> AppResult<()> {
    app.emit("transfer-progress", transfer).map_err(|err| err.to_string())
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show SimplePass", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let mut builder = TrayIconBuilder::new();
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn configure_autostart(app: &AppHandle, enabled: bool) -> AppResult<()> {
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(|err| err.to_string())
    } else {
        manager.disable().map_err(|err| err.to_string())
    }
}

/// Only http(s) URLs are safe to hand to the OS opener. Anything else
/// (`file://`, UNC paths, custom protocol handlers) could leak credentials or
/// launch a registered handler, so we reject it.
fn is_http_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// Opens a received/clicked link, but only if it is an http(s) URL. Invoked from
/// the UI when the user clicks a link bubble.
#[tauri::command]
fn open_link(url: String) -> AppResult<()> {
    if !is_http_url(&url) {
        return Err("Only http(s) links can be opened.".to_string());
    }
    open_url(&url)
}

fn open_url(url: &str) -> AppResult<()> {
    if cfg!(target_os = "windows") {
        let chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];
        for path in chrome_paths {
            if Path::new(path).exists() {
                return std::process::Command::new(path)
                    .arg("--new-tab")
                    .arg(url)
                    .spawn()
                    .map(|_| ())
                    .map_err(|err| err.to_string());
            }
        }
    }

    if cfg!(target_os = "macos") {
        let chrome = Path::new("/Applications/Google Chrome.app");
        if chrome.exists() {
            return std::process::Command::new("open")
                .args(["-a", "Google Chrome", url])
                .spawn()
                .map(|_| ())
                .map_err(|err| err.to_string());
        }
    }

    open::that(url).map_err(|err| err.to_string())
}

fn receive_file_start(
    app: &AppHandle,
    state: &State<AppState>,
    peer_id: String,
    transfer_id: String,
    file_name: String,
    total_size: u64,
) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    if total_size > MAX_INCOMING_FILE_SIZE {
        return Err("The incoming file is too large.".to_string());
    }
    let peer_name = get_peer(state, &peer_id)
        .map(|peer| peer.name)
        .unwrap_or_else(|_| "Unknown device".to_string());
    let downloads = dirs::download_dir().ok_or_else(|| "Downloads folder was not found.".to_string())?;
    // Atomically reserves + creates the empty destination so chunks can be
    // appended in order and concurrent transfers can't collide on one path.
    let destination =
        available_destination(&downloads, std::ffi::OsStr::new(&file_name)).map_err(|err| err.to_string())?;
    // Keep one append handle open for the whole transfer (chunks are written under
    // the incoming_files lock, in order, on the connection's single thread).
    let file = fs::OpenOptions::new()
        .append(true)
        .open(&destination)
        .map_err(|err| err.to_string())?;

    {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.insert(
            transfer_id.clone(),
            IncomingFile {
                path: destination,
                file,
                expected_size: total_size,
                received_size: 0,
                peer_name: peer_name.clone(),
                file_name: file_name.clone(),
            },
        );
    }

    emit_transfer(
        app,
        TransferProgress {
            id: transfer_id,
            peer_id,
            peer_name,
            label: file_name,
            kind: "file".to_string(),
            progress: 0,
            state: "receiving".to_string(),
            error: None,
        },
    )
}

fn receive_file_chunk(
    app: &AppHandle,
    state: &State<AppState>,
    peer_id: String,
    transfer_id: String,
    data: String,
) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    let bytes = BASE64.decode(data).map_err(|err| err.to_string())?;
    let (progress, peer_name, file_name) = {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        let entry = incoming
            .get_mut(&transfer_id)
            .ok_or_else(|| "Received a chunk for an unknown transfer.".to_string())?;
        // Refuse to write past the size the sender declared in FileStart. Stops a
        // peer from streaming unbounded data into the Downloads folder. Abort the
        // transfer and remove the partial file.
        if entry.received_size + bytes.len() as u64 > entry.expected_size {
            let path = entry.path.clone();
            incoming.remove(&transfer_id);
            let _ = fs::remove_file(&path);
            return Err("Incoming file exceeded its declared size.".to_string());
        }
        entry.file.write_all(&bytes).map_err(|err| err.to_string())?;
        entry.received_size += bytes.len() as u64;
        let progress = (((entry.received_size as f64) / (entry.expected_size.max(1) as f64)) * 100.0)
            .round()
            .min(100.0) as u8;
        (progress, entry.peer_name.clone(), entry.file_name.clone())
    };

    emit_transfer(
        app,
        TransferProgress {
            id: transfer_id,
            peer_id,
            peer_name,
            label: file_name,
            kind: "file".to_string(),
            progress,
            state: "receiving".to_string(),
            error: None,
        },
    )
}

fn receive_file_end(
    app: &AppHandle,
    state: &State<AppState>,
    peer_id: String,
    transfer_id: String,
) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    let entry = {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.remove(&transfer_id)
    };
    let entry = entry.ok_or_else(|| "Received an end marker for an unknown transfer.".to_string())?;

    let mut message = make_chat_message(peer_id.clone(), "received", "file", entry.file_name.clone());
    message.file_name = Some(entry.file_name.clone());
    message.file_size = Some(entry.expected_size);
    message.file_path = Some(entry.path.to_string_lossy().to_string());
    record_chat_message(app, state, message)?;

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.transfers.push(TransferProgress {
            id: transfer_id.clone(),
            peer_id: peer_id.clone(),
            peer_name: entry.peer_name.clone(),
            label: entry.file_name.clone(),
            kind: "file".to_string(),
            progress: 100,
            state: "complete".to_string(),
            error: None,
        });
        trim_transfers(&mut persisted);
        save_state(&state.path, &persisted)?;
    }

    // Received files are *not* auto-opened: a paired (or spoofed) peer must not be
    // able to launch an executable/handler on this machine. The file sits in
    // Downloads and the chat record is clickable when the user wants to open it.

    emit_transfer(
        app,
        TransferProgress {
            id: transfer_id,
            peer_id,
            peer_name: entry.peer_name,
            label: entry.file_name,
            kind: "file".to_string(),
            progress: 100,
            state: "complete".to_string(),
            error: None,
        },
    )
}

/// Reserve a unique destination in `downloads`, creating the (empty) file
/// atomically with `create_new` so two concurrent transfers can never claim the
/// same path. Without this, a plain `exists()` check is a TOCTOU race: both
/// transfers see "no file", pick the same name, and interleave chunks into one
/// corrupt file.
fn available_destination(downloads: &Path, file_name: &std::ffi::OsStr) -> std::io::Result<PathBuf> {
    let original = Path::new(file_name);
    let stem = original
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = original.extension().and_then(|value| value.to_str());
    let mut candidate = downloads.join(file_name);
    let mut counter = 1;

    loop {
        match fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let next_name = match extension {
                    Some(ext) => format!("{stem} ({counter}).{ext}"),
                    None => format!("{stem} ({counter})"),
                };
                candidate = downloads.join(next_name);
                counter += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn app_data_file(app: &AppHandle) -> tauri::Result<PathBuf> {
    let dir = app.path().app_data_dir()?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join("state.json"))
}

fn load_state(path: &Path) -> PersistedState {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

fn save_state(path: &Path, state: &PersistedState) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let body = serde_json::to_string_pretty(state).map_err(|err| err.to_string())?;
    // Write to a sibling temp file, then rename over the target. A crash mid-write
    // leaves the old file intact instead of a truncated one that load_state would
    // discard (losing the identity key and all pairings). rename is atomic and, on
    // Windows, replaces the existing file.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body).map_err(|err| err.to_string())?;
    fs::rename(&tmp, path).map_err(|err| err.to_string())
}

/// Drops the oldest persisted transfer rows once the history exceeds the cap, so
/// `state.json` cannot grow without bound across many sends.
fn trim_transfers(state: &mut PersistedState) {
    let len = state.transfers.len();
    if len > MAX_PERSISTED_TRANSFERS {
        state.transfers.drain(0..len - MAX_PERSISTED_TRANSFERS);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> String {
    "Application state is unavailable.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_matches_on_both_devices() {
        let alice_secret = new_identity_secret();
        let bob_secret = new_identity_secret();
        let alice_public = derive_public_key(&alice_secret).expect("alice public key");
        let bob_public = derive_public_key(&bob_secret).expect("bob public key");

        let alice_shared = derive_shared_secret(&alice_secret, &bob_public).expect("alice shared");
        let bob_shared = derive_shared_secret(&bob_secret, &alice_public).expect("bob shared");

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn encryption_round_trip_uses_sender_peer_id() {
        let secret = new_shared_secret();
        let message = WireMessage::Chat {
            peer_id: "sender-device".to_string(),
            text: "hello".to_string(),
        };
        let envelope = encrypt_message(envelope_peer_id(&message).expect("peer id"), &secret, &message)
            .expect("encrypted envelope");

        match envelope {
            TransportEnvelope::Encrypted { peer_id, nonce, body } => {
                assert_eq!(peer_id, "sender-device");
                assert!(!nonce.is_empty());
                assert!(!body.is_empty());
            }
            TransportEnvelope::Plain { .. } => panic!("expected encrypted envelope"),
        }
    }

    #[test]
    fn file_messages_route_through_sender_peer_id() {
        let secret = new_shared_secret();
        for message in [
            WireMessage::FileStart {
                peer_id: "sender".to_string(),
                transfer_id: "t1".to_string(),
                file_name: "report.pdf".to_string(),
                total_size: 1024,
            },
            WireMessage::FileChunk {
                peer_id: "sender".to_string(),
                transfer_id: "t1".to_string(),
                data: BASE64.encode(b"chunk-bytes"),
            },
            WireMessage::FileEnd {
                peer_id: "sender".to_string(),
                transfer_id: "t1".to_string(),
            },
        ] {
            let peer_id = envelope_peer_id(&message).expect("peer id");
            assert_eq!(peer_id, "sender");
            let envelope = encrypt_message(peer_id, &secret, &message).expect("encrypted envelope");
            match envelope {
                TransportEnvelope::Encrypted { peer_id, body, .. } => {
                    assert_eq!(peer_id, "sender");
                    assert!(!body.is_empty());
                }
                TransportEnvelope::Plain { .. } => panic!("expected encrypted envelope"),
            }
        }
    }

    #[test]
    fn available_destination_renames_conflicts() {
        let temp_dir = std::env::temp_dir().join(format!("simplepass-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).expect("temp dir");
        fs::write(temp_dir.join("report.pdf"), b"first").expect("seed file");

        let destination =
            available_destination(&temp_dir, std::ffi::OsStr::new("report.pdf")).expect("destination");

        assert_eq!(destination.file_name().and_then(|name| name.to_str()), Some("report (1).pdf"));
        fs::remove_dir_all(temp_dir).expect("cleanup");
    }

    #[test]
    fn stale_online_peers_are_marked_offline() {
        let mut state = PersistedState::default();
        state.peers.push(PeerDevice {
            id: "peer-1".to_string(),
            name: "Peer".to_string(),
            host: "192.168.1.10".to_string(),
            port: TRANSPORT_PORT,
            public_key: None,
            os: "windows".to_string(),
            status: "online".to_string(),
            trust_state: "paired".to_string(),
            shared_secret: Some(new_shared_secret()),
            avatar: None,
            last_seen: 1_000,
        });

        let changed = apply_stale_peer_status(&mut state, 1_000 + PEER_OFFLINE_AFTER_MS + 1);

        assert!(changed);
        assert_eq!(state.peers[0].status, "offline");
    }

    fn peer_at(id: &str, host: &str, status: &str) -> PeerDevice {
        PeerDevice {
            id: id.to_string(),
            name: id.to_string(),
            host: host.to_string(),
            port: TRANSPORT_PORT,
            public_key: None,
            os: "windows".to_string(),
            status: status.to_string(),
            trust_state: "unpaired".to_string(),
            shared_secret: None,
            avatar: None,
            last_seen: 1_000,
        }
    }

    #[test]
    fn prune_drops_offline_same_host_duplicate() {
        let mut state = PersistedState::default();
        state.peers.push(peer_at("old", "192.168.1.67", "offline"));
        state.peers.push(peer_at("new", "192.168.1.67", "online"));

        let removed = prune_offline_host_duplicates(&mut state, "new", "192.168.1.67");

        assert!(removed);
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].id, "new");
    }

    #[test]
    fn only_http_urls_are_openable() {
        assert!(is_http_url("http://example.com"));
        assert!(is_http_url("https://example.com/path"));
        assert!(is_http_url("  HTTPS://EXAMPLE.COM  "));
        assert!(!is_http_url("file:///C:/secret.txt"));
        assert!(!is_http_url("\\\\attacker\\share"));
        assert!(!is_http_url("javascript:alert(1)"));
        assert!(!is_http_url("steam://run/123"));
    }

    #[test]
    fn trim_transfers_caps_history() {
        let mut state = PersistedState::default();
        for index in 0..(MAX_PERSISTED_TRANSFERS + 25) {
            state.transfers.push(TransferProgress {
                id: index.to_string(),
                peer_id: "p".to_string(),
                peer_name: "p".to_string(),
                label: "l".to_string(),
                kind: "file".to_string(),
                progress: 100,
                state: "complete".to_string(),
                error: None,
            });
        }
        trim_transfers(&mut state);
        assert_eq!(state.transfers.len(), MAX_PERSISTED_TRANSFERS);
        // Oldest dropped, newest kept.
        assert_eq!(state.transfers.last().unwrap().id, (MAX_PERSISTED_TRANSFERS + 24).to_string());
    }

    #[test]
    fn prune_keeps_online_and_other_host_peers() {
        let mut state = PersistedState::default();
        state.peers.push(peer_at("online-same-host", "192.168.1.67", "online"));
        state.peers.push(peer_at("offline-other-host", "192.168.1.50", "offline"));
        state.peers.push(peer_at("new", "192.168.1.67", "online"));

        let removed = prune_offline_host_duplicates(&mut state, "new", "192.168.1.67");

        assert!(!removed);
        assert_eq!(state.peers.len(), 3);
    }
}
