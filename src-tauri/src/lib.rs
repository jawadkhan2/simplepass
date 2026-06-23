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
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, State, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt;
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
/// Largest widget-staged file the sender keeps a durable copy of (in Downloads)
/// so it can be reopened from chat. Larger staged sends stay transient and carry
/// no chat path (no Open button), avoiding silent duplication of big files.
const MAX_SENDER_PERSIST_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
/// Largest single newline-delimited envelope read off a connection. Bounds
/// memory so a peer cannot OOM us with a multi-gigabyte line that never ends.
const MAX_LINE_BYTES: u64 = 1024 * 1024; // 1 MiB
/// Largest avatar data URL stored/forwarded. Keeps a peer from spamming huge
/// blobs into persisted state.
const MAX_AVATAR_LEN: usize = 256 * 1024; // 256 KiB
/// Cap on persisted transfer history so `state.json` cannot grow without bound.
const MAX_PERSISTED_TRANSFERS: usize = 200;
/// Per-call read/write timeout on a peer TCP connection. A silent or hung peer
/// can therefore never park a sender or receiver thread indefinitely.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Timeout for the initial dial to a peer. Bounds the wait when a peer's stored
/// address is stale/unreachable instead of relying on the OS SYN timeout.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Hard cap on concurrent inbound connection-handler threads, so a flood of TCP
/// connections cannot spawn unbounded threads and exhaust resources.
const MAX_CONNECTION_THREADS: usize = 128;
/// Largest peer-supplied device name we store. A discovery packet is untrusted;
/// without a bound a peer could persist a multi-megabyte name into state.json.
const MAX_DEVICE_NAME_LEN: usize = 80;
/// Hard cap on stored peers. A LAN spoofer broadcasting many device ids cannot
/// grow the peer list (and state.json) without bound; paired peers are never
/// evicted to make room.
const MAX_PEERS: usize = 256;
/// Largest widget-staged file we will assemble on disk. Bounds how much a runaway
/// or hostile staging stream can write into the temp dir before `send_staged_file`.
const MAX_STAGED_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
/// Minimum gap between auto-opens of received content. Stops a paired (or spoofed)
/// peer from forcing a burst of browser tabs / viewer launches ("tab bomb") by
/// streaming many links or files in quick succession while auto-open is enabled.
const AUTO_OPEN_MIN_INTERVAL_MS: i64 = 1200;

/// Number of live inbound connection-handler threads. Bounded by
/// `MAX_CONNECTION_THREADS` in `run_tcp_listener`.
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// File extensions we are willing to auto-open with the OS default handler. This
/// is an allowlist of inert, viewer-opened media/document types — never a
/// blocklist — so a type we have not vetted is never auto-launched. Critically it
/// excludes executables and shell-interpreted types (.exe/.bat/.cmd/.ps1/.msi/
/// .lnk/.url/.hta/.scr/.js/.vbs/...), an HTML page (script execution), and SVG
/// (can embed script). Matched case-insensitively.
const AUTO_OPEN_ALLOWED_EXT: &[&str] = &[
    // images
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "avif", "ico",
    // audio / video
    "mp4", "m4v", "mov", "webm", "mkv", "avi", "mp3", "wav", "flac", "ogg", "m4a", "aac",
    // documents / text
    "pdf", "txt", "md", "csv", "log", "rtf", "json", "xml", "yaml", "yml",
];

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
    /// Whether the always-on-top floating desktop icon is shown.
    #[serde(default)]
    floating_icon: bool,
    /// When set, received files and links are auto-opened with the OS default
    /// viewer as they arrive (files with no associated handler are skipped).
    #[serde(default)]
    auto_open: bool,
    /// UI color theme: "light" (Warm Paper, default) or "dark" (Warm Ember).
    #[serde(default = "default_theme")]
    theme: String,
    /// Last on-screen position of the floating icon, so it reappears where the
    /// user left it across launches.
    #[serde(default)]
    widget_x: Option<f64>,
    #[serde(default)]
    widget_y: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupResponse {
    configured: bool,
    device_id: String,
    device_name: String,
    start_at_login: bool,
    avatar: Option<String>,
    #[serde(default)]
    floating_icon: bool,
    #[serde(default)]
    auto_open: bool,
    #[serde(default = "default_theme")]
    theme: String,
    /// Our own X25519 public key (base64), so the UI can show a verification
    /// fingerprint the user can read out-of-band when approving a pairing.
    public_key: Option<String>,
}

fn default_theme() -> String {
    "light".to_string()
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
                floating_icon: false,
                auto_open: false,
                theme: default_theme(),
                widget_x: None,
                widget_y: None,
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
    // When true, this is a rescan probe: receivers should immediately re-announce
    // themselves so the requester learns about them without waiting for the next
    // periodic broadcast. `serde(default)` keeps it compatible with older peers.
    #[serde(default)]
    request: bool,
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
    FileCancel { peer_id: String, transfer_id: String },
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
    /// In-progress incoming transfers, keyed by transfer_id. Each entry is behind
    /// its own `Mutex` so a chunk write holds only that transfer's lock — the map
    /// lock is taken just long enough to clone the `Arc`, never across disk I/O.
    incoming_files: Mutex<HashMap<String, Arc<Mutex<IncomingFile>>>>,
    /// Per-transfer cancel flags, keyed by transfer_id. Set by `cancel_file_send`,
    /// polled by the streaming thread in `send_files`.
    cancels: Mutex<HashMap<String, Arc<AtomicBool>>>,
    /// Timestamp (ms) of the last auto-open, used to rate-limit auto-opening of
    /// received files/links. See `auto_open_rate_ok`.
    last_auto_open: Mutex<i64>,
    /// Resting top-left (physical px) of the widget, captured when it expands to
    /// show the status pill so `set_widget_active(false)` can restore it. When the
    /// widget grows leftward (no room on the right of its monitor) the window is
    /// moved, and this is the only record of where the resting icon belonged.
    widget_anchor: Mutex<Option<PhysicalPosition<i32>>>,
    /// True while the widget is expanded to show the status pill. Programmatic
    /// resizes/moves during expansion fire `onMoved` in the webview; this flag tells
    /// `save_widget_position` to ignore those so the persisted position stays the
    /// resting anchor rather than a transient expanded offset.
    widget_active: AtomicBool,
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

    let existing = state.inner.lock().map_err(lock_err)?.setup.clone();
    let setup = SetupState {
        configured: true,
        device_id: existing_device_id(&state)?,
        identity_secret: existing_identity_secret(&state)?,
        device_name: cleaned.to_string(),
        start_at_login,
        avatar: existing.avatar.clone(),
        floating_icon: existing.floating_icon,
        auto_open: existing.auto_open,
        theme: existing.theme.clone(),
        widget_x: existing.widget_x,
        widget_y: existing.widget_y,
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

/// The paired peer most recently chatted with (by latest message timestamp),
/// falling back to the most-recently-seen paired peer when there is no chat
/// history yet. The floating widget uses this to auto-pick a drop target.
#[tauri::command]
fn recent_peer(state: State<AppState>) -> AppResult<Option<PeerDevice>> {
    let persisted = state.inner.lock().map_err(lock_err)?;
    let mut paired: Vec<PeerDevice> = persisted
        .peers
        .iter()
        .filter(|peer| peer.trust_state == "paired")
        .cloned()
        .collect();
    if paired.is_empty() {
        return Ok(None);
    }
    let last_msg = |peer: &PeerDevice| -> Option<i64> {
        persisted
            .messages
            .iter()
            .filter(|message| message.peer_id == peer.id)
            .map(|message| message.created_at)
            .max()
    };
    // Newest chat first; peers with no messages (None) sort last, broken by last_seen.
    paired.sort_by(|a, b| last_msg(b).cmp(&last_msg(a)).then(b.last_seen.cmp(&a.last_seen)));
    Ok(paired.into_iter().next())
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

/// Completely forget a device: remove its record plus all chat history and
/// transfer rows tied to it. Unlike `revoke_peer` (which only un-pairs), the peer
/// disappears entirely. A device still broadcasting on the LAN will re-appear as
/// a fresh *unpaired* peer; deletion clears trust and history, not discovery.
#[tauri::command]
fn delete_peer(app: AppHandle, state: State<AppState>, peer_id: String) -> AppResult<()> {
    let peers = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.peers.retain(|peer| peer.id != peer_id);
        persisted.messages.retain(|message| message.peer_id != peer_id);
        persisted.transfers.retain(|transfer| transfer.peer_id != peer_id);
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        peers
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
}

/// Manually probe the LAN: broadcast a discovery packet with `request = true` so
/// every peer re-announces immediately (instead of waiting for its next periodic
/// broadcast), refresh stale status, and push the current peer list to the UI.
#[tauri::command]
fn rescan_peers(app: AppHandle, state: State<AppState>) -> AppResult<()> {
    let mut packet = local_discovery_packet(&state)?;
    packet.request = true;
    let body = serde_json::to_vec(&packet).map_err(|err| err.to_string())?;

    let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(|err| err.to_string())?;
    socket.set_broadcast(true).map_err(|err| err.to_string())?;
    socket
        .send_to(&body, SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT)))
        .map_err(|err| err.to_string())?;

    let _ = mark_stale_peers_offline(&app, &state, now_ms());
    let peers = { state.inner.lock().map_err(lock_err)?.peers.clone() };
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
    // The toast (and its click-to-open behavior) is raised on the frontend from
    // the `chat-message` event, so a click can focus the window via `show_window`.
    record_chat_message(app, state, message)
}

// Records a link received from a paired peer. Internal only (called from
// `handle_message`), not a Tauri command — the frontend never injects links.
// Non-http(s) links are always dropped. By default the link is *not* auto-opened
// (the user opens it by clicking its bubble via `open_link`); only when the user
// has explicitly enabled the auto-open toggle do we hand the validated http(s)
// URL to the OS opener as it arrives.
fn receive_link(app: &AppHandle, state: &State<AppState>, peer_id: String, url: String) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    if !is_http_url(&url) {
        return Ok(());
    }
    let auto = auto_open_enabled(state)?;
    let mut message = make_chat_message(peer_id, "received", "link", url.clone());
    message.url = Some(url.clone());
    record_chat_message(app, state, message)?;
    // Rate-limit auto-open so a peer streaming many links can't spawn a burst of
    // browser tabs. Links that exceed the rate are still recorded in chat.
    if auto && auto_open_rate_ok(state) {
        let _ = open_url(&url);
    }
    Ok(())
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
            send_one_file(&app, &local_id, &targets, &path, None, Some(&path));
        }
    });
    Ok(())
}

/// Connect to every target, stream a single file in chunks, and record the sent
/// message. Best-effort: a per-peer failure marks only that row failed; a cancel
/// stops the stream and skips the chat record.
///
/// `display_name` overrides the name shown to the receiver (used when streaming a
/// staged temp file whose on-disk name is a random session id). `record_path` is
/// the local path stored on the sent chat message for click-to-open, or `None`
/// when the source is transient (e.g. a widget byte-drop) and has no stable path.
fn send_one_file(
    app: &AppHandle,
    local_id: &str,
    targets: &[(PeerDevice, String)],
    path: &str,
    display_name: Option<&str>,
    record_path: Option<&str>,
) {
    let state = app.state::<AppState>();
    let transfer_id = Uuid::new_v4().to_string();
    let source = Path::new(path);
    let file_name = display_name
        .map(|name| name.to_string())
        .unwrap_or_else(|| {
            source
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string())
        });

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
        match dial_peer(peer.host.as_str(), peer.port) {
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
    } else if cancelled {
        // Tell each receiver to discard the partial file it has been writing.
        for conn in conns.iter_mut().filter(|conn| !conn.failed) {
            let _ = write_encrypted_line(
                &mut conn.stream,
                local_id,
                &conn.secret,
                &WireMessage::FileCancel {
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
            message.file_path = record_path.map(|p| p.to_string());
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

/// Temp path a widget byte-drop is staged into. The session id is generated by the
/// frontend (a UUID); we still constrain it to a safe alphabet so it can never
/// escape the temp dir or collide with an unrelated file.
fn staged_file_path(session_id: &str) -> AppResult<PathBuf> {
    if session_id.is_empty()
        || !session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("Invalid staging id.".to_string());
    }
    Ok(std::env::temp_dir().join(format!("simplepass-stage-{session_id}")))
}

/// Append a base64 chunk of a dropped file to its staging temp file. The floating
/// widget runs with native drag-drop disabled (so it can also accept text/links),
/// which means dropped files arrive as in-page bytes with no OS path. The frontend
/// reads the file in slices and streams them here; `send_staged_file` then sends
/// the assembled temp file through the normal chunked transport.
#[tauri::command]
fn stage_file_chunk(session_id: String, data: String) -> AppResult<()> {
    let path = staged_file_path(&session_id)?;
    let bytes = BASE64.decode(data.as_bytes()).map_err(|err| err.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| err.to_string())?;
    file.write_all(&bytes).map_err(|err| err.to_string())?;
    // Cap the assembled size so a runaway or hostile staging stream can't fill the
    // temp dir. On overflow, delete the partial file and abort the staging session.
    let size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if size > MAX_STAGED_FILE_SIZE {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err("The staged file is too large.".to_string());
    }
    Ok(())
}

/// Remove widget staging temp files orphaned by a previous run. A staged file is
/// only meaningful within the session that produced it (the frontend's in-memory
/// session id is gone after a restart), so any `simplepass-stage-*` file present
/// at startup is dead and safe to delete. Best-effort.
fn cleanup_stale_staged_files() {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("simplepass-stage-") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Send a file previously assembled by `stage_file_chunk` to the given peers under
/// its original name. Reuses the same chunked, cancelable streaming path as
/// `send_files`. Small staged files (<= `MAX_SENDER_PERSIST_BYTES`) are first
/// copied into the sender's Downloads so the sender can reopen them from chat
/// (the chat record carries that path); larger ones stay transient and carry no
/// chat path. The temp staging file is always removed afterward.
#[tauri::command]
fn send_staged_file(
    app: AppHandle,
    state: State<AppState>,
    peer_ids: Vec<String>,
    session_id: String,
    file_name: String,
) -> AppResult<()> {
    if peer_ids.is_empty() {
        return Err("No target devices.".to_string());
    }
    let staged = staged_file_path(&session_id)?;
    if !staged.exists() {
        return Err("Nothing was staged to send.".to_string());
    }
    let local_id = existing_device_id(&state)?;

    // Resolve + validate targets up front, mirroring send_files, so problems surface
    // synchronously instead of inside the worker thread.
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

    let name = if file_name.trim().is_empty() {
        "file".to_string()
    } else {
        file_name
    };
    thread::spawn(move || {
        // Keep a durable copy in Downloads for small files so the sender's chat
        // record points at something openable; large files stay transient.
        let persisted = persist_staged_copy(&staged, &name);
        let send_path = persisted
            .as_ref()
            .map(|dest| dest.to_string_lossy().to_string())
            .unwrap_or_else(|| staged.to_string_lossy().to_string());
        let record_path = persisted
            .as_ref()
            .map(|dest| dest.to_string_lossy().to_string());
        send_one_file(&app, &local_id, &targets, &send_path, Some(&name), record_path.as_deref());
        let _ = fs::remove_file(&staged);
    });
    Ok(())
}

/// Copy a staged temp file into the sender's Downloads under a non-colliding
/// name and return that path, so the sender can open it from chat. Returns
/// `None` (file stays transient, no chat path / no Open button) when the file
/// exceeds `MAX_SENDER_PERSIST_BYTES` or persistence fails for any reason.
fn persist_staged_copy(staged: &Path, file_name: &str) -> Option<PathBuf> {
    let size = fs::metadata(staged).ok()?.len();
    if size > MAX_SENDER_PERSIST_BYTES {
        return None;
    }
    let downloads = dirs::download_dir()?;
    // Reserves + creates an empty destination; the copy below overwrites it.
    let dest = available_destination(&downloads, file_name).ok()?;
    match fs::copy(staged, &dest) {
        Ok(_) => Some(dest),
        Err(_) => {
            let _ = fs::remove_file(&dest); // drop the empty reserved file
            None
        }
    }
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

/// Whether the user has opted into auto-opening received files/links.
fn auto_open_enabled(state: &State<AppState>) -> AppResult<bool> {
    Ok(state.inner.lock().map_err(lock_err)?.setup.auto_open)
}

/// Throttle auto-opens. Returns `true` (and records "now") only if at least
/// `AUTO_OPEN_MIN_INTERVAL_MS` has elapsed since the previous auto-open, so a
/// peer cannot trigger a flood of viewer/browser launches by streaming many
/// files or links in quick succession. On a poisoned lock we deny (return false).
fn auto_open_rate_ok(state: &State<AppState>) -> bool {
    let mut last = match state.last_auto_open.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    let now = now_ms();
    if now - *last >= AUTO_OPEN_MIN_INTERVAL_MS {
        *last = now;
        true
    } else {
        false
    }
}

/// Whether a received file is safe to auto-open. Only files whose extension is in
/// the inert-viewer allowlist (`AUTO_OPEN_ALLOWED_EXT`) qualify; everything else —
/// notably executables, scripts, installers, shortcuts (.lnk/.url), .hta, .html,
/// and extensionless files — is excluded so auto-open can never launch code.
fn is_safe_to_auto_open(path: &std::path::Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => AUTO_OPEN_ALLOWED_EXT.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Best-effort auto-open of a freshly received file with its default viewer.
///
/// Gated by an extension allowlist (`is_safe_to_auto_open`): handing an
/// attacker-supplied path to the OS shell would otherwise be remote code
/// execution (a paired/spoofed peer could send `invoice.exe`, a `.lnk`, a `.bat`,
/// etc. and have it launched on receipt). `open::that_detached` returns an error
/// (no "Open with" picker) when an allowlisted type has no associated handler, so
/// unviewable-but-safe files are silently skipped — which is what the toggle promises.
fn auto_open_received_file(path: &std::path::Path) {
    if is_safe_to_auto_open(path) {
        let _ = open::that_detached(path);
    }
}

#[tauri::command]
fn open_path(path: String) -> AppResult<()> {
    // that_detached -> ShellExecuteExW on Windows (passes the full UTF-16 path to the
    // shell). Plain open::that goes via `cmd /c start`, which corrupts non-ASCII chars
    // in the path (e.g. an em dash in a received file name) so the OS can't find it.
    open::that_detached(path).map_err(|err| err.to_string())
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
    let mut builder = tauri::Builder::default();
    // Must be the FIRST plugin registered so it intercepts a duplicate launch before
    // any window is created. When the updater relaunches us on Windows the old instance
    // can still be tearing down; without this the two processes race for the ports and
    // WebView2 user-data dir, leaving the new window stuck on "Starting SimplePass…".
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            reveal_main_window(app);
        }));
    }
    builder
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
            let widget = (
                persisted.setup.floating_icon,
                persisted.setup.widget_x,
                persisted.setup.widget_y,
            );
            // Remove any widget staging temp files orphaned by a previous run.
            cleanup_stale_staged_files();
            app.manage(AppState {
                path,
                inner: Mutex::new(persisted),
                incoming_files: Mutex::new(HashMap::new()),
                cancels: Mutex::new(HashMap::new()),
                last_auto_open: Mutex::new(0),
                widget_anchor: Mutex::new(None),
                widget_active: AtomicBool::new(false),
            });
            build_tray(app.handle())?;
            if widget.0 {
                // Centre on launch too (per request), with the same radar pulse.
                let _ = open_widget_window(app.handle(), widget.1, widget.2, true);
                // The widget webview is still loading, so its reveal listener is
                // not ready yet; emit after a short delay so the radar fires.
                let radar_handle = app.handle().clone();
                thread::spawn(move || {
                    thread::sleep(std::time::Duration::from_millis(1500));
                    let _ = radar_handle.emit_to(WIDGET_LABEL, "widget-reveal", ());
                });
            }
            keep_widget_on_top(app.handle());
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
            recent_peer,
            pair_peer,
            accept_pairing,
            deny_pairing,
            revoke_peer,
            delete_peer,
            rescan_peers,
            list_messages,
            send_message,
            send_link,
            send_files,
            stage_file_chunk,
            send_staged_file,
            cancel_file_send,
            send_typing,
            clear_messages,
            clear_transfers,
            set_avatar,
            open_path,
            open_link,
            show_window,
            set_floating_icon,
            set_auto_open,
            set_theme,
            collapse_widget,
            set_widget_active,
            save_widget_position
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

/// Retry a socket bind for a few seconds before giving up. A too-fast restart can
/// leave the previous instance briefly holding the port; a single bind attempt
/// would then fail and kill the transport for the whole session (only a banner, no
/// recovery until the next launch). Retrying rides out the stale bind. ~5s budget.
fn bind_with_retry<T>(mut bind: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut attempt = 0;
    loop {
        match bind() {
            Ok(value) => return Ok(value),
            Err(err) => {
                attempt += 1;
                if attempt >= 10 {
                    return Err(err);
                }
                thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

fn run_tcp_listener(app: AppHandle) {
    let listener = match bind_with_retry(|| TcpListener::bind(("0.0.0.0", TRANSPORT_PORT))) {
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
        // Bound concurrent handler threads so a connection flood can't spawn
        // unbounded threads. Over the cap, drop the socket (closes on drop).
        if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_CONNECTION_THREADS {
            continue;
        }
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        let app = app.clone();
        thread::spawn(move || {
            let _ = handle_stream(app, stream);
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn handle_stream(app: AppHandle, stream: TcpStream) -> AppResult<()> {
    let remote_addr = stream.peer_addr().ok();
    // Bound per-read/-write waits so a peer that connects then stalls (or vanishes
    // mid-transfer) can't pin this handler thread forever.
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
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
        WireMessage::FileCancel { peer_id, transfer_id } => {
            receive_file_cancel(app, state, peer_id, transfer_id)?;
        }
    }
    Ok(())
}

fn run_discovery(app: AppHandle) {
    let socket = match bind_with_retry(|| UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))) {
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
                        let is_request = packet.request;
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Ok(local_id) = existing_device_id(&state) {
                                if packet.device_id != local_id {
                                    let mut packet_with_host = packet;
                                    let _ = upsert_peer_from_addr(&app, &state, &mut packet_with_host, addr);
                                    // Answer a rescan probe by immediately announcing
                                    // ourselves so the requester sees us right away.
                                    if is_request {
                                        if let Ok(reply) = local_discovery_packet(&state) {
                                            if let Ok(body) = serde_json::to_vec(&reply) {
                                                let _ = socket.send_to(&body, addr);
                                            }
                                        }
                                    }
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
    // Discovery packets are untrusted; bound the name before it is persisted.
    packet.device_name = clamp_device_name(&packet.device_name);
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
        enforce_peer_cap(&mut persisted);
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

/// Bound an untrusted, peer-supplied device name: trim, cap to
/// `MAX_DEVICE_NAME_LEN` characters (by `char`, not bytes, so multi-byte names are
/// never split mid-codepoint), and substitute a placeholder when empty. Prevents a
/// discovery packet from persisting an unbounded string into `state.json`.
fn clamp_device_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "Unknown device".to_string();
    }
    trimmed.chars().take(MAX_DEVICE_NAME_LEN).collect()
}

/// Bound the stored peer list to `MAX_PEERS`. A LAN spoofer broadcasting many
/// device ids must not be able to grow the list (and `state.json`) without bound.
/// Paired peers are never evicted; the stalest *unpaired* peers (oldest
/// `last_seen` first) are dropped until under the cap, stopping if only paired
/// peers remain.
fn enforce_peer_cap(state: &mut PersistedState) {
    while state.peers.len() > MAX_PEERS {
        let victim = state
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer.trust_state != "paired")
            .min_by_key(|(_, peer)| peer.last_seen)
            .map(|(index, _)| index);
        match victim {
            Some(index) => {
                state.peers.remove(index);
            }
            None => break,
        }
    }
}

/// Drops stale duplicate identities of the same physical machine. On a LAN each
/// device owns one IP, so an *offline* peer sharing `host` with a different,
/// currently-seen `keep_id` is a dead prior identity (e.g. the peer reinstalled
/// and regenerated its device id). Returns whether anything was removed.
///
/// Paired peers are never pruned: a paired identity carries the shared secret and
/// trust the user explicitly established, and IPs are reassigned by DHCP, so a
/// transient address collision must not silently delete a trusted peer.
fn prune_offline_host_duplicates(state: &mut PersistedState, keep_id: &str, host: &str) -> bool {
    if host.trim().is_empty() {
        return false;
    }
    let before = state.peers.len();
    state.peers.retain(|peer| {
        !(peer.id != keep_id
            && peer.host == host
            && peer.status == "offline"
            && peer.trust_state != "paired")
    });
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
    mut packet: DiscoveryPacket,
    trust_state: &str,
    remote_addr: Option<SocketAddr>,
    shared_secret: Option<String>,
) -> AppResult<PeerDevice> {
    let host = remote_addr.map(|addr| addr.ip().to_string()).unwrap_or_default();
    // Untrusted packet; bound the name before it is persisted.
    packet.device_name = clamp_device_name(&packet.device_name);
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
        enforce_peer_cap(&mut persisted);
        let peers = persisted.peers.clone();
        save_state(&state.path, &persisted)?;
        (peers, changed_peer)
    };
    app.emit("peers-changed", peers).map_err(|err| err.to_string())?;
    Ok(changed_peer)
}

/// Dial a peer with a bounded connect timeout, then arm read/write timeouts on
/// the socket so neither the connect nor any later send can block this thread
/// indefinitely against a stale address or a peer that stalls mid-write.
fn dial_peer(host: &str, port: u16) -> std::io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for peer"))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

fn send_plain_wire(peer: &PeerDevice, message: WireMessage) -> AppResult<()> {
    if peer.host.trim().is_empty() {
        return Err(format!("{} does not have a network address yet.", peer.name));
    }
    let mut stream = dial_peer(peer.host.as_str(), peer.port).map_err(|err| err.to_string())?;
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
    let mut stream = dial_peer(peer.host.as_str(), peer.port).map_err(|err| err.to_string())?;
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
        | WireMessage::FileCancel { peer_id, .. }
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
        floating_icon: setup.floating_icon,
        auto_open: setup.auto_open,
        theme: setup.theme.clone(),
        public_key: derive_public_key(&setup.identity_secret).ok(),
    }
}

/// Whether a `Plain` (unencrypted) envelope may carry this message. Only the
/// pairing handshake qualifies — every other variant must be encrypted.
fn plain_envelope_allowed(message: &WireMessage) -> bool {
    matches!(
        message,
        WireMessage::PairRequest { .. } | WireMessage::PairAccepted { .. }
    )
}

fn decrypt_envelope(state: &State<AppState>, envelope: TransportEnvelope) -> AppResult<WireMessage> {
    match envelope {
        // Pairing is the only handshake that legitimately travels in the clear
        // (no shared secret exists yet). Every other message — chat, links,
        // files, typing, profile — must arrive encrypted, or a LAN attacker
        // could inject unauthenticated plaintext that bypasses E2EE entirely.
        TransportEnvelope::Plain { message } => {
            if plain_envelope_allowed(&message) {
                Ok(message)
            } else {
                Err("Rejected an unencrypted message; only pairing may be sent in the clear.".to_string())
            }
        }
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
        request: false,
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
            "show" => reveal_main_window(app),
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                reveal_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

/// Fully shut the app down from the tray. We destroy the webview windows *before*
/// exiting so WebView2 tears down its host processes (msedgewebview2.exe) cleanly.
/// A bare `app.exit(0)` does a fast process exit while the windows are still open,
/// orphaning those host processes — and on Windows they keep the per-app WebView2
/// user-data dir (EBWebView) locked. The *next* launch's WebView2 then can't open
/// that locked dir, so the new window hangs forever on the "Starting SimplePass"
/// loading screen until the orphan finally dies. destroy() force-closes without the
/// CloseRequested handler, which would otherwise just hide the window. The short
/// delay lets the host processes exit before we terminate.
fn quit_app(app: &AppHandle) {
    for (_, window) in app.webview_windows() {
        let _ = window.destroy();
    }
    let app = app.clone();
    thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(300));
        app.exit(0);
    });
}

fn reveal_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Frontend-callable: bring the main window to the foreground. Used when the user
/// clicks a notification toast or the floating desktop icon.
#[tauri::command]
fn show_window(app: AppHandle) -> AppResult<()> {
    reveal_main_window(&app);
    Ok(())
}

const WIDGET_LABEL: &str = "widget";

/// Square (logical px) the widget grows to while the radar pulse plays, so the
/// expanding rings have room. Must match `RADAR_SIZE` in `FloatingIcon.tsx`: the
/// window is sized to this *before* it is shown so it appears already centred at
/// full size, and the frontend collapses it back to the resting icon afterwards.
const WIDGET_RADAR_SIZE: f64 = 220.0;

/// Resting size (logical px) of the widget once the radar pulse is done. Must
/// match `IDLE_SIZE` in `FloatingIcon.tsx`.
const WIDGET_IDLE_SIZE: f64 = 72.0;

/// Reveal the always-on-top floating desktop icon. The widget is a window declared
/// in `tauri.conf.json` (hidden at launch) rather than one built here at runtime:
/// it must have `dragDropEnabled: false` so the webview receives HTML5 drag-drop
/// (text, links, *and* file bytes), and that flag is only honoured when set in the
/// config — `WebviewWindowBuilder::drag_and_drop(false)` is silently ignored on
/// Windows (tauri-apps/tauri#13761). `main.tsx` renders `<FloatingIcon>` for the
/// `widget` label instead of the full app.
///
/// `center: true` ignores the saved position and parks the widget in the middle of
/// the current screen (used when the user first enables it, so it always appears
/// somewhere visible). Otherwise the last saved position is restored. Saved
/// coordinates come from the JS `onMoved` event, which reports *physical* pixels,
/// so they must be restored as `PhysicalPosition` — restoring them as logical
/// scaled them by the display factor on HiDPI screens and shoved the widget
/// off-screen, which is why it "stopped showing up".
fn open_widget_window(app: &AppHandle, x: Option<f64>, y: Option<f64>, center: bool) -> AppResult<()> {
    let window = app
        .get_webview_window(WIDGET_LABEL)
        .ok_or_else(|| "Floating widget window is unavailable.".to_string())?;
    if center {
        // Size to the full radar square first, then centre, so the widget appears
        // already centred at its final size — no grow-then-recentre jump.
        let _ = window.set_size(LogicalSize::new(WIDGET_RADAR_SIZE, WIDGET_RADAR_SIZE));
        let _ = window.center();
    } else if let (Some(x), Some(y)) = (x, y) {
        let _ = window.set_position(PhysicalPosition::new(x, y));
    }
    window.show().map_err(|err| err.to_string())?;
    // center() before show() can resolve against the wrong monitor on some
    // platforms, so re-center once the window is realised.
    if center {
        let _ = window.center();
    }
    // Re-assert topmost on every reveal: the config flag is set once at creation,
    // but Windows drops a window's topmost z-order when another app claims it
    // (fullscreen apps, explorer.exe restarts), so it must be re-applied.
    let _ = window.set_always_on_top(true);
    let _ = window.set_focus();
    Ok(())
}

/// Keep the floating widget pinned above other windows. Windows silently revokes a
/// window's topmost flag when another process grabs it (fullscreen apps, taskbar/
/// explorer restarts, display changes), which makes the widget "randomly" vanish
/// behind other windows. Re-asserting topmost on a slow interval restores it; the
/// reassert is a no-op `SetWindowPos` (no move/resize, no flicker) and only runs
/// while the widget is actually visible, so it never un-hides a disabled widget.
fn keep_widget_on_top(app: &AppHandle) {
    let app = app.clone();
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(2));
        if let Some(win) = app.get_webview_window(WIDGET_LABEL) {
            if matches!(win.is_visible(), Ok(true)) {
                let _ = win.set_always_on_top(true);
            }
        }
    });
}

fn close_widget_window(app: &AppHandle) {
    // Hide rather than close: the window is declared in the config, so closing it
    // would destroy it with no builder to recreate it on the next toggle.
    if let Some(win) = app.get_webview_window(WIDGET_LABEL) {
        let _ = win.hide();
    }
}

/// Toggle the floating desktop icon on/off and persist the preference.
#[tauri::command]
fn set_floating_icon(app: AppHandle, state: State<AppState>, enabled: bool) -> AppResult<SetupResponse> {
    let response = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.setup.floating_icon = enabled;
        save_state(&state.path, &persisted)?;
        setup_response(&persisted.setup)
    };
    if enabled {
        // Explicit enable always centers the widget on screen, so it can never
        // reappear off-screen from a stale saved position.
        open_widget_window(&app, None, None, true)?;
        // Tell the widget webview to play the radar pulse that guides the user's
        // eye to the screen centre where it just appeared.
        let _ = app.emit_to(WIDGET_LABEL, "widget-reveal", ());
    } else {
        close_widget_window(&app);
    }
    let _ = app.emit("setup-changed", response.clone());
    Ok(response)
}

/// Toggle whether incoming files/links are auto-opened with the OS default
/// viewer as they arrive. Off by default; files with no associated handler are
/// skipped (see `auto_open_received_file`).
#[tauri::command]
fn set_auto_open(app: AppHandle, state: State<AppState>, enabled: bool) -> AppResult<SetupResponse> {
    let response = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.setup.auto_open = enabled;
        save_state(&state.path, &persisted)?;
        setup_response(&persisted.setup)
    };
    let _ = app.emit("setup-changed", response.clone());
    Ok(response)
}

/// Set the UI color theme ("light" or "dark") and persist the preference. Any
/// unrecognized value falls back to "light".
#[tauri::command]
fn set_theme(app: AppHandle, state: State<AppState>, theme: String) -> AppResult<SetupResponse> {
    let theme = if theme == "dark" { "dark" } else { "light" }.to_string();
    let response = {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.setup.theme = theme;
        save_state(&state.path, &persisted)?;
        setup_response(&persisted.setup)
    };
    let _ = app.emit("setup-changed", response.clone());
    Ok(response)
}

/// Collapse the widget from its radar square back to the resting icon, keeping it
/// centred. Done in Rust because a JS `center()` right after a resize races the
/// resize and leaves the icon offset (up-left) instead of centred.
#[tauri::command]
fn collapse_widget(app: AppHandle) -> AppResult<()> {
    if let Some(win) = app.get_webview_window(WIDGET_LABEL) {
        let _ = win.set_size(LogicalSize::new(WIDGET_IDLE_SIZE, WIDGET_IDLE_SIZE));
        let _ = win.center();
    }
    Ok(())
}

/// Decide which side of the icon the status pill will expand toward, given the
/// resting top-left `anchor`, without touching the window. Returns the side plus,
/// for a leftward grow, the new top-left x to move to (the window shifts left by the
/// extra width so the icon stays put and the pill fills the space to its left).
///
/// Multi-monitor safe: bounds come from the widget's current monitor, not the
/// primary display. Falls back to growing right (top-left fixed) when there is no
/// monitor info or the icon isn't near the right edge.
fn widget_grow_plan(
    win: &tauri::WebviewWindow,
    anchor: PhysicalPosition<i32>,
    active_width: f64,
) -> (bool, i32) {
    let monitor = match win.current_monitor() {
        Ok(Some(m)) => m,
        _ => return (false, anchor.x),
    };
    let scale = monitor.scale_factor();
    let idle_px = (WIDGET_IDLE_SIZE * scale).round() as i32;
    let active_px = (active_width * scale).round() as i32;
    let extra_px = (active_px - idle_px).max(0);
    let left_bound = monitor.position().x;
    let right_bound = left_bound + monitor.size().width as i32;

    // Grow left only when the expanded window would overflow the right edge but there
    // is room once it's shifted back.
    let grow_left = anchor.x + active_px > right_bound && anchor.x - extra_px >= left_bound;
    if grow_left {
        ((true), (anchor.x - extra_px).max(left_bound))
    } else {
        (false, anchor.x)
    }
}

/// Expand the widget window to show the status pill, or collapse it back to the
/// resting icon. Split into a non-mutating *decide* phase (`apply = false`) and an
/// *apply* phase (`apply = true`) so the webview can commit its layout flip (icon to
/// the right, pill to the left, for a leftward grow) *before* the window actually
/// moves — otherwise the icon flashes on the wrong side for a frame. The frontend
/// calls decide → flip its DOM → apply.
///
/// The window grows sideways from the resting `WIDGET_IDLE_SIZE` square to
/// `active_width`. Growing right keeps the top-left fixed; growing left moves the
/// window so the icon stays put. Returns the side the pill ends up on
/// ("left"/"right").
#[tauri::command]
fn set_widget_active(
    app: AppHandle,
    state: State<AppState>,
    active: bool,
    active_width: f64,
    apply: bool,
) -> AppResult<String> {
    let win = app
        .get_webview_window(WIDGET_LABEL)
        .ok_or_else(|| "Floating widget window is unavailable.".to_string())?;

    if !active {
        // Collapse: restore the resting square at the captured anchor, then clear it.
        let anchor = state.widget_anchor.lock().map_err(lock_err)?.take();
        let _ = win.set_size(LogicalSize::new(WIDGET_IDLE_SIZE, WIDGET_IDLE_SIZE));
        if let Some(pos) = anchor {
            let _ = win.set_position(pos);
        }
        state.widget_active.store(false, Ordering::SeqCst);
        return Ok("right".to_string());
    }

    // Capture the resting top-left before any resize/move so collapse can restore it,
    // and so both phases plan against the same anchor. Only capture the first time we
    // expand (the decide phase): an apply must not re-read an already-moved position.
    let anchor = {
        let mut guard = state.widget_anchor.lock().map_err(lock_err)?;
        if guard.is_none() {
            *guard = Some(win.outer_position().map_err(|err| err.to_string())?);
        }
        guard.expect("anchor set above")
    };
    state.widget_active.store(true, Ordering::SeqCst);

    let (grow_left, new_x) = widget_grow_plan(&win, anchor, active_width);

    if apply {
        if grow_left {
            // Move left first (still the resting size), then grow back to the right.
            // The webview has already flipped to a right-anchored layout, so the icon
            // lands exactly where it rested with the pill filling the space to its left.
            let _ = win.set_position(PhysicalPosition::new(new_x, anchor.y));
        }
        let _ = win.set_size(LogicalSize::new(active_width, WIDGET_IDLE_SIZE));
    }

    Ok(if grow_left { "left" } else { "right" }.to_string())
}

/// Persist where the user dragged the floating icon, so it returns there next time.
/// Ignored while the widget is expanded for the status pill: those moves are
/// programmatic (see `set_widget_active`) and would overwrite the resting anchor.
#[tauri::command]
fn save_widget_position(state: State<AppState>, x: f64, y: f64) -> AppResult<()> {
    if state.widget_active.load(Ordering::SeqCst) {
        return Ok(());
    }
    let mut persisted = state.inner.lock().map_err(lock_err)?;
    persisted.setup.widget_x = Some(x);
    persisted.setup.widget_y = Some(y);
    save_state(&state.path, &persisted)
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
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: don't flash a console window when launching Chrome.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];
        for path in chrome_paths {
            if Path::new(path).exists() {
                return std::process::Command::new(path)
                    .creation_flags(CREATE_NO_WINDOW)
                    .arg("--new-tab")
                    .arg(url)
                    .spawn()
                    .map(|_| ())
                    .map_err(|err| err.to_string());
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let chrome = Path::new("/Applications/Google Chrome.app");
        if chrome.exists() {
            return std::process::Command::new("open")
                .args(["-a", "Google Chrome", url])
                .spawn()
                .map(|_| ())
                .map_err(|err| err.to_string());
        }
    }

    open::that_detached(url).map_err(|err| err.to_string())
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
    // Peer-controlled; reduce to a bare base name so the label we display and the
    // path we write to agree, and neither can carry directory components.
    let file_name = sanitize_file_name(&file_name);
    let peer_name = get_peer(state, &peer_id)
        .map(|peer| peer.name)
        .unwrap_or_else(|_| "Unknown device".to_string());
    let downloads = dirs::download_dir().ok_or_else(|| "Downloads folder was not found.".to_string())?;
    // Atomically reserves + creates the empty destination so chunks can be
    // appended in order and concurrent transfers can't collide on one path.
    let destination =
        available_destination(&downloads, &file_name).map_err(|err| err.to_string())?;
    // Keep one append handle open for the whole transfer (chunks are written under
    // the per-transfer lock, in order, on the connection's single thread).
    let file = fs::OpenOptions::new()
        .append(true)
        .open(&destination)
        .map_err(|err| err.to_string())?;

    {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.insert(
            transfer_id.clone(),
            Arc::new(Mutex::new(IncomingFile {
                path: destination,
                file,
                expected_size: total_size,
                received_size: 0,
                peer_name: peer_name.clone(),
                file_name: file_name.clone(),
            })),
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
    // Take the map lock only long enough to clone the per-transfer handle, so the
    // disk write below holds just this transfer's lock — never the shared map lock.
    let entry_arc = {
        let incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.get(&transfer_id).cloned()
    }
    .ok_or_else(|| "Received a chunk for an unknown transfer.".to_string())?;

    let outcome: Result<(u8, String, String), PathBuf> = {
        let mut entry = entry_arc.lock().map_err(lock_err)?;
        // Refuse to write past the size the sender declared in FileStart. Stops a
        // peer from streaming unbounded data into the Downloads folder. Abort the
        // transfer and remove the partial file.
        if entry.received_size + bytes.len() as u64 > entry.expected_size {
            Err(entry.path.clone())
        } else {
            entry.file.write_all(&bytes).map_err(|err| err.to_string())?;
            entry.received_size += bytes.len() as u64;
            let progress = (((entry.received_size as f64) / (entry.expected_size.max(1) as f64))
                * 100.0)
                .round()
                .min(100.0) as u8;
            Ok((progress, entry.peer_name.clone(), entry.file_name.clone()))
        }
    };

    let (progress, peer_name, file_name) = match outcome {
        Ok(values) => values,
        Err(path) => {
            let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
            incoming.remove(&transfer_id);
            drop(incoming);
            let _ = fs::remove_file(&path);
            return Err("Incoming file exceeded its declared size.".to_string());
        }
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
    let entry_arc = {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.remove(&transfer_id)
    };
    let entry_arc =
        entry_arc.ok_or_else(|| "Received an end marker for an unknown transfer.".to_string())?;
    // We hold the only remaining `Arc`; copy out what we need, then drop the guard
    // (and with it the append handle, flushing/closing the file) before continuing.
    let (path, file_name, expected_size, peer_name) = {
        let entry = entry_arc.lock().map_err(lock_err)?;
        (
            entry.path.clone(),
            entry.file_name.clone(),
            entry.expected_size,
            entry.peer_name.clone(),
        )
    };

    let mut message = make_chat_message(peer_id.clone(), "received", "file", file_name.clone());
    message.file_name = Some(file_name.clone());
    message.file_size = Some(expected_size);
    message.file_path = Some(path.to_string_lossy().to_string());
    record_chat_message(app, state, message)?;

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.transfers.push(TransferProgress {
            id: transfer_id.clone(),
            peer_id: peer_id.clone(),
            peer_name: peer_name.clone(),
            label: file_name.clone(),
            kind: "file".to_string(),
            progress: 100,
            state: "complete".to_string(),
            error: None,
        });
        trim_transfers(&mut persisted);
        save_state(&state.path, &persisted)?;
    }

    // By default received files are *not* auto-opened: a paired (or spoofed) peer
    // must not silently launch a handler on this machine. The file sits in
    // Downloads and the chat record is clickable. Only when the user has opted
    // into auto-open do we hand it to the default viewer — and even then only for
    // an allowlisted, inert file type (see `auto_open_received_file`) and subject
    // to a rate limit, so a burst of files can't launch a burst of viewers.
    if auto_open_enabled(state)? && auto_open_rate_ok(state) {
        auto_open_received_file(&path);
    }

    emit_transfer(
        app,
        TransferProgress {
            id: transfer_id,
            peer_id,
            peer_name,
            label: file_name,
            kind: "file".to_string(),
            progress: 100,
            state: "complete".to_string(),
            error: None,
        },
    )
}

/// Receiver side of a sender-initiated cancel: drop the in-progress entry, delete
/// the partial file from disk (best-effort), and report the transfer cancelled.
fn receive_file_cancel(
    app: &AppHandle,
    state: &State<AppState>,
    peer_id: String,
    transfer_id: String,
) -> AppResult<()> {
    ensure_paired(state, &peer_id)?;
    let entry_arc = {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.remove(&transfer_id)
    };
    // Nothing reserved (e.g. cancel arrived before FileStart) — nothing to clean up.
    let Some(entry_arc) = entry_arc else {
        return Ok(());
    };
    let (path, file_name, peer_name) = {
        let entry = entry_arc.lock().map_err(lock_err)?;
        (
            entry.path.clone(),
            entry.file_name.clone(),
            entry.peer_name.clone(),
        )
    };

    let _ = fs::remove_file(&path);

    emit_transfer(
        app,
        TransferProgress {
            id: transfer_id,
            peer_id,
            peer_name,
            label: file_name,
            kind: "file".to_string(),
            progress: 0,
            state: "cancelled".to_string(),
            error: None,
        },
    )
}

/// Reduce a peer-supplied file name to a single, safe path component.
///
/// A received name is fully attacker-controlled. Passed straight to `Path::join`
/// it is a write-anywhere primitive: `..\..` walks out of Downloads, and an
/// absolute path (`C:\Windows\...`, `/etc/...`) or UNC path (`\\host\share`)
/// *replaces* the join base entirely. We therefore split on both `/` and `\`
/// (a backslash is not a separator on Unix, so `Path::file_name` alone would miss
/// it there), keep only the final segment, and reject the empty/`.`/`..` cases —
/// falling back to a fixed name. The result is guaranteed to contain no path
/// separators, so the subsequent `downloads.join(..)` stays inside `downloads`.
fn sanitize_file_name(file_name: &str) -> String {
    let last = file_name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("")
        .trim();
    if last.is_empty() || last == "." || last == ".." {
        "received-file".to_string()
    } else {
        last.to_string()
    }
}

/// Reserve a unique destination in `downloads`, creating the (empty) file
/// atomically with `create_new` so two concurrent transfers can never claim the
/// same path. Without this, a plain `exists()` check is a TOCTOU race: both
/// transfers see "no file", pick the same name, and interleave chunks into one
/// corrupt file.
fn available_destination(downloads: &Path, file_name: &str) -> std::io::Result<PathBuf> {
    // The name is peer-controlled. Reduce it to a bare file name first so a
    // hostile value (`..\..\Startup\evil.bat`, an absolute `C:\...` path, a UNC
    // share) can never escape `downloads` once joined. See `sanitize_file_name`.
    let safe = sanitize_file_name(file_name);
    let original = Path::new(&safe);
    let stem = original
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = original.extension().and_then(|value| value.to_str());
    let mut candidate = downloads.join(&safe);
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
    fn plain_envelopes_allowed_only_for_pairing() {
        let device = DiscoveryPacket {
            magic: DISCOVERY_MAGIC.to_string(),
            device_id: "peer".to_string(),
            device_name: "Peer".to_string(),
            public_key: "key".to_string(),
            os: "windows".to_string(),
            port: TRANSPORT_PORT,
            request: false,
        };
        assert!(plain_envelope_allowed(&WireMessage::PairRequest { device: device.clone() }));
        assert!(plain_envelope_allowed(&WireMessage::PairAccepted { device }));

        // Chat, links, files, typing, profile must never be accepted in the clear.
        assert!(!plain_envelope_allowed(&WireMessage::Chat {
            peer_id: "peer".to_string(),
            text: "hi".to_string(),
        }));
        assert!(!plain_envelope_allowed(&WireMessage::FileChunk {
            peer_id: "peer".to_string(),
            transfer_id: "t1".to_string(),
            data: BASE64.encode(b"bytes"),
        }));
    }

    #[test]
    fn available_destination_renames_conflicts() {
        let temp_dir = std::env::temp_dir().join(format!("simplepass-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).expect("temp dir");
        fs::write(temp_dir.join("report.pdf"), b"first").expect("seed file");

        let destination =
            available_destination(&temp_dir, "report.pdf").expect("destination");

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

    #[test]
    fn prune_never_drops_paired_peer() {
        let mut state = PersistedState::default();
        let mut paired = peer_at("paired-old", "192.168.1.67", "offline");
        paired.trust_state = "paired".to_string();
        state.peers.push(paired);
        state.peers.push(peer_at("new", "192.168.1.67", "online"));

        let removed = prune_offline_host_duplicates(&mut state, "new", "192.168.1.67");

        assert!(!removed);
        assert_eq!(state.peers.len(), 2);
        assert!(state.peers.iter().any(|peer| peer.id == "paired-old"));
    }

    #[test]
    fn sanitize_file_name_strips_path_components() {
        // Traversal and absolute/UNC paths collapse to a bare component.
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name(r"..\..\Startup\evil.bat"), "evil.bat");
        assert_eq!(sanitize_file_name(r"C:\Windows\system32\calc.exe"), "calc.exe");
        assert_eq!(sanitize_file_name(r"\\attacker\share\x.txt"), "x.txt");
        assert_eq!(sanitize_file_name("plain.pdf"), "plain.pdf");
        // Degenerate names fall back to a fixed safe name.
        assert_eq!(sanitize_file_name(".."), "received-file");
        assert_eq!(sanitize_file_name(""), "received-file");
        assert_eq!(sanitize_file_name("   "), "received-file");
        // A dotfile keeps its leading dot.
        assert_eq!(sanitize_file_name(".gitignore"), ".gitignore");
    }

    #[test]
    fn available_destination_never_escapes_downloads() {
        let temp_dir = std::env::temp_dir().join(format!("simplepass-trav-{}", now_ms()));
        fs::create_dir_all(&temp_dir).expect("temp dir");
        let dest = available_destination(&temp_dir, "../../escape.txt").expect("destination");
        assert_eq!(dest.parent(), Some(temp_dir.as_path()));
        assert_eq!(dest.file_name().and_then(|n| n.to_str()), Some("escape.txt"));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn auto_open_allowlist_excludes_executables() {
        use std::path::Path;
        // Inert, viewer-opened types are allowed.
        assert!(is_safe_to_auto_open(Path::new("photo.PNG")));
        assert!(is_safe_to_auto_open(Path::new("notes.txt")));
        assert!(is_safe_to_auto_open(Path::new("doc.pdf")));
        // Executables / scripts / shortcuts / markup are never auto-opened.
        for unsafe_name in [
            "invoice.exe", "run.bat", "go.cmd", "x.ps1", "setup.msi", "link.lnk",
            "site.url", "page.hta", "index.html", "vector.svg", "macro.docm", "noext",
        ] {
            assert!(
                !is_safe_to_auto_open(Path::new(unsafe_name)),
                "{unsafe_name} must not be auto-openable"
            );
        }
    }

    #[test]
    fn enforce_peer_cap_drops_stalest_unpaired_first() {
        let mut state = PersistedState::default();
        // One paired peer that must survive, plus MAX_PEERS unpaired ones.
        let mut paired = peer_at("keep-paired", "10.0.0.1", "offline");
        paired.trust_state = "paired".to_string();
        paired.last_seen = 0; // stalest of all, yet must not be evicted
        state.peers.push(paired);
        for index in 0..MAX_PEERS {
            let mut peer = peer_at(&format!("u{index}"), "10.0.0.2", "online");
            peer.last_seen = (index as i64) + 1;
            state.peers.push(peer);
        }
        assert_eq!(state.peers.len(), MAX_PEERS + 1);

        enforce_peer_cap(&mut state);

        assert_eq!(state.peers.len(), MAX_PEERS);
        assert!(state.peers.iter().any(|peer| peer.id == "keep-paired"));
        // The stalest unpaired peer (u0, last_seen=1) was the one dropped.
        assert!(!state.peers.iter().any(|peer| peer.id == "u0"));
    }

    #[test]
    fn clamp_device_name_bounds_length() {
        let long = "a".repeat(MAX_DEVICE_NAME_LEN + 50);
        assert_eq!(clamp_device_name(&long).chars().count(), MAX_DEVICE_NAME_LEN);
        assert_eq!(clamp_device_name("  Desk  "), "Desk");
        assert_eq!(clamp_device_name("   "), "Unknown device");
    }
}
