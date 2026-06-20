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
    sync::Mutex,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupState {
    configured: bool,
    device_id: String,
    #[serde(default = "new_identity_secret")]
    identity_secret: String,
    device_name: String,
    start_at_login: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupResponse {
    configured: bool,
    device_id: String,
    device_name: String,
    start_at_login: bool,
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
}

#[derive(Debug, Clone)]
struct IncomingFile {
    path: PathBuf,
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
    let _ = send_plain_wire(&peer, WireMessage::PairRequest { device: packet });
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
    app.emit("peers-changed", peers).map_err(|err| err.to_string())
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
    let message = ChatMessage {
        id: Uuid::new_v4().to_string(),
        peer_id,
        direction: "sent".to_string(),
        text,
        created_at: now_ms(),
    };

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.messages.push(message.clone());
        save_state(&state.path, &persisted)?;
    }

    app.emit("chat-message", message).map_err(|err| err.to_string())
}

#[tauri::command]
fn receive_message(app: AppHandle, state: State<AppState>, peer_id: String, text: String) -> AppResult<()> {
    ensure_paired(&state, &peer_id)?;
    let message = ChatMessage {
        id: Uuid::new_v4().to_string(),
        peer_id,
        direction: "received".to_string(),
        text,
        created_at: now_ms(),
    };

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.messages.push(message.clone());
        save_state(&state.path, &persisted)?;
    }

    let _ = app
        .notification()
        .builder()
        .title("SimplePass")
        .body("New chat message")
        .show();
    app.emit("chat-message", message).map_err(|err| err.to_string())
}

#[tauri::command]
fn receive_link(state: State<AppState>, peer_id: String, url: String) -> AppResult<()> {
    ensure_paired(&state, &peer_id)?;
    open_url(&url)
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
        save_state(&state.path, &persisted)?;
    }

    Ok(transfers)
}

#[tauri::command]
fn send_files(
    app: AppHandle,
    state: State<AppState>,
    peer_ids: Vec<String>,
    paths: Vec<String>,
) -> AppResult<Vec<TransferProgress>> {
    if peer_ids.is_empty() || paths.is_empty() {
        return Ok(Vec::new());
    }

    let labels = paths
        .iter()
        .map(|path| Path::new(path).file_name().and_then(|name| name.to_str()).unwrap_or(path))
        .collect::<Vec<_>>()
        .join(", ");
    let transfers = make_transfers(&state, &peer_ids, &labels, "file")?;
    let mut transfers = transfers
        .into_iter()
        .map(|mut transfer| {
            transfer.progress = 0;
            transfer.state = "queued".to_string();
            transfer
        })
        .collect::<Vec<_>>();
    let local_id = existing_device_id(&state)?;
    for transfer in &mut transfers {
        emit_transfer(&app, transfer.clone())?;
        let peer = get_peer(&state, &transfer.peer_id)?;
        transfer.state = "sending".to_string();
        let total_bytes = paths
            .iter()
            .map(|path| fs::metadata(path).map(|metadata| metadata.len()).map_err(|err| err.to_string()))
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .sum::<u64>()
            .max(1);
        let mut sent_bytes = 0_u64;

        for path in &paths {
            let source = Path::new(path);
            let file_name = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "File path has no filename.".to_string())?
                .to_string();
            let transfer_id = Uuid::new_v4().to_string();
            match send_file_to_peer(&peer, &local_id, &transfer_id, source, &file_name, total_bytes, &mut sent_bytes, |progress| {
                transfer.progress = progress;
                emit_transfer(&app, transfer.clone())
            }) {
                Ok(()) => {
                    transfer.progress = ((sent_bytes as f64 / total_bytes as f64) * 100.0).round() as u8;
                    emit_transfer(&app, transfer.clone())?;
                }
                Err(err) => {
                    transfer.state = "failed".to_string();
                    transfer.error = Some(err);
                    emit_transfer(&app, transfer.clone())?;
                    break;
                }
            }
        }
        if transfer.state != "failed" {
            transfer.progress = 100;
            transfer.state = "complete".to_string();
            emit_transfer(&app, transfer.clone())?;
        }
    }

    {
        let mut persisted = state.inner.lock().map_err(lock_err)?;
        persisted.transfers.extend(transfers.clone());
        save_state(&state.path, &persisted)?;
    }

    Ok(transfers)
}

pub fn run() {
    tauri::Builder::default()
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
            });
            build_tray(app.handle())?;
            start_transport(app.handle().clone());
            Ok(())
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
            receive_message,
            receive_link,
            send_link,
            send_files
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
        Err(_) => return,
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
        let read = reader.read_line(&mut body).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
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
            let shared_secret = {
                let persisted = state.inner.lock().map_err(lock_err)?;
                derive_shared_secret(&persisted.setup.identity_secret, &device.public_key)?
            };
            upsert_discovered_peer(app, state, device, "paired", remote_addr, Some(shared_secret))?;
        }
        WireMessage::Chat { peer_id, text } => {
            receive_message(app.clone(), state.clone(), peer_id, text)?;
        }
        WireMessage::Link { peer_id, url } => {
            receive_link(state.clone(), peer_id, url)?;
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
        Err(_) => return,
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
                peer.host = host;
                peer.port = packet.port;
                peer.public_key = Some(packet.public_key.clone());
                peer.os = packet.os.clone();
                peer.status = "online".to_string();
                peer.last_seen = now_ms();
            }
            None => persisted.peers.push(PeerDevice {
                id: packet.device_id.clone(),
                name: packet.device_name.clone(),
                host,
                port: packet.port,
                public_key: Some(packet.public_key.clone()),
                os: packet.os.clone(),
                status: "online".to_string(),
                trust_state: "unpaired".to_string(),
                shared_secret: None,
                last_seen: now_ms(),
            }),
        }
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

/// Streams a single file to a peer over one TCP connection as `FileStart`,
/// repeated `FileChunk`s, then `FileEnd`. Keeping the whole file on one
/// connection guarantees the receiver processes the chunks in order.
fn send_file_to_peer<F>(
    peer: &PeerDevice,
    local_id: &str,
    transfer_id: &str,
    source: &Path,
    file_name: &str,
    total_bytes: u64,
    sent_bytes: &mut u64,
    mut on_progress: F,
) -> AppResult<()>
where
    F: FnMut(u8) -> AppResult<()>,
{
    if peer.host.trim().is_empty() {
        return Err(format!("{} does not have a network address yet.", peer.name));
    }
    let secret = peer
        .shared_secret
        .as_deref()
        .ok_or_else(|| format!("{} does not have a shared secret yet.", peer.name))?;
    let file_size = fs::metadata(source).map_err(|err| err.to_string())?.len();
    let file = fs::File::open(source).map_err(|err| err.to_string())?;
    let mut reader = BufReader::new(file);
    let mut stream = TcpStream::connect((peer.host.as_str(), peer.port)).map_err(|err| err.to_string())?;

    write_encrypted_line(
        &mut stream,
        local_id,
        secret,
        &WireMessage::FileStart {
            peer_id: local_id.to_string(),
            transfer_id: transfer_id.to_string(),
            file_name: file_name.to_string(),
            total_size: file_size,
        },
    )?;

    let mut buffer = vec![0_u8; FILE_CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        write_encrypted_line(
            &mut stream,
            local_id,
            secret,
            &WireMessage::FileChunk {
                peer_id: local_id.to_string(),
                transfer_id: transfer_id.to_string(),
                data: BASE64.encode(&buffer[..read]),
            },
        )?;
        *sent_bytes += read as u64;
        let progress = (((*sent_bytes as f64) / (total_bytes.max(1) as f64)) * 100.0)
            .round()
            .min(100.0) as u8;
        on_progress(progress)?;
    }

    write_encrypted_line(
        &mut stream,
        local_id,
        secret,
        &WireMessage::FileEnd {
            peer_id: local_id.to_string(),
            transfer_id: transfer_id.to_string(),
        },
    )?;
    stream.flush().map_err(|err| err.to_string())
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
        | WireMessage::FileEnd { peer_id, .. } => Ok(peer_id),
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

    TrayIconBuilder::new()
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
    let peer_name = get_peer(state, &peer_id)
        .map(|peer| peer.name)
        .unwrap_or_else(|_| "Unknown device".to_string());
    let downloads = dirs::download_dir().ok_or_else(|| "Downloads folder was not found.".to_string())?;
    let destination = available_destination(&downloads, std::ffi::OsStr::new(&file_name));
    // Create/truncate the destination so chunks can be appended in order.
    fs::write(&destination, b"").map_err(|err| err.to_string())?;

    {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        incoming.insert(
            transfer_id.clone(),
            IncomingFile {
                path: destination,
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
            state: "sending".to_string(),
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
    let progress = {
        let mut incoming = state.incoming_files.lock().map_err(lock_err)?;
        let entry = incoming
            .get_mut(&transfer_id)
            .ok_or_else(|| "Received a chunk for an unknown transfer.".to_string())?;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&entry.path)
            .map_err(|err| err.to_string())?;
        file.write_all(&bytes).map_err(|err| err.to_string())?;
        entry.received_size += bytes.len() as u64;
        (((entry.received_size as f64) / (entry.expected_size.max(1) as f64)) * 100.0)
            .round()
            .min(100.0) as u8
    };

    let (peer_name, file_name) = {
        let incoming = state.incoming_files.lock().map_err(lock_err)?;
        match incoming.get(&transfer_id) {
            Some(entry) => (entry.peer_name.clone(), entry.file_name.clone()),
            None => return Ok(()),
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
            state: "sending".to_string(),
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
    open::that(&entry.path).map_err(|err| err.to_string())?;

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

fn available_destination(downloads: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let original = Path::new(file_name);
    let stem = original
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let extension = original.extension().and_then(|value| value.to_str());
    let mut candidate = downloads.join(file_name);
    let mut counter = 1;

    while candidate.exists() {
        let next_name = match extension {
            Some(ext) => format!("{stem} ({counter}).{ext}"),
            None => format!("{stem} ({counter})"),
        };
        candidate = downloads.join(next_name);
        counter += 1;
    }

    candidate
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
    fs::write(path, body).map_err(|err| err.to_string())
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

        let destination = available_destination(&temp_dir, std::ffi::OsStr::new("report.pdf"));

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
            last_seen: 1_000,
        });

        let changed = apply_stale_peer_status(&mut state, 1_000 + PEER_OFFLINE_AFTER_MS + 1);

        assert!(changed);
        assert_eq!(state.peers[0].status, "offline");
    }
}
