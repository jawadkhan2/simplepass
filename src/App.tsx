import { useEffect, useMemo, useRef, useState } from "react";
import {
  Check,
  Download,
  FileText,
  Image as ImageIcon,
  Laptop,
  Link as LinkIcon,
  MessageSquare,
  Minus,
  Monitor,
  MoreVertical,
  RefreshCw,
  Settings,
  Share2,
  Square,
  Trash2,
  X
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import {
  isPermissionGranted,
  onAction as onNotificationAction,
  requestPermission,
  sendNotification
} from "@tauri-apps/plugin-notification";
import { api, events } from "./tauri";
import { applyPendingUpdate, checkForUpdate, startAutoUpdate } from "./updater";
import type { AvailableUpdate } from "./updater";
import type { ChatMessage, PeerDevice, SetupState, TransferProgress } from "./types";

const TRANSFER_LIMIT = 8;
const looksLikeUrl = (value: string) => /^https?:\/\/\S+$/i.test(value.trim());

// One-line preview of an incoming message for a toast body.
function notificationBody(message: ChatMessage): string {
  if (message.kind === "file") return `Sent a file: ${message.fileName ?? "file"}`;
  if (message.kind === "link") return message.url ?? "Sent a link";
  return message.text;
}

// Show an OS toast for an incoming message, but only while the main window is
// hidden — when it's visible the in-app chat is already the notification. The
// notification permission is requested lazily the first time we need it.
async function notifyIfHidden(message: ChatMessage): Promise<void> {
  try {
    if (await getCurrentWindow().isVisible()) return;
    let granted = await isPermissionGranted();
    if (!granted) granted = (await requestPermission()) === "granted";
    if (!granted) return;
    sendNotification({ title: "SimplePass", body: notificationBody(message) });
  } catch {
    // Notifications are best-effort; a failure here must not break message handling.
  }
}

function AppIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="tbIcon" x1="4" y1="4" x2="44" y2="44" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#e8a07e" />
          <stop offset="1" stopColor="#c8643c" />
        </linearGradient>
      </defs>
      <rect x="3" y="3" width="42" height="42" rx="11" fill="url(#tbIcon)" />
      <path
        d="M14 24h4l3-7 4 14 3-7h6"
        stroke="#ffffff"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="10" cy="24" r="4.2" fill="#ffe6d6" />
      <circle cx="38" cy="24" r="4.2" fill="#ffffff" />
    </svg>
  );
}

function TitleBar() {
  const win = getCurrentWindow();
  return (
    <div className="titlebar">
      <div className="titlebar-drag" data-tauri-drag-region>
        <span className="titlebar-icon"><AppIcon size={18} /></span>
        <span className="titlebar-title">SimplePass</span>
      </div>
      <div className="titlebar-controls">
        <button className="titlebar-btn" title="Minimize" onClick={() => win.minimize()}>
          <Minus size={15} strokeWidth={1.8} />
        </button>
        <button className="titlebar-btn" title="Maximize" onClick={() => win.toggleMaximize()}>
          <Square size={12} strokeWidth={1.8} />
        </button>
        <button className="titlebar-btn close" title="Close" onClick={() => win.close()}>
          <X size={16} strokeWidth={1.8} />
        </button>
      </div>
    </div>
  );
}

function WindowFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="window-root">
      <TitleBar />
      <div className="window-body">{children}</div>
    </div>
  );
}

function formatBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

// Downscale an image file to a square PNG data URL so avatars stay small enough
// to send to peers over the wire.
function resizeImageToDataUrl(file: File, size = 128): Promise<string> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        URL.revokeObjectURL(url);
        reject(new Error("Canvas is unavailable."));
        return;
      }
      const scale = Math.max(size / img.width, size / img.height);
      const w = img.width * scale;
      const h = img.height * scale;
      ctx.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);
      URL.revokeObjectURL(url);
      resolve(canvas.toDataURL("image/png"));
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Could not read the image."));
    };
    img.src = url;
  });
}

function Avatar({ src, size = 34 }: { src?: string | null; size?: number }) {
  if (src) {
    return <img className="avatar-img" src={src} alt="" draggable={false} />;
  }
  return <Laptop size={size} />;
}

// Short, human-comparable fingerprint of a base64 X25519 public key. Both devices
// derive the same value for the same key, so the person approving a pairing can
// read it out-of-band to confirm they're trusting the right machine — the only
// real defence against a LAN device spoofing another's name.
async function fingerprintOf(publicKey: string): Promise<string> {
  const raw = Uint8Array.from(atob(publicKey), (c) => c.charCodeAt(0));
  const digest = await crypto.subtle.digest("SHA-256", raw);
  return Array.from(new Uint8Array(digest))
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
    .join("")
    .replace(/(.{4})(?=.)/g, "$1 ");
}

function KeyFingerprint({ publicKey }: { publicKey?: string | null }) {
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    if (!publicKey) {
      setFingerprint(null);
      return;
    }
    void fingerprintOf(publicKey).then((value) => {
      if (active) setFingerprint(value);
    });
    return () => {
      active = false;
    };
  }, [publicKey]);
  if (!fingerprint) return null;
  return <code className="key-fingerprint">{fingerprint}</code>;
}

export default function App() {
  const [setup, setSetup] = useState<SetupState | null>(null);
  const [peers, setPeers] = useState<PeerDevice[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [chatPeerId, setChatPeerId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [transfers, setTransfers] = useState<TransferProgress[]>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pairingRequest, setPairingRequest] = useState<PeerDevice | null>(null);
  const [dragPeerId, setDragPeerId] = useState<string | null>(null);
  const [chatDragActive, setChatDragActive] = useState(false);
  const [typingPeers, setTypingPeers] = useState<Record<string, boolean>>({});
  const [update, setUpdate] = useState<AvailableUpdate | null>(null);
  const [rescanning, setRescanning] = useState(false);

  const typingTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  // The native drag-drop listener is set up once; it reads live selection/peer
  // state through refs to avoid a stale closure.
  const peersRef = useRef(peers);
  const selectedIdsRef = useRef(selectedIds);
  const chatPeerIdRef = useRef(chatPeerId);
  peersRef.current = peers;
  selectedIdsRef.current = selectedIds;
  chatPeerIdRef.current = chatPeerId;

  const selectedPeers = useMemo(
    () => peers.filter((peer) => selectedIds.includes(peer.id) && peer.trustState === "paired"),
    [peers, selectedIds]
  );

  useEffect(() => {
    void api.getSetupState().then(setSetup);
    void api.listPeers().then(setPeers);

    const unsubs = [
      events.onPeersChanged(setPeers),
      events.onPairingRequest(setPairingRequest),
      events.onSetupChanged(setSetup),
      events.onTransportError(setError),
      events.onMessage((message) => {
        // Read the open chat through a ref so this listener is set up once instead
        // of being torn down and rebuilt on every chat switch (peer updates arrive
        // separately via onPeersChanged).
        setMessages((current) =>
          message.peerId === chatPeerIdRef.current ? [...current, message] : current
        );
        // Toast incoming messages only when the window is hidden, so the user is
        // alerted without being interrupted while the app is already in front.
        // Clicking the toast surfaces the window (see the onAction effect below).
        if (message.direction === "received") void notifyIfHidden(message);
      }),
      events.onTransfer((transfer) => {
        // The dock only shows in-flight transfers. Finished rows (complete/failed)
        // drop off — the chat retains the permanent record of files and links.
        setTransfers((current) => {
          const rest = current.filter((item) => item.id !== transfer.id);
          if (["complete", "failed", "cancelled"].includes(transfer.state)) return rest;
          return [transfer, ...rest].slice(0, TRANSFER_LIMIT);
        });
      }),
      events.onTyping(({ peerId, isTyping }) => {
        setTypingPeers((current) => ({ ...current, [peerId]: isTyping }));
        clearTimeout(typingTimers.current[peerId]);
        if (isTyping) {
          typingTimers.current[peerId] = setTimeout(
            () => setTypingPeers((current) => ({ ...current, [peerId]: false })),
            4000
          );
        }
      })
    ];

    return () => {
      void Promise.all(unsubs.map(async (unsubscribe) => (await unsubscribe)()));
    };
  }, []);

  useEffect(() => startAutoUpdate(setUpdate), []);

  // A click on an incoming-message toast brings the main window forward. The
  // action listener is process-wide, so it is registered once.
  useEffect(() => {
    let listener: { unregister: () => Promise<void> } | undefined;
    let cancelled = false;
    void onNotificationAction(() => void api.showWindow().catch(() => undefined)).then((handle) => {
      if (cancelled) void handle.unregister();
      else listener = handle;
    });
    return () => {
      cancelled = true;
      if (listener) void listener.unregister();
    };
  }, []);

  // Native OS drag-drop (dragDropEnabled in tauri.conf.json) delivers real file
  // paths, unlike HTML5 drops. We hit-test the cursor position to find the target
  // tile or the chat panel, then stream the dropped paths to that peer.
  useEffect(() => {
    function targetAt(physicalX: number, physicalY: number) {
      const cssX = physicalX / window.devicePixelRatio;
      const cssY = physicalY / window.devicePixelRatio;
      const el = document.elementFromPoint(cssX, cssY);
      if (!el) return null;
      const tile = el.closest("[data-peer-id]");
      if (tile) return { kind: "peer" as const, id: tile.getAttribute("data-peer-id") ?? "" };
      if (el.closest(".chat-panel")) return { kind: "chat" as const };
      return null;
    }

    function targetIdsForPeerId(peerId: string): string[] {
      const list = peersRef.current;
      const selected = selectedIdsRef.current;
      const peer = list.find((item) => item.id === peerId);
      if (!peer || peer.trustState !== "paired") return [];
      if (selected.includes(peerId)) {
        return list
          .filter((item) => selected.includes(item.id) && item.trustState === "paired")
          .map((item) => item.id);
      }
      return [peerId];
    }

    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void getCurrentWebview()
      .onDragDropEvent((event) => {
        const payload = event.payload;
        if (payload.type === "enter" || payload.type === "over") {
          const target = targetAt(payload.position.x, payload.position.y);
          setDragPeerId(target?.kind === "peer" ? target.id : null);
          setChatDragActive(target?.kind === "chat");
        } else if (payload.type === "leave") {
          setDragPeerId(null);
          setChatDragActive(false);
        } else if (payload.type === "drop") {
          setDragPeerId(null);
          setChatDragActive(false);
          const paths = payload.paths ?? [];
          if (paths.length === 0) return;
          const target = targetAt(payload.position.x, payload.position.y);
          let peerIds: string[] = [];
          if (target?.kind === "peer") peerIds = targetIdsForPeerId(target.id);
          else if (target?.kind === "chat" && chatPeerIdRef.current) {
            peerIds = targetIdsForPeerId(chatPeerIdRef.current);
          }
          if (peerIds.length === 0) return;
          api.sendFiles(peerIds, paths).catch((err) => setError(String(err)));
        }
      })
      .then((fn) => {
        // If cleanup already ran before this promise resolved (StrictMode mounts
        // the effect twice), detach immediately so we never leak a second live
        // listener — a leaked listener fires every drop twice.
        if (cancelled) {
          fn();
          return;
        }
        unlisten = fn;
      });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  useEffect(() => {
    if (!chatPeerId) return;
    void api.listMessages(chatPeerId).then(setMessages);
  }, [chatPeerId]);

  if (!setup) {
    return (
      <WindowFrame>
        <main className="loading">Starting SimplePass...</main>
      </WindowFrame>
    );
  }

  if (!setup.configured) {
    return (
      <WindowFrame>
        <FirstRun onComplete={setSetup} />
      </WindowFrame>
    );
  }

  const activeChatPeer = peers.find((peer) => peer.id === chatPeerId) ?? null;

  function targetPeerIdsFor(peer: PeerDevice) {
    const targetPeers = selectedIds.includes(peer.id)
      ? selectedPeers
      : [peer].filter((item) => item.trustState === "paired");
    return targetPeers.map((item) => item.id);
  }

  async function openShareDialog(peer: PeerDevice) {
    const peerIds = targetPeerIdsFor(peer);
    if (peerIds.length === 0) return;
    try {
      const selection = await openFileDialog({ multiple: true });
      if (!selection) return;
      const paths = Array.isArray(selection) ? selection : [selection];
      if (paths.length === 0) return;
      await api.sendFiles(peerIds, paths);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function toggleSelected(peerId: string) {
    setSelectedIds((current) =>
      current.includes(peerId) ? current.filter((id) => id !== peerId) : [...current, peerId]
    );
  }

  return (
    <WindowFrame>
    <main className="app-shell">
      {update && (
        <div className="update-banner">
          <Download size={16} />
          <div className="update-banner-text">
            <span>SimplePass {update.version} is available.</span>
            {update.notes && <p className="update-banner-notes">{update.notes}</p>}
          </div>
          <button
            className="update-banner-apply"
            onClick={() => applyPendingUpdate().catch((err) => setError(String(err)))}
          >
            Update now
          </button>
          <button className="update-banner-dismiss" title="Later" onClick={() => setUpdate(null)}>
            <X size={14} />
          </button>
        </div>
      )}
      <header className="topbar">
        <div className="brand">
          <BrandMark />
          <div>
            <h1>Simple<span className="brand-accent">Pass</span></h1>
            <p>{setup.deviceName}</p>
          </div>
        </div>
        <div className="topbar-right">
          <span className="me-avatar" title="You">
            <Avatar src={setup.avatar} size={20} />
          </span>
          <button className="icon-button" title="Settings" onClick={() => setSettingsOpen(true)}>
            <Settings size={20} />
          </button>
        </div>
      </header>

      <section className="workspace">
        <div className="devices-panel">
          <div className="section-heading">
            <h2>Nearby Computers</h2>
            <span>{peers.filter((peer) => peer.status === "online").length} online</span>
            <button
              className="rescan-button"
              title="Rescan the network"
              disabled={rescanning}
              onClick={() => {
                setRescanning(true);
                api.rescanPeers()
                  .catch((err) => setError(String(err)))
                  // Keep the spinner up briefly so a near-instant reply still reads as a scan.
                  .finally(() => setTimeout(() => setRescanning(false), 900));
              }}
            >
              <RefreshCw size={16} className={rescanning ? "spinning" : ""} />
            </button>
          </div>
          <div className="device-grid">
            {peers.map((peer) => (
              <DeviceTile
                key={peer.id}
                peer={peer}
                selected={selectedIds.includes(peer.id)}
                dragActive={dragPeerId === peer.id}
                onSelect={() => toggleSelected(peer.id)}
                onPair={() => api.pairPeer(peer.id).catch((err) => setError(String(err)))}
                onChat={() => setChatPeerId(peer.id)}
                onShare={() => openShareDialog(peer)}
                onDelete={() => {
                  if (!window.confirm(`Delete ${peer.name}? This removes the pairing and its chat history.`)) return;
                  api.deletePeer(peer.id).catch((err) => setError(String(err)));
                }}
              />
            ))}
            {peers.length === 0 && (
              <div className="empty-state">
                <Monitor size={42} />
                <p>Looking for SimplePass computers on this network.</p>
              </div>
            )}
          </div>
        </div>

        <ChatPanel
          peer={activeChatPeer}
          messages={messages}
          peerTyping={activeChatPeer ? Boolean(typingPeers[activeChatPeer.id]) : false}
          dragActive={chatDragActive}
          onClose={() => setChatPeerId(null)}
          onError={setError}
        />
      </section>

      {transfers.length > 0 && (
        <section className="transfer-dock">
          {transfers.map((transfer) => (
            <div className="transfer-row" key={transfer.id}>
              <div>
                <strong>{transfer.peerName}</strong>
                <span>{transfer.label}</span>
              </div>
              <progress value={transfer.progress} max={100} />
              <small>{transfer.state}</small>
              {(transfer.state === "sending" || transfer.state === "queued") && (
                <button
                  className="transfer-cancel"
                  title="Cancel transfer"
                  onClick={() => api.cancelFileSend(transfer.id.split(":")[0]).catch((err) => setError(String(err)))}
                >
                  <X size={14} />
                </button>
              )}
            </div>
          ))}
        </section>
      )}

      {error && (
        <div className="toast-error" role="alert">
          <span>{error}</span>
          <button onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {pairingRequest && (
        <PairingModal
          peer={pairingRequest}
          onAccept={() => {
            api.acceptPairing(pairingRequest.id)
              .then(() => setPairingRequest(null))
              .catch((err) => setError(String(err)));
          }}
          onDeny={() => {
            api.denyPairing(pairingRequest.id)
              .then(() => setPairingRequest(null))
              .catch((err) => setError(String(err)));
          }}
        />
      )}

      {settingsOpen && (
        <SettingsPanel
          setup={setup}
          peers={peers}
          onClose={() => setSettingsOpen(false)}
          onSetup={setSetup}
          onError={setError}
          onClearedMessages={() => setMessages([])}
        />
      )}
    </main>
    </WindowFrame>
  );
}

// Pulse Link mark: two nodes with a live signal pulse between them.
function BrandMark({ size = 38 }: { size?: number }) {
  return (
    <span className="brand-mark" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M14 24h4l3-7 4 14 3-7h6" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="10" cy="24" r="5" fill="#ffe6d6" />
        <circle cx="38" cy="24" r="5" fill="#fff" />
      </svg>
    </span>
  );
}

function FirstRun({ onComplete }: { onComplete: (setup: SetupState) => void }) {
  const [deviceName, setDeviceName] = useState("");
  const [startAtLogin, setStartAtLogin] = useState(true);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const saved = await api.saveSetup(deviceName.trim(), startAtLogin);
    onComplete(saved);
  }

  return (
    <main className="setup-screen">
      <form className="setup-card" onSubmit={submit}>
        <BrandMark size={52} />
        <h1>SimplePass</h1>
        <p>Name this computer so other people can recognize it on your network.</p>
        <label>
          Device name
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} autoFocus required />
        </label>
        <label className="check-row">
          <input type="checkbox" checked={startAtLogin} onChange={(event) => setStartAtLogin(event.target.checked)} />
          Start SimplePass when I log in
        </label>
        <button type="submit">Continue</button>
      </form>
    </main>
  );
}

function DeviceTile(props: {
  peer: PeerDevice;
  selected: boolean;
  dragActive: boolean;
  onSelect: () => void;
  onPair: () => void;
  onChat: () => void;
  onShare: () => void;
  onDelete: () => void;
}) {
  const { peer } = props;
  const paired = peer.trustState === "paired";

  return (
    <article
      data-peer-id={peer.id}
      className={`device-tile ${props.selected ? "selected" : ""} ${paired ? "paired" : "unpaired"} ${
        props.dragActive ? "drag-over" : ""
      }`}
      onClick={props.onSelect}
    >
      <div className="tile-menu">
        <button title="Delete computer" onClick={(event) => { event.stopPropagation(); props.onDelete(); }}>
          <Trash2 size={16} />
        </button>
        <MoreVertical size={16} />
      </div>
      <div className="device-avatar">
        <Avatar src={peer.avatar} size={34} />
      </div>
      <h3>{peer.name}</h3>
      <p>{peer.os || peer.host}{peer.host ? ` · ${peer.host}` : ""}</p>
      <span className={`status-dot ${peer.status}`}>{peer.status}</span>
      <div className="tile-actions">
        {paired ? (
          <>
            <button onClick={(event) => { event.stopPropagation(); props.onChat(); }}>
              <MessageSquare size={16} />
              Chat
            </button>
            <button className="ghost-btn" title="Send a file" onClick={(event) => { event.stopPropagation(); props.onShare(); }}>
              <Share2 size={16} />
              Share
            </button>
          </>
        ) : peer.trustState === "pending" ? (
          <button disabled>
            <Check size={16} />
            Pending
          </button>
        ) : (
          <button onClick={(event) => { event.stopPropagation(); props.onPair(); }}>
            <Check size={16} />
            Pair
          </button>
        )}
      </div>
      {props.dragActive && (
        <div className="drop-overlay">
          <Download size={26} />
          <span>Drop to send</span>
        </div>
      )}
    </article>
  );
}

function PairingModal({ peer, onAccept, onDeny }: { peer: PeerDevice; onAccept: () => void; onDeny: () => void }) {
  return (
    <div className="modal-backdrop">
      <section className="pairing-panel">
        <div className="device-avatar">
          <Avatar src={peer.avatar} size={34} />
        </div>
        <h2>{peer.name} wants to pair</h2>
        <p>{peer.os || "Computer"} {peer.host ? `on ${peer.host}` : ""}</p>
        {peer.publicKey && (
          <p className="pairing-verify">
            Verify this matches the key shown on that computer:
            <KeyFingerprint publicKey={peer.publicKey} />
          </p>
        )}
        <div className="pairing-actions">
          <button className="secondary" onClick={onDeny}>Deny</button>
          <button className="primary" onClick={onAccept}>Accept</button>
        </div>
      </section>
    </div>
  );
}

function MessageBubble({ message }: { message: ChatMessage }) {
  if (message.kind === "file") {
    const path = message.filePath;
    const openable = Boolean(path);
    return (
      <div
        className={`message file-message ${message.direction}${openable ? " openable" : ""}`}
        title={openable ? "Open file" : undefined}
        role={openable ? "button" : undefined}
        tabIndex={openable ? 0 : undefined}
        onClick={() => openable && path && api.openPath(path).catch(() => undefined)}
        onKeyDown={(event) => {
          if (openable && path && (event.key === "Enter" || event.key === " ")) {
            event.preventDefault();
            api.openPath(path).catch(() => undefined);
          }
        }}
      >
        <span className="file-icon"><FileText size={18} /></span>
        <div className="file-meta">
          <strong>{message.fileName ?? "File"}</strong>
          <small>{formatBytes(message.fileSize)}{message.direction === "received" ? " · saved to Downloads" : ""}</small>
        </div>
        {openable && <span className="file-open">Open</span>}
      </div>
    );
  }

  if (message.kind === "link" && message.url) {
    const url = message.url;
    return (
      <div
        className={`message link-message ${message.direction} openable`}
        title={`Open ${url}`}
        role="button"
        tabIndex={0}
        onClick={() => api.openLink(url).catch(() => undefined)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            api.openLink(url).catch(() => undefined);
          }
        }}
      >
        <span className="file-icon"><LinkIcon size={16} /></span>
        <span className="link-text">{url}</span>
      </div>
    );
  }

  return <p className={`message ${message.direction}`}>{message.text}</p>;
}

function ChatPanel({
  peer,
  messages,
  peerTyping,
  dragActive,
  onClose,
  onError
}: {
  peer: PeerDevice | null;
  messages: ChatMessage[];
  peerTyping: boolean;
  dragActive: boolean;
  onClose: () => void;
  onError: (message: string) => void;
}) {
  const [text, setText] = useState("");
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const typingSent = useRef(false);
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const peerId = peer?.id ?? null;

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, peerTyping]);

  // Stop signalling "typing" when the chat closes or switches peers.
  useEffect(() => {
    return () => {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      if (typingSent.current && peerId) {
        void api.sendTyping(peerId, false).catch(() => undefined);
        typingSent.current = false;
      }
    };
  }, [peerId]);

  if (!peer || !peerId) {
    return (
      <aside className="chat-panel empty-chat">
        <MessageSquare size={34} />
        <p>Select a paired computer to chat.</p>
      </aside>
    );
  }

  function onChange(event: React.ChangeEvent<HTMLInputElement>) {
    setText(event.target.value);
    if (!peerId) return;
    if (!typingSent.current) {
      typingSent.current = true;
      void api.sendTyping(peerId, true).catch(() => undefined);
    }
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = setTimeout(() => {
      typingSent.current = false;
      if (peerId) void api.sendTyping(peerId, false).catch(() => undefined);
    }, 1500);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const value = text.trim();
    if (!value || !peerId) return;
    try {
      // Native drag-drop replaces HTML5 URL drops, so the composer doubles as the
      // way to share a link: a bare URL is sent as a link (opens on both sides).
      if (looksLikeUrl(value)) {
        await api.sendLink([peerId], value);
      } else {
        await api.sendMessage(peerId, value);
      }
      setText("");
      if (idleTimer.current) clearTimeout(idleTimer.current);
      typingSent.current = false;
      void api.sendTyping(peerId, false).catch(() => undefined);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <aside className={`chat-panel${dragActive ? " drag-over" : ""}`}>
      {dragActive && (
        <div className="drop-overlay">
          <Download size={26} />
          <span>Drop to send</span>
        </div>
      )}
      <header>
        <div className="chat-peer">
          <span className="chat-avatar"><Avatar src={peer.avatar} size={22} /></span>
          <div>
            <h2>{peer.name}</h2>
            <span>{peerTyping ? "typing…" : peer.status}</span>
          </div>
        </div>
        <button className="icon-button" title="Close chat" onClick={onClose}><X size={18} /></button>
      </header>
      <div className="message-list">
        {messages.map((message) => (
          <MessageBubble key={message.id} message={message} />
        ))}
        {peerTyping && (
          <div className="message received typing-bubble">
            <span className="typing-dot" />
            <span className="typing-dot" />
            <span className="typing-dot" />
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <form className="composer" onSubmit={submit}>
        <input value={text} onChange={onChange} placeholder="Message" />
        <button type="submit">Send</button>
      </form>
    </aside>
  );
}

function SettingsPanel(props: {
  setup: SetupState;
  peers: PeerDevice[];
  onClose: () => void;
  onSetup: (setup: SetupState) => void;
  onError: (message: string) => void;
  onClearedMessages: () => void;
}) {
  const [deviceName, setDeviceName] = useState(props.setup.deviceName);
  const [startAtLogin, setStartAtLogin] = useState(props.setup.startAtLogin);
  const [avatar, setAvatar] = useState<string | null>(props.setup.avatar ?? null);
  const [floatingIcon, setFloatingIcon] = useState(props.setup.floatingIcon ?? false);
  const [autoOpen, setAutoOpen] = useState(props.setup.autoOpen ?? false);
  // Serialize floating-icon toggles: rapid clicks fire overlapping set_floating_icon
  // commands that the backend can complete out of order, so a late show()/hide()
  // wins over the user's final choice. Run one command at a time and always reapply
  // the latest desired state.
  const toggleRunning = useRef(false);
  const desiredFloating = useRef<boolean | null>(null);
  const [version, setVersion] = useState("");
  const [updateStatus, setUpdateStatus] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [updateReady, setUpdateReady] = useState(false);
  const [installing, setInstalling] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    void getVersion().then(setVersion);
  }, []);

  async function pickAvatar(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      const dataUrl = await resizeImageToDataUrl(file);
      setAvatar(dataUrl);
      const updated = await api.setAvatar(dataUrl);
      props.onSetup(updated);
    } catch (err) {
      props.onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function removeAvatar() {
    setAvatar(null);
    try {
      const updated = await api.setAvatar(null);
      props.onSetup(updated);
    } catch (err) {
      props.onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function save() {
    const setup = await api.saveSetup(deviceName.trim(), startAtLogin);
    props.onSetup(setup);
    props.onClose();
  }

  async function toggleFloatingIcon(enabled: boolean) {
    // Optimistic flip so the checkbox responds instantly; record the target and let
    // the running loop pick it up (coalescing rapid clicks to the latest value).
    setFloatingIcon(enabled);
    desiredFloating.current = enabled;
    if (toggleRunning.current) return;
    toggleRunning.current = true;
    try {
      while (desiredFloating.current !== null) {
        const target = desiredFloating.current;
        desiredFloating.current = null;
        const updated = await api.setFloatingIcon(target);
        props.onSetup(updated);
      }
    } catch (err) {
      // Revert to the last value the backend actually confirmed.
      desiredFloating.current = null;
      setFloatingIcon(!enabled);
      props.onError(err instanceof Error ? err.message : String(err));
    } finally {
      toggleRunning.current = false;
    }
  }

  async function toggleAutoOpen(enabled: boolean) {
    setAutoOpen(enabled); // optimistic
    try {
      const updated = await api.setAutoOpen(enabled);
      props.onSetup(updated);
    } catch (err) {
      setAutoOpen(!enabled); // revert on failure
      props.onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function clearChat() {
    try {
      await api.clearMessages();
      props.onClearedMessages();
    } catch (err) {
      props.onError(err instanceof Error ? err.message : String(err));
    }
  }

  async function checkUpdates() {
    setChecking(true);
    setUpdateReady(false);
    setUpdateStatus("Checking for updates...");
    const outcome = await checkForUpdate();
    setChecking(false);
    if (outcome.status === "up-to-date") {
      setUpdateStatus("You're on the latest version.");
    } else if (outcome.status === "available") {
      setUpdateStatus(`Version ${outcome.version} is available.`);
      setUpdateReady(true);
    } else {
      setUpdateStatus(`Update check failed: ${outcome.message}`);
    }
  }

  async function installUpdate() {
    setInstalling(true);
    setUpdateStatus("Downloading and installing...");
    try {
      await applyPendingUpdate();
    } catch (err) {
      setInstalling(false);
      setUpdateStatus(`Update failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return (
    <div className="modal-backdrop">
      <section className="settings-panel">
        <header>
          <h2>Settings</h2>
          <button className="icon-button" onClick={props.onClose}><X size={18} /></button>
        </header>

        <div className="avatar-row">
          <span className="avatar-preview"><Avatar src={avatar} size={32} /></span>
          <div className="avatar-actions">
            <input ref={avatarInputRef} type="file" accept="image/*" hidden onChange={pickAvatar} />
            <button className="secondary" onClick={() => avatarInputRef.current?.click()}>
              <ImageIcon size={16} /> Choose picture
            </button>
            {avatar && <button className="link-button" onClick={removeAvatar}>Remove</button>}
          </div>
        </div>

        <label>
          Device name
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
        </label>
        <label className="check-row">
          <input type="checkbox" checked={startAtLogin} onChange={(event) => setStartAtLogin(event.target.checked)} />
          Start SimplePass when I log in
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={floatingIcon}
            onChange={(event) => void toggleFloatingIcon(event.target.checked)}
          />
          Show a floating desktop icon
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={autoOpen}
            onChange={(event) => void toggleAutoOpen(event.target.checked)}
          />
          Open received files &amp; links automatically
        </label>

        {props.setup.publicKey && (
          <div className="device-key-row">
            <span className="muted">This computer's key</span>
            <KeyFingerprint publicKey={props.setup.publicKey} />
          </div>
        )}

        <h3>Trusted devices</h3>
        <div className="trusted-list">
          {props.peers.filter((peer) => peer.trustState === "paired").map((peer) => (
            <div key={peer.id}>
              <span>{peer.name}</span>
              <div className="trusted-actions">
                <button onClick={() => api.revokePeer(peer.id).catch((err) => props.onError(String(err)))}>Unpair</button>
                <button
                  className="link-button danger"
                  onClick={() => {
                    if (!window.confirm(`Delete ${peer.name}? This removes the pairing and its chat history.`)) return;
                    api.deletePeer(peer.id).catch((err) => props.onError(String(err)));
                  }}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
          {props.peers.filter((peer) => peer.trustState === "paired").length === 0 && (
            <p className="muted">No paired devices yet.</p>
          )}
        </div>

        <h3>History</h3>
        <div className="history-actions">
          <button className="secondary" onClick={clearChat}>Clear all chat history</button>
        </div>

        <h3>Updates</h3>
        <div className="update-row">
          <span>Version {version || "…"}</span>
          {updateReady ? (
            <button className="primary" onClick={installUpdate} disabled={installing}>
              {installing ? "Installing…" : "Update now"}
            </button>
          ) : (
            <button onClick={checkUpdates} disabled={checking}>Check for updates</button>
          )}
        </div>
        {updateStatus && <p className="update-status">{updateStatus}</p>}

        <button className="primary" onClick={save}>Save</button>
      </section>
    </div>
  );
}
