import { useEffect, useMemo, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Check, Laptop, MessageSquare, Monitor, MoreVertical, Settings, Trash2, X } from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";
import { api, events } from "./tauri";
import { checkForUpdate, startAutoUpdate } from "./updater";
import type { ChatMessage, PeerDevice, SetupState, TransferProgress } from "./types";

const TRANSFER_LIMIT = 8;
const looksLikeUrl = (value: string) => /^https?:\/\/\S+$/i.test(value.trim());
const isRecentNativeDrop = (drop: NativeFileDrop | null) => drop !== null && Date.now() - drop.createdAt < 1200;

// Merge incoming transfers with the existing list, replacing rows that share an
// id (the backend also streams progress events for the same ids) instead of
// appending duplicates.
function mergeTransfers(incoming: TransferProgress[], current: TransferProgress[]): TransferProgress[] {
  const byId = new Map<string, TransferProgress>();
  for (const transfer of [...incoming, ...current]) {
    if (!byId.has(transfer.id)) byId.set(transfer.id, transfer);
  }
  return Array.from(byId.values()).slice(0, TRANSFER_LIMIT);
}

interface NativeFileDrop {
  paths: string[];
  x: number;
  y: number;
  createdAt: number;
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
  const [nativeFileDrop, setNativeFileDrop] = useState<NativeFileDrop | null>(null);

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
      events.onMessage((message) => {
        setMessages((current) => (message.peerId === chatPeerId ? [...current, message] : current));
        void api.listPeers().then(setPeers);
      }),
      events.onTransfer((transfer) => {
        setTransfers((current) => {
          const existing = current.findIndex((item) => item.id === transfer.id);
          if (existing === -1) return [transfer, ...current].slice(0, TRANSFER_LIMIT);
          const next = [...current];
          next[existing] = transfer;
          return next;
        });
      })
    ];

    return () => {
      void Promise.all(unsubs.map(async (unsubscribe) => (await unsubscribe)()));
    };
  }, [chatPeerId]);

  useEffect(() => {
    let active = true;
    let cleanup: (() => void) | null = null;

    void getCurrentWebview()
      .onDragDropEvent((event) => {
        if (!active) return;
        if (event.payload.type === "drop") {
          const drop = {
            paths: event.payload.paths,
            x: event.payload.position.x,
            y: event.payload.position.y,
            createdAt: Date.now()
          };
          setNativeFileDrop(drop);

          const element = document.elementFromPoint(drop.x, drop.y);
          const peerId = element?.closest<HTMLElement>("[data-peer-id]")?.dataset.peerId;
          const peer = peers.find((item) => item.id === peerId);
          if (peer) {
            void sendFilesToPeer(peer, drop.paths);
          }
        } else if (event.payload.type === "leave") {
          setNativeFileDrop(null);
        }
      })
      .then((unlisten) => {
        cleanup = unlisten;
      })
      .catch((err) => setError(String(err)));

    return () => {
      active = false;
      cleanup?.();
    };
  }, [peers, selectedIds, selectedPeers]);

  useEffect(() => startAutoUpdate(), []);

  useEffect(() => {
    if (!chatPeerId) return;
    void api.listMessages(chatPeerId).then(setMessages);
  }, [chatPeerId]);

  if (!setup) return <main className="loading">Starting SimplePass...</main>;

  if (!setup.configured) {
    return <FirstRun onComplete={setSetup} />;
  }

  const activeChatPeer = peers.find((peer) => peer.id === chatPeerId) ?? null;

  function targetPeerIdsFor(peer: PeerDevice) {
    const targetPeers = selectedIds.includes(peer.id) ? selectedPeers : [peer].filter((item) => item.trustState === "paired");
    return targetPeers.map((item) => item.id);
  }

  async function sendFilesToPeer(peer: PeerDevice, paths: string[]) {
    const peerIds = targetPeerIdsFor(peer);
    if (peerIds.length === 0 || paths.length === 0) return;

    try {
      setNativeFileDrop(null);
      const created = await api.sendFiles(peerIds, paths);
      setTransfers((current) => mergeTransfers(created, current));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleDrop(peer: PeerDevice, event: React.DragEvent) {
    event.preventDefault();
    const peerIds = targetPeerIdsFor(peer);
    if (peerIds.length === 0) return;

    const text = event.dataTransfer.getData("text/uri-list") || event.dataTransfer.getData("text/plain");
    const nativeDrop = isRecentNativeDrop(nativeFileDrop) ? nativeFileDrop : null;
    const rect = event.currentTarget.getBoundingClientRect();
    const nativeDropLandedHere = nativeDrop
      ? nativeDrop.x >= rect.left && nativeDrop.x <= rect.right && nativeDrop.y >= rect.top && nativeDrop.y <= rect.bottom
      : false;
    const paths = nativeDrop && nativeDropLandedHere ? nativeDrop.paths : [];

    try {
      if (paths.length > 0) {
        await sendFilesToPeer(peer, paths);
        return;
      }

      if (text && looksLikeUrl(text)) {
        const created = await api.sendLink(peerIds, text.trim());
        setTransfers((current) => mergeTransfers(created, current));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function toggleSelected(peerId: string) {
    setSelectedIds((current) => current.includes(peerId) ? current.filter((id) => id !== peerId) : [...current, peerId]);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>SimplePass</h1>
          <p>{setup.deviceName}</p>
        </div>
        <button className="icon-button" title="Settings" onClick={() => setSettingsOpen(true)}>
          <Settings size={20} />
        </button>
      </header>

      <section className="workspace">
        <div className="devices-panel">
          <div className="section-heading">
            <h2>Nearby Computers</h2>
            <span>{peers.filter((peer) => peer.status === "online").length} online</span>
          </div>
          <div className="device-grid">
            {peers.map((peer) => (
              <DeviceTile
                key={peer.id}
                peer={peer}
                selected={selectedIds.includes(peer.id)}
                onSelect={() => toggleSelected(peer.id)}
                onDrop={(event) => handleDrop(peer, event)}
                onPair={() => api.pairPeer(peer.id).catch((err) => setError(String(err)))}
                onChat={() => setChatPeerId(peer.id)}
                onRevoke={() => api.revokePeer(peer.id).catch((err) => setError(String(err)))}
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

        <ChatPanel peer={activeChatPeer} messages={messages} onClose={() => setChatPeerId(null)} />
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

      {settingsOpen && <SettingsPanel setup={setup} peers={peers} onClose={() => setSettingsOpen(false)} onSetup={setSetup} />}
    </main>
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
  onSelect: () => void;
  onDrop: (event: React.DragEvent) => void;
  onPair: () => void;
  onChat: () => void;
  onRevoke: () => void;
}) {
  const { peer } = props;
  const paired = peer.trustState === "paired";

  return (
    <article
      data-peer-id={peer.id}
      className={`device-tile ${props.selected ? "selected" : ""} ${paired ? "paired" : "unpaired"}`}
      onDragOver={(event) => paired && event.preventDefault()}
      onDrop={props.onDrop}
      onClick={props.onSelect}
    >
      <div className="tile-menu">
        {paired && (
          <button title="Remove paired computer" onClick={(event) => { event.stopPropagation(); props.onRevoke(); }}>
            <Trash2 size={16} />
          </button>
        )}
        <MoreVertical size={16} />
      </div>
      <div className="device-avatar">
        <Laptop size={34} />
      </div>
      <h3>{peer.name}</h3>
      <p>{peer.os || peer.host}{peer.host ? ` · ${peer.host}` : ""}</p>
      <span className={`status-dot ${peer.status}`}>{peer.status}</span>
      <div className="tile-actions">
        {paired ? (
          <button onClick={(event) => { event.stopPropagation(); props.onChat(); }}>
            <MessageSquare size={16} />
            Chat
          </button>
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
    </article>
  );
}

function PairingModal({ peer, onAccept, onDeny }: { peer: PeerDevice; onAccept: () => void; onDeny: () => void }) {
  return (
    <div className="modal-backdrop">
      <section className="pairing-panel">
        <div className="device-avatar">
          <Laptop size={34} />
        </div>
        <h2>{peer.name} wants to pair</h2>
        <p>{peer.os || "Computer"} {peer.host ? `on ${peer.host}` : ""}</p>
        <div className="pairing-actions">
          <button className="secondary" onClick={onDeny}>Deny</button>
          <button className="primary" onClick={onAccept}>Accept</button>
        </div>
      </section>
    </div>
  );
}

function ChatPanel({ peer, messages, onClose }: { peer: PeerDevice | null; messages: ChatMessage[]; onClose: () => void }) {
  const [text, setText] = useState("");

  if (!peer) {
    return (
      <aside className="chat-panel empty-chat">
        <MessageSquare size={34} />
        <p>Select a paired computer to chat.</p>
      </aside>
    );
  }

  const peerId = peer.id;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!text.trim()) return;
    await api.sendMessage(peerId, text.trim());
    setText("");
  }

  return (
    <aside className="chat-panel">
      <header>
        <div>
          <h2>{peer.name}</h2>
          <span>{peer.status}</span>
        </div>
        <button className="icon-button" title="Close chat" onClick={onClose}><X size={18} /></button>
      </header>
      <div className="message-list">
        {messages.map((message) => (
          <p key={message.id} className={`message ${message.direction}`}>{message.text}</p>
        ))}
      </div>
      <form className="composer" onSubmit={submit}>
        <input value={text} onChange={(event) => setText(event.target.value)} placeholder="Message" />
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
}) {
  const [deviceName, setDeviceName] = useState(props.setup.deviceName);
  const [startAtLogin, setStartAtLogin] = useState(props.setup.startAtLogin);
  const [version, setVersion] = useState("");
  const [updateStatus, setUpdateStatus] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    void getVersion().then(setVersion);
  }, []);

  async function save() {
    const setup = await api.saveSetup(deviceName.trim(), startAtLogin);
    props.onSetup(setup);
    props.onClose();
  }

  async function checkUpdates() {
    setChecking(true);
    setUpdateStatus("Checking for updates...");
    const outcome = await checkForUpdate(true);
    setChecking(false);
    if (outcome.status === "up-to-date") {
      setUpdateStatus("You're on the latest version.");
    } else if (outcome.status === "available") {
      // Reached only if the install/relaunch did not take over the process.
      setUpdateStatus(`Installing version ${outcome.version}...`);
    } else {
      setUpdateStatus(`Update check failed: ${outcome.message}`);
    }
  }

  return (
    <div className="modal-backdrop">
      <section className="settings-panel">
        <header>
          <h2>Settings</h2>
          <button className="icon-button" onClick={props.onClose}><X size={18} /></button>
        </header>
        <label>
          Device name
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
        </label>
        <label className="check-row">
          <input type="checkbox" checked={startAtLogin} onChange={(event) => setStartAtLogin(event.target.checked)} />
          Start SimplePass when I log in
        </label>
        <h3>Trusted devices</h3>
        <div className="trusted-list">
          {props.peers.filter((peer) => peer.trustState === "paired").map((peer) => (
            <div key={peer.id}>
              <span>{peer.name}</span>
              <button onClick={() => api.revokePeer(peer.id)}>Remove</button>
            </div>
          ))}
        </div>
        <h3>Updates</h3>
        <div className="update-row">
          <span>Version {version || "…"}</span>
          <button onClick={checkUpdates} disabled={checking}>Check for updates</button>
        </div>
        {updateStatus && <p className="update-status">{updateStatus}</p>}
        <button className="primary" onClick={save}>Save</button>
      </section>
    </div>
  );
}
