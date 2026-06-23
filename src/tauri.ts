import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { ChatMessage, PeerDevice, SetupState, TransferProgress, TypingSignal } from "./types";

export const api = {
  getSetupState: () => invoke<SetupState>("get_setup_state"),
  saveSetup: (deviceName: string, startAtLogin: boolean) =>
    invoke<SetupState>("save_setup", { deviceName, startAtLogin }),
  setAvatar: (avatar: string | null) => invoke<SetupState>("set_avatar", { avatar }),
  setFloatingIcon: (enabled: boolean) => invoke<SetupState>("set_floating_icon", { enabled }),
  setAutoOpen: (enabled: boolean) => invoke<SetupState>("set_auto_open", { enabled }),
  setTheme: (theme: "light" | "dark") => invoke<SetupState>("set_theme", { theme }),
  collapseWidget: () => invoke<void>("collapse_widget"),
  setWidgetActive: (active: boolean, activeWidth: number, apply: boolean) =>
    invoke<"left" | "right">("set_widget_active", { active, activeWidth, apply }),
  saveWidgetPosition: (x: number, y: number) => invoke<void>("save_widget_position", { x, y }),
  showWindow: () => invoke<void>("show_window"),
  listPeers: () => invoke<PeerDevice[]>("list_peers"),
  recentPeer: () => invoke<PeerDevice | null>("recent_peer"),
  rescanPeers: () => invoke<void>("rescan_peers"),
  pairPeer: (peerId: string) => invoke<void>("pair_peer", { peerId }),
  acceptPairing: (peerId: string) => invoke<void>("accept_pairing", { peerId }),
  denyPairing: (peerId: string) => invoke<void>("deny_pairing", { peerId }),
  revokePeer: (peerId: string) => invoke<void>("revoke_peer", { peerId }),
  deletePeer: (peerId: string) => invoke<void>("delete_peer", { peerId }),
  listMessages: (peerId: string) => invoke<ChatMessage[]>("list_messages", { peerId }),
  sendMessage: (peerId: string, text: string) => invoke<void>("send_message", { peerId, text }),
  sendTyping: (peerId: string, isTyping: boolean) =>
    invoke<void>("send_typing", { peerId, isTyping }),
  sendLink: (peerIds: string[], url: string) => invoke<TransferProgress[]>("send_link", { peerIds, url }),
  sendFiles: (peerIds: string[], paths: string[]) => invoke<void>("send_files", { peerIds, paths }),
  stageFileChunk: (sessionId: string, data: string) =>
    invoke<void>("stage_file_chunk", { sessionId, data }),
  sendStagedFile: (peerIds: string[], sessionId: string, fileName: string) =>
    invoke<void>("send_staged_file", { peerIds, sessionId, fileName }),
  cancelFileSend: (transferId: string) => invoke<void>("cancel_file_send", { transferId }),
  clearMessages: () => invoke<void>("clear_messages"),
  openPath: (path: string) => invoke<void>("open_path", { path }),
  openLink: (url: string) => invoke<void>("open_link", { url })
};

export const events = {
  onPeersChanged: (handler: (peers: PeerDevice[]) => void) =>
    listen<PeerDevice[]>("peers-changed", (event) => handler(event.payload)),
  onPairingRequest: (handler: (peer: PeerDevice) => void) =>
    listen<PeerDevice>("pairing-request", (event) => handler(event.payload)),
  onMessage: (handler: (message: ChatMessage) => void) =>
    listen<ChatMessage>("chat-message", (event) => handler(event.payload)),
  onTransfer: (handler: (transfer: TransferProgress) => void) =>
    listen<TransferProgress>("transfer-progress", (event) => handler(event.payload)),
  onTyping: (handler: (signal: TypingSignal) => void) =>
    listen<TypingSignal>("peer-typing", (event) => handler(event.payload)),
  onSetupChanged: (handler: (setup: SetupState) => void) =>
    listen<SetupState>("setup-changed", (event) => handler(event.payload)),
  onTransportError: (handler: (message: string) => void) =>
    listen<string>("transport-error", (event) => handler(event.payload)),
  // Fired at the widget window when it is freshly revealed/centered, so it can
  // play the radar pulse that points the user to the screen centre.
  onWidgetReveal: (handler: () => void) =>
    listen("widget-reveal", () => handler())
};
