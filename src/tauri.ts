import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { ChatMessage, PeerDevice, SetupState, TransferProgress, TypingSignal } from "./types";

export const api = {
  getSetupState: () => invoke<SetupState>("get_setup_state"),
  saveSetup: (deviceName: string, startAtLogin: boolean) =>
    invoke<SetupState>("save_setup", { deviceName, startAtLogin }),
  setAvatar: (avatar: string | null) => invoke<SetupState>("set_avatar", { avatar }),
  listPeers: () => invoke<PeerDevice[]>("list_peers"),
  pairPeer: (peerId: string) => invoke<void>("pair_peer", { peerId }),
  acceptPairing: (peerId: string) => invoke<void>("accept_pairing", { peerId }),
  denyPairing: (peerId: string) => invoke<void>("deny_pairing", { peerId }),
  revokePeer: (peerId: string) => invoke<void>("revoke_peer", { peerId }),
  listMessages: (peerId: string) => invoke<ChatMessage[]>("list_messages", { peerId }),
  sendMessage: (peerId: string, text: string) => invoke<void>("send_message", { peerId, text }),
  sendTyping: (peerId: string, isTyping: boolean) =>
    invoke<void>("send_typing", { peerId, isTyping }),
  sendLink: (peerIds: string[], url: string) => invoke<TransferProgress[]>("send_link", { peerIds, url }),
  beginFileSend: (peerIds: string[], fileName: string, totalSize: number) =>
    invoke<string>("begin_file_send", { peerIds, fileName, totalSize }),
  sendFileChunk: (sessionId: string, data: string, byteLen: number) =>
    invoke<void>("send_file_chunk", { sessionId, data, byteLen }),
  finishFileSend: (sessionId: string) => invoke<void>("finish_file_send", { sessionId }),
  clearMessages: () => invoke<void>("clear_messages"),
  openPath: (path: string) => invoke<void>("open_path", { path })
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
    listen<SetupState>("setup-changed", (event) => handler(event.payload))
};
