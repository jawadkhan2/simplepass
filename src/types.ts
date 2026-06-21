export type PeerStatus = "online" | "offline";
export type TrustState = "paired" | "unpaired" | "pending";

export interface SetupState {
  configured: boolean;
  deviceId: string;
  deviceName: string;
  startAtLogin: boolean;
  avatar?: string | null;
  floatingIcon?: boolean;
  publicKey?: string | null;
}

export interface PeerDevice {
  id: string;
  name: string;
  host: string;
  port: number;
  os: string;
  status: PeerStatus;
  trustState: TrustState;
  publicKey?: string | null;
  avatar?: string | null;
  lastSeen: number;
}

export interface ChatMessage {
  id: string;
  peerId: string;
  direction: "sent" | "received";
  text: string;
  createdAt: number;
  kind: "text" | "file" | "link";
  fileName?: string | null;
  fileSize?: number | null;
  filePath?: string | null;
  url?: string | null;
}

export interface TypingSignal {
  peerId: string;
  isTyping: boolean;
}

export interface TransferProgress {
  id: string;
  peerId: string;
  peerName: string;
  label: string;
  kind: "file" | "link";
  progress: number;
  state: "queued" | "sending" | "complete" | "failed" | "cancelled";
  error?: string;
}
