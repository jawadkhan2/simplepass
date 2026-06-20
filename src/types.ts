export type PeerStatus = "online" | "offline";
export type TrustState = "paired" | "unpaired" | "pending";

export interface SetupState {
  configured: boolean;
  deviceId: string;
  deviceName: string;
  startAtLogin: boolean;
}

export interface PeerDevice {
  id: string;
  name: string;
  host: string;
  port: number;
  os: string;
  status: PeerStatus;
  trustState: TrustState;
  lastSeen: number;
}

export interface ChatMessage {
  id: string;
  peerId: string;
  direction: "sent" | "received";
  text: string;
  createdAt: number;
}

export interface TransferProgress {
  id: string;
  peerId: string;
  peerName: string;
  label: string;
  kind: "file" | "link";
  progress: number;
  state: "queued" | "sending" | "complete" | "failed";
  error?: string;
}
