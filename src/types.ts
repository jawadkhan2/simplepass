export type PeerStatus = "online" | "offline";
export type TrustState = "paired" | "unpaired" | "pending";

export interface SetupState {
  configured: boolean;
  deviceId: string;
  deviceName: string;
  startAtLogin: boolean;
  avatar?: string | null;
  floatingIcon?: boolean;
  autoOpen?: boolean;
  theme?: "light" | "dark";
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
  deliveryState?: "delivered" | "failed" | "queued";
  error?: string | null;
}

export interface MessageDeleted {
  peerId: string;
  messageId: string;
}

// A stored message changed in place (e.g. a queued file was delivered and took
// its final id). `previousId` is the id the UI currently holds.
export interface MessageUpdated {
  previousId: string;
  message: ChatMessage;
}

// A file waiting in the offline outbox for one peer; delivered automatically
// the next time that peer is reachable.
export interface QueuedFile {
  id: string;
  peerId: string;
  path: string;
  fileName: string;
  size: number;
  queuedAt: number;
  recordPath?: string | null;
  messageId: string;
  attempts: number;
  lastAttempt?: number | null;
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
  // "waiting" = the file went to the offline outbox (see QueuedFile); the
  // outbox list, not the transfer dock, shows it from then on.
  state: "queued" | "sending" | "complete" | "failed" | "cancelled" | "waiting";
  error?: string;
}
