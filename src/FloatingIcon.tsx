import { useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Check, Download, X } from "lucide-react";
import { api, events } from "./tauri";
import type { PeerDevice, TransferProgress } from "./types";
import "./styles.css";

// Pixels of pointer travel before a press is treated as a drag rather than a click.
const DRAG_THRESHOLD = 4;

// Native window moves during a browser drag can briefly report "left the
// webview", especially when the widget grows left and its top-left changes.
const DRAG_LEAVE_GRACE_MS = 250;

// Width (logical px) the widget window grows to while showing a status pill during
// a drop / send / result. The backend (`set_widget_active`) handles the resize and,
// near a screen edge, the reposition so the pill stays on-screen; at rest the window
// is the square WIDGET_IDLE_SIZE. Keep in sync with the backend's idle size.
const ACTIVE_WIDTH = 252;

// How long the radar pulse plays before the window collapses back to the resting
// icon. The radar square size itself is set by the backend (WIDGET_RADAR_SIZE)
// before the window is shown, so it appears already centred at full size.
const RADAR_DURATION = 3000;

// A dropped file has no OS path here (see the component note), so it is read in
// memory and streamed to the backend in slices of this size to bound peak usage.
const STAGE_CHUNK = 1024 * 1024;

const looksLikeUrl = (value: string) => /^https?:\/\/\S+$/i.test(value.trim());

// Convert a `file://` URL to a local path the backend can open. Returns null for
// anything that isn't a local file URL. Forward slashes are fine for the backend
// on every platform, so only the Windows "/C:/x" drive prefix is normalised.
function fileUrlToPath(fileUrl: string): string | null {
  try {
    const url = new URL(fileUrl);
    if (url.protocol !== "file:") return null;
    let path = decodeURIComponent(url.pathname);
    if (/^\/[A-Za-z]:/.test(path)) path = path.slice(1);
    return path || null;
  } catch {
    return null;
  }
}

type Feedback =
  | { kind: "idle" }
  | { kind: "dragover"; name: string | null }
  | { kind: "sending"; name: string }
  | { kind: "success"; name: string; detail: string }
  | { kind: "cancelled"; name: string }
  | { kind: "error"; message: string };

// Tracks the terminal rows of one drop's worth of file transfers so we can report
// a single success/cancel/error once every file has finished.
type Batch = {
  peerId: string;
  name: string;
  total: number;
  done: Set<string>;
  success: number;
  cancelled: number;
};

const TERMINAL = ["complete", "failed", "cancelled"];

// Encode raw bytes as base64 for the staging IPC call. Chunked through
// fromCharCode to avoid blowing the argument limit on large slices.
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    binary += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(binary);
}

// Pull a droppable string (URL or plain text) out of an HTML5 drop. URLs arrive as
// `text/uri-list` (one URL per line, `#` lines are comments); plain text as
// `text/plain`. Returns null when the drop carries neither.
function extractDroppedText(data: DataTransfer | null): string | null {
  if (!data) return null;
  const uriList = data.getData("text/uri-list");
  if (uriList) {
    const url = uriList
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line && !line.startsWith("#"));
    if (url) return url;
  }
  const text = data.getData("text/plain").trim();
  return text || null;
}

// The floating desktop widget: a frameless, always-on-top icon. Dragging it moves
// the window via the OS; a plain click (no drag) surfaces the main window; dropping
// content onto it sends it to the most recently chatted-with computer.
//
// The widget window is declared with `dragDropEnabled: false`, so Tauri's native
// drag-drop is off and everything — files, links, and text — arrives through the
// DOM `drop` event. The trade-off is that dropped files have no OS path (browser
// sandbox): we read their bytes in slices, stage them in the backend, then send.
// A single window cannot do both native (path-based) file drops and DOM text drops
// (tauri-apps/tauri discussions #9696), so the widget takes the DOM route for all.
//
// We don't use `data-tauri-drag-region` because it swallows the click we need to
// distinguish "open" from "move". Instead we start the OS drag only once the
// pointer actually moves; if it never moves, mouseup is a click.
export default function FloatingIcon() {
  const press = useRef<{ x: number; y: number; dragging: boolean } | null>(null);
  const iconRef = useRef<HTMLButtonElement | null>(null);
  const [feedback, setFeedback] = useState<Feedback>({ kind: "idle" });
  const [radar, setRadar] = useState(false);
  // Which side of the icon the status pill expands toward. The backend decides
  // based on the room left on the widget's current monitor and returns the side so
  // the layout can flip (icon stays put; pill grows into the available space).
  const [side, setSide] = useState<"left" | "right">("right");

  // Live state for the once-mounted drop/transfer listeners (avoids stale closures).
  const batch = useRef<Batch | null>(null);
  const hovering = useRef(false);
  const locked = useRef(false); // a send is in flight or its result is on screen
  const targetName = useRef<string | null>(null);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dragLeaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Last expanded/collapsed state pushed to the backend, so repeated feedback
  // transitions don't re-issue the window move that causes flicker (see setActive).
  const activeApplied = useRef(false);

  // Persist the window position whenever the user drops it somewhere new, so the
  // widget reappears in place on the next launch.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    void getCurrentWindow()
      .onMoved(({ payload }) => {
        void api.saveWidgetPosition(payload.x, payload.y).catch(() => undefined);
      })
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  // When the backend reveals the widget (the user just ticked the box), grow the
  // window to a centred square, play a radar pulse so the user spots it in the
  // middle of the screen, then collapse back to the resting icon.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    // The backend already sized the window to the radar square and centred it
    // before showing it, so just play the rings, then ask the backend to collapse
    // it back to the resting icon (resize + re-centre done in Rust so the icon
    // doesn't end up offset from a JS resize/center race).
    function playRadar() {
      setRadar(true);
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        setRadar(false);
        void api.collapseWidget().catch(() => undefined);
      }, RADAR_DURATION);
    }

    void events
      .onWidgetReveal(() => void playRadar())
      .then((fn) => {
        if (cancelled) fn();
        else unlisten = fn;
      });

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      if (unlisten) unlisten();
    };
  }, []);

  // DOM drag-drop (files, links, text) plus the transfer-progress stream (which
  // reports whether a file send succeeded). All set up once.
  useEffect(() => {
    // Grow/shrink the widget window for the status pill. The backend resizes (and,
    // near a screen edge, repositions) the window so the pill never lands off-screen
    // on any monitor, and tells us which side it placed the pill on.
    //
    // A single drop drives several feedback states (dragover → sending → result),
    // each calling setActive(true). Only the transition into/out of the expanded
    // state should touch the window — re-calling on every state change makes a
    // left-growing window jump repeatedly (visible flicker). Guard on the last
    // applied state so repeats are no-ops.
    //
    // For a leftward grow the window moves, and the layout must flip (icon to the
    // right, pill to its left). If we flipped *after* the move, the icon would flash
    // on the wrong side for a frame. So: decide the side first (no window change),
    // commit the DOM flip synchronously with flushSync, then apply the move — the
    // window only ever paints with the icon already on its final side.
    async function setActive(active: boolean) {
      if (active === activeApplied.current) return;
      activeApplied.current = active;
      try {
        if (active) {
          const placedSide = await api.setWidgetActive(true, ACTIVE_WIDTH, false);
          // A collapse may have superseded us during the decide round-trip; bail so
          // we don't re-expand a window that should be idle.
          if (activeApplied.current !== true) return;
          flushSync(() => setSide(placedSide));
          await api.setWidgetActive(true, ACTIVE_WIDTH, true);
        } else {
          flushSync(() => setSide("right"));
          await api.setWidgetActive(false, ACTIVE_WIDTH, true);
        }
      } catch {
        // Roll back so a later attempt can retry the transition.
        activeApplied.current = !active;
      }
    }

    function isOverIcon(event: DragEvent) {
      const icon = iconRef.current;
      if (!icon) return true;
      const rect = icon.getBoundingClientRect();
      return (
        event.clientX >= rect.left &&
        event.clientX <= rect.right &&
        event.clientY >= rect.top &&
        event.clientY <= rect.bottom
      );
    }

    function clearDragLeaveTimer() {
      if (dragLeaveTimer.current) {
        clearTimeout(dragLeaveTimer.current);
        dragLeaveTimer.current = null;
      }
    }

    function scheduleDragLeaveTimeout() {
      clearDragLeaveTimer();
      dragLeaveTimer.current = setTimeout(() => {
        dragLeaveTimer.current = null;
        if (!locked.current) toIdle();
      }, DRAG_LEAVE_GRACE_MS);
    }

    function toIdle() {
      clearDragLeaveTimer();
      batch.current = null;
      hovering.current = false;
      locked.current = false;
      setFeedback({ kind: "idle" });
      setActive(false);
    }

    function scheduleIdle(ms: number) {
      if (resetTimer.current) clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(toIdle, ms);
    }

    function fail(message: string) {
      batch.current = null;
      locked.current = true;
      setFeedback({ kind: "error", message });
      setActive(true);
      scheduleIdle(2800);
    }

    // Show the "drop to send to X" hint, resolving the target name lazily.
    function showDragover() {
      if (locked.current) return;
      clearDragLeaveTimer();
      if (!hovering.current) {
        hovering.current = true;
        setActive(true);
        void api
          .recentPeer()
          .then((peer) => {
            targetName.current = peer?.name ?? null;
            if (hovering.current && !locked.current) {
              setFeedback({ kind: "dragover", name: targetName.current });
            }
          })
          .catch(() => undefined);
      }
      setFeedback({ kind: "dragover", name: targetName.current });
    }

    // Resolve the most-recently-chatted peer, or report why we can't send.
    async function resolveTarget(): Promise<PeerDevice | null> {
      let peer: PeerDevice | null = null;
      try {
        peer = await api.recentPeer();
      } catch {
        peer = null;
      }
      if (!peer) fail("No paired computer to send to");
      return peer;
    }

    // Fold one transfer's terminal state into the active batch, reporting the
    // batch's overall outcome once every file has finished. Also used for files
    // that failed before any transfer row existed (a staging/dispatch error),
    // so the batch can still resolve.
    function recordDone(id: string, kind: "complete" | "cancelled" | "failed") {
      const current = batch.current;
      if (!current || current.done.has(id)) return;
      current.done.add(id);
      if (kind === "complete") current.success += 1;
      else if (kind === "cancelled") current.cancelled += 1;
      if (current.done.size < current.total) return;

      const { name, success, cancelled } = current;
      batch.current = null;
      // A user-initiated cancel reads as "cancelled", not a failure. Completed
      // files still win (partial batch); only when nothing completed do cancel /
      // error states surface.
      if (success > 0) {
        setFeedback({ kind: "success", name, detail: success > 1 ? `${success} files` : "file" });
      } else if (cancelled > 0) {
        setFeedback({ kind: "cancelled", name });
      } else {
        setFeedback({ kind: "error", message: `Couldn't send to ${name}` });
      }
      setActive(true);
      scheduleIdle(2800);
    }

    // Start a batch for a drop, or fold it into one already in flight to the same
    // peer. A second large drop can land while the first is still staging; merging
    // (rather than overwriting batch.current) keeps both files' terminal rows
    // counted so the pill reports the combined "Sent N files" instead of dropping
    // the first batch and under-reporting.
    function beginOrExtendBatch(peer: PeerDevice, count: number) {
      const current = batch.current;
      if (current && current.peerId === peer.id) {
        current.total += count;
      } else {
        batch.current = {
          peerId: peer.id,
          name: peer.name,
          total: count,
          done: new Set(),
          success: 0,
          cancelled: 0,
        };
      }
      locked.current = true;
      setFeedback({ kind: "sending", name: peer.name });
      setActive(true);
    }

    // Read a dropped file in slices, stage the bytes in the backend, then hand it
    // to the chunked transport. Throws if staging or dispatch fails.
    async function stageAndSend(peerId: string, file: File) {
      const sessionId = crypto.randomUUID();
      if (file.size === 0) {
        await api.stageFileChunk(sessionId, "");
      } else {
        for (let offset = 0; offset < file.size; offset += STAGE_CHUNK) {
          const slice = file.slice(offset, Math.min(offset + STAGE_CHUNK, file.size));
          const bytes = new Uint8Array(await slice.arrayBuffer());
          await api.stageFileChunk(sessionId, bytesToBase64(bytes));
        }
      }
      await api.sendStagedFile([peerId], sessionId, file.name);
    }

    // Files: bytes are staged then streamed; results arrive via transfer-progress.
    async function handleFileDrop(files: File[]) {
      const peer = await resolveTarget();
      if (!peer) return;
      beginOrExtendBatch(peer, files.length);
      for (const file of files) {
        try {
          await stageAndSend(peer.id, file);
        } catch {
          // Count the un-dispatched file as a failed member so the batch resolves.
          recordDone(`stage-error:${file.name}:${crypto.randomUUID()}`, "failed");
        }
      }
    }

    // Send local files by path (used when a browser shortcut resolves to a
    // file:// target). The backend reads them from this machine's disk, so the
    // receiver gets the real bytes rather than a dead .url shortcut.
    async function handlePathDrop(label: string, paths: string[]) {
      const peer = await resolveTarget();
      if (!peer) return;
      beginOrExtendBatch(peer, paths.length);
      try {
        await api.sendFiles([peer.id], paths);
      } catch {
        recordDone(`path-error:${label}:${crypto.randomUUID()}`, "failed");
      }
    }

    // A browser link-drag arrives as a synthesized ".url"/".website" shortcut
    // File plus the URL in text/uri-list. Read the shortcut to recover its real
    // target: an http(s) link is sent as a link; a file:// target is sent as the
    // actual file. Chrome blanks file:// drags to "about:blank#blocked", so when
    // nothing usable comes back we tell the user to drag the file itself.
    async function handleShortcutDrop(file: File, fallbackText: string | null) {
      let url: string | null = fallbackText && looksLikeUrl(fallbackText) ? fallbackText : null;
      let localPath: string | null = null;
      try {
        const target = (await file.text()).match(/^URL=(.+)$/im)?.[1]?.trim();
        if (target) {
          if (/^file:\/\//i.test(target)) localPath = fileUrlToPath(target);
          else if (looksLikeUrl(target)) url = target;
        }
      } catch {
        // Unreadable shortcut: fall back to whatever the drop text gave us.
      }
      if (localPath) await handlePathDrop(file.name, [localPath]);
      else if (url) await handleTextDrop(url);
      else fail("Can't send that link — drag the file itself instead");
    }

    // Text / URL: sent synchronously, so the result is known when the call resolves.
    async function handleTextDrop(raw: string) {
      const text = raw.trim();
      if (!text) return;
      // A browser blocks dragging local-file URLs, exposing "about:blank#blocked"
      // instead. Don't send that placeholder as a message.
      if (/^about:blank/i.test(text)) {
        fail("Can't send that from the browser — drag the file itself instead");
        return;
      }
      locked.current = true;
      setFeedback({ kind: "sending", name: targetName.current ?? "…" });
      setActive(true);
      const peer = await resolveTarget();
      if (!peer) return;
      const isUrl = looksLikeUrl(text);
      setFeedback({ kind: "sending", name: peer.name });
      try {
        if (isUrl) await api.sendLink([peer.id], text);
        else await api.sendMessage(peer.id, text);
        setFeedback({ kind: "success", name: peer.name, detail: isUrl ? "link" : "message" });
        setActive(true);
        scheduleIdle(2800);
      } catch (err) {
        fail(messageOf(err));
      }
    }

    function onTransfer(transfer: TransferProgress) {
      const current = batch.current;
      if (current && transfer.peerId === current.peerId) {
        if (TERMINAL.includes(transfer.state)) {
          recordDone(transfer.id, transfer.state as "complete" | "cancelled" | "failed");
        }
        return;
      }
      // A transfer the widget didn't start (e.g. a send from the main window) that
      // failed: surface it by the widget too, unless the widget is already busy
      // showing its own send/result (don't clobber that).
      if (transfer.state === "failed" && !locked.current && !batch.current) {
        fail(transfer.error ? `${transfer.peerName}: ${transfer.error}` : `Couldn't send to ${transfer.peerName}`);
      }
    }

    let unlistenTransfer: (() => void) | undefined;
    let cancelled = false;

    void events.onTransfer(onTransfer).then((fn) => {
      if (cancelled) fn();
      else unlistenTransfer = fn;
    });

    // preventDefault on dragover is required for a drop to fire at all; on drop it
    // stops the webview from navigating to a dropped URL or opening a dropped file.
    const onDomDragOver = (event: DragEvent) => {
      event.preventDefault();
      const overIcon = isOverIcon(event);
      if (event.dataTransfer) event.dataTransfer.dropEffect = overIcon ? "copy" : "none";
      if (overIcon) showDragover();
      else if (!locked.current && hovering.current) toIdle();
    };
    const onDomDragLeave = (event: DragEvent) => {
      // Fires with no relatedTarget when the pointer leaves the window entirely.
      // When the widget grows left, the native move/resize can produce the same
      // signal even though the pointer is still over the icon. Give the next
      // dragover a moment to arrive before treating it as a real leave.
      if (!event.relatedTarget && !locked.current) {
        scheduleDragLeaveTimeout();
      }
    };
    const onDomDrop = (event: DragEvent) => {
      event.preventDefault();
      clearDragLeaveTimer();
      if (!locked.current && !isOverIcon(event)) {
        toIdle();
        return;
      }
      const data = event.dataTransfer;
      const files = data?.files ? Array.from(data.files) : [];
      const text = extractDroppedText(data);
      // A link dragged from a browser tab/address bar arrives as BOTH a
      // synthesized ".url"/".website" shortcut File and the real URL in
      // text/uri-list. Shipping the shortcut yields a broken .url on the
      // receiver (its target only exists on the sender), so when every dropped
      // file is just a shortcut, send the URL as a link instead.
      const shortcut =
        files.length === 1 && /\.(url|website)$/i.test(files[0].name) ? files[0] : null;
      if (shortcut) {
        void handleShortcutDrop(shortcut, text);
      } else if (files.length > 0) {
        void handleFileDrop(files);
      } else if (text) {
        void handleTextDrop(text);
      } else if (!locked.current) {
        toIdle();
      }
    };
    window.addEventListener("dragover", onDomDragOver);
    window.addEventListener("dragleave", onDomDragLeave);
    window.addEventListener("drop", onDomDrop);

    return () => {
      cancelled = true;
      if (resetTimer.current) clearTimeout(resetTimer.current);
      clearDragLeaveTimer();
      if (unlistenTransfer) unlistenTransfer();
      window.removeEventListener("dragover", onDomDragOver);
      window.removeEventListener("dragleave", onDomDragLeave);
      window.removeEventListener("drop", onDomDrop);
    };
  }, []);

  function onMouseDown(event: React.MouseEvent) {
    if (event.button !== 0) return;
    press.current = { x: event.screenX, y: event.screenY, dragging: false };
  }

  function onMouseMove(event: React.MouseEvent) {
    const start = press.current;
    if (!start || start.dragging) return;
    const moved = Math.hypot(event.screenX - start.x, event.screenY - start.y);
    if (moved > DRAG_THRESHOLD) {
      start.dragging = true;
      // Once the OS takes over the drag, the webview stops receiving the matching
      // mouseup — which is fine, a drag should not also open the window.
      void getCurrentWindow().startDragging().catch(() => undefined);
    }
  }

  function onMouseUp() {
    const start = press.current;
    press.current = null;
    if (start && !start.dragging) void api.showWindow().catch(() => undefined);
  }

  return (
    <div className={`fi-root${radar ? " radar" : ""}${side === "left" ? " pill-left" : ""}`}>
      {radar && (
        <div className="fi-radar" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
      )}
      <button
        ref={iconRef}
        className={`floating-icon${feedback.kind === "dragover" ? " drag-over" : ""}`}
        title="Open SimplePass — or drop files, links, or text to send"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
      >
        <svg width={44} height={44} viewBox="0 0 48 48" fill="none" aria-hidden="true">
          <defs>
            <linearGradient id="fiIcon" x1="4" y1="4" x2="44" y2="44" gradientUnits="userSpaceOnUse">
              <stop offset="0" stopColor="#e8a07e" />
              <stop offset="1" stopColor="#c8643c" />
            </linearGradient>
          </defs>
          <rect x="3" y="3" width="42" height="42" rx="13" fill="url(#fiIcon)" />
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
      </button>
      {feedback.kind !== "idle" && <StatusPill feedback={feedback} />}
    </div>
  );
}

function messageOf(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return "Send failed";
}

function StatusPill({ feedback }: { feedback: Feedback }) {
  if (feedback.kind === "dragover") {
    return (
      <div className="fi-status dragover">
        <Download size={16} />
        <span className="fi-status-text">
          {feedback.name ? `Drop to send to ${feedback.name}` : "No paired computer"}
        </span>
      </div>
    );
  }
  if (feedback.kind === "sending") {
    return (
      <div className="fi-status sending">
        <span className="fi-spinner" aria-hidden="true" />
        <span className="fi-status-text">Sending to {feedback.name}…</span>
      </div>
    );
  }
  if (feedback.kind === "success") {
    return (
      <div className="fi-status success">
        <Check size={16} />
        <span className="fi-status-text">
          Sent {feedback.detail} to {feedback.name}
        </span>
      </div>
    );
  }
  if (feedback.kind === "cancelled") {
    return (
      <div className="fi-status cancelled">
        <X size={16} />
        <span className="fi-status-text">Transfer cancelled</span>
      </div>
    );
  }
  if (feedback.kind === "error") {
    return (
      <div className="fi-status error">
        <X size={16} />
        <span className="fi-status-text">{feedback.message}</span>
      </div>
    );
  }
  return null;
}
