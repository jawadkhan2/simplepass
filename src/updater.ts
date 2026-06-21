import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// SimplePass lives in the tray and rarely restarts, so a launch-only check
// would leave long-running instances stale. We check once at startup and then
// poll on this interval — but we surface availability instead of auto-installing,
// so the user decides when to update.
const POLL_INTERVAL_MS = 12 * 60 * 60 * 1000; // 12 hours

export type UpdateOutcome =
  | { status: "up-to-date" }
  | { status: "available"; version: string }
  | { status: "error"; message: string };

// The most recent Update handle returned by check(). downloadAndInstall must be
// called on the same object check() produced, so we hold it here for the UI to
// install on demand rather than re-checking.
let pending: Update | null = null;

// Check for an update once. Stores the handle if one is found; never installs.
export async function checkForUpdate(): Promise<UpdateOutcome> {
  try {
    const update = await check();
    if (!update) {
      pending = null;
      return { status: "up-to-date" };
    }
    pending = update;
    return { status: "available", version: update.version };
  } catch (err) {
    return { status: "error", message: err instanceof Error ? err.message : String(err) };
  }
}

// Download + install the pending update, then relaunch into the new version.
// Relaunch terminates the process, so nothing after the await runs on success.
// No-op when nothing is pending.
export async function applyPendingUpdate(): Promise<void> {
  if (!pending) return;
  await pending.downloadAndInstall();
  await relaunch();
}

// Check at launch, then every 12 hours. Reports availability to the caller so it
// can prompt the user, instead of installing in the background.
// Returns a cleanup function that stops the polling timer.
export function startAutoUpdate(onAvailable: (version: string) => void): () => void {
  const run = async () => {
    const outcome = await checkForUpdate();
    if (outcome.status === "available") onAvailable(outcome.version);
  };
  void run();
  const timer = window.setInterval(() => void run(), POLL_INTERVAL_MS);
  return () => window.clearInterval(timer);
}
