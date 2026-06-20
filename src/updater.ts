import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// SimplePass lives in the tray and rarely restarts, so a launch-only check
// would leave long-running instances stale. We check once at startup and then
// poll on this interval, auto-installing whatever GitHub Releases serves.
const POLL_INTERVAL_MS = 12 * 60 * 60 * 1000; // 12 hours

export type UpdateOutcome =
  | { status: "up-to-date" }
  | { status: "available"; version: string }
  | { status: "error"; message: string };

// Download + install an update, then relaunch into the new version. Relaunch
// terminates the process, so anything after the await never runs on success.
async function installAndRestart(update: Update): Promise<void> {
  await update.downloadAndInstall();
  await relaunch();
}

// Check for an update once. When `apply` is true, install + relaunch if one is
// found; otherwise just report availability.
export async function checkForUpdate(apply: boolean): Promise<UpdateOutcome> {
  try {
    const update = await check();
    if (!update) return { status: "up-to-date" };
    if (apply) await installAndRestart(update);
    return { status: "available", version: update.version };
  } catch (err) {
    return { status: "error", message: err instanceof Error ? err.message : String(err) };
  }
}

// Check at launch, then every 12 hours, installing in the background.
// Returns a cleanup function that stops the polling timer.
export function startAutoUpdate(): () => void {
  void checkForUpdate(true);
  const timer = window.setInterval(() => void checkForUpdate(true), POLL_INTERVAL_MS);
  return () => window.clearInterval(timer);
}
