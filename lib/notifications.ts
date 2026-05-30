export async function requestPermission(): Promise<boolean> {
  if (!("Notification" in window)) return false;
  if (Notification.permission === "granted") return true;
  if (Notification.permission === "denied") return false;
  const result = await Notification.requestPermission();
  return result === "granted";
}

export function notify(title: string, body: string): void {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  new Notification(title, { body });
}

export function notifyScanComplete(contractAddress: string, critical: number, high: number): void {
  const severity = critical > 0 ? `${critical} critical` : high > 0 ? `${high} high` : "no critical";
  notify(
    "Scan complete",
    `${contractAddress.slice(0, 8)}… — ${severity} finding${critical + high !== 1 ? "s" : ""}`
  );
}

export function notifyScanError(contractAddress: string, message: string): void {
  notify("Scan failed", `${contractAddress.slice(0, 8)}… — ${message}`);
}
