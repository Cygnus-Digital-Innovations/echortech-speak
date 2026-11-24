// Runs before the crypto library loads, so returning people never see the unlock form flash.
let returning = false;
try {
  returning = localStorage.getItem("sayit.key") !== null || (JSON.parse(localStorage.getItem("sayit.codes") ?? "[]") as unknown[]).length > 0;
} catch {
  returning = false;
}
if (returning) {
  (document.getElementById("view-unlock") as HTMLElement).hidden = true;
  (document.getElementById("view-opening") as HTMLElement).hidden = false;
}
