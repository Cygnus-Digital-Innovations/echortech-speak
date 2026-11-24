import { createPlainKeyFile, generateReaderKeys, isValidPin, type ReaderKeyPair } from "../crypto";
import { rememberKeys } from "./device";
import { api, boot, el, focusHeading, showError, solvePow, warnBeforeLeaving, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("create"), el("error"));

const form = el<HTMLFormElement>("setup-form");
const nameInput = el<HTMLInputElement>("name");
const createButton = el<HTMLButtonElement>("create");
const error = el("error");
const saved = el<HTMLInputElement>("saved");
const stay = el<HTMLInputElement>("stay");
const pinInput = el<HTMLInputElement>("pin");
const finish = el<HTMLButtonElement>("finish");
const registerError = el("register-error");
let keyFileUrl = "";
let downloadName = "";
let publicKey = "";
let newKeys: ReaderKeyPair | null = null;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  error.hidden = true;
  void withBusy(createButton, "Making your keys…", async () => {
    try {
      await api("/api/register/check", { name: nameInput.value, pow: await solvePow() });
      const keys = generateReaderKeys();
      const file = createPlainKeyFile(keys);
      newKeys = keys;
      publicKey = file.publicKey;
      keyFileUrl = URL.createObjectURL(new Blob([JSON.stringify(file)], { type: "application/json" }));
      downloadName = `${nameInput.value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-") || "my"}.key.json`;
      el("view-form").hidden = true;
      el("view-save").hidden = false;
      el("links").hidden = true;
      addEventListener("beforeunload", warnBeforeLeaving);
      focusHeading("view-save");
    } catch (failure) {
      showError(error, failure);
    }
  });
});

const download = el("download");
download.addEventListener("click", () => {
  const link = document.createElement("a");
  link.href = keyFileUrl;
  link.download = downloadName;
  link.click();
  download.textContent = "Download again";
  download.classList.add("quiet");
  el("download-hint").hidden = false;
  saved.disabled = false;
});
saved.addEventListener("change", () => {
  finish.hidden = !saved.checked;
});
stay.addEventListener("change", () => {
  el("pin-field").hidden = !stay.checked;
});
finish.addEventListener("click", () => {
  registerError.hidden = true;
  const pin = stay.checked ? pinInput.value.trim() : "";
  if (pin && !isValidPin(pin)) {
    showError(registerError, new Error("Your PIN needs to be 4 digits, or leave it empty"));
    return;
  }
  void withBusy(finish, "Adding you…", async () => {
    try {
      await api("/api/register", { name: nameInput.value, publicKey, pow: await solvePow() });
      const signedIn = newKeys !== null && stay.checked && rememberKeys(newKeys, pin);
      el("done-sub").textContent = signedIn
        ? "You're signed in here. You'll only need your key file on a new device, after signing out, or if this browser's data is cleared."
        : "People can message you now. Open your key file in Messages to read them.";
      removeEventListener("beforeunload", warnBeforeLeaving);
      URL.revokeObjectURL(keyFileUrl);
      pinInput.value = "";
      el("view-save").hidden = true;
      el("view-done").hidden = false;
      el("links").hidden = false;
      focusHeading("view-done");
    } catch (failure) {
      showError(registerError, failure);
    }
  });
});
