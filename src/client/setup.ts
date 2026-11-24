import { createKeyFile, generateReaderKeys, MIN_PASSPHRASE_CHARS, type ReaderKeyPair } from "../crypto";
import { rememberKeys } from "./device";
import { api, boot, copyText, el, focusHeading, showError, solvePow, warnBeforeLeaving, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("create"), el("error"));

const form = el<HTMLFormElement>("setup-form");
const nameInput = el<HTMLInputElement>("name");
const inviteInput = el<HTMLInputElement>("invite");
const passphrase = el<HTMLInputElement>("passphrase");
const confirmation = el<HTMLInputElement>("confirm");
const createButton = el<HTMLButtonElement>("create");
const error = el("error");
const saved = el<HTMLInputElement>("saved");
const finish = el<HTMLButtonElement>("finish");
const registerError = el("register-error");
let keyFileUrl = "";
let downloadName = "";
let publicKey = "";
let newKeys: ReaderKeyPair | null = null;
let generated = false;

const PASSPHRASE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789a";
function generatePassphrase(): string {
  const chars = Array.from(crypto.getRandomValues(new Uint8Array(20)), (byte) => PASSPHRASE_ALPHABET[byte & 31]);
  return chars.join("").replace(/(.{5})(?=.)/g, "$1-");
}

const copyPassphrase = el("copy-passphrase");
el("generate").addEventListener("click", () => {
  generated = true;
  passphrase.type = "text";
  passphrase.value = generatePassphrase();
  confirmation.value = passphrase.value;
  el("confirm-field").hidden = true;
  el("passphrase-hint").textContent = "Copy this into your password manager. You'll need it on a new device or after signing out.";
  copyPassphrase.hidden = false;
  copyPassphrase.textContent = "Copy passphrase";
  el("generate").textContent = "Generate another";
});
copyPassphrase.addEventListener("click", () => copyText(passphrase.value, copyPassphrase, "Copied ✓", el("copy-passphrase-status")));
// Editing a generated passphrase turns it into a normal typed one.
passphrase.addEventListener("input", () => {
  if (!generated) return;
  generated = false;
  passphrase.type = "password";
  confirmation.value = "";
  el("confirm-field").hidden = false;
  el("passphrase-hint").textContent = "At least 12 characters, or generate one.";
  copyPassphrase.hidden = true;
  el("generate").textContent = "Generate one for me";
});
const saveCopy = el("save-copy-passphrase");
saveCopy.addEventListener("click", () => copyText(el("saved-passphrase").textContent ?? "", saveCopy, "Copied ✓", el("save-copy-status")));

form.addEventListener("submit", (event) => {
  event.preventDefault();
  error.hidden = true;
  if (Array.from(passphrase.value).length < MIN_PASSPHRASE_CHARS) {
    showError(error, new Error(`Your passphrase needs at least ${MIN_PASSPHRASE_CHARS} characters`));
    return;
  }
  if (passphrase.value !== confirmation.value) {
    showError(error, new Error("Those passphrases don't match"));
    return;
  }
  void withBusy(createButton, "Making your keys…", async () => {
    try {
      await api("/api/register/check", { name: nameInput.value, inviteCode: inviteInput.value, pow: await solvePow() });
      const keys = generateReaderKeys();
      const file = createKeyFile(keys, passphrase.value);
      newKeys = keys;
      if (generated) {
        el("saved-passphrase").textContent = passphrase.value;
        el("saved-passphrase-block").hidden = false;
        el("save-title").textContent = "Save your key file and passphrase";
        el("save-sub").textContent = "You need both to open your inbox. We can't recover either.";
        el("saved-label").textContent = "I've saved my key file and my passphrase";
      }
      passphrase.value = "";
      confirmation.value = "";
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
finish.addEventListener("click", () => {
  registerError.hidden = true;
  void withBusy(finish, "Adding you…", async () => {
    try {
      await api("/api/register", { name: nameInput.value, inviteCode: inviteInput.value, publicKey, pow: await solvePow() });
      const signedIn = newKeys !== null && el<HTMLInputElement>("stay").checked && rememberKeys(newKeys);
      el("done-sub").textContent = signedIn
        ? "You're signed in here. You'll need your key file and passphrase on a new device, after signing out, or if this browser's data is cleared."
        : "People can message you now. Use your key file and passphrase to open Messages.";
      removeEventListener("beforeunload", warnBeforeLeaving);
      URL.revokeObjectURL(keyFileUrl);
      el("saved-passphrase").textContent = "";
      el("view-save").hidden = true;
      el("view-done").hidden = false;
      el("links").hidden = false;
      focusHeading("view-done");
    } catch (failure) {
      showError(registerError, failure);
    }
  });
});
