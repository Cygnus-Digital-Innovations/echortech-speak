import { createPinKeyFile, generateReaderKeys, isValidPin, type ReaderKeyPair } from "../crypto";
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
const pinAgain = el<HTMLInputElement>("pin-again");
let pin = "";
const finish = el<HTMLButtonElement>("finish");
const registerError = el("register-error");
let keyFileUrl = "";
let downloadName = "";
let publicKey = "";
let newKeys: ReaderKeyPair | null = null;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  error.hidden = true;
  if (!isValidPin(pinInput.value.trim())) {
    showError(error, new Error("Your PIN needs to be 4 digits"));
    return;
  }
  if (pinInput.value.trim() !== pinAgain.value.trim()) {
    showError(error, new Error("Those PINs don't match"));
    return;
  }
  void withBusy(createButton, "Making your keys…", async () => {
    try {
      await api("/api/register/check", { name: nameInput.value, pow: await solvePow() });
      const keys = generateReaderKeys();
      pin = pinInput.value.trim();
      const file = createPinKeyFile(keys, pin);
      pinInput.value = "";
      pinAgain.value = "";
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
finish.addEventListener("click", () => {
  registerError.hidden = true;
  void withBusy(finish, "Adding you…", async () => {
    try {
      await api("/api/register", { name: nameInput.value, publicKey, pow: await solvePow() });
      const signedIn = newKeys !== null && stay.checked && rememberKeys(newKeys, pin);
      pin = "";
      el("done-sub").textContent = signedIn
        ? "You're signed in here. Next time, just enter your PIN. On a new device, use your key file and PIN."
        : "People can message you now. Open Messages with your key file and PIN to read them.";
      removeEventListener("beforeunload", warnBeforeLeaving);
      URL.revokeObjectURL(keyFileUrl);
      el("view-save").hidden = true;
      el("view-done").hidden = false;
      el("links").hidden = false;
      focusHeading("view-done");
    } catch (failure) {
      showError(registerError, failure);
    }
  });
});
