import sodium from "libsodium-wrappers-sumo";
import { createKeyFile, generateReaderKeys, MIN_PASSPHRASE_CHARS } from "../crypto";
import { boot, copyText, el, focusHeading, showError, warnBeforeLeaving, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("create"), el("error"));

const form = el<HTMLFormElement>("setup-form");
const nameInput = el<HTMLInputElement>("name");
const passphrase = el<HTMLInputElement>("passphrase");
const confirmation = el<HTMLInputElement>("confirm");
const createButton = el<HTMLButtonElement>("create");
const error = el("error");
const saved = el<HTMLInputElement>("saved");
const finish = el<HTMLButtonElement>("finish");
let keyFileUrl = "";
let downloadName = "";

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
      const keys = generateReaderKeys();
      const file = createKeyFile(keys, passphrase.value);
      sodium.memzero(keys.privateKey);
      passphrase.value = "";
      confirmation.value = "";
      keyFileUrl = URL.createObjectURL(new Blob([JSON.stringify(file)], { type: "application/json" }));
      downloadName = `${nameInput.value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-") || "my"}.key.json`;
      el("public-line").textContent = JSON.stringify({ name: nameInput.value.trim(), publicKey: file.publicKey, status: "active" });
      el("view-form").hidden = true;
      el("view-save").hidden = false;
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
el("copy").addEventListener("click", () => copyText(el("public-line").textContent ?? "", el("copy"), "Copied ✓", el("copy-status")));
saved.addEventListener("change", () => {
  el("admin-step").hidden = !saved.checked;
});
finish.addEventListener("click", () => {
  removeEventListener("beforeunload", warnBeforeLeaving);
  URL.revokeObjectURL(keyFileUrl);
  el("view-save").hidden = true;
  el("view-done").hidden = false;
  focusHeading("view-done");
});
