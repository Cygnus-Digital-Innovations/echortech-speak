import {
  deriveFromCode,
  deriveSenderCode,
  encryptMessage,
  hashAccessToken,
  MAX_MESSAGE_CHARS,
  newOneWayThreadKey,
  newSecretCode,
  newThreadId,
  sealThreadKey,
} from "../crypto";
import type { DirectoryEntry } from "../types";
import { rememberedKeys, saveCode } from "./device";
import { findSentChats } from "./sent";
import { api, b64, boot, copyText, el, focusHeading, fromB64, showError, solvePow, warnBeforeLeaving, wireCounter, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("send"), el("error"));

const people = JSON.parse(el("people-data").textContent || "[]") as DirectoryEntry[];
const form = el<HTMLFormElement>("compose");
const recipient = el<HTMLInputElement>("recipient");
const message = el<HTMLTextAreaElement>("message");
const allowReply = el<HTMLInputElement>("allow-reply");
const sendButton = el<HTMLButtonElement>("send");
const error = el("error");
const resetCounter = wireCounter(message, el("counter"), MAX_MESSAGE_CHARS);


function show(view: string): void {
  for (const id of ["view-compose", "view-code", "view-sent"]) el(id).hidden = id !== view;
  el("links").hidden = view === "view-code";
  focusHeading(view);
}

const updateSendLabel = () => {
  const person = people.find((p) => String(p.keyId) === recipient.value);
  sendButton.textContent = person ? `Send to ${person.name}` : "Send it";
};
recipient.addEventListener("change", () => {
  el("recipient-error").hidden = true;
  updateSendLabel();
});
// Anything chosen before this script finished loading should still count.
updateSendLabel();
el("signed-in-note").hidden = rememberedKeys() === null;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  error.hidden = true;
  const person = people.find((p) => String(p.keyId) === recipient.value);
  if (!person) {
    showError(el("recipient-error"), new Error("Pick who this is for"));
    el("recipient-search").focus();
    return;
  }
  void withBusy(sendButton, "Locking it…", async () => {
    try {
      let code: string | null = null;
      let derived: ReturnType<typeof deriveFromCode> | null = null;
      if (allowReply.checked) {
        const keys = rememberedKeys();
        code = keys ? deriveSenderCode(keys.privateKey, (await findSentChats(keys.privateKey)).nextIndex) : newSecretCode();
        derived = deriveFromCode(code);
      }
      const threadKey = derived?.threadKey ?? newOneWayThreadKey();
      const threadId = newThreadId();
      const ciphertext = encryptMessage(threadKey, { threadId, seq: 1 }, { author: "sender", sentAt: new Date(), text: message.value });
      await api("/api/threads", {
        id: b64(threadId),
        recipientKeyId: person.keyId,
        sealedThreadKey: b64(sealThreadKey(threadKey, fromB64(person.publicKey))),
        accessTokenHash: derived ? b64(hashAccessToken(derived.accessToken)) : null,
        ciphertext: b64(ciphertext),
        pow: await solvePow(),
      });
      message.value = "";
      resetCounter();
      const remembered = code !== null && saveCode(code);
      el("sent-sub").textContent = remembered ? `Only ${person.name} can open it. Their replies will show in Messages.` : code ? `Only ${person.name} can open it. Paste your code in Messages to see replies.` : `Only ${person.name} can open it.`;
      el("see-replies").hidden = !code;
      const browserOnly = remembered && rememberedKeys() === null;
      el("sent-note").hidden = !browserOnly;
      el("backup").hidden = !browserOnly;
      el("backup-block").hidden = true;
      el("backup-code").textContent = code ?? "";
      if (code && !remembered) {
        el("code").textContent = code;
        addEventListener("beforeunload", warnBeforeLeaving);
        show("view-code");
      } else {
        show("view-sent");
      }
    } catch (failure) {
      showError(error, failure);
    }
  });
});

const saved = el<HTMLInputElement>("saved");
const continueButton = el<HTMLButtonElement>("continue");
saved.addEventListener("change", () => {
  continueButton.disabled = !saved.checked;
});
el("copy").addEventListener("click", () => copyText(el("code").textContent ?? "", el("copy"), "Copied ✓", el("copy-status")));
continueButton.addEventListener("click", () => {
  removeEventListener("beforeunload", warnBeforeLeaving);
  el("code").textContent = "";
  saved.checked = false;
  continueButton.disabled = true;
  el("copy").textContent = "Copy code";
  show("view-sent");
});
el("show-backup").addEventListener("click", () => {
  el("backup-block").hidden = false;
});
el("copy-backup").addEventListener("click", () => copyText(el("backup-code").textContent ?? "", el("copy-backup"), "Copied ✓", el("copy-backup-status")));
el("again").addEventListener("click", () => {
  form.reset();
  resetCounter();
  updateSendLabel();
  show("view-compose");
});
