import {
  deriveFromCode,
  encryptMessage,
  hashAccessToken,
  MAX_MESSAGE_CHARS,
  newOneWayThreadKey,
  newSecretCode,
  newThreadId,
  sealThreadKey,
} from "../crypto";
import type { DirectoryEntry } from "../types";
import { api, b64, boot, copyText, el, focusHeading, fromB64, showError, solvePow, warnBeforeLeaving, wireCounter, withBusy } from "./ui";

declare const __DIRECTORY__: DirectoryEntry[];

await boot(el<HTMLButtonElement>("send"), el("error"));

const people = __DIRECTORY__.filter((person) => person.status === "active").sort((a, b) => a.name.localeCompare(b.name));
const form = el<HTMLFormElement>("compose");
const recipient = el<HTMLSelectElement>("recipient");
const message = el<HTMLTextAreaElement>("message");
const allowReply = el<HTMLInputElement>("allow-reply");
const sendButton = el<HTMLButtonElement>("send");
const error = el("error");
const resetCounter = wireCounter(message, el("counter"), MAX_MESSAGE_CHARS);

if (people.length === 0) {
  form.hidden = true;
  el("no-people").hidden = false;
}
for (const person of people) recipient.add(new Option(person.name, String(person.keyId)));

function show(view: string): void {
  for (const id of ["view-compose", "view-code", "view-sent"]) el(id).hidden = id !== view;
  el("links").hidden = view === "view-code";
  focusHeading(view);
}

const updateSendLabel = () => {
  const person = people.find((p) => String(p.keyId) === recipient.value);
  sendButton.textContent = person ? `Send to ${person.name}` : "Send it";
};
recipient.addEventListener("change", updateSendLabel);

form.addEventListener("submit", (event) => {
  event.preventDefault();
  error.hidden = true;
  const person = people.find((p) => String(p.keyId) === recipient.value);
  if (!person) {
    showError(error, new Error("Pick who this is for"));
    return;
  }
  void withBusy(sendButton, "Locking it…", async () => {
    try {
      const code = allowReply.checked ? newSecretCode() : null;
      const derived = code ? deriveFromCode(code) : null;
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
      el("sent-sub").textContent = `Only ${person.name} can open it.`;
      if (code) {
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
el("again").addEventListener("click", () => {
  form.reset();
  resetCounter();
  updateSendLabel();
  show("view-compose");
});
