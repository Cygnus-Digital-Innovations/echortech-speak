import { deriveFromCode, encryptMessage, MAX_MESSAGE_CHARS } from "../crypto";
import type { WireMessage } from "../types";
import { api, ApiError, b64, boot, el, focusElement, fromB64, renderMessages, showError, solvePow, wireCounter, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("open"), el("code-error"));

interface Thread {
  id: string;
  status: string;
  messages: WireMessage[];
}

let session: { threadKey: Uint8Array; accessToken: Uint8Array; thread: Thread } | null = null;

const codeForm = el<HTMLFormElement>("code-form");
const codeInput = el<HTMLInputElement>("code-input");
const openButton = el<HTMLButtonElement>("open");
const codeError = el("code-error");
const messages = el("messages");
const replyForm = el<HTMLFormElement>("reply-form");
const replyInput = el<HTMLTextAreaElement>("reply");
const replyButton = el<HTMLButtonElement>("send-reply");
const replyError = el("reply-error");
const resetCounter = wireCounter(replyInput, el("counter"), MAX_MESSAGE_CHARS);

async function refresh(): Promise<void> {
  if (!session) return;
  session.thread = await api<Thread>("/api/sender/thread", { accessToken: b64(session.accessToken) });
  renderMessages(messages, session.threadKey, fromB64(session.thread.id), session.thread.messages, "sender");
  const closed = session.thread.status !== "open";
  replyForm.hidden = closed;
  el("closed-note").hidden = !closed;
}

codeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  codeError.hidden = true;
  void withBusy(openButton, "Opening…", async () => {
    try {
      const derived = deriveFromCode(codeInput.value);
      session = { ...derived, thread: { id: "", status: "open", messages: [] } };
      await refresh();
      codeInput.value = "";
      el("view-code").hidden = true;
      el("view-chat").hidden = false;
      document.body.classList.add("wide");
      focusElement(el("chat-title"));
    } catch (failure) {
      session = null;
      showError(codeError, failure instanceof ApiError ? failure : new Error("That code doesn't look right. Check it and try again"));
    }
  });
});

const refreshButton = el<HTMLButtonElement>("refresh");
const chatStatus = el("chat-status");
refreshButton.addEventListener("click", () => {
  chatStatus.hidden = true;
  void withBusy(refreshButton, "Checking…", async () => {
    const before = session?.thread.messages.length ?? 0;
    try {
      await refresh();
      if ((session?.thread.messages.length ?? 0) === before) {
        chatStatus.textContent = "Nothing new yet";
        chatStatus.hidden = false;
      }
    } catch (failure) {
      showError(chatStatus, failure);
    }
  });
});

async function postReply(text: string, retry: boolean): Promise<void> {
  if (!session) return;
  const seq = (session.thread.messages.at(-1)?.seq ?? 0) + 1;
  const ciphertext = encryptMessage(session.threadKey, { threadId: fromB64(session.thread.id), seq }, { author: "sender", sentAt: new Date(), text });
  try {
    await api("/api/sender/messages", { accessToken: b64(session.accessToken), seq, ciphertext: b64(ciphertext), pow: await solvePow() });
  } catch (failure) {
    if (retry && failure instanceof ApiError && failure.status === 409) {
      await refresh();
      await postReply(text, false);
      return;
    }
    throw failure;
  }
}

replyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  replyError.hidden = true;
  void withBusy(replyButton, "Sending…", async () => {
    try {
      await postReply(replyInput.value, true);
      replyInput.value = "";
      resetCounter();
      await refresh().catch(() => showError(replyError, new Error("Sent, but couldn't refresh the chat")));
    } catch (failure) {
      showError(replyError, failure);
    }
  });
});
