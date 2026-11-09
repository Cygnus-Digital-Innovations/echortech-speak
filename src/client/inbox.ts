import {
  answerLoginChallenge,
  decryptWireMessage,
  encryptMessage,
  MAX_MESSAGE_CHARS,
  openKeyFile,
  openThreadKey,
  type KeyFile,
  type ReaderKeyPair,
} from "../crypto";
import type { WireMessage } from "../types";
import { api, ApiError, b64, boot, el, focusElement, focusHeading, fromB64, nextFrame, renderMessages, showError, wireCounter, withBusy } from "./ui";

await boot(el<HTMLButtonElement>("unlock"), el("unlock-error"));

interface ThreadSummary {
  id: string;
  sealedThreadKey: string;
  canReply: boolean;
  isChat: boolean;
  hidden: boolean;
  lastReadSeq: number;
  last: WireMessage;
}

interface ListedThread extends ThreadSummary {
  threadKey: Uint8Array | null;
  preview: string;
  sentAt: number;
}

let keys: ReaderKeyPair | null = null;
let threads: ListedThread[] = [];
let openId: string | null = null;
let openMessages: WireMessage[] = [];
let showingHidden = false;
const drafts = new Map<string, string>();

const unlockForm = el<HTMLFormElement>("unlock-form");
const keyFileInput = el<HTMLInputElement>("key-file");
const passphrase = el<HTMLInputElement>("passphrase");
const unlockButton = el<HTMLButtonElement>("unlock");
const unlockError = el("unlock-error");
const list = el("thread-list");
const empty = el("empty");
const pane = el("pane");
const messages = el("messages");
const replyForm = el<HTMLFormElement>("reply-form");
const replyInput = el<HTMLTextAreaElement>("reply");
const replyButton = el<HTMLButtonElement>("send-reply");
const paneError = el("pane-error");
const hideButton = el<HTMLButtonElement>("hide");
const closeButton = el<HTMLButtonElement>("close");
const resetCounter = wireCounter(replyInput, el("counter"), MAX_MESSAGE_CHARS);

const listError = el("list-error");
const listStatus = el("list-status");
const stopDialog = el<HTMLDialogElement>("stop-dialog");

function clearErrors(): void {
  paneError.hidden = true;
  listError.hidden = true;
  listStatus.hidden = true;
}

function lockOut(message: string): void {
  keys = null;
  threads = [];
  openId = null;
  drafts.clear();
  messages.replaceChildren();
  list.replaceChildren();
  replyInput.value = "";
  resetCounter();
  pane.hidden = true;
  el("placeholder").hidden = false;
  el("shell").classList.remove("reading");
  document.body.classList.remove("wide");
  el("view-inbox").hidden = true;
  el("view-unlock").hidden = false;
  showError(unlockError, new Error(message));
  focusHeading("view-unlock");
}

function fail(failure: unknown): void {
  if (failure instanceof ApiError && failure.status === 401) {
    lockOut(failure.message);
    return;
  }
  showError(el("shell").classList.contains("reading") ? paneError : listError, failure);
}

const listed = (id: string | null) => threads.find((thread) => thread.id === id);

function prepare(summary: ThreadSummary): ListedThread {
  let threadKey: Uint8Array;
  try {
    threadKey = openThreadKey(fromB64(summary.sealedThreadKey), keys!);
  } catch {
    return { ...summary, threadKey: null, preview: "Couldn't open this one", sentAt: 0 };
  }
  try {
    const content = decryptWireMessage(threadKey, fromB64(summary.id), summary.last);
    return { ...summary, threadKey, preview: content.text, sentAt: content.sentAt.getTime() };
  } catch {
    return { ...summary, threadKey, preview: "This message couldn't be shown", sentAt: 0 };
  }
}

function renderList(): void {
  const visible = threads.filter((thread) => thread.hidden === showingHidden).sort((a, b) => b.sentAt - a.sentAt);
  list.replaceChildren(
    ...visible.map((thread) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `thread${thread.id === openId ? " active" : ""}`;
      const title = document.createElement("strong");
      title.textContent = thread.isChat ? "Anonymous chat" : "Anonymous note";
      const preview = document.createElement("span");
      preview.textContent = thread.preview;
      button.append(title, preview);
      if (thread.sentAt > 0) {
        const time = document.createElement("small");
        time.textContent = new Date(thread.sentAt).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
        button.append(time);
      }
      if (thread.last.seq > thread.lastReadSeq) {
        const dot = document.createElement("i");
        dot.className = "dot";
        dot.setAttribute("aria-label", "unread");
        button.append(dot);
      }
      button.addEventListener("click", () => {
        button.disabled = true;
        void openThread(thread.id).finally(() => {
          button.disabled = false;
        });
      });
      return button;
    }),
  );
  empty.textContent = showingHidden ? "Nothing hidden." : "No messages yet. When someone says something, it lands here.";
  empty.hidden = visible.length > 0;
  el("inbox-title").textContent = showingHidden ? "Hidden" : "Inbox";
  el("toggle-hidden").textContent = showingHidden ? "Back to inbox" : "Hidden";
}

async function loadInbox(): Promise<void> {
  const known = new Map(threads.map((thread) => [thread.id, thread]));
  const loaded: ListedThread[] = [];
  let after: string | null = null;
  do {
    const page: { threads: ThreadSummary[]; nextAfter: string | null } = await api(`/api/inbox${after ? `?after=${after}` : ""}`);
    for (const summary of page.threads) {
      const previous = known.get(summary.id);
      loaded.push(previous?.threadKey && previous.last.seq === summary.last.seq ? { ...previous, ...summary } : prepare(summary));
    }
    after = page.nextAfter;
    await nextFrame();
  } while (after);
  threads = loaded;
  renderList();
}

function renderPane(): void {
  const thread = listed(openId);
  if (!thread || !thread.threadKey) return;
  renderMessages(messages, thread.threadKey, fromB64(thread.id), openMessages, "recipient");
  replyForm.hidden = !thread.canReply;
  closeButton.hidden = !thread.canReply;
  el("no-reply-note").hidden = thread.canReply;
  el("no-reply-note").textContent = thread.isChat ? "This chat is stopped." : "They didn't ask for a reply on this one.";
  hideButton.textContent = thread.hidden ? "Unhide" : "Hide";
}

async function openThread(id: string): Promise<void> {
  clearErrors();
  const thread = listed(id);
  if (!thread) return;
  if (!thread.threadKey) {
    fail(new Error("This one couldn't be opened with your key"));
    return;
  }
  try {
    openMessages = (await api<{ messages: WireMessage[] }>(`/api/inbox/${id}/messages`)).messages;
    const switching = openId !== id;
    if (openId && switching) drafts.set(openId, replyInput.value);
    openId = id;
    if (switching) {
      replyInput.value = drafts.get(id) ?? "";
      resetCounter();
    }
    pane.hidden = false;
    el("placeholder").hidden = true;
    el("shell").classList.add("reading");
    renderPane();
    if (switching) focusElement(el("pane-title"));
    const latest = openMessages.at(-1)?.seq ?? 0;
    if (latest > thread.lastReadSeq) {
      await api(`/api/inbox/${id}/read`, { seq: latest });
      thread.lastReadSeq = latest;
    }
    renderList();
  } catch (failure) {
    fail(failure);
  }
}

unlockForm.addEventListener("submit", (event) => {
  event.preventDefault();
  unlockError.hidden = true;
  const file = keyFileInput.files?.[0];
  if (!file) {
    showError(unlockError, new Error("Choose your key file first"));
    return;
  }
  void withBusy(unlockButton, "Unlocking…", async () => {
    try {
      let parsed: KeyFile;
      try {
        parsed = JSON.parse(await file.text()) as KeyFile;
      } catch {
        throw new Error("That doesn't look like a key file");
      }
      try {
        keys = openKeyFile(parsed, passphrase.value);
      } catch {
        throw new Error("Wrong passphrase, or that key file is damaged");
      }
      const { challengeId, challenge } = await api<{ challengeId: string; challenge: string }>("/api/login/start", { publicKey: b64(keys.publicKey) });
      await api("/api/login/finish", { challengeId, answer: b64(answerLoginChallenge(fromB64(challenge), keys)) });
      passphrase.value = "";
      await loadInbox();
      el("view-unlock").hidden = true;
      el("view-inbox").hidden = false;
      document.body.classList.add("wide");
      focusHeading("view-inbox");
    } catch (failure) {
      keys = null;
      showError(unlockError, failure);
    }
  });
});

el("back").addEventListener("click", () => {
  el("shell").classList.remove("reading");
  focusElement(document.querySelector<HTMLElement>(".thread.active"));
});
const refreshButton = el<HTMLButtonElement>("refresh");
const activity = () => threads.reduce((total, thread) => total + thread.last.seq, 0);
refreshButton.addEventListener("click", () => {
  clearErrors();
  void withBusy(refreshButton, "Checking…", async () => {
    const before = activity();
    try {
      await loadInbox();
      if (openId) await openThread(openId);
      if (activity() === before) {
        listStatus.textContent = "Nothing new yet";
        listStatus.hidden = false;
      }
    } catch (failure) {
      fail(failure);
    }
  });
});
el("toggle-hidden").addEventListener("click", () => {
  showingHidden = !showingHidden;
  renderList();
});
el("lock").addEventListener("click", () => {
  void api("/api/inbox/logout", {})
    .catch(() => undefined)
    .finally(() => location.reload());
});

hideButton.addEventListener("click", () => {
  const thread = listed(openId);
  if (!thread || hideButton.disabled) return;
  hideButton.disabled = true;
  void api(`/api/inbox/${thread.id}/hide`, { hidden: !thread.hidden })
    .then(() => {
      thread.hidden = !thread.hidden;
      renderPane();
      renderList();
    })
    .catch(fail)
    .finally(() => {
      hideButton.disabled = false;
    });
});

closeButton.addEventListener("click", () => stopDialog.showModal());
el("stop-cancel").addEventListener("click", () => stopDialog.close());
const stopConfirm = el<HTMLButtonElement>("stop-confirm");
stopConfirm.addEventListener("click", () => {
  const thread = listed(openId);
  if (!thread) return;
  void withBusy(stopConfirm, "Stopping…", async () => {
    try {
      await api(`/api/inbox/${thread.id}/close`, {});
      thread.canReply = false;
      renderPane();
    } catch (failure) {
      fail(failure);
    } finally {
      stopDialog.close();
    }
  });
});

async function postReply(thread: ListedThread, text: string, retry: boolean): Promise<void> {
  const seq = (openMessages.at(-1)?.seq ?? 0) + 1;
  const ciphertext = encryptMessage(thread.threadKey!, { threadId: fromB64(thread.id), seq }, { author: "recipient", sentAt: new Date(), text });
  try {
    await api(`/api/inbox/${thread.id}/messages`, { seq, ciphertext: b64(ciphertext) });
  } catch (failure) {
    if (retry && failure instanceof ApiError && failure.status === 409) {
      openMessages = (await api<{ messages: WireMessage[] }>(`/api/inbox/${thread.id}/messages`)).messages;
      await postReply(thread, text, false);
      return;
    }
    throw failure;
  }
}

replyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  clearErrors();
  const thread = listed(openId);
  if (!thread) return;
  void withBusy(replyButton, "Sending…", async () => {
    try {
      await postReply(thread, replyInput.value, true);
      replyInput.value = "";
      resetCounter();
      try {
        await openThread(thread.id);
        const latest = openMessages.at(-1);
        if (latest) Object.assign(thread, prepare({ ...thread, last: latest }));
        renderList();
      } catch {
        fail(new Error("Sent, but couldn't refresh the chat"));
      }
    } catch (failure) {
      fail(failure);
    }
  });
});
