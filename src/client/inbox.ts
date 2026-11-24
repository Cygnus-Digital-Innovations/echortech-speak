import {
  answerLoginChallenge,
  decryptWireMessage,
  encryptMessage,
  MAX_MESSAGE_CHARS,
  openThreadKey,
  type ReaderKeyPair,
} from "../crypto";
import type { WireMessage } from "../types";
import { forgetCodes, forgetKeys, markRead, readUpTo, removeCodes, rememberedKeys, rememberKeys, saveCode, savedCodes } from "./device";
import { findSentChats, lookupCodes, type SentChat } from "./sent";
import { api, ApiError, b64, boot, copyText, el, focusElement, focusHeading, fromB64, nextFrame, readKeyFile, renderMessages, showError, solvePow, wireCounter, withBusy } from "./ui";

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

interface ListedSent extends SentChat {
  preview: string;
  sentAt: number;
}

type View = "inbox" | "sent" | "hidden";

let keys: ReaderKeyPair | null = null;
let threads: ListedThread[] = [];
let sentChats: ListedSent[] = [];
let sentState: "loading" | "ready" | "failed" = "loading";
let view: View = "inbox";
let openId: string | null = null;
let openSent: ListedSent | null = null;
let openMessages: WireMessage[] = [];
let sending = false;
let signingOut = false;
const drafts = new Map<string, string>();

const unlockForm = el<HTMLFormElement>("unlock-form");
const keyFileInput = el<HTMLInputElement>("key-file");
const passphrase = el<HTMLInputElement>("passphrase");
const unlockButton = el<HTMLButtonElement>("unlock");
const unlockError = el("unlock-error");
const codeForm = el<HTMLFormElement>("code-form");
const codeInput = el<HTMLInputElement>("code-input");
const openButton = el<HTMLButtonElement>("open-code");
const codeError = el("code-error");
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
const listError = el("list-error");
const listStatus = el("list-status");
const stopDialog = el<HTMLDialogElement>("stop-dialog");
const signoutDialog = el<HTMLDialogElement>("signout-dialog");
const forgetDialog = el<HTMLDialogElement>("forget-dialog");
const resetCounter = wireCounter(replyInput, el("counter"), MAX_MESSAGE_CHARS);

try {
  await boot(unlockButton, unlockError);
  openButton.disabled = false;
} catch (failure) {
  el("view-opening").hidden = true;
  el("view-unlock").hidden = false;
  throw failure;
}

function clearErrors(): void {
  paneError.hidden = true;
  listError.hidden = true;
  listStatus.hidden = true;
}

const hasUnread = (chat: ListedSent) => chat.last.author === "recipient" && chat.last.seq > readUpTo(chat.id);
const listed = (id: string | null) => threads.find((thread) => thread.id === id);
const visibleError = () => (el("shell").classList.contains("reading") ? paneError : listError);

function showShell(): void {
  el("view-opening").hidden = true;
  el("view-unlock").hidden = true;
  el("view-inbox").hidden = false;
  document.body.classList.add("wide");
  renderList();
}

function showUnlock(): void {
  el("view-opening").hidden = true;
  el("view-inbox").hidden = true;
  el("view-unlock").hidden = false;
  document.body.classList.remove("wide");
  el("unlock-back").hidden = sentChats.length === 0;
  el<HTMLDetailsElement>("paste").open = sentChats.length === 0 && savedCodes().length === 0 ? el<HTMLDetailsElement>("paste").open : false;
}

function closePane(): void {
  openId = null;
  openSent = null;
  messages.replaceChildren();
  pane.hidden = true;
  el("placeholder").hidden = false;
  el("shell").classList.remove("reading");
}

function fail(failure: unknown): void {
  if (failure instanceof ApiError && failure.status === 401 && keys) {
    // Sessions expire, but the key is still here, so sign back in without losing anything typed.
    const target = visibleError();
    void login().then(
      () => showError(target, new Error("You were signed back in. Please try that again.")),
      () => {
        keys = null;
        closePane();
        showUnlock();
        showError(unlockError, new Error("Please unlock your messages again"));
      },
    );
    return;
  }
  showError(visibleError(), failure);
}

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

function listSent(chat: SentChat): ListedSent {
  try {
    const content = decryptWireMessage(chat.threadKey, fromB64(chat.id), chat.last);
    return { ...chat, preview: content.text, sentAt: content.sentAt.getTime() };
  } catch {
    return { ...chat, preview: "This message couldn't be shown", sentAt: 0 };
  }
}

function row(title: string, previewText: string, sentAt: number, isActive: boolean, unread: boolean, unreadLabel: string, onOpen: () => Promise<void>): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `thread${isActive ? " active" : ""}`;
  const heading = document.createElement("strong");
  heading.textContent = title;
  const preview = document.createElement("span");
  preview.textContent = previewText;
  button.append(heading, preview);
  if (sentAt > 0) {
    const time = document.createElement("small");
    time.textContent = new Date(sentAt).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    button.append(time);
  }
  if (unread) {
    const dot = document.createElement("i");
    dot.className = "dot";
    dot.setAttribute("aria-label", unreadLabel);
    button.append(dot);
  }
  button.addEventListener("click", () => {
    if (sending) return;
    button.disabled = true;
    void onOpen().finally(() => {
      button.disabled = false;
    });
  });
  return button;
}

function renderTabs(): void {
  for (const name of ["inbox", "sent", "hidden"] as const) el(`tab-${name}`).setAttribute("aria-pressed", String(view === name));
  const replied = sentChats.filter(hasUnread).length;
  el("tab-sent").textContent = replied ? `Sent (${replied})` : "Sent";
  el("tab-hidden").hidden = !keys;
  el("lock").hidden = !keys;
  el("inbox-title").textContent = view === "sent" ? "Sent" : view === "hidden" ? "Hidden" : "Received";
  el("sent-tools").hidden = view !== "sent";
  el("forget").hidden = savedCodes().length === 0;
}

function renderList(): void {
  renderTabs();
  if (view === "sent") {
    const ordered = [...sentChats].sort((a, b) => b.sentAt - a.sentAt);
    list.replaceChildren(...ordered.map((chat) => row(`To ${chat.recipient}`, chat.preview, chat.sentAt, chat.id === openSent?.id, hasUnread(chat), "they replied", () => openSentChat(chat.id))));
    empty.textContent =
      sentState === "loading" ? "Loading your chats…" : sentState === "failed" ? "Couldn't load your chats. Click Refresh to try again." : 'No chats saved in this browser. Send a message with "Let them reply" ticked and it\'ll show up here.';
    empty.hidden = ordered.length > 0;
    return;
  }
  const showingHidden = view === "hidden";
  const visible = threads.filter((thread) => thread.hidden === showingHidden).sort((a, b) => b.sentAt - a.sentAt);
  list.replaceChildren(
    ...visible.map((thread) =>
      row(thread.isChat ? "Anonymous chat" : "Anonymous note", thread.preview, thread.sentAt, thread.id === openId, thread.last.seq > thread.lastReadSeq, "unread", () => openThread(thread.id)),
    ),
  );
  empty.textContent = showingHidden ? "Nothing hidden." : "No messages yet. When someone says something, it lands here.";
  empty.hidden = visible.length > 0;
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

async function loadSent(): Promise<void> {
  try {
    const [fromDevice, fromKey] = await Promise.all([lookupCodes(savedCodes()), keys ? findSentChats(keys.privateKey) : Promise.resolve({ chats: [] as SentChat[] })]);
    const merged = new Map([...fromDevice, ...fromKey.chats].map((chat) => [chat.id, chat]));
    sentChats = [...merged.values()].map(listSent);
    sentState = "ready";
  } catch (failure) {
    sentState = "failed";
    renderList();
    throw failure;
  }
  if (openSent) openSent = sentChats.find((chat) => chat.id === openSent!.id) ?? null;
  renderList();
}

function switchDraft(id: string): boolean {
  const current = openSent?.id ?? openId;
  if (current === id) return false;
  if (current) drafts.set(current, replyInput.value);
  replyInput.value = drafts.get(id) ?? "";
  resetCounter();
  return true;
}

function renderPane(): void {
  const thread = listed(openId);
  if (!thread || !thread.threadKey) return;
  renderMessages(messages, thread.threadKey, fromB64(thread.id), openMessages, "recipient");
  replyForm.hidden = !thread.canReply;
  closeButton.hidden = !thread.canReply;
  el("no-reply-note").hidden = thread.canReply;
  el("no-reply-note").textContent = thread.isChat ? "This chat is stopped." : "They didn't ask for a reply on this one.";
  hideButton.hidden = false;
  hideButton.textContent = thread.hidden ? "Unhide" : "Hide";
  el("device-code").hidden = true;
}

function revealPane(): void {
  pane.hidden = false;
  el("placeholder").hidden = true;
  el("shell").classList.add("reading");
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
    const switching = switchDraft(id);
    openId = id;
    openSent = null;
    revealPane();
    el("pane-title").textContent = "Anonymous";
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

async function openSentChat(id: string): Promise<void> {
  clearErrors();
  const chat = sentChats.find((item) => item.id === id);
  if (!chat) return;
  try {
    const thread = await api<{ status: string; messages: WireMessage[] }>("/api/sender/thread", { accessToken: b64(chat.accessToken) });
    const switching = switchDraft(id);
    chat.status = thread.status;
    openMessages = thread.messages;
    openSent = chat;
    openId = null;
    revealPane();
    renderMessages(messages, chat.threadKey, fromB64(chat.id), openMessages, "sender");
    const canReply = chat.status === "open";
    replyForm.hidden = !canReply;
    hideButton.hidden = true;
    closeButton.hidden = true;
    el("no-reply-note").hidden = canReply;
    el("no-reply-note").textContent = "This chat is stopped.";
    el("pane-title").textContent = `To ${chat.recipient}`;
    el("device-code").hidden = false;
    if (switching) {
      el("code-block").hidden = true;
      el("show-code").setAttribute("aria-expanded", "false");
      el("copy-chat-code").textContent = "Copy code";
      focusElement(el("pane-title"));
    }
    el("chat-code").textContent = chat.code;
    const latest = openMessages.at(-1)?.seq ?? 0;
    if (latest > 0) markRead(chat.id, latest);
    renderList();
  } catch (failure) {
    fail(failure);
  }
}

async function login(): Promise<void> {
  const { challengeId, challenge } = await api<{ challengeId: string; challenge: string }>("/api/login/start", { publicKey: b64(keys!.publicKey) });
  await api("/api/login/finish", { challengeId, answer: b64(answerLoginChallenge(fromB64(challenge), keys!)) });
}

async function signIn(): Promise<void> {
  await login();
  passphrase.value = "";
  await loadInbox();
  view = "inbox";
  showShell();
  focusHeading("view-inbox");
  void loadSent().catch(fail);
}

async function startSignedOut(): Promise<void> {
  keys = null;
  try {
    await loadSent();
  } catch (failure) {
    showError(unlockError, failure);
  }
  if (sentChats.length > 0) {
    view = "sent";
    showShell();
  } else {
    showUnlock();
  }
}

unlockForm.addEventListener("submit", (event) => {
  event.preventDefault();
  unlockError.hidden = true;
  void withBusy(unlockButton, "Unlocking…", async () => {
    const previous = keys;
    try {
      keys = await readKeyFile(keyFileInput.files?.[0], passphrase.value);
      await signIn();
      if (el<HTMLInputElement>("stay").checked) rememberKeys(keys);
    } catch (failure) {
      keys = previous;
      showError(unlockError, failure);
    }
  });
});

codeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  codeError.hidden = true;
  void withBusy(openButton, "Opening…", async () => {
    try {
      const code = codeInput.value.trim();
      let chat: SentChat | undefined;
      try {
        [chat] = await lookupCodes([code]);
      } catch (failure) {
        if (failure instanceof ApiError) throw failure;
        throw new Error("That code doesn't look right. Check it and try again");
      }
      if (!chat) throw new Error("We couldn't find a chat for that code");
      saveCode(code);
      codeInput.value = "";
      await loadSent();
      view = "sent";
      showShell();
      await openSentChat(chat.id);
    } catch (failure) {
      showError(codeError, failure);
    }
  });
});

el("unlock-back").addEventListener("click", () => {
  view = "sent";
  showShell();
});
el("have-code").addEventListener("click", () => {
  closePane();
  showUnlock();
  el<HTMLDetailsElement>("paste").open = true;
  codeInput.focus();
});

el("back").addEventListener("click", () => {
  el("shell").classList.remove("reading");
  focusElement(document.querySelector<HTMLElement>(".thread.active"));
});

const refreshButton = el<HTMLButtonElement>("refresh");
const activity = () => [...threads, ...sentChats].reduce((total, thread) => total + thread.last.seq, 0);
refreshButton.addEventListener("click", () => {
  clearErrors();
  void withBusy(refreshButton, "Checking…", async () => {
    const before = activity();
    try {
      await Promise.all([keys ? loadInbox() : Promise.resolve(), loadSent()]);
      if (openId) await openThread(openId);
      if (openSent) await openSentChat(openSent.id);
      if (activity() === before) {
        listStatus.textContent = "Nothing new yet";
        listStatus.hidden = false;
      }
    } catch (failure) {
      fail(failure);
    }
  });
});

for (const name of ["inbox", "sent", "hidden"] as const) {
  el(`tab-${name}`).addEventListener("click", () => {
    if (name === "inbox" && !keys) {
      showUnlock();
      return;
    }
    view = name;
    renderList();
  });
}

el("show-code").addEventListener("click", () => {
  const block = el("code-block");
  block.hidden = !block.hidden;
  el("show-code").setAttribute("aria-expanded", String(!block.hidden));
});
el("copy-chat-code").addEventListener("click", () => copyText(el("chat-code").textContent ?? "", el("copy-chat-code"), "Copied ✓", el("copy-chat-status")));

el("lock").addEventListener("click", () => {
  el("signout-extra").hidden = !sentChats.some((chat) => !chat.fromKey);
  signoutDialog.showModal();
});
el("signout-cancel").addEventListener("click", () => signoutDialog.close());
signoutDialog.addEventListener("cancel", (event) => {
  if (signingOut) event.preventDefault();
});
const signoutConfirm = el<HTMLButtonElement>("signout-confirm");
signoutConfirm.addEventListener("click", () => {
  signingOut = true;
  el<HTMLButtonElement>("signout-cancel").disabled = true;
  void withBusy(signoutConfirm, "Signing out…", async () => {
    // Chats tied to the key come back on sign-in, so they shouldn't stay visible here.
    removeCodes(sentChats.filter((chat) => chat.fromKey).map((chat) => chat.code));
    forgetKeys();
    await api("/api/inbox/logout", {}).catch(() => undefined);
    location.reload();
  });
});

el("forget").addEventListener("click", () => forgetDialog.showModal());
el("forget-cancel").addEventListener("click", () => forgetDialog.close());
el("forget-confirm").addEventListener("click", () => {
  forgetCodes();
  forgetDialog.close();
  closePane();
  void loadSent()
    .catch(fail)
    .finally(() => focusHeading("view-inbox"));
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

function sendBusy(work: () => Promise<void>): Promise<void> {
  sending = true;
  replyInput.readOnly = true;
  return withBusy(replyButton, "Sending…", work).finally(() => {
    sending = false;
    replyInput.readOnly = false;
  });
}

async function postSentReply(chat: ListedSent, text: string, retry: boolean): Promise<void> {
  const seq = (openMessages.at(-1)?.seq ?? 0) + 1;
  const ciphertext = encryptMessage(chat.threadKey, { threadId: fromB64(chat.id), seq }, { author: "sender", sentAt: new Date(), text });
  try {
    await api("/api/sender/messages", { accessToken: b64(chat.accessToken), seq, ciphertext: b64(ciphertext), pow: await solvePow() });
  } catch (failure) {
    if (retry && failure instanceof ApiError && failure.status === 409) {
      openMessages = (await api<{ messages: WireMessage[] }>("/api/sender/thread", { accessToken: b64(chat.accessToken) })).messages;
      await postSentReply(chat, text, false);
      return;
    }
    throw failure;
  }
}

replyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  clearErrors();
  if (openSent) {
    const chat = openSent;
    void sendBusy(async () => {
      try {
        await postSentReply(chat, replyInput.value, true);
        replyInput.value = "";
        resetCounter();
        try {
          await openSentChat(chat.id);
          const latest = openMessages.at(-1);
          if (latest) Object.assign(chat, listSent({ ...chat, last: latest }));
          renderList();
        } catch {
          fail(new Error("Sent, but couldn't refresh the chat"));
        }
      } catch (failure) {
        fail(failure);
      }
    });
    return;
  }
  const thread = listed(openId);
  if (!thread) return;
  void sendBusy(async () => {
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

async function start(): Promise<void> {
  const saved = rememberedKeys();
  el("opening-retry").hidden = true;
  el("opening-title").textContent = "Opening your messages…";
  if (!saved) {
    await startSignedOut();
    return;
  }
  keys = saved;
  try {
    await signIn();
  } catch (failure) {
    if (failure instanceof ApiError && failure.status !== 0) {
      // A removed key can never sign in again, so stop trying it on this device.
      if (failure.status === 404) forgetKeys();
      await startSignedOut();
      showError(unlockError, failure);
      return;
    }
    el("view-unlock").hidden = true;
    el("view-opening").hidden = false;
    el("opening-title").textContent = "Couldn't reach Say It. You're still signed in.";
    el("opening-retry").hidden = false;
  }
}

el("opening-retry").addEventListener("click", () => void start());

await start();
