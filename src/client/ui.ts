import sodium from "libsodium-wrappers-sumo";
import { decryptWireMessage, initCrypto } from "../crypto";
import { hasLeadingZeroBits, type PowSolution, type WireMessage } from "../types";

export const b64 = (value: Uint8Array) => sodium.to_base64(value);
export const fromB64 = (value: string) => sodium.from_base64(value);

export function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Couldn't connect. Check your internet and try again");
  }
  const data = (await response.json().catch(() => ({}))) as { error?: string };
  if (!response.ok) throw new ApiError(response.status, data.error ?? "Something went wrong, try again");
  return data as T;
}

export const nextFrame = () => new Promise((resolve) => setTimeout(resolve, 30));

export async function solvePow(): Promise<PowSolution> {
  const { payload, signature, bits } = await api<{ payload: string; signature: string; bits: number }>("/api/pow");
  const encoder = new TextEncoder();
  for (let counter = 0; ; counter++) {
    if (hasLeadingZeroBits(sodium.crypto_hash_sha256(encoder.encode(`${payload}:${counter}`)), bits)) {
      return { payload, signature, counter };
    }
    if (counter % 20000 === 19999) await nextFrame();
  }
}

export async function boot(button: HTMLButtonElement, error: HTMLElement): Promise<void> {
  try {
    await initCrypto();
    button.disabled = false;
  } catch (failure) {
    error.textContent = "Couldn't load. Refresh to try again";
    error.hidden = false;
    throw failure;
  }
}

export function focusElement(target: HTMLElement | null | undefined): void {
  if (!target) return;
  target.setAttribute("tabindex", "-1");
  target.focus();
}

export const focusHeading = (viewId: string) => focusElement(el(viewId).querySelector<HTMLElement>("h1"));

export const warnBeforeLeaving = (event: BeforeUnloadEvent) => event.preventDefault();

export function copyText(text: string, button: HTMLElement, doneLabel: string, status: HTMLElement): void {
  status.hidden = true;
  const failed = () => {
    status.textContent = "Couldn't copy. Select it and copy by hand";
    status.hidden = false;
  };
  if (!navigator.clipboard) {
    failed();
    return;
  }
  navigator.clipboard.writeText(text).then(() => {
    button.textContent = doneLabel;
  }, failed);
}

export function showError(target: HTMLElement, error: unknown): void {
  target.textContent = error instanceof Error ? error.message : "Something went wrong, try again";
  target.hidden = false;
}

export async function withBusy(button: HTMLButtonElement, label: string, work: () => Promise<void>): Promise<void> {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  await nextFrame();
  try {
    await work();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

export function renderMessages(
  container: HTMLElement,
  threadKey: Uint8Array,
  threadId: Uint8Array,
  messages: WireMessage[],
  myRole: "sender" | "recipient",
): void {
  container.replaceChildren(
    ...messages.map((message) => {
      const row = document.createElement("div");
      try {
        const content = decryptWireMessage(threadKey, threadId, message);
        row.className = `bubble ${content.author === myRole ? "mine" : "theirs"}`;
        row.textContent = content.text;
        const time = document.createElement("time");
        time.textContent = content.sentAt.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
        row.append(time);
      } catch {
        row.className = "bubble broken";
        row.textContent = "This message failed its safety check and can't be shown";
      }
      return row;
    }),
  );
  container.scrollTop = container.scrollHeight;
}

export function wireCounter(input: HTMLTextAreaElement, counter: HTMLElement, max: number): () => void {
  const update = () => {
    const used = Array.from(input.value).length;
    counter.textContent = `${used} / ${max}`;
    counter.classList.toggle("over", used > max);
  };
  input.addEventListener("input", update);
  update();
  return update;
}
