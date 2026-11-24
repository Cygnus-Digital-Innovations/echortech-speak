# DESIGN.md

## Product and users
Internal anonymous messaging for EchorTech. Anyone can message a coworker without being identified. The tone is lowkey and Gen Z: short, casual sentence-case copy and no corporate language. Clarity still wins on anything that can cause permanent loss, such as secret codes and key files.

## Tokens
Source of truth: `public/style.css` (`:root`). System font only, because outside fonts would leak visits.
- Canvas: pale mint gradient, fixed to the viewport. Keep it low contrast
- Surface: white floating card, 28px radius
- Accent: deep teal, for interactive elements and the sender's own chat bubbles
- Status: red for errors, amber for "this can't be undone" notes
- Spacing: 4px base

## Layout
Single-purpose pages use one centred card, 460px wide. The inbox uses one wide floating card with a list and a chat, showing one pane at a time on phones.

## Components
| Component | Class | Use when | Don't |
|---|---|---|---|
| Primary button | `.btn` | One per view | Two side by side |
| Quiet button | `.btn.quiet` | Secondary actions | Main action |
| Code box | `.code` | Secret code, shown once | Normal text |
| Bubble | `.bubble.mine` / `.bubble.theirs` | Chat messages | Anything else |

## Navigation
Every page shares one top menu: Send, Messages, Get an inbox. Messages holds Received and Sent together. The menu hides while something shown only once is on screen.

## Forms
People are picked with a searchable list that works before the main script loads. Setup asks for a name only. The key file needs no passphrase, and an optional 4-digit PIN locks the saved key on that browser.

## Remembering people
Don't ask for a code or key file on every visit. This browser remembers chats and stays signed in. Codes only appear for moving to another device.

## States
Errors appear in `.error` under the form, and typed text is kept. Long work changes the button label ("Locking it…"). Empty lists say what happens next.

## Decisions
- 2026-11-09: Moved to teal on soft mint, and replaced footer links with one top menu to make the product feel simpler.
- 2026-11-09: Layout based on Navan's gradient-and-card screen. Colours softened from a bold gradient to pale tones for a cleaner, more professional feel.
- 2026-11-09: No third-party scripts, fonts or images, to protect anonymity.
