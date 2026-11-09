# DESIGN.md

## Product and users
Internal anonymous messaging for EchorTech. Anyone can message a coworker without being identified. The tone is lowkey and Gen Z: short, casual sentence-case copy and no corporate language. Clarity still wins on anything that can cause permanent loss, such as secret codes and key files.

## Tokens
Source of truth: `public/style.css` (`:root`). System font only, because outside fonts would leak visits.
- Canvas: pale lavender to blush to peach gradient, fixed to the viewport. Keep it low contrast
- Surface: white floating card, 28px radius
- Accent: violet, for interactive elements only
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

## States
Errors appear in `.error` under the form, and typed text is kept. Long work changes the button label ("Locking it…"). Empty lists say what happens next.

## Decisions
- 2026-11-09: Layout based on Navan's gradient-and-card screen. Colours softened from a bold gradient to pale tones for a cleaner, more professional feel.
- 2026-11-09: No third-party scripts, fonts or images, to protect anonymity.
