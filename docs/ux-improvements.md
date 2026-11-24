# UX improvements

| ID | Area | Problem (reported by users) | Fix | Check | Status |
|---|---|---|---|---|---|
| U1 | Send | Name list empty for a few seconds | Names built into the page, picker loads separately from crypto | Names listed as soon as the page shows | fixed, unverified on live |
| U2 | Send | Hard to find a person in a long list | Searchable picker with keyboard support | Type part of a name, choose it | fixed, unverified on live |
| U3 | Setup | 12-character passphrase is a chore | One-click generator with copy, shown again on the save screen | Generate, sign up, unlock with it | fixed, unverified on live |
| U4 | All | Unclear which step is first and which code to paste | Rewrote page intros, labels and hints; numbered unlock steps | Each page says what to do and where the code comes from | fixed, unverified on live |
| U5 | Chats | Secret code is awkward for people with an inbox | Chats can be opened with the inbox key, under Sent | Send with key, see it in Sent with no code | fixed, unverified on live |
| U6 | Setup | Invite code was hard to type | Short company code, capitals ignored | Any capitalisation accepted | fixed, unverified on live |

## Independent review findings

| ID | Problem | Status |
|---|---|---|
| R1 | "Say something else" kept the last recipient | fixed |
| R2 | Choices made before the main script loaded were ignored | fixed |
| R3 | Save screen undersold the generated passphrase | fixed |
| R4 | No signal for replies under Sent | fixed |
| R5 | Switching chats during sending lost drafts | fixed |
| R6 | Failed Sent lookup looked like no chats | fixed |
| R7 | Typed full name did not count, error far from field | fixed |
| R8 | Menu visible on the save screen | fixed |
| R9 | Generated passphrase could not be edited safely | fixed |
| R10 | Chat card broke at short heights | fixed, unverified |
| R11 | Purple dialog backdrop | fixed |
| R14 | "Done" hid what the step does | fixed |
| R16 | Passphrase label not bold | fixed |
| R17-R21 | Sign-out, shared browser and browser-only chat risks weren't communicated | fixed |
| R22 | Expired session wiped a typed reply | fixed |
| R23-R24 | Chat page race and lost drafts | fixed by merging into Messages |
| R25 | Reply dot never cleared | fixed |
| R26, R28 | Loading could hang or show the unlock form when offline | fixed |
| R27, R32 | Setup always signed in, claim could be untrue | fixed |
| R29-R31, R33, R35, R36, R39 | Backup code, empty state and copy issues | fixed |
| R34 | Retry after list failure | fixed via Refresh |
| R37-R38 | Row alignment and error styling on the old chat page | removed with that page |
| R12 | Picker screen reader details, chosen row marker | open |
| R13 | Arrow does not toggle the list | open |
| R15 | Generated passphrase not announced, tab group role | open |

Not covered in this pass: phone layout, real screen readers.
