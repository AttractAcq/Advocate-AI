# Console accessibility source review

**Scope:** React Console source and CSS on the synthetic development branch.
This is a source review and build check, not a rendered WCAG 2.1 AA audit.
The computer-use browser service was unavailable in this environment, so
keyboard, screen-reader and 200% zoom behavior still need direct testing.

| Check | Evidence and action | Result |
|---|---|---|
| Landmarks and form names | Main, navigation, labeled sign-in, search, department and question controls are present. View heading receives focus when signed-in view changes. | Source check passed; screen-reader behavior unverified |
| Keyboard access | Buttons, form controls, disclosure and source checkboxes use native elements. Mobile now exposes new conversation and history controls. | Source check passed; keyboard traversal unverified |
| Focus indicator | All buttons, links and disclosure summaries receive a visible outline; fields have a focus ring. | Source check passed; rendered visibility unverified |
| Text contrast | Checked selected text/background pairs by WCAG relative luminance. Changed accent on white from 3.83:1 to 6.15:1, muted text from 4.44:1 to 4.97:1 and hint text from 3.33:1 to 4.81:1. | Selected pairs pass 4.5:1; full visual audit pending |
| Dynamic results | Errors have `role=alert`; model activity has `role=status`. The full transcript is no longer a live region that could repeat earlier answers. | Source check passed; announcement behavior unverified |
| Citation inspection | Citation buttons request the cited passage ordinal through Core, verify returned source hash/version and show a labeled preview with a close control. A Core test confirms a later passage is linked by its ordinal. | Console builds and API test passes; rendered interaction and revocation behavior need review |

Run the Console on the synthetic lab and test each workflow with keyboard only,
VoiceOver or NVDA, 200% zoom and a contrast analyzer. Record browser and
assistive-technology versions, issues and retest results. Do not claim a WCAG
conformance result from the source check alone.
