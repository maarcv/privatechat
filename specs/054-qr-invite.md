# 054 — Invitations: create a channel, show, export and import a config

Status: draft
Phase: 5
Related ADRs: 0008, 0017, 0022, 0028, 0031, 0038
Depends on: 011-config-format, 022-peers-tofu, 027-core-api, 040-uniffi, 041-desktop-bridge, 053-device-security
Blocks: 050-desktop-mvp, 051-android-mvp, 052-ios-mvp, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The channel config is the only secret of the system, and the invitation is how it travels (`docs/spec.md` §5, ADR 0028). The core already does the cryptography: `create_channel`, `export_qr`, `export_file`, `import_qr` and `import_file` (spec 027-core-api R4–R6), with the formats, expiries and errors of spec 011-config-format. This spec fixes what the three clients do around those calls: the create form and its server check, how the invitation QR is shown, how the `.chatcfg` file and its seven-word password are exported, how a config is imported by camera or from a file, the confirmation before an import joins, and what the user is told for each outcome. It also owns the camera scanner that spec 055-verify-ui reuses for `verify:` QRs, and the "Create new channel" action of `docs/spec.md` §7 "Config compromise".

The largest risk of the whole model is a user who shares the config by photo or messaging (`docs/spec.md` §12, "Risks"). The mitigations are here: the in-person QR is the default, it is shown only after a confirmation and only for 60 s, the app offers no way to save, copy or share it as an image or text, the file needs a password that is shown once and told over another route, and every export warns that whoever holds the config reads the whole channel. The scanner library was decided with the human reviewer on 2026-09-26: ZXing on Android, the platform's own scanner on iOS, and no camera on the desktop (`docs/audit-log.md`, "Phase 5 drafts", Q3). During audit M the reviewer decided that no platform imports pasted text, since no client ever produces an invitation as text; that an import asks for confirmation before it joins; that iOS screenshots, which cannot be blocked, are answered with a warning; and that on Android the app's own system screens do not lock it for up to 120 s (`docs/audit-log.md`, "Audit M", M-Q1 to M-Q4).

**In plain words.** To invite someone in person, you open the channel, tap "Show invitation", accept a warning, and a QR appears for one minute; the other person scans it with this app, and only with this app. To invite someone at a distance, you save an invitation file and send it by any route; the app shows you seven words once, which you tell the other person by another route (a call, for instance), never in the same message as the file. Before joining, the app shows what the invitation is (its name, its server, how long messages last) and asks you to confirm. The app never puts an invitation on the clipboard, never lets you save the QR as a picture, and never opens a scanned text as a link. A computer has no camera: it joins from an invitation file.

## Requirements

**Create a channel**

- R1 The create form MUST ask for a name, a message lifetime and a server. The name is 1..=64 bytes of UTF-8 with no Cc character, the suggested name of spec 011-config-format R4. The lifetime is one of 1 h, 24 h, 7 days and 30 days, with 24 h preselected, or a custom whole number of minutes whose value in seconds lies in 60..=2 592 000. The server field is prefilled with `settings().default_server_url` and offers as suggestions the distinct `server_url`s of `channels()`, in the order `channels()` returns them. The form MUST refuse, before any core call, a name or lifetime outside those ranges and a server URL over 256 bytes.
- R2 Before `create_channel`, the client MUST check the server with the probe of spec 027-core-api R12: on the desktop `probe_server` (spec 041-desktop-bridge R14); on Android and iOS `probe_plan` through `Core`, a socket along the route opened by the socket layer of spec 051-android-mvp or 052-ios-mvp, and `probeHello` of its first frame. Only `Supported` (`probeHello` true) leads to `create_channel`. Each other outcome MUST keep the form filled and show its message:
  - `Unsupported` (false): "This server runs a version of the protocol this app does not speak.";
  - `Unreachable`, `ProxyRefused` or a failed socket: "The server could not be reached." with a retry action;
  - `NotYet` (`probe_plan` returned `None`): the settings-reset notice of spec 027-core-api R2, with no probe;
  - `BadConfig`: "This is not a valid server address.", and for a `.onion` host or a `ws://` URL with no loopback proxy, "Onion servers need the Tor proxy set in the settings.".
  There is no "create anyway": a channel whose server was never checked is never created (`docs/spec.md` §5).
- R3 A created channel MUST open its channel screen, and the channel card MUST show its server and lifetime as read-only values, with no way to edit them (`docs/spec.md` §5, ADR 0008). The card MUST offer "Create new channel", which opens the create form prefilled with this channel's name and server, and shows, under the form, the help text of `docs/spec.md` §7 "Config compromise": "A new channel has a new key. Invite again only the members you have verified, and find out how the old invitation leaked." The old channel is left as it is; leaving it is the ordinary leave action. This spec owns that action for the three platforms.

**Show the invitation QR**

- R4 "Show invitation" MUST first show a confirmation with the warning "Whoever has this invitation can read the whole channel, past and future. Show it only to the person in front of you, and ask them to scan it with this app only: other camera apps can send the picture to third parties." Only its action button ("Show QR") calls `export_qr`, and the QR MUST NOT be shown before that tap. Each "Show invitation" asks again: there is no "do not ask again".
- R5 On Android and iOS the client MUST draw the QR on the device from the text `export_qr` returned, at error correction level M, into a bitmap held only by the screen: on Android with ZXing's `QRCodeWriter` (`com.google.zxing:core`), which writes one byte segment; on iOS with Core Image's `CIQRCodeGenerator`, whose segments it chooses itself, since it takes no mode (measured on 2026-09-26). It MUST overwrite its byte copy of the text with zeros once the bitmap is drawn (`docs/spec.md` §5). On the desktop the QR is the image of the `qr` scheme that spec 041-desktop-bridge R6 serves, built from one byte segment at level M; the text never reaches the web view. Every renderer's output MUST decode, with ZXing's reader and with the iOS reader, to the exact text (T05).
- R6 The QR MUST be shown for at most 60 000 ms, with a visible countdown, and MUST be removed at the end of the countdown, when the screen is left, when the app goes to the background or locks, and on the desktop when the main window loses focus. Showing it again needs a new "Show invitation", which calls `export_qr` again and so gives a new invitation expiry of 10 min (spec 011-config-format R18). The screen MUST state that expiry as "A photo of this code stops working at HH:MM", from the moment of the export plus 600 000 ms.
- R7 The QR screen MUST be a full screen in the app's own window, never a dialog, popup or sheet, and MUST offer no action to save, copy, print or share the image or its text. Screen capture follows spec 053-device-security R12: on Android `FLAG_SECURE`, and every Compose `Dialog` and `Popup` the app shows uses `SecureFlagPolicy.SecureOn`; on iOS the QR is covered on `willResignActive` and while the scene's `sceneCaptureState` is `.active` (recording, mirroring), and the bitmap is dropped when covered; on the desktop the window's capture protection of spec 053-device-security R12 where the system offers it. iOS cannot block a screenshot, only report it afterwards (decided with the human reviewer, `docs/audit-log.md`, "Audit M", M-Q2): on `userDidTakeScreenshotNotification` the client MUST remove the QR at once and show "A screenshot of this invitation is in your Photos. Delete it; if it has left this phone, create a new channel.", with the "Create new channel" action of R3.

**Export the invitation file**

- R8 "Send invitation file" MUST first show a confirmation with the warning of R4 and: "Send the file by any route, and tell the seven words by another route, for instance in a call. Never send them in the same message as the file. The file can be opened until HH:MM tomorrow." Only after it does the client call `export_file`. On the desktop, spec 041-desktop-bridge R6 opens the save dialog first, then exports, writes, and shows the words. On Android and iOS, no secret is produced before a system screen the app opens returns (spec 053-device-security R8, `docs/audit-log.md`, "Audit M", M-Q1):
  - "Save to a file": the destination picker (Android `ACTION_CREATE_DOCUMENT`, iOS `fileExporter`) opens first; on its return, `export_file`, the file written to the chosen place, then the words (R10);
  - "Share": `export_file`, the file written to the temporary file of R9, the words (R10) and the user's "I have told them the words" or "I will tell them later"; only then the share sheet opens, with the words already gone.
- R9 On Android and iOS the file MUST be written, 1 085 bytes, with the name `invitation.chatcfg`, which never carries the channel's name, either to the place the user chose or to a temporary file in the app's cache directory handed to the system share sheet:
  - Android: `Intent.createChooser` over `ACTION_SEND` with the file's URI from a `FileProvider` that is not exported and grants read permission to that one URI; no `EXTRA_TEXT` and no `EXTRA_SUBJECT`; a `ClipData` label that is the fixed string `invitation`.
  - iOS: `UIActivityViewController` with `excludedActivityTypes` holding `.copyToPasteboard`, `.print` and `.assignToContact`, and a `completionWithItemsHandler`.
  The temporary file MUST be deleted when the iOS completion handler runs, 600 000 ms after the share sheet opened, at the next unlock and at the next start, and never at the lock that the share sheet itself causes, since the target app may still be reading it.
- R10 The seven words MUST be shown once, numbered 1–7, on a full screen that follows a successful export, from the byte array the export returned. They are not selectable and no action copies or shares them. The screen MUST say: "Tell these seven words by another route. Anyone with the file and the words reads the channel. Leaving the app erases them: write them down or tell them now." The array MUST be overwritten with zeros, and the screen dropped, when the user leaves it, when the app goes to the background or locks, when the desktop's main window loses focus, and on an iOS screenshot, which also shows the warning of R7 with "file" for "invitation". There is no way to show the same words again: a new export draws a new password (spec 011-config-format R16).

**Import**

- R11 The import screen MUST offer, on Android and iOS, "Scan QR" (default) and "Open invitation file"; on the desktop, "Open invitation file" alone. No platform imports pasted text, and no platform reads the clipboard: no client ever produces an invitation as text, so a text invitation came through a route the model advises against (decided with the human reviewer, `docs/audit-log.md`, "Audit M", M-Q3, which narrows "Phase 5 drafts" Q6).
- R12 The scanner of this spec MUST be the one component, per platform, that reads a QR from the camera, and spec 055-verify-ui MUST reuse it with its purpose:
  - It takes a `purpose`, `Invite` or `Verify`, which changes only its texts.
  - On Android, CameraX (`androidx.camera` `camera-camera2`, `camera-lifecycle`, `camera-view`) for the preview and `ImageAnalysis`, and ZXing `com.google.zxing:core` (Apache-2.0, acceptable to F-Droid) with a `QRCodeMultiReader` restricted to `BarcodeFormat.QR_CODE`. The payload is the result's `text`: every character MUST be printable ASCII (0x21..=0x7E) and there are at most 700 of them, converted to bytes one per character; any other result is ignored and scanning goes on. Byte segments are not used, since the desktop and iOS renderers mix segment kinds (measured). Every `ImageProxy` is closed as soon as it is decoded, and no frame is kept, copied or written.
  - On iOS, `AVCaptureSession` with `AVCaptureMetadataOutput` restricted to `.qr`. The payload is the object's `stringValue` under the same ASCII and length rule, as bytes. No `AVCapturePhotoOutput` or video output is attached, so no frame is kept.
  - A frame in which more than one QR is decoded delivers nothing, so that a code planted next to the real one never wins by position.
  - The scanner delivers one payload to its caller, then stops the camera. It never interprets, opens or follows the text: it is not a URL handler, and it offers no import from saved pictures.
  - Its caller MUST overwrite the payload with zeros after the one core call it makes, whatever the purpose and the result, since a payload scanned by mistake may be an invitation.
  - The camera permission is asked when the scanner first opens, never at start. On Android, the `CAMERA` runtime permission; on iOS, `NSCameraUsageDescription` in the iOS app's `Info.plist` ("To scan invitations and verification codes shown by other members."), which the iOS app needs; spec 041-desktop-bridge R8's rule of no usage description is for the macOS desktop bundle only. When the permission is refused the scanner shows, for `Invite`, "The camera is needed to scan an invitation." and, for `Verify`, "The camera is needed to scan a verification code.", with an action to the system settings.
- R13 A file MUST be opened with the system picker (Android `ACTION_OPEN_DOCUMENT`, iOS `fileImporter`, the desktop's `choose_chatcfg` of spec 041-desktop-bridge R6), accepting any file; on Android and iOS the client reads at most 1 086 bytes and refuses a longer one with the `BadConfig` message of R16 before asking for the password. The picker's result (a URI, never the bytes) is kept across the return, within spec 053-device-security R8's bounded exception. No platform registers a file type or a URL scheme for `.chatcfg`: the file is opened from inside the app. A scanned text reaches the core as bytes, and the client zeroes its copies as R12 and R15 say (spec 040-uniffi R9 on mobile; spec 041-desktop-bridge R6 on the desktop).
- R14 The password field MUST follow spec 053-device-security R15: on Android `KeyboardType.Password`, `IME_FLAG_NO_PERSONALIZED_LEARNING` set through `InterceptPlatformTextInput` (Compose sets `IME_FLAG_NO_FULLSCREEN` itself, in place of `flagNoExtractUi`), and the field excluded from autofill; on iOS `SecureField` with `textContentType` nil and `autocorrectionType = .no`; on the desktop `<input type="password" autocomplete="off">`. On submit the text is copied into a `ByteArray`, `Data` or `Uint8Array` and the field is cleared; the field's own `String` is a residual (Security). It accepts at most 1 024 bytes (spec 011-config-format R15), and the core canonicalises what it receives, so the client never trims or lowercases it.
- R15 An import MUST NOT join before the user confirms it (decided with the human reviewer, `docs/audit-log.md`, "Audit M", M-Q4). The client first calls `preview_qr(text, now)` or `preview_file(bytes, password, now)`, which parse the invitation and commit nothing (R17). The confirmation screen then shows:
  - the suggested name, editable, cleaned as spec 022-peers-tofu R6 says;
  - the server's host, and "This server is new to this device" when no channel of `channels()` has it;
  - the message lifetime;
  - "You already have a channel with a very similar name: check that this is the one you expect." when the preview says the name collides (R17).
  Only its "Join" action calls `import_qr` or `import_file`, with the same bytes and password, and then, when the user edited the name, `rename_channel` with it. "Cancel" calls nothing. The client keeps the text, the file bytes and the password only while this screen is open, and zeroes them when it closes, when the app goes to the background or locks, and after the import.
- R16 Each outcome of a preview or an import MUST lead to exactly one of these, mapped once at the state owner:
  - `Ok` with `is_new = true`: the new channel's screen opens.
  - `Ok` with `is_new = false`: "You already have this channel." and its screen opens.
  - `InviteExpired`: "This invitation has expired. Ask for a new one, or check this device's date and time."
  - `BadConfig`: "This is not a valid invitation.", except that a scanned text starting with `verify:` gives "This is a verification code: open the channel's verification screen."
  - `UnsupportedVersion`: "This invitation was made by a newer version of the app. Update the app to import it."
  - `BadPassword`: "Wrong password, or a damaged file." The client MUST NOT say which, since the core cannot tell (spec 011-config-format R14), and it keeps the chosen file for another try.
  - `ConfigMismatch`: "Different config for the same channel: you already have it with another server. The two cannot be merged; ask for a new invitation." (`docs/spec.md` §5).
  - `Store(Corrupt)` or `Store(UnsupportedVersion)`: the replace confirmation of spec 027-core-api R3 and R5, with its texts. On the desktop it is the native confirmation of spec 041-desktop-bridge R6 and R16; on Android and iOS an in-app destructive dialog whose action is "Replace", after which the client calls again with `replace_broken = true`.
  - Any other `Store` reason: "The app could not save the channel on this device."
  - On the desktop only: `Cancelled` and `Suppressed` leave the screen as it was, and `FileIo` shows "The file could not be read."
  - Any other error (`Locked`, `Closed`, `Internal`, `KeyLost` and the rest): "Something went wrong. Try again."
  No outcome shows a byte of the config, the password or a key.
- R17 This spec amends spec 027-core-api with two functions of `Device` that commit nothing, and specs 040-uniffi and 041-desktop-bridge with their twins and commands:
  - `preview_qr(text: &[u8], now: u64) -> Result<ConfigPreview, Error>` and `preview_file(bytes: &[u8], password: &[u8], now: u64) -> Result<ConfigPreview, Error>`, which run the parse and the checks of `import_qr` and `import_file` (spec 027-core-api R5) up to, and not including, the first store call, and return the errors those would return before it;
  - `ConfigPreview { suggested_name: String, server_url: String, ttl_seconds: u32, is_open: bool, server_known: bool, name_collides: bool }`, where `is_open` says a channel with that `channel_id` is open, `server_known` that an open channel has that `server_url`, and `name_collides` that the `name_key` of the suggested name (spec 022-peers-tofu R4) equals the key of an open channel's `local_name` or `suggested_name`. The collision is computed by the core, since the UI holds no logic (architecture skill §7).
  The amendments MUST be written into specs 027, 040 and 041 in the pull request that marks this spec `accepted`. `preview_file` runs the password derivation, so a file import costs it twice, about one second each.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Channel name | 1..=64 B UTF-8, no Cc | refused in the form |
| Message lifetime | 1 h, 24 h, 7 days, 30 days, or custom minutes with 60..=2 592 000 s | refused in the form |
| Server URL | ≤ 256 B; the grammar is the core's (spec 011-config-format R5) | refused in the form; `BadConfig` from the probe |
| QR on screen | ≤ 60 000 ms | removed |
| Invitation expiry | QR 600 000 ms, file 86 400 000 ms from the export (spec 011-config-format R18) | `InviteExpired` at import |
| Scanned payload | 1..=700 printable ASCII characters; one QR in the frame | ignored, scanning goes on |
| File read (mobile) | ≤ 1 085 B; at most 1 086 B read | `BadConfig` message |
| Typed password | ≤ 1 024 B | refused in the field |
| Temporary export file | until the iOS completion handler, 600 000 ms after the share, the next unlock or the next start | deleted |

## Interface

```
clients/android/app/src/main/kotlin/org/privatechat/
  ui/CreateChannelScreen.kt, ui/InviteQrScreen.kt, ui/ExportFileScreen.kt, ui/ImportScreen.kt, ui/ImportConfirmScreen.kt, ui/QrScannerView.kt
  viewmodel/CreateChannelViewModel.kt, viewmodel/InviteViewModel.kt, viewmodel/ImportViewModel.kt
  platform/QrScanner.kt       CameraX + ZXing QRCodeMultiReader (R12)
  platform/QrDrawer.kt        ZXing QRCodeWriter (R5)
  platform/InviteFiles.kt     write, share and delete the temporary file; the FileProvider (R9)
clients/ios/Privatechat/
  Views/CreateChannelView.swift, Views/InviteQRView.swift, Views/ExportFileView.swift, Views/ImportView.swift, Views/ImportConfirmView.swift, Views/QRScannerView.swift
  ViewModels/CreateChannelModel.swift, ViewModels/InviteModel.swift, ViewModels/ImportModel.swift
  Platform/QRScanner.swift    AVCaptureMetadataOutput (R12)
  Platform/QRDrawer.swift     CIQRCodeGenerator (R5)
  Platform/InviteFiles.swift  the temporary file and UIActivityViewController (R9)
clients/desktop/src/lib/
  ui/CreateChannel.svelte, ui/InviteQr.svelte, ui/ExportFile.svelte, ui/Import.svelte, ui/ImportConfirm.svelte
  state/createChannel.svelte.ts, state/invite.svelte.ts, state/import.svelte.ts
```

Screen states and intents, the same on the three platforms:

```
CreateChannelState = Editing(form, suggestions) | Probing(form) | Failed(form, ProbeFailure) | Created(ChannelId)
CreateChannelIntent = Edit(field, value) | Submit | Retry | Cancel
InviteState = Warning(kind: Qr | File) | ChoosingDestination | ShowingQr(bitmap, secondsLeft, expiresAt) | Exporting
            | ShowingWords(words, expiresAt) | Sharing | Closed
InviteIntent = Confirm | Dismiss | Tick | Leave | ToldThem | Destination(uri)
ImportState = Choosing | Scanning(permission) | EnteringPassword(fileUri) | Previewing | Confirming(ConfigPreview, name)
            | Importing | ConfirmReplace(reason) | Done(ChannelId, isNew) | Failed(ImportFailure)
ImportIntent = Scan | OpenFile | Scanned(bytes) | Password(bytes) | EditName(text) | Join | Replace | Cancel
```

```kotlin
// platform/QrScanner.kt (camera and decoding); ui/QrScannerView.kt (the Composable) — reused by spec 055-verify-ui
enum class ScanPurpose { Invite, Verify }
fun interface QrScanned { fun onPayload(bytes: ByteArray) }   // called once, then the camera stops; the caller zeroes the bytes
@Composable fun QrScannerView(purpose: ScanPurpose, onScanned: QrScanned, onPermissionDenied: () -> Unit)
```

```swift
// Platform/QRScanner.swift (the capture session); Views/QRScannerView.swift (the thin UIKit wrapper the swift skill allows for the camera)
enum ScanPurpose { case invite, verify }
struct QRScannerView: UIViewControllerRepresentable {
    let purpose: ScanPurpose
    let onPayload: @MainActor (Data) -> Void               // called once, then the session stops; the caller zeroes the bytes
    let onPermissionDenied: @MainActor () -> Void
}
```

```rust
// spec 027-core-api, amended by R17
pub struct ConfigPreview { pub suggested_name: String, pub server_url: String, pub ttl_seconds: u32, pub is_open: bool, pub server_known: bool, pub name_collides: bool }
impl Device {
    pub fn preview_qr(&self, text: &[u8], now: u64) -> Result<ConfigPreview, Error>;
    pub fn preview_file(&self, bytes: &[u8], password: &[u8], now: u64) -> Result<ConfigPreview, Error>;
}
```

Dependencies each justified in the pull request that adds them (AGENTS 8): on Android `com.google.zxing:core` and the three CameraX artefacts, pinned in the version catalog; on iOS none beyond the system frameworks; on the desktop none.

**PR slices** (AGENTS 14), one per platform and group: (a) create form and probe (R1–R3); (b) QR display and file export (R4–R10); (c) the scanner (R12), which spec 055-verify-ui then reuses; (d) the core's preview (R17), in `crates/core`, before any platform's (e); (e) import by file, the confirmation and the outcomes (R11, R13–R16). Each platform slice lands inside the platform specs 050, 051 and 052.

## Security

- The config never reaches the clipboard, the share sheet as text, a notification, a log or a file name (R7, R9, R10, R11). The only shareable form is the encrypted 1 085-byte file, whose size says nothing about the channel (ADR 0031).
- The QR lives on screen for at most a minute, only after a tap on a warning, and is removed on background, lock or focus loss (R4, R6). Screen capture is blocked on Android; on iOS recording and mirroring are covered, but a screenshot cannot be blocked: the client removes the QR or the words at once and tells the user to delete the picture and, if it left the phone, to create a new channel (R7, R10). This is a documented residual of `docs/spec.md` §8, as is capture on a desktop where the system offers no protection (spec 053-device-security R12).
- The seven words are shown once, from bytes, and cleared when the screen goes; a lost password means a new export (R10). They are never on screen while a system screen or share target is in front (R8).
- The scanner never keeps a frame and never acts on the text it reads (R12); what it reads goes to the core, which decides, and nothing joins before the user has seen the name, the server and the lifetime (R15). A frame with two QRs gives nothing, and a look-alike channel name or a server new to the device is flagged (R15, R17).
- These copies are not zeroed: ZXing and AVFoundation hold the decoded text as a `String` inside the library before the client copies it to bytes; ZXing's `QRCodeWriter` and `CIQRCodeGenerator` take the text as a `String` or `Data` of their own; the drawn QR bitmap holds the config in its pixels until the screen drops it; the password field holds a `String`. `docs/spec.md` §8 promises non-retention outside the core, not erasure; these are documented residuals.
- "Create new channel" is the only answer to a leaked config (ADR 0008), and its help text says whom to invite again (R3).

## Public API changes

Two functions and one record are added to the core by R17: `Device::preview_qr`, `Device::preview_file` and `ConfigPreview`, with their twins in spec 040-uniffi (`previewQr`, `previewFile`, `FfiConfigPreview`) and their commands in spec 041-desktop-bridge (`preview_file` over the pending file and a raw password body). Specs 027, 040 and 041 are amended when this spec is accepted.

## Test cases

State-owner tests run on each platform against fakes of `Core` or the bridge; the UI test is the "import a config" flow of the architecture skill §7. Each test is named per platform: Kotlin `s054_tTT_rRR_snake_case`, Swift `s054_tTT_rRR_camelCase`, desktop `s054_tTT_rRR_camelCase`, and the core's `s054_tTT_rRR_snake_case`.

- T01 (covers R1): `s054_t01_r01_create_form`: a 65-byte name, a lifetime of 59 s and of 2 592 001 s, and a URL of 257 bytes are refused with no core call; the server is prefilled with the default and the suggestions are the distinct servers of `channels()`.
- T02 (covers R2): `s054_t02_r02_probe_before_create`: `Supported` then `create_channel` once; each other outcome keeps the form and shows its message, with no `create_channel`; `NotYet` makes no socket.
- T03 (covers R3): `s054_t03_r03_card_and_new_channel`: the card has no editable server or lifetime; "Create new channel" prefills name and server and shows the help text.
- T04 (covers R4): `s054_t04_r04_warning_first`: no `export_qr` before the warning's action; dismissing the warning calls nothing.
- T05 (covers R5): `s054_t05_r05_draw_and_zero`: the QR drawn from 011 `config_reference`'s QR text, and from 014 `qr_reference`'s text, by each of the three renderers (ZXing `QRCodeWriter`, `CIQRCodeGenerator`, the desktop's `qrcode` SVG rasterised) decodes to the exact text with ZXing's reader and with the iOS reader; the client's byte copy is all zeros after drawing.
- T06 (covers R6): `s054_t06_r06_sixty_seconds`: with a fake clock, the QR is gone at 60 000 ms, on leaving the screen, on background and on lock; the stated time is the export time plus 600 000 ms, under "A photo of this code stops working at".
- T07 (covers R7): `s054_t07_r07_no_share`: the QR screen has no save, copy, print or share action and is not a dialog; on Android a screenshot of an app dialog is blank; on iOS the QR is covered while captured, and a screenshot notification removes it and shows the warning.
- T08 (covers R8): `s054_t08_r08_file_order`: no `export_file` before the warning's action; on mobile, "Save to a file" opens the picker before `export_file`, and "Share" opens the share sheet only after the words are gone.
- T09 (covers R9): `s054_t09_r09_temporary_file`: the file is 1 085 bytes and named `invitation.chatcfg`; the Android intent has no `EXTRA_TEXT` or `EXTRA_SUBJECT` and the label `invitation`; the iOS sheet excludes the three activity types; the temporary file survives the lock the share causes and is gone after the completion handler, after 600 000 ms, after the next unlock and after a restart; the `FileProvider` is not exported.
- T10 (covers R10): `s054_t10_r10_words_once`: seven numbered words on a full screen; no copy action; the array is all zeros after leaving, background, lock and desktop focus loss; the screen cannot be reopened with the same words.
- T11 (covers R11): `s054_t11_r11_import_sources`: no platform has a paste action; the desktop has only "Open invitation file"; nothing reads the clipboard.
- T12 (covers R12): `s054_t12_r12_scanner`: a fake camera feed with a QR of 011 `config_reference` delivers its bytes once and stops; a QR of 701 characters, a non-ASCII text and a frame with two QRs deliver nothing; a QR holding `https://example.org/` is delivered as bytes and opens nothing; the payload is all zeros after its caller's call, for each purpose; a refused permission shows the text of each purpose and the settings action; no frame is written to disk.
- T13 (covers R13): `s054_t13_r13_files`: a 1 086-byte file on mobile is refused before the password; the picker's URI survives the return; the manifest and `Info.plist` register no `.chatcfg` type and no URL scheme.
- T14 (covers R14): `s054_t14_r14_password_field`: the field flags of each platform, autofill excluded; the field is empty after submit; a 1 025-byte entry is refused; the bytes passed to the core are those typed, untrimmed.
- T15 (covers R15): `s054_t15_r15_confirm_before_join`: no `import_qr` or `import_file` before "Join"; "Cancel" calls nothing and zeroes the kept bytes; an edited name is passed to `rename_channel`; a server absent from `channels()` shows the new-server mark; `name_collides` shows the warning; the kept bytes are zeros after background and after the import.
- T16 (covers R16): `s054_t16_r16_outcomes`, and the UI test `s054_t16_r16_import_ui` of the architecture skill §7: each outcome of R16 maps to its state and text; a scanned `verify:` text gives the verification-code text; `BadPassword` keeps the file; the replace dialog appears only for `Corrupt` and `UnsupportedVersion`, and its action calls again with `replace_broken = true`; an unmapped error gives the generic text. The UI test imports 011 `config_reference` and `chatcfg_reference` with its password through the confirmation, and 011 `invite_expired` gives the expired text.
- T17 (covers R17): `s054_t17_r17_preview` in `crates/core`: `preview_qr` of 011 `config_reference` returns its name, server and lifetime, commits nothing (a `FailingVault` sees no call) and makes no plan; `preview_file` of `chatcfg_reference` with its password the same; each error vector of 011 gives the error `import_qr` gives; `is_open`, `server_known` and `name_collides` are set against a device holding a channel with that id, that server, and a name whose key is equal (022's collision vectors).

## Vectors

None of its own. T05, T12, T15, T16 and T17 use the vectors of spec 011-config-format (`config_reference`, `chatcfg_reference` with its password, `invite_expired` and the error vectors), 014-fingerprint's `qr_reference`, and the name collisions of spec 022-peers-tofu.

## Acceptance criterion

The tests of each platform green in the CI jobs of specs 050, 051 and 052, and T17 in `cargo test`. Non-automatable: on a real Android phone and iPhone, the invitation QR of each of the three platforms is scanned by both phones and the confirmation shows the channel; the Android build with the ZXing and CameraX artefacts passes an F-Droid scanner check (no proprietary dependency); a second person reads the three platforms' import and export screens and confirms that none offers a way to copy, save or share the config, and that nothing joins before "Join".

## Out of scope

- The verification screens and the `verify:` QR flow, which reuse the scanner of R12 with `Verify` (spec 055-verify-ui).
- The layout, navigation and styling of each app, and where these screens sit in it (specs 050-desktop-mvp, 051-android-mvp, 052-ios-mvp).
- The sockets that carry the probe on Android and iOS (specs 051 and 052).
- The lock, the keystore, when the app locks and the bounded exception for system screens (spec 053-device-security).
- The split invitation (a short QR plus dictated words), a v2 option of `docs/spec.md` §12.

## Open questions

None.

## History

- 2026-09-26 draft
- 2026-09-26 revised after audit M round 1 (`docs/audit-log.md`): the Android scanner reads the text, ASCII and at most 700 characters, since other renderers mix segments; one QR per frame; the scanner's purpose; payloads zeroed by the caller; no paste on any platform; a confirmation with the core's preview before an import joins; the mobile export order and the share file's lifetime under spec 053's bounded exception; the words dropped on background and lock; the iOS screenshot warning; full screens and secure dialogs; autofill excluded; texts aligned with §5 and an outcome for every error
