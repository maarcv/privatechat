# 054 — Invitations: create a channel, show, export and import a config

Status: draft
Phase: 5
Related ADRs: 0008, 0017, 0022, 0028, 0031, 0038
Depends on: 011-config-format, 027-core-api, 040-uniffi, 041-desktop-bridge
Blocks: 050-desktop-mvp, 051-android-mvp, 052-ios-mvp, 055-verify-ui
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

The channel config is the only secret of the system, and the invitation is how it travels (`docs/spec.md` §5, ADR 0028). The core already does the cryptography: `create_channel`, `export_qr`, `export_file`, `import_qr` and `import_file` (spec 027-core-api R4–R6), with the formats, expiries and errors of spec 011-config-format. This spec fixes what the three clients do around those calls: the create form and its server check, how the invitation QR is shown, how the `.chatcfg` file and its seven-word password are exported, how a config is imported by camera, by pasted text or from a file, and what the user is told for each outcome. It also owns the camera scanner that spec 055-verify-ui reuses for `verify:` QRs.

The largest risk of the whole model is a user who shares the config by photo or messaging (`docs/spec.md` §12, "Risks"). The mitigations are here: the in-person QR is the default, it is shown only after a confirmation and only for 60 s, it can never be saved, copied or shared as an image, the file needs a password that is shown once and spoken over another route, and every export warns that whoever holds the config reads the whole channel. The scanner library was decided with the human reviewer on 2026-09-26: ZXing on Android, the platform's own scanner on iOS, and no camera at all on the desktop, which imports by pasted text or by file (`docs/audit-log.md`, "Phase 5 drafts", Q3).

**In plain words.** To invite someone in person, you open the channel, tap "Show invitation", accept a warning, and a QR appears for one minute; the other person scans it with this app, and only with this app. To invite someone at a distance, you save an invitation file and send it by any route; the app shows you seven words once, which you tell the other person by another route (a call, for instance), never in the same message as the file. The app never puts an invitation on the clipboard, never lets you save the QR as a picture, and never opens a scanned text as a link. On a computer there is no camera: you import a file, or paste the invitation text.

## Requirements

**Create a channel**

- R1 The create form MUST ask for a name, a message lifetime and a server. The name is 1..=64 bytes of UTF-8 with no Cc character, the suggested name of spec 011-config-format R4. The lifetime is one of 1 h, 24 h, 7 days and 30 days, with 24 h preselected, or a custom whole number of minutes whose value in seconds lies in 60..=2 592 000. The server field is prefilled with `settings().default_server_url` and offers as suggestions the distinct `server_url`s of `channels()`, in the order `channels()` returns them. The form MUST refuse, before any core call, a name or lifetime outside those ranges and a server URL over 256 bytes.
- R2 Before `create_channel`, the client MUST check the server with the probe of spec 027-core-api R12: on the desktop `probe_server` (spec 041-desktop-bridge R14); on Android and iOS `probe_plan` through `Core`, a socket along the route opened by the socket layer of spec 051-android-mvp or 052-ios-mvp, and `probeHello` of its first frame. Only `Supported` (`probeHello` true) leads to `create_channel`. Each other outcome MUST keep the form filled and show its message:
  - `Unsupported` (false): "This server runs a version of the protocol this app does not speak.";
  - `Unreachable`, `ProxyRefused` or a failed socket: "The server could not be reached." with a retry action;
  - `NotYet` (`probe_plan` returned `None`): the settings-reset notice of spec 027-core-api R2, with no probe;
  - `BadConfig`: "This is not a valid server address.", and for a `.onion` host or a `ws://` URL with no loopback proxy, "Onion servers need the Tor proxy set in the settings.".
  There is no "create anyway": a channel whose server was never checked is never created (`docs/spec.md` §5).
- R3 A created channel MUST open its channel screen, and the channel card MUST show its server and lifetime as read-only values, with no way to edit them (`docs/spec.md` §5, ADR 0008). The card MUST offer "Create new channel", which opens the create form prefilled with this channel's name and server, and shows, under the form, the help text of `docs/spec.md` §7 "Config compromise": "A new channel has a new key. Invite again only the members you have verified, and find out how the old invitation leaked." The old channel is left as it is; leaving it is the ordinary leave action.

**Show the invitation QR**

- R4 "Show invitation" MUST first show a confirmation with the warning "Whoever has this invitation can read the whole channel, past and future. Show it only to the person in front of you, and ask them to scan it with this app only: other camera apps can send the picture to third parties." Only its action button ("Show QR") calls `export_qr`, and the QR MUST NOT be shown before that tap. Each "Show invitation" asks again: there is no "do not ask again".
- R5 On Android and iOS the client MUST draw the QR on the device from the bytes `export_qr` returned, in byte mode with error correction level M, with ZXing's `QRCodeWriter` (`com.google.zxing:core`) on Android and Core Image's `CIQRCodeGenerator` on iOS, into a bitmap held only by the screen. It MUST overwrite the text bytes with zeros once the bitmap is drawn (`docs/spec.md` §5). On the desktop the QR is the image of the `qr` scheme that spec 041-desktop-bridge R6 serves; the text never reaches the web view.
- R6 The QR MUST be shown for at most 60 000 ms, with a visible countdown, and MUST be removed at the end of the countdown, when the screen is left, when the app goes to the background or locks, and on the desktop when the main window loses focus. Showing it again needs a new "Show invitation", which calls `export_qr` again and so gives a new invitation expiry of 10 min (spec 011-config-format R18). The screen MUST state that expiry: "This invitation can be scanned until HH:MM", from the moment of the export plus 600 000 ms.
- R7 The QR screen MUST offer no action to save, copy, print or share the image or its text. On Android the whole app carries `FLAG_SECURE` (`docs/spec.md` §8); on iOS the QR is covered on `willResignActive` and while `UIScreen.isCaptured` is true (`capturedDidChange`), and the bitmap is dropped when covered; on the desktop no screenshot can be blocked, a documented residual of §8.

**Export the invitation file**

- R8 "Send invitation file" MUST first show a confirmation with the warning of R4 and: "Send the file by any route, and tell the seven words by another route, for instance in a call. Never send them in the same message as the file. The file can be opened until HH:MM tomorrow." Only after it does the client call `export_file` (on the desktop through spec 041-desktop-bridge R6, which opens the save dialog first).
- R9 On Android and iOS the file MUST be written, 1 085 bytes, either to a place the user chooses (Android `ACTION_CREATE_DOCUMENT`, iOS `fileExporter`) or to a temporary file in the app's cache directory handed to the system share sheet (Android `ACTION_SEND` through a `FileProvider` that is not exported and grants read permission to that one URI; iOS `ShareLink`), with the name `invitation.chatcfg`. The temporary file MUST be deleted when the share sheet closes, when the app locks, and at the next start. The file name MUST NOT carry the channel's name.
- R10 The seven words MUST be shown once, numbered 1–7, on the screen that follows a successful export, from the byte array the export returned. They are not selectable and no action copies or shares them. The array MUST be overwritten with zeros when that screen goes away, and there is no way to show the same words again: a new export draws a new password (spec 011-config-format R16). That screen MUST repeat: "Tell these seven words by another route. Anyone with the file and the words reads the channel."

**Import**

- R11 The import screen MUST offer, on Android and iOS, "Scan QR" (default) and "Open invitation file"; on the desktop, "Open invitation file" (default) and "Paste invitation text". No platform imports from the clipboard on its own, and the mobile clients offer no paste: an invitation that arrives as text on a phone came through a route the model advises against.
- R12 The scanner of this spec MUST be the one component, per platform, that reads a QR from the camera, and spec 055-verify-ui MUST reuse it:
  - On Android, CameraX (`androidx.camera` `camera-camera2`, `camera-lifecycle`, `camera-view`) for the preview and `ImageAnalysis`, and ZXing `com.google.zxing:core` (Apache-2.0, open source, acceptable to F-Droid) with a `QRCodeReader` restricted to `BarcodeFormat.QR_CODE`. The payload is taken from the result's `BYTE_SEGMENTS` metadata; a result with no byte segment, or more than one, is ignored. Every `ImageProxy` is closed as soon as it is decoded, and no frame is kept, copied or written.
  - On iOS, `AVCaptureSession` with `AVCaptureMetadataOutput` restricted to `.qr`. The payload is the object's `stringValue` encoded as UTF-8 bytes. No `AVCapturePhotoOutput` or video output is attached, so no frame is kept.
  - The scanner delivers the first payload of at most 700 bytes to its caller as bytes, then stops the camera. A longer payload is ignored. It never interprets, opens or follows the text: it is not a URL handler, and it offers no torch-and-gallery import from saved pictures.
  - The camera permission is asked when the scanner first opens, never at start. On Android, the `CAMERA` runtime permission; when refused, the scanner shows "The camera is needed to scan an invitation." with an action to the system settings. On iOS, `NSCameraUsageDescription` in the iOS app's `Info.plist` ("To scan invitations and verification codes shown by other members."), which the iOS app needs; spec 041-desktop-bridge R8's rule of no usage description is for the macOS desktop bundle only.
- R13 A scanned or pasted text MUST reach `import_qr` as bytes, and the client MUST overwrite its copy with zeros after the call, on every path (spec 040-uniffi R9 on mobile; spec 041-desktop-bridge R6 on the desktop, where the pasted text is the raw IPC body). The desktop paste field is a single-line field of at most 700 bytes that is cleared as soon as the import returns. A file MUST be opened with the system picker (Android `ACTION_OPEN_DOCUMENT`, iOS `fileImporter`, the desktop's `choose_chatcfg` of spec 041-desktop-bridge R6), accepting any file, and on Android and iOS the client reads at most 1 086 bytes and refuses a longer one with the `BadConfig` message of R15 before asking for the password. No platform registers a file type or a URL scheme for `.chatcfg`: the file is opened from inside the app.
- R14 The password field MUST be `ByteArray`- or `Data`-backed, with `textPassword`, `IME_FLAG_NO_PERSONALIZED_LEARNING` and `flagNoExtractUi` on Android, `textContentType(.oneTimeCode)` off, `secureTextEntry` and `autocorrectionType = .no` on iOS, and an `<input type="password" autocomplete="off">` copied into a `Uint8Array` and cleared on the desktop (`docs/spec.md` §8 "Keyboard", "FFI boundary"). It accepts at most 1 024 bytes (spec 011-config-format R15), and the core canonicalises what it receives, so the client never trims or lowercases it.
- R15 Each import outcome MUST lead to exactly one of these, mapped once at the state owner:
  - `Ok` with `is_new = true`: the new channel's screen opens.
  - `Ok` with `is_new = false`: "You already have this channel." and its screen opens.
  - `InviteExpired`: "This invitation has expired. Ask for a new one."
  - `BadConfig`: "This is not a valid invitation."
  - `UnsupportedVersion`: "This invitation was made by a newer version of the app. Update the app to import it."
  - `BadPassword`: "Wrong password, or a damaged file." The client MUST NOT say which, since the core cannot tell (spec 011-config-format R14), and it keeps the chosen file for another try.
  - `ConfigMismatch`: "You already have this channel with a different server. The two cannot be merged; ask for a new invitation." (`docs/spec.md` §5).
  - `Store(Corrupt)` or `Store(UnsupportedVersion)`: the replace confirmation of spec 027-core-api R3 and R5, with its texts. On the desktop it is the native confirmation of spec 041-desktop-bridge R6 and R16; on Android and iOS an in-app destructive dialog whose action is "Replace", after which the client calls again with `replace_broken = true`.
  - Any other `Store` reason: "The app could not save the channel on this device."
  - On the desktop only: `Cancelled` and `Suppressed` leave the screen as it was, and `FileIo` shows "The file could not be read."
  No outcome shows a byte of the config, the password or a key.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| Channel name | 1..=64 B UTF-8, no Cc | refused in the form |
| Message lifetime | 1 h, 24 h, 7 days, 30 days, or custom minutes with 60..=2 592 000 s | refused in the form |
| Server URL | ≤ 256 B; the grammar is the core's (spec 011-config-format R5) | refused in the form; `BadConfig` from the probe |
| QR on screen | ≤ 60 000 ms | removed |
| Invitation expiry | QR 600 000 ms, file 86 400 000 ms from the export (spec 011-config-format R18) | `InviteExpired` at import |
| Scanned payload | ≤ 700 B, one byte segment | ignored, scanning goes on |
| Pasted text (desktop) | ≤ 700 B | refused in the field |
| File read (mobile) | ≤ 1 085 B; at most 1 086 B read | `BadConfig` message |
| Typed password | ≤ 1 024 B | refused in the field |
| Temporary export file | until the share sheet closes, the app locks, or the next start | deleted |

## Interface

```
clients/android/app/src/main/java/org/privatechat/
  ui/CreateChannelScreen.kt, ui/InviteQrScreen.kt, ui/ExportFileScreen.kt, ui/ImportScreen.kt, ui/QrScanner.kt
  viewmodel/CreateChannelViewModel.kt, viewmodel/InviteViewModel.kt, viewmodel/ImportViewModel.kt
  platform/QrScanner.kt       CameraX + ZXing QRCodeReader (R12)
  platform/QrDrawer.kt        ZXing QRCodeWriter (R5)
  platform/InviteFiles.kt     create, share and delete the temporary file; the FileProvider (R9)
clients/ios/PrivateChat/
  Views/CreateChannelView.swift, Views/InviteQRView.swift, Views/ExportFileView.swift, Views/ImportView.swift, Views/QRScannerView.swift
  ViewModels/CreateChannelModel.swift, ViewModels/InviteModel.swift, ViewModels/ImportModel.swift
  Platform/QRScanner.swift    AVCaptureMetadataOutput (R12)
  Platform/QRDrawer.swift     CIQRCodeGenerator (R5)
clients/desktop/src/lib/
  ui/CreateChannel.svelte, ui/InviteQr.svelte, ui/ExportFile.svelte, ui/Import.svelte
  state/createChannel.svelte.ts, state/invite.svelte.ts, state/import.svelte.ts
```

Screen states and intents, the same on the three platforms:

```
CreateChannelState = Editing(form, suggestions) | Probing(form) | Failed(form, ProbeFailure) | Created(ChannelId)
CreateChannelIntent = Edit(field, value) | Submit | Retry | Cancel
InviteState = Warning(kind: Qr | File) | ShowingQr(bitmap, secondsLeft, expiresAt) | Exporting | ShowingWords(words, expiresAt) | Closed
InviteIntent = Confirm | Dismiss | Tick | Leave
ImportState = Choosing | Scanning(permission) | EnteringPassword(file) | Importing | ConfirmReplace(reason) | Done(ChannelId, isNew) | Failed(ImportFailure)
ImportIntent = Scan | OpenFile | Paste(bytes) | Scanned(bytes) | Password(bytes) | Replace | Cancel
```

```kotlin
// platform/QrScanner.kt — reused by spec 055-verify-ui
fun interface QrScanned { fun onPayload(bytes: ByteArray) }   // called once, then the camera stops
@Composable fun QrScanner(onScanned: QrScanned, onPermissionDenied: () -> Unit)
```

```swift
// Platform/QRScanner.swift — reused by spec 055-verify-ui
struct QRScannerView: UIViewControllerRepresentable {   // the thin UIKit wrapper the swift skill allows for the camera
    let onPayload: @MainActor (Data) -> Void               // called once, then the session stops
    let onPermissionDenied: @MainActor () -> Void
}
```

Dependencies each justified in the pull request that adds them (AGENTS 8): on Android `com.google.zxing:core` and the three CameraX artefacts, pinned in the version catalog; on iOS none beyond the system frameworks; on the desktop none.

**PR slices** (AGENTS 14), one per platform and group: (a) create form and probe (R1–R3); (b) QR display and file export (R4–R10); (c) the scanner (R12), which spec 055-verify-ui then reuses; (d) import by file and by paste, and the outcomes (R11, R13–R15). Each slice lands once per platform, inside the platform specs 050, 051 and 052.

## Security

- The config never reaches the clipboard, the share sheet as text, a notification, a log or a file name (R7, R9, R10, R11). The only shareable form is the encrypted 1 085-byte file, whose size says nothing about the channel (ADR 0031).
- The QR lives on screen for at most a minute, only after a tap on a warning, and is removed on background, lock or focus loss (R4, R6). Screenshots are blocked on Android and covered on iOS; the desktop cannot block them, a residual of `docs/spec.md` §8.
- The seven words are shown once, from bytes, and cleared when the screen goes; a lost password means a new export (R10).
- The scanner never keeps a frame and never acts on the text it reads (R12); what it reads goes to the core, which decides. A config that a hostile QR carries is only a channel the user joins by choice.
- These copies are not zeroed: ZXing and AVFoundation hold the decoded text as a `String` inside the library before the client copies it to bytes, and the drawn QR bitmap holds the config in its pixels until the screen drops it. `docs/spec.md` §8 promises non-retention outside the core, not erasure; these are documented residuals.
- "Create new channel" is the only answer to a leaked config (ADR 0008), and its help text says whom to invite again (R3).

## Public API changes

None. The clients call the core functions of spec 027-core-api as they stand, through spec 040-uniffi and spec 041-desktop-bridge.

## Test cases

State-owner tests run on each platform against fakes of `Core` or the bridge; the UI test is the "import a config" flow of the architecture skill §7.

- T01 (covers R1): `s054_t01_r01_create_form` (Kotlin `s054_t01_r01_create_form`, Swift `s054_t01_r01_createForm`, desktop `s054_t01_r01_createForm`): a 65-byte name, a lifetime of 59 s and of 2 592 001 s, and a 257-byte URL are refused with no core call; the server is prefilled with the default and the suggestions are the distinct servers of `channels()`.
- T02 (covers R2): `s054_t02_r02_probe_before_create`: `Supported` then `create_channel` once; each other outcome keeps the form and shows its message, with no `create_channel`; `NotYet` makes no socket.
- T03 (covers R3): `s054_t03_r03_card_and_new_channel`: the card has no editable server or lifetime; "Create new channel" prefills name and server and shows the help text.
- T04 (covers R4): `s054_t04_r04_warning_first`: no `export_qr` before the warning's action; dismissing the warning calls nothing.
- T05 (covers R5): `s054_t05_r05_draw_and_zero`: the drawn QR decodes, with the platform's own reader, to the bytes of 011 `config_reference`'s QR text; the text array is all zeros after drawing.
- T06 (covers R6): `s054_t06_r06_sixty_seconds`: with a fake clock, the QR is gone at 60 000 ms, on leaving the screen, on background and on lock; the stated expiry is the export time plus 600 000 ms.
- T07 (covers R7): `s054_t07_r07_no_share`: the QR screen has no save, copy, print or share action; on iOS the QR is covered while captured.
- T08 (covers R8): `s054_t08_r08_file_warning`: no `export_file` before the warning's action.
- T09 (covers R9): `s054_t09_r09_temporary_file`: the file is 1 085 bytes and named `invitation.chatcfg`; the temporary file is gone after the sheet closes, after lock and after a restart; the `FileProvider` is not exported.
- T10 (covers R10): `s054_t10_r10_words_once`: seven numbered words shown; no copy action; the array is all zeros after the screen goes; the screen cannot be reopened with the same words.
- T11 (covers R11): `s054_t11_r11_import_sources`: the mobile import screen has no paste action; the desktop has paste and file; nothing reads the clipboard on its own.
- T12 (covers R12): `s054_t12_r12_scanner`: a fake camera feed with a QR of 011 `config_reference` delivers its bytes once and stops; a 701-byte QR and a QR with two byte segments are ignored; a QR holding `https://example.org/` is delivered as bytes and opens nothing; a refused permission shows the settings action; no frame is written to disk.
- T13 (covers R13): `s054_t13_r13_bytes_and_files`: the scanned and pasted bytes are zeros after `import_qr`; a 1 086-byte file on mobile is refused before the password; the manifest and `Info.plist` register no `.chatcfg` type and no URL scheme.
- T14 (covers R14): `s054_t14_r14_password_field`: the field flags of each platform; a 1 025-byte entry is refused; the bytes passed to `import_file` are those typed, untrimmed.
- T15 (covers R15): `s054_t15_r15_outcomes`, and the UI test `s054_t15_r15_import_ui` of the architecture skill §7: each outcome of R15 maps to its state and text; `BadPassword` keeps the file; the replace dialog appears only for `Corrupt` and `UnsupportedVersion`, and its action calls again with `replace_broken = true`. The UI test imports 011 `config_reference` and `chatcfg_reference` with its password, and 011 `invite_expired` gives the expired text.

## Vectors

None of its own. T05, T12 and T15 use the vectors of spec 011-config-format: `config_reference`, `chatcfg_reference` with its password, and `invite_expired`.

## Acceptance criterion

The tests of each platform green in the CI jobs of specs 050, 051 and 052. Non-automatable: on a real Android phone and iPhone, the invitation QR of one device is scanned by the other and the channel opens; the Android build with the ZXing and CameraX artefacts passes an F-Droid scanner check (no proprietary dependency); a second person reads the three platforms' import screens and confirms that none offers a way to copy, save or share the config.

## Out of scope

- The verification screens and the `verify:` QR flow, which reuse the scanner of R12 (spec 055-verify-ui).
- The layout, navigation and styling of each app, and where these screens sit in it (specs 050-desktop-mvp, 051-android-mvp, 052-ios-mvp).
- The sockets that carry the probe on Android and iOS (specs 051 and 052).
- The lock, the keystore and when the app locks (spec 053-device-security).
- The split invitation (a short QR plus dictated words), a v2 option of `docs/spec.md` §12.

## Open questions

None.

## History

- 2026-09-26 draft
