# 053 — Device security: the storage key, the app lock and the device measures of §8

Status: draft
Phase: 5
Related ADRs: 0020, 0021, 0028, 0037
Depends on: 020-store-files, 027-core-api, 040-uniffi, 041-desktop-bridge
Blocks: 050-desktop-mvp, 051-android-mvp, 052-ios-mvp
Human reviewer: Marc Vilardebó · Accepted on: —

## Context

`docs/spec.md` §8 lists the measures that protect a device: where the storage key `K_db` lives and what unwraps it, when the app locks, what is kept out of backups, screenshots, notifications, the clipboard, the keyboard and the build flags. This spec turns that table into requirements, one mechanism per platform, so that the three UI specs (050, 051, 052) build on one definition of "locked" and "unlocked". The desktop's keychain entry, its lock routine and its web view already live in spec 041-desktop-bridge; this spec adds what 041 left to it (the operating system's authentication at unlock, when the app locks on its own, notifications, the clipboard) and references the rest.

Before drafting, the human reviewer decided on 2026-09-26 (`docs/audit-log.md`, "Phase 5 drafts"): every desktop unlock asks the operating system's user authentication where one exists (Q2), and local notifications exist on the desktop only (Q4).

**In plain words.** Everything the app keeps on a device is encrypted with one 32-byte key. On a phone, that key is itself locked by the phone's secure chip, and only the phone's own fingerprint, face or PIN prompt can open it; on a computer, it sits in the system keychain, and the system's Touch ID, Windows Hello or password prompt must be passed before the app reads it. "Locked" means the key has been wiped from memory, the files are closed and the app is offline; the app locks when it goes to the background, when the screen turns off, when the computer's session locks, or when the user asks. Nothing the app holds goes into backups, screenshots or notification texts, and nothing is sent to any analytics service.

## Requirements

**The storage key on Android**

- R1 `platform/StorageKey.kt` MUST keep `K_db` as the AES-GCM encryption, under one Android Keystore key, of 32 bytes drawn with `Core.generateStorageKey` (spec 040-uniffi R8). The Keystore key MUST be an AES key of 256 bits with block mode GCM, no padding, `setUserAuthenticationParameters(t, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)` where `t` is the grace of R7, `setInvalidatedByBiometricEnrollment(false)`, `setUnlockedDeviceRequired(true)` and `setIsStrongBoxBacked(true)` when `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present (a `StrongBoxUnavailableException` falls back to the TEE once, at creation). The wrapped key MUST be the file `noBackupFilesDir/storage-key.wrap`, holding the 12-byte IV followed by the ciphertext and its 16-byte tag, written with a temporary file and a rename. The unwrapped bytes go once to `Core.open`, which zeroes them (spec 040-uniffi R9); the class exposes `unwrap(): ByteArray` and `create(): ByteArray` and nothing else.

**The storage key on iOS**

- R2 `Platform/StorageKey.swift` MUST keep `K_db` as the encryption, under one P-256 key in the Secure Enclave, of 32 bytes drawn with `Core.generateStorageKey`. The Secure Enclave key MUST be created with `kSecAttrTokenIDSecureEnclave`, `SecAccessControl(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence])`, and a fixed application tag. The 32 bytes are encrypted with `SecKeyCreateEncryptedData` and `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM` to the key's public half, and the ciphertext is one Keychain generic-password item, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so that neither leaves the device or reaches an iCloud backup. Decryption passes the `LAContext` of R6 as `kSecUseAuthenticationContext`. The class exposes `unwrap(context:) async throws -> Data` and `create() async throws -> Data` and nothing else. This wrapping is the operating system's own cryptography, which §8 mandates; it touches only `K_db`, never a channel key or the wire format (AGENTS 2).

**The storage key on the desktop**

- R3 On macOS the entry of spec 041-desktop-bridge R16 MUST be a data-protection Keychain item written through the `security-framework` crate with the access control `USER_PRESENCE` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, in place of `keyring`'s macOS store, so that reading it makes the system ask for Touch ID or the account password before it returns the key. The item keeps 041 R16's service and user. This spec amends spec 041-desktop-bridge R16 for macOS in the pull request that marks it `accepted`.
- R4 On Windows every `unlock` MUST first ask `Windows.Security.Credentials.UI.UserConsentVerifier::RequestVerificationAsync` (the `windows` crate's WinRT projection), with the fixed text of R19, and read the Credential Manager entry of spec 041-desktop-bridge R16 only after `Verified`. `Canceled`, `RetriesExhausted` or any other result returns `Cancelled` with nothing read. When `CheckAvailabilityAsync` is not `Available` (no Windows Hello and no PIN set up), `unlock` falls back to the native confirmation of spec 041-desktop-bridge R9 and R16. On Linux, where no standard equivalent exists, `unlock` keeps 041's confirmation. On macOS and Windows, where the system prompt asks for the user, it replaces 041's `Unlock` confirmation, and it is asked at every `unlock`, the first of the process included.

**Unlocking**

- R5 On Android and iOS, `unlock` MUST follow the rules of spec 041-desktop-bridge R16 for the key's presence, with the wrapped key (R1, R2) in place of the keychain entry and the same meaning of "holds data" (041 R15):
  - A wrapped key and a Keystore or Secure Enclave key that decrypts it, and the directory holds data: open.
  - The directory holds no data: delete any wrapped key and platform key, create both (R1, R2), unwrap the new key once to check it, and open.
  - The directory holds data, and the wrapped key or the platform key is missing, or the platform reports the key permanently invalidated (`KeyPermanentlyInvalidatedException`, `errSecItemNotFound` on the Secure Enclave key): return `KeyLost` and create nothing.
  - The prompt was cancelled, failed or timed out, or the platform reports a transient error: return `Cancelled` or `KeychainUnavailable`, stay locked, and create nothing. No transient failure ever draws a new key (`docs/spec.md` §8 "Loss of the wrapping key").
  After `KeyLost` the app offers only `reset_local_data`, behind a destructive confirmation that says the local history is lost and that each channel comes back by importing a new invitation (`docs/spec.md` §7 "Leave channel", §8).
- R6 The app lock MUST be the operating system's prompt and nothing else, with no app PIN or password: `BiometricPrompt` with `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` on Android, an `LAContext` evaluating `.deviceOwnerAuthentication` on iOS, and R3 and R4 on the desktop. The prompt's title and reason are fixed texts of R19 that name no channel.
- R7 `lock_timeout_seconds` (spec 027-core-api R13, default 60, 0..=86 400) MUST be the grace within which a return to the app unlocks without a prompt, counted from the last successful prompt:
  - Android: it is the Keystore key's `t` (R1). A change of the setting re-wraps `K_db` under a new Keystore key with the new `t`, after one prompt, and deletes the old key only once the new wrap is written. `t = 0` needs a `CryptoObject` with every prompt.
  - iOS: the evaluated `LAContext` of R6 is kept for that many seconds after the app goes to the background and invalidated afterwards (`invalidate()`); a return within the grace decrypts with it and shows no prompt.
  - Desktop: no grace; every `unlock` prompts (R3, R4, Q2).
  `0` is the "strict" option of §8: every return prompts. The grace never keeps the device unlocked: locking (R8) always happens, only the next prompt is skipped.
- R8 The app MUST lock (close the `Core` on mobile, run spec 041-desktop-bridge R17's lock routine on the desktop) on each of these events:
  - Android: `ProcessLifecycleOwner` `ON_STOP`; `ACTION_SCREEN_OFF`; "Lock now".
  - iOS: `sceneDidEnterBackground`; `protectedDataWillBecomeUnavailable`; "Lock now".
  - Desktop: the main window unfocused for `lock_timeout_seconds` (0: at once), which the operating system's session lock also triggers; the session lock itself, where the platform reports it without `unsafe` (logind's `Lock` signal over D-Bus on Linux); "Lock now"; quit (041 R17).
  Locked is disconnected: no socket stays open and no work runs in the background (`docs/spec.md` §8 "Background").
- R9 On Android and iOS, one `LockController` per app MUST serialise lock and unlock as spec 041-desktop-bridge R15 does: a first-in, first-out queue held for the whole of each, never across a prompt, with every `Core.open` awaiting the last `Core.close` (spec 040-uniffi R9). An `unlock` while unlocked returns at once; a lock requested while a prompt is open dismisses the prompt's result and locks.
- R10 "Lock now" MUST exist on every platform: an in-app action on every screen of 050, 051 and 052; an app shortcut on Android (`ShortcutManager`, static, with no data); a home-screen quick action on iOS (`UIApplicationShortcutItem`, with no data); and a menu item with the accelerator `CmdOrCtrl+L` on the desktop.

**Storage, backups and screens**

- R11 The data directory MUST be kept out of backups and device transfer:
  - Android: `noBackupFilesDir/data`, with `android:allowBackup="false"`, `android:fullBackupContent="false"` and `dataExtractionRules` that exclude every domain from `cloud-backup` and `device-transfer`.
  - iOS: `Application Support/data`, with `isExcludedFromBackup = true` and the file protection `.complete`, so that its files cannot be read while the device is locked.
  - Desktop: spec 041-desktop-bridge R15 (the macOS attribute); on Windows and Linux the data lives outside the user's sync folders, and the help says that File History and similar tools should exclude it.
- R12 Screens MUST NOT be captured:
  - Android: `FLAG_SECURE` on the one activity, for the whole app.
  - iOS: an opaque cover over the whole window on `sceneWillResignActive` and while `UIScreen.isCaptured` is true (`capturedDidChange`), removed on `sceneDidBecomeActive` when the screen is not captured.
  - Desktop: not possible; the help says so.
- R13 Local notifications MUST exist on the desktop only (Q4). While the device is unlocked and the main window is not focused, a `core-event` `Message` from a peer raises one notification whose title is the app name and whose body is the fixed text "New messages" of R19, at most one every 60 000 ms, through `tauri-plugin-notification` from the Rust side, with no channel, peer, count or content. Android and iOS MUST NOT request notification permission (`POST_NOTIFICATIONS`, `UNUserNotificationCenter`) and post none.
- R14 The clipboard MUST hold only what the user copied from a message, and only for 60 000 ms: copying a message's text sets `ClipDescription.EXTRA_IS_SENSITIVE` on Android, `UIPasteboard.setItems(_, options: [.localOnly: true, .expirationDate: now + 60 s])` on iOS, and on the desktop goes through a Rust command that writes the text and clears the clipboard after 60 000 ms when it still holds that text. On Android the app clears it after 60 000 ms when the clip is still its own. An invitation text, a `.chatcfg` password and the export password MUST NOT be copied by any action of the app.
- R15 Text entry MUST follow §8 "Keyboard": on Android the `.chatcfg` and export password fields use `textPassword`, `IME_FLAG_NO_PERSONALIZED_LEARNING` and `flagNoExtractUi`, and the app shows a one-time warning when the default input method (`Settings.Secure.DEFAULT_INPUT_METHOD`) is not a system app; on iOS password fields use `isSecureTextEntry`, the composer uses `autocorrectionType = .no` and `spellCheckingType = .no`, and the app refuses custom keyboards (`application(_:shouldAllowExtensionPointIdentifier:)` returns `false` for `.keyboard`).

**The build**

- R16 No client MUST link a third-party analytics, crash-reporting or advertising SDK. Each client MUST have an allowlist of its resolved dependencies, checked in CI: `clients/android/dependencies.allow` against Gradle's resolved runtime classpath, `clients/ios/Package.resolved` against `clients/ios/dependencies.allow`, and the desktop's `Cargo.lock` and `pnpm-lock.yaml` against `clients/desktop/dependencies.allow`. A dependency not listed fails the build; adding one to a list is justified in its pull request (AGENTS 8).
- R17 The Android release build MUST be `debuggable = false`, with `android:usesCleartextTraffic="false"`, a `networkSecurityConfig` that permits cleartext only for the domain `onion` and its subdomains (spec 027-core-api R10's `ws://` onion routes through a loopback proxy), no `exported` component other than the launcher activity, no custom URL scheme and no `INTERNET`-unrelated dangerous permission beyond `CAMERA` (spec 054-qr-invite). The iOS app MUST declare no background mode, no URL scheme and no App Transport Security exception, and only the camera usage description that spec 054-qr-invite needs.
- R18 The app MUST show a one-time, dismissible warning, stored in the settings of the platform (not in the core), when it detects a rooted Android device (an `su` binary on `PATH`, or `Build.TAGS` containing `test-keys`) or a jailbroken iOS device (a write outside the sandbox succeeding, or `/Applications/Cydia.app` present). It never blocks the app.

**Texts and amendments**

- R19 Every fixed text of this spec (prompt titles and reasons, "New messages", the warnings of R15 and R18, the `KeyLost` explanation) MUST come from the platform's string resources, English source and the UI languages of `docs/spec.md` §12, with no channel, peer or server name in it.
- R20 In the pull request that marks this spec `accepted`:
  - `docs/spec.md` §8 "Storage key `K_db`" MUST name, for the desktop, the macOS access control of R3;
  - §8 "App lock" MUST name, for the desktop, the prompts of R3 and R4 and the Linux fallback;
  - §8 "Key life cycle" MUST name the desktop triggers of R8;
  - §8 "Local notifications" MUST say that Android and iOS post none;
  - §8 "Keyboard" MUST name R15's iOS refusal of custom keyboards;
  - spec 041-desktop-bridge R16 MUST name R3's macOS store and R4's prompts;
  - the swift skill MUST name the file protection of R11 and `Data` for the key.
  - `docs/spec.md` §9 and the kotlin skill MUST set `minSdk 30` (Android 11), which `setUserAuthenticationParameters` of R1 and R7 needs, decided with the human reviewer (`docs/audit-log.md`, "Phase 5 drafts", Q5), and spec 040-uniffi R11 builds at API level 30.

## Limits

| Input | Range | Out of range |
| --- | --- | --- |
| `K_db` | exactly 32 bytes | `KeyLost` |
| `storage-key.wrap` | 12 + 32 + 16 bytes | `KeyLost` when the directory holds data |
| `lock_timeout_seconds` | 0..=86 400 (spec 020-store-files) | `BadConfig` from the core |
| Grace after a prompt | `lock_timeout_seconds`; none on the desktop | a new prompt |
| Desktop window unfocused | `lock_timeout_seconds` | locked |
| Notifications | at most one per 60 000 ms | dropped |
| Clipboard lifetime | 60 000 ms | cleared |

## Interface

```
clients/android/app/src/main/kotlin/org/privatechat/platform/StorageKey.kt       R1, R5
clients/android/app/src/main/kotlin/org/privatechat/platform/LockController.kt   R6–R9
clients/android/app/src/main/kotlin/org/privatechat/platform/Clipboard.kt        R14
clients/android/app/src/main/kotlin/org/privatechat/platform/DeviceWarnings.kt   R15, R18
clients/android/app/src/main/AndroidManifest.xml                                 R11, R12, R17
clients/android/app/src/main/res/xml/data_extraction_rules.xml                   R11
clients/android/app/src/main/res/xml/network_security_config.xml                 R17
clients/android/dependencies.allow                                               R16
clients/ios/App/Platform/StorageKey.swift                                        R2, R5
clients/ios/App/Platform/LockController.swift                                    R6–R9
clients/ios/App/Platform/PrivacyCover.swift                                      R12
clients/ios/App/Platform/Pasteboard.swift                                        R14
clients/ios/App/Platform/DeviceWarnings.swift                                    R15, R18
clients/ios/App/Info.plist                                                       R17
clients/ios/dependencies.allow                                                   R16
clients/desktop/src-tauri/src/key.rs                                             R3 (macOS store), R4
clients/desktop/src-tauri/src/idle.rs                                            R8 (focus timer, logind)
clients/desktop/src-tauri/src/notify.rs                                          R13
clients/desktop/src-tauri/src/clipboard.rs                                       R14
clients/desktop/dependencies.allow                                               R16
scripts/check_client_dependencies.sh                                             R16
```

```kotlin
// org.privatechat.platform
class StorageKey(private val context: Context) {
    suspend fun create(activity: FragmentActivity): ByteArray   // draws, wraps, returns K_db once
    suspend fun unwrap(activity: FragmentActivity): ByteArray   // prompts unless within the grace
    suspend fun rewrap(activity: FragmentActivity, graceSeconds: Int)
}
sealed interface UnlockResult { data object Unlocked; data object Cancelled; data object KeyLost; data object Unavailable }
class LockController(private val key: StorageKey, private val dataDir: File) {
    suspend fun unlock(activity: FragmentActivity): UnlockResult
    suspend fun lock()
}
```

```swift
// Platform
final class StorageKey {
    func create() async throws -> Data
    func unwrap(context: LAContext) async throws -> Data
}
enum UnlockResult { case unlocked, cancelled, keyLost, unavailable }
@CoreActor final class LockController {
    func unlock() async -> UnlockResult
    func lock() async
}
```

```rust
// clients/desktop/src-tauri
pub trait UserPresence: Send + Sync { fn verify(&self, reason: &str) -> BoxFuture<'static, Presence>; }
pub enum Presence { Verified, Declined, Unavailable }   // Unavailable → the confirmation of 041 R9
```

The desktop dependencies added here (`security-framework`, `windows` with the `Security_Credentials_UI` feature, `tauri-plugin-notification`, and a clipboard crate) MUST pass spec 041-desktop-bridge R2's `deny.toml` unchanged, or amend 041 R2 in the same pull request.

**PR slices** (AGENTS 14): (a) Android `StorageKey`, `LockController` and the lifecycle (R1, R5–R10 for Android); (b) iOS the same (R2, R5–R10 for iOS); (c) desktop `UserPresence`, the macOS store and the focus timer (R3, R4, R8, R10 for the desktop); (d) backups, screens and manifests (R11, R12, R17); (e) notifications, clipboard, keyboard and warnings (R13–R15, R18, R19); (f) the dependency allowlists and the amendments (R16, R20).

## Security

- `K_db` is unwrapped only after the operating system's prompt (R1–R4, R6) and lives only in Rust while unlocked; the platform code holds it for one call and zeroes it (spec 040-uniffi R9). On Android and iOS the wrapping key never leaves the secure hardware; on macOS the Keychain enforces user presence; on Windows the prompt is a check the app makes before reading an entry any process of the user can read, and on Linux there is only 041's confirmation. Both are documented residuals of `docs/spec.md` §8 ("within the session, any process of the user can read keychain and files").
- The grace of R7 skips a prompt, never a lock: a stolen, unlocked phone opened within `lock_timeout_seconds` of the last prompt shows the app without asking. `0` removes the grace.
- `KeyLost` never draws a new key over data (R5), so a Keystore or Secure Enclave failure costs at most a prompt, and a lost key costs the local history, never silently the files.
- The file protection `.complete` (R11) keeps iOS files unreadable while the device is locked, even to the app.
- Notifications carry no content or name (R13), the clipboard holds a copied message for 60 s at most and never an invitation or a password (R14), and no third-party SDK is linked (R16).
- The warnings of R15 and R18 inform; they do not protect. A rooted device or a third-party keyboard can read what the user types.
- The OS pasteboard and keyboard histories, the macOS Notification Center's record of the notification time, and Windows' clipboard history (Win+V) are outside the app's reach; the help says so.

## Public API changes

None. The clients use spec 027-core-api through spec 040-uniffi and spec 041-desktop-bridge as they stand.

## Test cases

- T01 (covers R1): Kotlin `s053_t01_r01_keystore_parameters`: the `KeyGenParameterSpec` that `StorageKey` builds (read through a pure builder function) has AES 256, GCM, no padding, `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` with the grace, `invalidatedByBiometricEnrollment = false`, `unlockedDeviceRequired = true`, and StrongBox when the feature is present; `storage-key.wrap` is 60 bytes and written by rename.
- T02 (covers R2): Swift `s053_t02_r02_secureEnclaveAttributes`: the key attributes and the access control built for the Secure Enclave key, and the Keychain item's attributes, are exactly those of R2 (over an in-memory fake of the Keychain).
- T03 (covers R3): `s053_t03_r03_macos_access_control`: the item that `key.rs` writes on macOS carries `USER_PRESENCE` and `WhenUnlockedThisDeviceOnly` (a `cfg(test)` builder of the item's attributes).
- T04 (covers R4): `s053_t04_r04_user_presence`: with a fake `UserPresence`, `Declined` → `Cancelled` and no keychain read; `Unavailable` → the confirmation of 041 R9; `Verified` → the entry read; on macOS and Windows the first `unlock` of the process prompts.
- T05 (covers R5): Kotlin `s053_t05_r05_unlock_table` and Swift `s053_t05_r05UnlockTable`, over fakes: each row of R5 gives its result, and no path after a transient error or a cancelled prompt creates a key.
- T06 (covers R6): Kotlin `s053_t06_r06_prompt_is_the_lock` and Swift `s053_t06_r06PromptIsTheLock`: `unlock` never opens the `Core` without a successful prompt outside the grace; no screen offers a PIN.
- T07 (covers R7): Kotlin `s053_t07_r07_grace` and Swift `s053_t07_r07Grace`, with a fake clock: a return 59 s after the prompt with a grace of 60 opens without a prompt; 61 s prompts; a grace of 0 always prompts; changing the grace on Android re-wraps and keeps the old wrap until the new one is written.
- T08 (covers R8): Kotlin `s053_t08_r08_lock_triggers`, Swift `s053_t08_r08LockTriggers` and `s053_t08_r08_desktop_idle`: each listed event closes the `Core` or runs the lock routine; on the desktop, a window unfocused for the timeout locks, and refocused before it does not.
- T09 (covers R9): Kotlin `s053_t09_r09_lock_controller_order` and Swift `s053_t09_r09LockControllerOrder`: a `lock` and an `unlock` from two coroutines or tasks run in call order, and the `open` follows the `close`; a lock during an open prompt ends locked.
- T10 (covers R10): Kotlin `s053_t10_r10_lock_now`, Swift `s053_t10_r10LockNow`, `s053_t10_r10_desktop_lock_now`: the shortcut, the quick action and the menu item lock.
- T11 (covers R11): Kotlin `s053_t11_r11_backup_rules` (the manifest and `data_extraction_rules.xml` parsed), Swift `s053_t11_r11ExcludedAndProtected` (the directory's resource values and protection).
- T12 (covers R12): Kotlin `s053_t12_r12_flag_secure`; Swift `s053_t12_r12CoverOnResignAndCapture`.
- T13 (covers R13): `s053_t13_r13_notifications`: a `Message` while unfocused raises one notification with exactly the fixed title and body; a second within 60 000 ms none; none while focused or locked; Kotlin `s053_t13_r13_no_notification_permission` and Swift `s053_t13_r13NoNotificationRequest`.
- T14 (covers R14): Kotlin `s053_t14_r14_clipboard`, Swift `s053_t14_r14Pasteboard`, `s053_t14_r14_desktop_clipboard`: a copied message is sensitive and cleared after 60 000 ms (fake clock); no action copies an invitation or a password.
- T15 (covers R15): Kotlin `s053_t15_r15_password_fields` and Swift `s053_t15_r15KeyboardRules`.
- T16 (covers R16): CI step `s053_t16_r16_dependency_allowlists`: a dependency added to each client and not listed fails the step.
- T17 (covers R17): Kotlin `s053_t17_r17_manifest` (release manifest and network security config parsed) and Swift `s053_t17_r17InfoPlist`.
- T18 (covers R18): Kotlin `s053_t18_r18_root_warning` and Swift `s053_t18_r18JailbreakWarning`: shown once over fakes, never again after dismissal.
- T19 (covers R19): Kotlin `s053_t19_r19_strings`, Swift `s053_t19_r19Strings`, `s053_t19_r19_desktop_strings`: every fixed text exists in each UI language.
- T20 (covers R20): `check_s053_t20_r20_amendments` in `scripts/doc_lint.py`, once this spec is `accepted`.

## Vectors

None. The core's behaviour is unchanged; the platform measures are checked by the tests above and by hand.

## Acceptance criterion

The tests of each platform green in the CI jobs of specs 050, 051 and 052, and the dependency allowlists green. Non-automatable, on real hardware:
- on an Android phone with StrongBox and on one without, the key is created, the prompt unlocks, a biometric enrolment change keeps the data, and removing the screen lock gives `KeyLost`;
- on an iPhone, the prompt unlocks, a restore from backup onto another device gives `KeyLost`, and the data directory is unreadable while the device is locked;
- on macOS, reading the entry shows the Touch ID or password prompt; on Windows, Windows Hello is asked at every unlock and the fallback applies on a machine without it;
- screenshots and screen recording show nothing of the app on Android, and the cover on iOS;
- the desktop notification says only "New messages".

## Out of scope

- The screens that show the lock, the prompts' placement and the `KeyLost` flow's layout (specs 050, 051, 052).
- Scanning QR codes and the camera permission's use (spec 054-qr-invite).
- Reproducible builds, signing and store publication (spec 060-reproducible-builds).
- An app password for a desktop with no keychain (`docs/spec.md` §8): not in v1.

## Open questions

- 053-R3: a data-protection Keychain item needs the `keychain-access-groups` entitlement, so a development build must be signed with a development certificate; whether an ad-hoc build can use it is to be measured before slice (c).
- 053-R4: `RequestVerificationAsync` from a desktop process takes no window handle, so its prompt may open behind the main window; the handle-taking variant is a COM interop call that needs `unsafe`, which spec 041-desktop-bridge R1 forbids. To be measured before slice (c); the fallback is to accept the placement.

## History

- 2026-09-26 draft
- 2026-09-26 open question 053-R1 decided with the human reviewer: `minSdk 30` (`docs/audit-log.md`, "Phase 5 drafts", Q5)
