//! Tests of the settings and their gate (spec 027-core-api R2, R13, and
//! R21 for the setters).

use super::{Fixture, SERVER, defaults_view};
use crate::Error;
use crate::storage::StoreError;
use crate::testing::{settings, settings_eq};

const PROXY: &str = "127.0.0.1:9050";
const OTHER_SERVER: &str = "wss://other.example.org";

/// A fixture with one channel and the settings `(OTHER_SERVER, 30,
/// PROXY)` saved.
fn with_stored_proxy() -> Fixture {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.save_settings(&settings(OTHER_SERVER, 30, Some(PROXY)));
    fixture
}

/// Spec 027, R2: while the gate is up a setter other than the proxy's
/// changes memory alone, and the gate stays up across a reopen; the
/// acknowledgement and the proxy setter each save and lower it.
#[test]
fn s027_t02_r02_settings_reset_gate() {
    for lower_with_proxy in [false, true] {
        let fixture = Fixture::new();
        fixture.plant_channel(1, Vec::new());
        let mut device = fixture.open().unwrap();
        assert!(device.status().settings_reset);
        device.set_lock_timeout_seconds(10).unwrap();
        assert_eq!(device.settings().lock_timeout_seconds, 10);
        assert!(device.status().settings_reset);
        assert!(fixture.vault.settings_raw().is_none());
        drop(device);

        let mut device = fixture.open().unwrap();
        assert!(device.status().settings_reset);
        device.set_lock_timeout_seconds(10).unwrap();
        if lower_with_proxy {
            device.set_socks5_proxy(Some(PROXY)).unwrap();
        } else {
            device.acknowledge_settings(false).unwrap();
        }
        let status = device.status();
        assert!(!status.settings_reset);
        assert_eq!(status.settings_reason, None);
        let proxy = lower_with_proxy.then_some(PROXY);
        let stored = fixture.stored_settings().unwrap();
        let expected = settings(crate::DEFAULT_SERVER_URL, 10, proxy);
        assert!(settings_eq(&stored, &expected));
        // Lowered, the setters save again.
        device.set_lock_timeout_seconds(20).unwrap();
        assert_eq!(fixture.stored_settings().unwrap().lock_timeout_seconds, 20);
    }
}

/// Spec 027, R2: a save that fails while lowering the gate keeps the
/// settings, the flag and the reason.
#[test]
fn s027_t02_r02_failed_save_keeps_the_gate() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.vault.put_settings_raw(b"corrupt");
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_save_settings(true);
    assert_eq!(
        device.acknowledge_settings(false),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(
        device.set_socks5_proxy(Some(PROXY)),
        Err(Error::Store(StoreError::Io))
    );
    let status = device.status();
    assert!(status.settings_reset);
    assert_eq!(status.settings_reason, Some(StoreError::Corrupt));
    assert_eq!(device.settings(), defaults_view());
}

/// Spec 027, R2: after a passing `Io`, the acknowledgement adopts the file
/// that reads again: the stored proxy kept and nothing saved, even with
/// every save failing.
#[test]
fn s027_t02_r02_passing_io_keeps_the_stored_proxy() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    assert_eq!(device.status().settings_reason, Some(StoreError::Io));
    assert_eq!(device.settings().socks5_proxy, None);
    fixture.faults.fail_load_settings(false);
    fixture.faults.fail_save_settings(true);
    let before = fixture.vault.settings_raw();
    device.acknowledge_settings(false).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(device.status().settings_reason, None);
    assert_eq!(device.settings().socks5_proxy.as_deref(), Some(PROXY));
    assert_eq!(device.settings().default_server_url, OTHER_SERVER);
    assert_eq!(fixture.vault.settings_raw(), before);
}

/// Spec 027, R2: after a passing `Io`, the proxy setter keeps the stored
/// `default_server_url` and applies the proxy; a timeout set while the
/// flag was up is applied onto the stored file and saved by the
/// acknowledgement.
#[test]
fn s027_t02_r02_passing_io_applies_the_changes() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.set_socks5_proxy(Some("10.0.0.1:9050")).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(OTHER_SERVER, 30, Some("10.0.0.1:9050"))
    ));

    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.set_lock_timeout_seconds(10).unwrap();
    assert_eq!(device.settings().socks5_proxy, None);
    device.acknowledge_settings(false).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(OTHER_SERVER, 10, Some(PROXY))
    ));
    assert_eq!(device.settings().socks5_proxy.as_deref(), Some(PROXY));
}

/// Spec 027, R2: a newer app's `settings.bin` is never overwritten unless
/// the user replaces it: the acknowledgement lowers the gate with nothing
/// saved, the setters then change memory alone, and the reason stays.
#[test]
fn s027_t02_r02_newer_settings_are_kept() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    let mut device = fixture.open().unwrap();
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
    device.acknowledge_settings(false).unwrap();
    assert!(!device.status().settings_reset);
    device.set_lock_timeout_seconds(10).unwrap();
    device.set_socks5_proxy(Some(PROXY)).unwrap();
    assert_eq!(device.settings().lock_timeout_seconds, 10);
    assert_eq!(device.settings().socks5_proxy.as_deref(), Some(PROXY));
    assert_eq!(fixture.vault.settings_raw(), planted);
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
    // `replace_newer` replaces it, and the setters save again.
    device.acknowledge_settings(true).unwrap();
    assert_eq!(device.status().settings_reason, None);
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 10, Some(PROXY))
    ));
    device.set_lock_timeout_seconds(20).unwrap();
    assert_eq!(fixture.stored_settings().unwrap().lock_timeout_seconds, 20);
}

/// Spec 027, R2: the proxy setter over a newer app's file lowers the gate
/// with nothing saved.
#[test]
fn s027_t02_r02_proxy_over_newer_settings_saves_nothing() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    let mut device = fixture.open().unwrap();
    device.set_socks5_proxy(Some(PROXY)).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
    assert_eq!(fixture.vault.settings_raw(), planted);
}

/// Spec 027, R2: a passing `Io` over a newer app's file, then the
/// acknowledgement → nothing saved and the reason `UnsupportedVersion`.
#[test]
fn s027_t02_r02_passing_io_over_newer_settings() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    assert_eq!(device.status().settings_reason, Some(StoreError::Io));
    fixture.faults.fail_load_settings(false);
    device.acknowledge_settings(false).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
    assert_eq!(fixture.vault.settings_raw(), planted);
}

/// Spec 027, R2: `replace_newer` over a corrupt file acts as `false`.
#[test]
fn s027_t02_r02_replace_newer_over_corrupt() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.vault.put_settings_raw(b"corrupt");
    let mut device = fixture.open().unwrap();
    device.acknowledge_settings(true).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(device.status().settings_reason, None);
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));
}

/// Spec 027, R1, R2: on a fresh install the acknowledgement and the
/// first setter save the defaults; on saved settings the acknowledgement
/// saves nothing.
#[test]
fn s027_t02_r02_acknowledge_outside_the_gate() {
    let fixture = Fixture::new();
    let mut device = fixture.open().unwrap();
    device.acknowledge_settings(false).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));

    let fixture = Fixture::new();
    let mut device = fixture.open().unwrap();
    device.set_lock_timeout_seconds(5).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 5, None)
    ));
    fixture.faults.fail_save_settings(true);
    device.acknowledge_settings(true).unwrap();
}

/// Spec 027, R13: the defaults; each setter rejects a value outside its
/// grammar with `BadConfig` and saves nothing; saved values reload equal.
#[test]
fn s027_t13_r13_settings() {
    let fixture = Fixture::new();
    let mut device = fixture.open().unwrap();
    assert_eq!(device.settings(), defaults_view());
    for url in ["https://example.org", "wss://Example.org", "wss://a/b", ""] {
        assert_eq!(device.set_default_server_url(url), Err(Error::BadConfig));
    }
    assert_eq!(
        device.set_lock_timeout_seconds(86_401),
        Err(Error::BadConfig)
    );
    for proxy in ["127.0.0.1", "127.0.0.1:0", "host:09050", "[::1]:9050"] {
        assert_eq!(device.set_socks5_proxy(Some(proxy)), Err(Error::BadConfig));
    }
    assert!(fixture.vault.settings_raw().is_none());
    assert_eq!(device.settings(), defaults_view());

    device.set_default_server_url(OTHER_SERVER).unwrap();
    device.set_lock_timeout_seconds(86_400).unwrap();
    device.set_socks5_proxy(Some(PROXY)).unwrap();
    let view = device.settings();
    drop(device);
    let device = fixture.open().unwrap();
    assert_eq!(device.settings(), view);
    assert_eq!(view.default_server_url, OTHER_SERVER);
    assert_eq!(view.lock_timeout_seconds, 86_400);
    assert_eq!(view.socks5_proxy.as_deref(), Some(PROXY));
    let mut device = device;
    device.set_socks5_proxy(None).unwrap();
    assert_eq!(fixture.stored_settings().unwrap().socks5_proxy, None);
    device.set_lock_timeout_seconds(0).unwrap();
    assert_eq!(fixture.stored_settings().unwrap().lock_timeout_seconds, 0);
}

/// Spec 027, R21: each setter with `save_settings` failing → the state
/// after reopening is the one before; the acknowledgement over a corrupt
/// file and the replacement of a newer one, each with the save failing →
/// the file unchanged after reopening, the flag and the reason as before.
#[test]
fn s027_t21_r21_failing_settings_writes() {
    let fixture = with_stored_proxy();
    let mut device = fixture.open().unwrap();
    let before = device.settings();
    fixture.faults.fail_save_settings(true);
    assert!(device.set_default_server_url(SERVER).is_err());
    assert!(device.set_lock_timeout_seconds(5).is_err());
    assert!(device.set_socks5_proxy(None).is_err());
    assert_eq!(device.settings(), before);
    drop(device);
    fixture.faults.fail_save_settings(false);
    assert_eq!(fixture.open().unwrap().settings(), before);

    for newer in [false, true] {
        let fixture = Fixture::new();
        fixture.plant_channel(1, Vec::new());
        if newer {
            fixture.plant_newer_settings();
        } else {
            fixture.vault.put_settings_raw(b"corrupt");
        }
        let planted = fixture.vault.settings_raw();
        let mut device = fixture.open().unwrap();
        let reason = device.status().settings_reason;
        if newer {
            device.acknowledge_settings(false).unwrap();
        }
        let status = device.status();
        fixture.faults.fail_save_settings(true);
        assert!(device.acknowledge_settings(newer).is_err());
        assert_eq!(device.status(), status);
        drop(device);
        fixture.faults.fail_save_settings(false);
        assert_eq!(fixture.vault.settings_raw(), planted);
        let device = fixture.open().unwrap();
        assert!(device.status().settings_reset);
        assert_eq!(device.status().settings_reason, reason);
    }
}

/// Spec 027, R2: `acknowledge_settings(true)` while the gate is up over a
/// newer app's file replaces it at once: saved, the reason cleared, and
/// later setters save.
#[test]
fn s027_t02_r02_replace_newer_at_the_gate() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let mut device = fixture.open().unwrap();
    device.set_lock_timeout_seconds(10).unwrap();
    device.acknowledge_settings(true).unwrap();
    let status = device.status();
    assert!(!status.settings_reset);
    assert_eq!(status.settings_reason, None);
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 10, None)
    ));
    device.set_lock_timeout_seconds(20).unwrap();
    assert_eq!(fixture.stored_settings().unwrap().lock_timeout_seconds, 20);
}

/// Spec 027, R2: `replace_newer` counts only for the reason the user was
/// shown: after a passing `Io` over a newer app's file it replaces
/// nothing, and the reason becomes `UnsupportedVersion`.
#[test]
fn s027_t02_r02_replace_newer_after_a_passing_io() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.acknowledge_settings(true).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
    assert_eq!(fixture.vault.settings_raw(), planted);
}

/// Spec 027, R2: once a newer app's file is kept, a second
/// `acknowledge_settings(false)` still writes nothing.
#[test]
fn s027_t02_r02_second_acknowledgement_keeps_newer() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let planted = fixture.vault.settings_raw();
    let mut device = fixture.open().unwrap();
    device.acknowledge_settings(false).unwrap();
    device.acknowledge_settings(false).unwrap();
    assert_eq!(fixture.vault.settings_raw(), planted);
    assert_eq!(
        device.status().settings_reason,
        Some(StoreError::UnsupportedVersion)
    );
}

/// Spec 027, R2: the proxy set over a newer app's file is kept in memory.
#[test]
fn s027_t02_r02_proxy_over_newer_settings_in_memory() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.plant_newer_settings();
    let mut device = fixture.open().unwrap();
    device.set_socks5_proxy(Some(PROXY)).unwrap();
    assert_eq!(device.settings().socks5_proxy.as_deref(), Some(PROXY));
}

/// Spec 027, R2: after a passing `Io`, a save that fails while adopting
/// the stored file keeps the settings, the flag and the reason.
#[test]
fn s027_t02_r02_failed_save_after_a_passing_io() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.set_lock_timeout_seconds(10).unwrap();
    let before = device.settings();
    fixture.faults.fail_save_settings(true);
    assert_eq!(
        device.acknowledge_settings(false),
        Err(Error::Store(StoreError::Io))
    );
    assert_eq!(device.settings(), before);
    assert_eq!(before.lock_timeout_seconds, 10);
    assert_eq!(before.socks5_proxy, None);
    assert!(device.status().settings_reset);
    assert_eq!(device.status().settings_reason, Some(StoreError::Io));
}

/// Spec 027, R2: when the re-read after an `Io` still fails, the
/// acknowledgement saves the settings in memory and lowers the gate.
#[test]
fn s027_t02_r02_persistent_io() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    device.acknowledge_settings(false).unwrap();
    assert!(!device.status().settings_reset);
    assert_eq!(device.status().settings_reason, None);
    fixture.faults.fail_load_settings(false);
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));
}

/// Spec 027, R1, R2: saved settings, whether read at `open` or adopted
/// after a passing `Io`, are not saved again by an acknowledgement.
#[test]
fn s027_t02_r02_acknowledging_saved_settings_saves_nothing() {
    let fixture = with_stored_proxy();
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_save_settings(true);
    device.acknowledge_settings(false).unwrap();
    device.acknowledge_settings(true).unwrap();

    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.acknowledge_settings(false).unwrap();
    fixture.faults.fail_save_settings(true);
    device.acknowledge_settings(false).unwrap();
}

/// Spec 027, R2: a server URL set while the gate is up is applied onto the
/// stored file adopted after a passing `Io`.
#[test]
fn s027_t02_r02_passing_io_applies_the_url() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.set_default_server_url(SERVER).unwrap();
    device.acknowledge_settings(false).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(&stored, &settings(SERVER, 30, Some(PROXY))));
}

/// Spec 027, R13: a proxy outside the grammar is refused while the gate is
/// up too, the gate kept and nothing saved.
#[test]
fn s027_t13_r13_bad_proxy_at_the_gate() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    let mut device = fixture.open().unwrap();
    assert_eq!(
        device.set_socks5_proxy(Some("127.0.0.1")),
        Err(Error::BadConfig)
    );
    assert!(device.status().settings_reset);
    assert!(fixture.vault.settings_raw().is_none());
}

/// Spec 027, R2: two changes of one field at the gate are applied onto the
/// adopted file in order.
#[test]
fn s027_t02_r02_passing_io_applies_changes_in_order() {
    let fixture = with_stored_proxy();
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.set_lock_timeout_seconds(10).unwrap();
    device.set_lock_timeout_seconds(20).unwrap();
    device.acknowledge_settings(false).unwrap();
    assert_eq!(fixture.stored_settings().unwrap().lock_timeout_seconds, 20);
}

/// Spec 027, R2: a re-read after `Io` that finds no file saves the settings.
#[test]
fn s027_t02_r02_passing_io_over_an_absent_file() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.faults.fail_load_settings(true);
    let mut device = fixture.open().unwrap();
    fixture.faults.fail_load_settings(false);
    device.acknowledge_settings(false).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));
}

/// Spec 027, R2: only an `Io` is re-read; a corrupt file is replaced.
#[test]
fn s027_t02_r02_corrupt_is_not_reread() {
    let fixture = Fixture::new();
    fixture.plant_channel(1, Vec::new());
    fixture.vault.put_settings_raw(b"corrupt");
    let mut device = fixture.open().unwrap();
    fixture.save_settings(&settings(OTHER_SERVER, 30, Some(PROXY)));
    device.acknowledge_settings(false).unwrap();
    let stored = fixture.stored_settings().unwrap();
    assert!(settings_eq(
        &stored,
        &settings(crate::DEFAULT_SERVER_URL, 60, None)
    ));
}
