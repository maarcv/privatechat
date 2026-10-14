//! Spec 027-core-api R20 in a process of its own: no test has initialised
//! libsodium before this one, so `create_channel` shows the core works
//! without `init()`.

// Tests may relax this lint to build fixtures (AGENTS 4).
#![allow(clippy::unwrap_used)]

use privatechat_core::Device;
use privatechat_core::testing::MemoryVault;

/// Spec 027, R20: `create_channel` works with no call of `init()` before.
#[test]
fn s027_t20_r20_create_channel_without_init() {
    let mut device = Device::open(Box::new(MemoryVault::new()), 1_790_000_040_000).unwrap();
    let info = device
        .create_channel("wss://example.org", 3_600, "room", 1_790_000_040_000)
        .unwrap();
    assert_eq!(device.channels(), [info]);
}
