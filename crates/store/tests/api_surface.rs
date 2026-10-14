//! The `pub` surface of `store` (spec 027-core-api R16): `DataDir::open`,
//! whose stores come out as `Box<dyn Store>`, coerced to a function pointer
//! of its exact type, so that a changed or missing signature fails to
//! compile.

use std::path::Path;

use privatechat_core::{StorageKey, StoreError, Vault};
use privatechat_store::DataDir;

/// Spec 027, R16: the one `pub` function of `store`, and its vault.
#[test]
fn s027_t16_r16_store_items() {
    let _: fn(&Path, StorageKey) -> Result<DataDir, StoreError> = DataDir::open;
    fn is_vault<T: Vault>() {}
    is_vault::<DataDir>();
}
