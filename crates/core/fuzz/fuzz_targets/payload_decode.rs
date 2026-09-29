#![no_main]

use libfuzzer_sys::fuzz_target;
use privatechat_core::fuzz_entry;

fuzz_target!(|data: &[u8]| {
    fuzz_entry::payload_decode(data);
});
