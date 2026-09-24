#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    logthing::fuzz_harness::wef_event(data);
});
