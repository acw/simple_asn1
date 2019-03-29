#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate simple_asn1;

fuzz_target!(|data: &[u8]| {
    let _ = simple_asn1::from_der(data);
});
