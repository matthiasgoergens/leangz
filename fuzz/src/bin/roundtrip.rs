//! AFL++ target: generate well-formed `.olean` files from the input and
//! check that they survive compression and decompression.
//!
//! Set LEANGZ_FUZZ_NEGATIVE_MPZ to also generate negative big numbers.
use leangz_fuzz::{check_roundtrip, Options};

fn main() {
  let opts = Options { negative_mpz: std::env::var_os("LEANGZ_FUZZ_NEGATIVE_MPZ").is_some() };
  afl::fuzz!(|data: &[u8]| check_roundtrip(data, opts));
}
