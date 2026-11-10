//! AFL++ target: feed the input to the decompressor as an lgz stream.
//!
//! The decompressor returns an error on malformed input, so every panic is
//! a bug, and AFL reports it as a crash, together with aborts (stack
//! overflows, failed allocations); hangs it reports as hangs.  The first
//! byte chooses one file or a module of three.
use std::io::Cursor;

fn main() {
  afl::fuzz!(|data: &[u8]| {
    let Some((&k, data)) = data.split_first() else { return };
    let n = if k & 1 == 0 { 1 } else { 3 };
    let _ = leangz::lgz::decompress(Cursor::new(data), n);
  });
}
