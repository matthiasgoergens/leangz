//! The decompressor on malformed input: it returns an error instead of
//! panicking.

use leangz::lgz::{decompress, DecompressError};
use std::fs;
use std::io::{Cursor, ErrorKind};

const STRING: u8 = 0x30;
const MPZ: u8 = 0x40;
const ARRAY: u8 = 0x00;
const BIG_CTOR: u8 = 0x10;
const EXPRISH: u8 = 0x80;
const UINT0: u8 = 0xd0;
const BACKREF0: u8 = 0xf0;
const EXPRISH_NORMAL: u8 = 0x20;
const EXPRISH_NAME_STR: u8 = 0x00;
const EXPRISH_EXPR_BVAR: u8 = 0x07;
const EXPRISH_EXPR_APP: u8 = 0x20;

/// An lgz stream of one .olean, with a version 2 header that claims `size`
/// bytes, followed by `body`.
fn stream(size: u64, body: &[u8]) -> Vec<u8> {
  let mut s = b"LGZ2".to_vec();
  s.extend_from_slice(&1u32.to_le_bytes()); // base: 64 KiB
  s.extend_from_slice(&size.to_le_bytes());
  s.extend_from_slice(&[b'0'; 40]); // githash
  s.push(1); // flags: GMP
  s.extend_from_slice(&[4, 34, 1, 0xff]); // Lean 4.34.1
  s.extend_from_slice(body);
  s
}

fn invalid(input: &[u8]) -> &'static str {
  match decompress(Cursor::new(input), 1) {
    Err(DecompressError::Invalid(what)) => what,
    r => panic!("expected invalid data, got {:?}", r.map(|_| ())),
  }
}

fn module() -> Vec<Vec<u8>> {
  let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/module");
  ["Attr.olean", "Attr.olean.server", "Attr.olean.private"]
    .iter()
    .map(|f| fs::read(format!("{dir}/{f}")).unwrap())
    .collect()
}

/// Proper prefixes of a valid stream end early: every one of a small file,
/// and a selection of those of a module of three.
#[test]
fn test_truncated() {
  let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/module");
  let small = fs::read(format!("{dir}/ScalarArray.olean")).unwrap();
  let module = module();
  for parts in [vec![&small[..]], module.iter().map(|p| &p[..]).collect()] {
    let mut lgz = vec![];
    leangz::lgz::compress(&parts, &mut lgz);
    assert!(decompress(Cursor::new(&lgz), parts.len()).is_ok());
    let sample = |len: &usize| parts.len() == 1 || len.is_multiple_of(97) || len + 200 > lgz.len();
    for len in (0..lgz.len()).filter(sample) {
      match decompress(Cursor::new(&lgz[..len]), parts.len()) {
        Err(DecompressError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {}
        r => panic!("prefix of {len} bytes: {:?}", r.map(|_| ())),
      }
    }
  }
}

#[test]
fn test_unknown_format() {
  let mut s = stream(1 << 10, &[UINT0]);
  s[3] = b'3';
  assert_eq!(invalid(&s), "unrecognized LGZ version");
}

#[test]
fn test_unknown_opcode() {
  assert_eq!(invalid(&stream(1 << 10, &[0xc0])), "unknown opcode");
  assert_eq!(invalid(&stream(1 << 10, &[EXPRISH, 0x10])), "unknown exprish opcode");
  assert_eq!(invalid(&stream(1 << 10, &[EXPRISH, 0x60])), "unknown exprish opcode");
}

#[test]
fn test_backref_out_of_range() {
  assert_eq!(invalid(&stream(1 << 10, &[BACKREF0])), "backref out of range");
}

#[test]
fn test_not_an_integer() {
  // an array whose length is not an integer
  assert_eq!(invalid(&stream(1 << 10, &[ARRAY, BIG_CTOR])), "expected an integer");
}

/// The decompressor recomputes hashes from the objects it has written, so it
/// rejects objects that the code reading them would read past: here the
/// string of a `Name.str` is a constructor with the tag of a string, and the
/// index of a bound variable is a big number without limbs.
#[test]
fn test_unreadable_field() {
  let name_str = [EXPRISH, EXPRISH_NAME_STR, UINT0, BIG_CTOR, 249, 0, 0, 0];
  assert_eq!(invalid(&stream(1 << 10, &name_str)), "constructor tag out of range");
  let bvar = [EXPRISH, EXPRISH_EXPR_BVAR, MPZ, UINT0];
  assert_eq!(invalid(&stream(1 << 10, &bvar)), "big number without limbs");
  // and a constructor too large for the size field of its header
  let ctor = [BIG_CTOR, 0, 255, 0xff, 0xff];
  assert_eq!(invalid(&stream(1 << 10, &ctor)), "constructor too large");
}

/// Exprish objects whose fields are not what their hashes are computed from.
#[test]
fn test_wrong_field() {
  // `Name.str` of a string and a string
  let name_str = [EXPRISH, EXPRISH_NAME_STR, EXPRISH_NORMAL, STRING, b'a', 0, STRING, b'b', 0];
  assert_eq!(invalid(&stream(1 << 10, &name_str)), "expected a name");
  // an application of the number 1 to the number 2
  let app = [EXPRISH, EXPRISH_EXPR_APP + 1, UINT0 + 1, UINT0 + 2];
  assert_eq!(invalid(&stream(1 << 10, &app)), "expected an expression");
}
