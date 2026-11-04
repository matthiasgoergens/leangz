//! The decompressor on malformed input: it returns an error instead of
//! panicking.

use leangz::lgz::{decompress, DecompressError};
use std::fs;
use std::io::{Cursor, ErrorKind};

const BYTE_ARRAY: u8 = 0x20;
const STRING: u8 = 0x30;
const SIZED_STRING: u8 = 0xb0;
const MPZ: u8 = 0x40;
const ARRAY: u8 = 0x00;
const BIG_CTOR: u8 = 0x10;
const EXPRISH: u8 = 0x80;
const UINT0: u8 = 0xd0;
const INT4: u8 = 0xfa;
const INT8: u8 = 0xfb;
const BACKREF0: u8 = 0xf0;
const EXPRISH_NORMAL: u8 = 0x20;
const EXPRISH_NAME_STR: u8 = 0x00;
const EXPRISH_EXPR_BVAR: u8 = 0x07;
const EXPRISH_EXPR_APP: u8 = 0x20;
/// Object bases are multiples of 64 KiB.
const BASE: u64 = 1 << 16;
const TAG_MPZ: u8 = 250;

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

/// An object with a length `len` in the input, but no data after it.
fn claims(len: i64) -> Vec<Vec<u8>> {
  let int8 = |n: i64| [&[INT8][..], &n.to_le_bytes()].concat();
  vec![
    [&[ARRAY][..], &int8(len)].concat(),
    [&[BYTE_ARRAY][..], &int8(len)].concat(),
    [&[SIZED_STRING][..], &int8(len)].concat(),
    // a big number of 2^31 - 1 limbs, 16 GiB
    vec![MPZ, INT4, 0xff, 0xff, 0xff, 0x7f],
  ]
}

fn ends_early(input: &[u8]) {
  match decompress(Cursor::new(input), 1) {
    Err(DecompressError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {}
    r => panic!("expected an early end, got {:?}", r.map(|_| ())),
  }
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

/// The decompressor checks the lengths in the input against the size of the
/// output that the header gives, and its memory grows only as data arrives,
/// so that a length cannot make it allocate more than the input fills.
#[test]
fn test_huge_lengths() {
  // a header claiming more than any address space holds
  assert!(decompress(Cursor::new(&stream(1 << 62, &[UINT0])), 1).is_ok());
  for body in claims(1 << 58) {
    assert_eq!(invalid(&stream(1 << 10, &body)), "larger than the size in the header");
    ends_early(&stream(1 << 63, &body));
  }
  // a string longer than the 32 bytes that the header leaves after itself
  let string = [&[STRING][..], &[b'a'; 40], &[0]].concat();
  assert_eq!(invalid(&stream(128, &string)), "larger than the size in the header");
  // thunks, each written once the object inside it is complete
  let thunks = [vec![0x50; 1000], vec![UINT0]].concat();
  assert_eq!(invalid(&stream(1 << 10, &thunks)), "larger than the size in the header");
}

/// A minimal version 2 `.olean` in the GMP layout, holding the objects that
/// `objects` appends after the header; it returns the address of the root.
fn olean(objects: impl FnOnce(&mut Vec<u8>) -> u64) -> Vec<u8> {
  let mut buf = b"olean\x02\x01".to_vec(); // version 2, flags: GMP
  let mut lean_version = [0u8; 33];
  lean_version[..6].copy_from_slice(b"4.34.1");
  buf.extend_from_slice(&lean_version);
  buf.extend_from_slice(&[b'0'; 40]); // githash
  buf.extend_from_slice(&BASE.to_le_bytes());
  buf.extend_from_slice(&[0; 8]); // root
  let root = objects(&mut buf);
  buf[88..96].copy_from_slice(&root.to_le_bytes());
  buf
}

/// Appends an object with tag `tag`, `num_fields` object fields and the 8-byte
/// words `words` after its header, and returns its address.
fn object(buf: &mut Vec<u8>, tag: u8, num_fields: u8, words: &[u64]) -> u64 {
  let ptr = BASE + buf.len() as u64;
  buf.extend_from_slice(&0u32.to_le_bytes()); // rc
  buf.extend_from_slice(&(8 * (1 + words.len()) as u16).to_le_bytes());
  buf.push(num_fields);
  buf.push(tag);
  words.iter().for_each(|w| buf.extend_from_slice(&w.to_le_bytes()));
  ptr
}

/// Corrupting any byte of a valid stream gives an error or some output,
/// never a panic or an abort.
#[test]
fn test_corrupted() {
  let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/module");
  // a negative big number: two limbs allocated, size -2, pointer to the limbs
  let negative_mpz = olean(|buf| {
    let ptr = BASE + buf.len() as u64;
    object(buf, TAG_MPZ, 0, &[2 | (-2i32 as u32 as u64) << 32, ptr + 24, 5, 7])
  });
  // a constructor with the shape of `Expr.lit` whose field has no fields
  let lit_shape = olean(|buf| {
    let a = object(buf, 0, 0, &[1000000]);
    object(buf, 9, 1, &[a, 7])
  });
  let small = fs::read(format!("{dir}/ScalarArray.olean")).unwrap();
  for olean in [small, negative_mpz, lit_shape] {
    let mut lgz = vec![];
    leangz::lgz::compress(&[&olean], &mut lgz);
    let (buf, ranges) = decompress(Cursor::new(&lgz), 1).unwrap();
    assert!(buf[ranges[0].clone()] == olean[..], "the round trip changed the .olean");
    for i in 0..lgz.len() {
      for byte in [0, 0xff, lgz[i] ^ 1, lgz[i] ^ 0x80, lgz[i].wrapping_add(1)] {
        let mut corrupt = lgz.clone();
        corrupt[i] = byte;
        let _ = decompress(Cursor::new(&corrupt), 1);
      }
    }
  }
}
