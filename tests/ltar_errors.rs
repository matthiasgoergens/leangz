//! Unpacking malformed .ltar files: leantar returns an error instead of
//! panicking or allocating what a corrupt length asks for.

use leangz::ltar::{unpack, UnpackError};
use std::io::{Cursor, ErrorKind};

const COMPRESSION_LGZ: u8 = 1;
const COMPRESSION_HASH_JSON: u8 = 3;
const COMPRESSION_LGZ_MODULE: u8 = 5;

/// A version 4 archive with a trace file, followed by `entries`.
fn ltar(entries: &[u8]) -> Vec<u8> {
  let mut t = b"LTR4".to_vec();
  t.push(1); // with a depHash
  t.extend_from_slice(&7u64.to_le_bytes());
  t.extend_from_slice(b"x.trace\0");
  t.push(COMPRESSION_HASH_JSON);
  t.extend_from_slice(&7u64.to_le_bytes());
  t.extend_from_slice(entries);
  t
}

fn unpack_in_temp_dir(archive: &[u8]) -> Result<u64, UnpackError> {
  let dir = tempfile::tempdir().unwrap();
  unpack(&[dir.path().to_owned()], Cursor::new(archive), false, None, false)
}

/// An entry whose length is far larger than the file.
#[test]
fn test_huge_entry() {
  let mut entry = vec![0];
  entry.extend_from_slice(b"x.olean\0");
  entry.push(COMPRESSION_LGZ);
  entry.extend_from_slice(&(1u64 << 62).to_le_bytes());
  match unpack_in_temp_dir(&ltar(&entry)) {
    Err(UnpackError::IOError(e)) if e.kind() == ErrorKind::UnexpectedEof => {}
    Err(e) => panic!("unexpected error: {e}"),
    Ok(_) => panic!("unpacked a truncated archive"),
  }
}

/// A module entry that ends before the paths of its .server and .private
/// parts.
#[test]
fn test_missing_module_paths() {
  let mut entry = vec![0];
  entry.extend_from_slice(b"x.olean\0");
  entry.push(COMPRESSION_LGZ_MODULE);
  assert!(matches!(unpack_in_temp_dir(&ltar(&entry)), Err(UnpackError::BadLtar)));
}
