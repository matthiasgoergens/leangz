//! Builds well-formed `.olean` files from arbitrary bytes, for fuzzing the
//! lgz round trip.
//!
//! The bytes drive the choice of a graph of Lean objects: constructors with
//! object and scalar fields, arrays, scalar arrays, strings (any characters,
//! NUL included), big numbers, thunks, tasks, refs, promises, and `Name`s
//! with the hashes the compressor checks for, so that its exprish encoding
//! is used for them. Each object may only point to objects created before
//! it, so the graph is acyclic. The graph is then laid out as Lean's
//! compactor does: the objects reachable from each root in post-order, each
//! object once, children in field order, so that decompression can give
//! back the same bytes.
//!
//! The input can describe one `.olean` or a module of three (`.olean`,
//! `.olean.server`, `.olean.private`) whose later parts point into earlier
//! ones.
//!
//! Targets, in `src/bin`: `roundtrip` checks the round trip of generated
//! files; `decompress` feeds raw input to the decompressor.  To run them with
//! AFL++ (https://github.com/rust-fuzz/afl.rs):
//!
//! ```text
//! cargo install cargo-afl
//! cargo afl build --release --features afl
//! mkdir seeds && head -c 256 /dev/urandom > seeds/random
//! cargo afl fuzz -i seeds -o out target/release/roundtrip
//! ```
//!
//! `cargo test` runs the round trip on pseudo-random inputs without AFL, and
//! `replay` reruns saved inputs and reports how each ends.

/// Object bases are multiples of 64 KiB.
const BASE: u64 = 1 << 16;
const HEADER_SIZE: usize = 96;

mod tag {
  pub const ARRAY: u8 = 246;
  pub const SCALAR_ARRAY: u8 = 248;
  pub const STRING: u8 = 249;
  pub const MPZ: u8 = 250;
  pub const THUNK: u8 = 251;
  pub const TASK: u8 = 252;
  pub const REF: u8 = 253;
  pub const PROMISE: u8 = 244;
  /// Constructor tags are below this.
  pub const MAX_CTOR: u8 = 244;
}

/// Options that switch on inputs which hit known failures, so that a
/// fuzzing run can otherwise look past them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
  /// Generate negative big numbers.
  pub negative_mpz: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum Val {
  /// A boxed scalar, below 2^63.
  Scalar(u64),
  /// An object, by index.
  Obj(usize),
}

#[derive(Debug)]
pub enum Obj {
  Ctor {
    tag: u8,
    fields: Vec<Val>,
    sdata: Vec<u8>,
  },
  Array(Vec<Val>),
  ScalarArray {
    elem_size: u8,
    data: Vec<u8>,
  },
  Str(String),
  /// Little-endian limbs with a nonzero top limb, as Lean normalises them.
  Mpz {
    neg: bool,
    limbs: Vec<u64>,
  },
  Thunk(Val),
  Task(Val),
  Ref(Val),
  Promise(Val),
}

/// Reads choices from the fuzzer's bytes; reads zeros once they run out.
struct Bytes<'a> {
  data: &'a [u8],
}

impl Bytes<'_> {
  fn is_empty(&self) -> bool { self.data.is_empty() }
  fn u8(&mut self) -> u8 {
    match self.data.split_first() {
      Some((&b, rest)) => {
        self.data = rest;
        b
      }
      None => 0,
    }
  }
  fn u16(&mut self) -> u16 { u16::from_le_bytes([self.u8(), self.u8()]) }
  fn u64(&mut self) -> u64 {
    let mut b = [0; 8];
    b.iter_mut().for_each(|b| *b = self.u8());
    u64::from_le_bytes(b)
  }
  fn below(&mut self, n: usize) -> usize {
    if n <= 256 {
      self.u8() as usize % n
    } else {
      self.u16() as usize % n
    }
  }
  fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.u8()).collect() }
}

pub struct Graph {
  pub use_gmp: bool,
  pub objs: Vec<Obj>,
  /// One root per file.
  pub roots: Vec<usize>,
}

impl Graph {
  fn name_hash(&self, v: Val) -> Option<u64> {
    // as `get_name_hash` in the compressor
    match v {
      Val::Scalar(0) => Some(leangz::lgz::NAME_ANON_HASH),
      Val::Scalar(_) => None,
      Val::Obj(i) => match &self.objs[i] {
        Obj::Ctor { sdata, .. } if sdata.len() >= 8 =>
          Some(u64::from_le_bytes(sdata[..8].try_into().unwrap())),
        _ => None,
      },
    }
  }

  fn str_hash(&self, v: Val) -> Option<u64> {
    match v {
      Val::Obj(i) => match &self.objs[i] {
        Obj::Str(s) => Some(str_hash(s.as_bytes())),
        _ => None,
      },
      Val::Scalar(_) => None,
    }
  }

  fn val(&self, b: &mut Bytes) -> Val {
    let k = b.u8();
    if self.objs.is_empty() || k < 64 {
      Val::Scalar(match k % 4 {
        0 => 0,
        1 => (k as u64) >> 2,
        2 => b.u64() >> 1,
        _ => b.u16() as u64,
      })
    } else {
      // prefer recent objects, but reach back anywhere
      let n = self.objs.len();
      if k < 160 {
        Val::Obj(n - 1 - b.below(n.min(8)))
      } else {
        Val::Obj(b.below(n))
      }
    }
  }

  fn string(b: &mut Bytes) -> String {
    let len = b.below(48);
    let mut s = String::new();
    for _ in 0..len {
      let k = b.u8();
      let c = match k % 8 {
        0 => '\0',
        1..=4 => (k >> 1) as char,
        5 => char::from_u32(0x80 + b.u16() as u32 % 0x780).unwrap(),
        6 => char::from_u32(0x800 + b.u16() as u32).unwrap_or('\u{fffd}'),
        _ => char::from_u32(0x10000 + (b.u16() as u32) * 16 + (k >> 4) as u32).unwrap(),
      };
      s.push(c)
    }
    s
  }

  fn obj(&mut self, b: &mut Bytes, opts: Options) -> Obj {
    match b.u8() % 16 {
      0..=3 => {
        let tag = b.u8() % tag::MAX_CTOR;
        let tag = if b.u8() < 200 { tag % 13 } else { tag };
        let nfields = if b.u8() < 220 { b.below(8) } else { b.below(256) };
        let fields = (0..nfields).map(|_| self.val(b)).collect();
        let nsfields = if b.u8() < 220 { b.below(3) } else { b.below(32) };
        Obj::Ctor { tag, fields, sdata: b.bytes(8 * nsfields) }
      }
      4 => {
        let n = b.below(16);
        Obj::Array((0..n).map(|_| self.val(b)).collect())
      }
      5 => {
        let elem_size = match b.u8() % 8 {
          0..=3 => 1,
          4 => 8,
          5 => 4,
          6 => 2,
          _ => 1 + b.below(16) as u8,
        };
        let n = b.below(32);
        Obj::ScalarArray { elem_size, data: b.bytes(n * elem_size as usize) }
      }
      6..=8 => Obj::Str(Self::string(b)),
      9 => {
        let n = 1 + b.below(4);
        let mut limbs: Vec<u64> = (0..n).map(|_| b.u64()).collect();
        if *limbs.last().unwrap() == 0 {
          *limbs.last_mut().unwrap() = 1
        }
        let neg = opts.negative_mpz && b.u8() & 1 == 1;
        Obj::Mpz { neg, limbs }
      }
      10 => Obj::Thunk(self.val(b)),
      11 => Obj::Task(self.val(b)),
      12 => Obj::Ref(self.val(b)),
      13 => Obj::Promise(self.val(b)),
      14 => {
        // Name.str, with a fresh string or an existing one
        let prefix = self.val(b);
        let s = if b.u8() & 1 == 0 {
          let s = Self::string(b);
          self.objs.push(Obj::Str(s));
          Val::Obj(self.objs.len() - 1)
        } else {
          self.val(b)
        };
        let hash = match (self.name_hash(prefix), self.str_hash(s)) {
          (Some(h1), Some(h2)) => leangz::lgz::mix_hash(h1, h2),
          _ => b.u64(),
        };
        Obj::Ctor { tag: 1, fields: vec![prefix, s], sdata: hash.to_le_bytes().to_vec() }
      }
      _ => {
        // Name.num
        let prefix = self.val(b);
        let n = self.val(b);
        let hash = match self.name_hash(prefix) {
          Some(h1) => leangz::lgz::mix_hash(h1, if let Val::Scalar(n) = n { n } else { 17 }),
          None => b.u64(),
        };
        Obj::Ctor { tag: 2, fields: vec![prefix, n], sdata: hash.to_le_bytes().to_vec() }
      }
    }
  }

  /// Generates a graph from the fuzzer's bytes.
  pub fn generate(data: &[u8], opts: Options) -> Graph {
    let mut b = Bytes { data };
    let flags = b.u8();
    let use_gmp = flags & 1 == 1;
    let nfiles = if flags & 2 == 2 { 3 } else { 1 };
    let mut g = Graph { use_gmp, objs: vec![], roots: vec![] };
    for file in 0..nfiles {
      let last = file + 1 == nfiles;
      // each file gets a share of the input, and at least its root
      let budget = if last { usize::MAX } else { b.below(64) };
      let mut n = 0;
      while n == 0 || (n < budget && !b.is_empty()) {
        let o = g.obj(&mut b, opts);
        g.objs.push(o);
        n += 1;
      }
      g.roots.push(g.objs.len() - 1);
    }
    g
  }

  fn children(&self, i: usize) -> Vec<Val> {
    match &self.objs[i] {
      Obj::Ctor { fields, .. } | Obj::Array(fields) => fields.clone(),
      Obj::ScalarArray { .. } | Obj::Str(_) | Obj::Mpz { .. } => vec![],
      Obj::Thunk(v) | Obj::Task(v) | Obj::Ref(v) | Obj::Promise(v) => vec![*v],
    }
  }

  /// Lays the graph out as one `.olean` per root.
  pub fn serialize(&self) -> Vec<Vec<u8>> {
    let mut addr: Vec<Option<u64>> = vec![None; self.objs.len()];
    let mut files = vec![];
    let mut base = BASE;
    for &root in &self.roots {
      let mut buf = header(self.use_gmp, base);
      // iterative post-order DFS, so deep graphs do not overflow the stack
      let mut stack = vec![(root, false)];
      while let Some((i, expanded)) = stack.pop() {
        if addr[i].is_some() {
          continue
        }
        if expanded {
          addr[i] = Some(base + buf.len() as u64);
          self.write_obj(&mut buf, i, &addr);
        } else {
          stack.push((i, true));
          for v in self.children(i).into_iter().rev() {
            if let Val::Obj(j) = v {
              if addr[j].is_none() {
                stack.push((j, false))
              }
            }
          }
        }
      }
      buf[HEADER_SIZE - 8..HEADER_SIZE].copy_from_slice(&addr[root].unwrap().to_le_bytes());
      base = (base + buf.len() as u64).next_multiple_of(BASE);
      files.push(buf);
    }
    files
  }

  fn write_obj(&self, buf: &mut Vec<u8>, i: usize, addr: &[Option<u64>]) {
    let ptr = |v: &Val| match *v {
      Val::Scalar(n) => (n << 1) | 1,
      Val::Obj(j) => addr[j].unwrap(),
    };
    match &self.objs[i] {
      Obj::Ctor { tag, fields, sdata } => {
        let cs_sz = 8 + 8 * fields.len() + sdata.len();
        obj_header(buf, *tag, cs_sz as u16, fields.len() as u8);
        fields.iter().for_each(|v| push_u64(buf, ptr(v)));
        buf.extend_from_slice(sdata);
      }
      Obj::Array(elems) => {
        obj_header(buf, tag::ARRAY, 1, 0);
        push_u64(buf, elems.len() as u64);
        push_u64(buf, elems.len() as u64);
        elems.iter().for_each(|v| push_u64(buf, ptr(v)));
      }
      Obj::ScalarArray { elem_size, data } => {
        let n = (data.len() / *elem_size as usize) as u64;
        obj_header(buf, tag::SCALAR_ARRAY, 1, *elem_size);
        push_u64(buf, n);
        push_u64(buf, n);
        buf.extend_from_slice(data);
      }
      Obj::Str(s) => {
        obj_header(buf, tag::STRING, 1, 0);
        push_u64(buf, s.len() as u64 + 1);
        push_u64(buf, s.len() as u64 + 1);
        push_u64(buf, s.chars().count() as u64);
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
      }
      Obj::Mpz { neg, limbs } => {
        let n = limbs.len();
        let obj = addr[i].unwrap();
        if self.use_gmp {
          // __mpz_struct: _mp_alloc, _mp_size (negative for negative numbers), _mp_d
          obj_header(buf, tag::MPZ, ((n + 3) << 3) as u16, 0);
          buf.extend_from_slice(&(n as u32).to_le_bytes());
          let size = if *neg { -(n as i32) } else { n as i32 };
          buf.extend_from_slice(&size.to_le_bytes());
          push_u64(buf, obj + 24);
          limbs.iter().for_each(|&l| push_u64(buf, l));
        } else {
          // Lean's own mpz: sign, size in 32-bit digits, digits
          let mut digits: Vec<u32> =
            limbs.iter().flat_map(|&l| [l as u32, (l >> 32) as u32]).collect();
          if *digits.last().unwrap() == 0 {
            digits.pop();
          }
          obj_header(buf, tag::MPZ, ((digits.len() + 8) << 2) as u16, 0);
          push_u64(buf, *neg as u64);
          push_u64(buf, digits.len() as u64);
          push_u64(buf, obj + 32);
          digits.iter().for_each(|d| buf.extend_from_slice(&d.to_le_bytes()));
        }
      }
      Obj::Thunk(v) | Obj::Task(v) => {
        let t = if matches!(self.objs[i], Obj::Thunk(_)) { tag::THUNK } else { tag::TASK };
        obj_header(buf, t, 3 << 3, 0);
        push_u64(buf, ptr(v));
        push_u64(buf, 0);
      }
      Obj::Ref(v) | Obj::Promise(v) => {
        let t = if matches!(self.objs[i], Obj::Ref(_)) { tag::REF } else { tag::PROMISE };
        obj_header(buf, t, 2 << 3, 0);
        push_u64(buf, ptr(v));
      }
    }
    buf.resize(buf.len().next_multiple_of(8), 0);
  }
}

fn header(use_gmp: bool, base: u64) -> Vec<u8> {
  let mut buf = vec![];
  buf.extend_from_slice(b"olean");
  buf.push(2); // version
  buf.push(use_gmp as u8); // flags
  let mut lean_version = [0u8; 33];
  lean_version[..6].copy_from_slice(b"4.34.1");
  buf.extend_from_slice(&lean_version);
  buf.extend_from_slice(&[b'0'; 40]); // githash
  push_u64(&mut buf, base);
  push_u64(&mut buf, 0); // root, filled in later
  assert_eq!(buf.len(), HEADER_SIZE);
  buf
}

fn obj_header(buf: &mut Vec<u8>, tag: u8, cs_sz: u16, other: u8) {
  buf.extend_from_slice(&0u32.to_le_bytes()); // rc
  buf.extend_from_slice(&cs_sz.to_le_bytes());
  buf.push(other);
  buf.push(tag);
}

fn push_u64(buf: &mut Vec<u8>, n: u64) { buf.extend_from_slice(&n.to_le_bytes()) }

/// `leangz::lgz::str_hash` reads the bytes as `u64` words, so it needs them
/// 8-byte aligned, as they are in an `.olean`; `String`'s bytes need not be.
fn str_hash(bytes: &[u8]) -> u64 {
  let mut words = vec![0u64; bytes.len() / 8 + 1];
  let aligned = zerocopy::IntoBytes::as_mut_bytes(&mut words[..]);
  aligned[..bytes.len()].copy_from_slice(bytes);
  leangz::lgz::str_hash(&aligned[..bytes.len()])
}

/// Generates `.olean` files from `data`, compresses them, decompresses the
/// result, and panics unless that gives back the same files.
pub fn check_roundtrip(data: &[u8], opts: Options) {
  let files = Graph::generate(data, opts).serialize();
  let refs: Vec<&[u8]> = files.iter().map(|f| &f[..]).collect();
  let mut lgz = vec![];
  leangz::lgz::compress(&refs, &mut lgz);
  let (buf, ranges) = leangz::lgz::decompress(std::io::Cursor::new(&lgz), refs.len()).unwrap();
  assert_eq!(ranges.len(), refs.len());
  for (i, (f, r)) in refs.iter().zip(ranges).enumerate() {
    assert!(*f == &buf[r], "file {i} differs after the round trip");
  }
}
