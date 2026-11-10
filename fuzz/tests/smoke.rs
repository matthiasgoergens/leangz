//! Runs the round trip on pseudo-random inputs, as a quick check of the
//! generator and of leangz without AFL, and checks that the generator
//! produces every kind of object it is meant to.
use leangz_fuzz::{check_roundtrip, Graph, Obj, Options, Val};

fn inputs() -> impl Iterator<Item = Vec<u8>> {
  let mut x: u64 = 0x2545f4914f6cdd1d;
  (0..4000).map(move |len| {
    (0..len % 600)
      .map(|_| {
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x as u8
      })
      .collect()
  })
}

#[test]
fn roundtrip_random_inputs() {
  for data in inputs() {
    check_roundtrip(&data, Options::default());
  }
}

#[test]
fn generator_coverage() {
  let mut seen = [0usize; 12];
  for data in inputs() {
    let g = Graph::generate(&data, Options::default());
    seen[0] += (g.roots.len() == 3) as usize;
    seen[1] += g.use_gmp as usize;
    for o in &g.objs {
      let k = match o {
        Obj::Ctor { tag: 1 | 2, sdata, .. } if sdata.len() == 8 => 2,
        Obj::Ctor { .. } => 3,
        Obj::Array(_) => 4,
        Obj::ScalarArray { elem_size: 1, .. } => 5,
        Obj::ScalarArray { .. } => 6,
        Obj::Str(s) if s.contains('\0') => 7,
        Obj::Str(_) => 8,
        Obj::Mpz { .. } => 9,
        Obj::Thunk(_) | Obj::Task(_) | Obj::Ref(_) | Obj::Promise(_) => 10,
      };
      seen[k] += 1;
      if let Obj::Ctor { fields, .. } | Obj::Array(fields) = o {
        seen[11] += fields.iter().filter(|v| matches!(v, Val::Obj(_))).count();
      }
    }
  }
  println!("{seen:?}");
  assert!(seen.iter().all(|&n| n > 0), "{seen:?}");
}
