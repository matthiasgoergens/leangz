//! Replays fuzz inputs without AFL and reports how each one ends.
//!
//! Usage: replay (roundtrip | roundtrip-negative-mpz | decompress) FILE...
//! Prints one line per file: "ok", "error" with the error that decompress
//! returned, or "panic" with the panic's location and message.  Aborts
//! (stack overflow, failed allocation) end the process.
//! Set LEANGZ_REPLAY_BACKTRACE to print a backtrace for each panic.
use leangz_fuzz::{check_roundtrip, Options};
use std::io::Cursor;
use std::sync::Mutex;

static LAST_PANIC: Mutex<Option<String>> = Mutex::new(None);

enum Target {
  Roundtrip(Options),
  Decompress,
}

fn main() {
  let mut args = std::env::args().skip(1);
  let target = match args.next().as_deref() {
    Some("roundtrip") => Target::Roundtrip(Options::default()),
    Some("roundtrip-negative-mpz") => Target::Roundtrip(Options { negative_mpz: true }),
    Some("decompress") => Target::Decompress,
    _ => panic!("usage: replay (roundtrip | roundtrip-negative-mpz | decompress) FILE..."),
  };
  let backtraces = std::env::var_os("LEANGZ_REPLAY_BACKTRACE").is_some();
  std::panic::set_hook(Box::new(move |info| {
    if backtraces {
      eprintln!("{info}\n{}", std::backtrace::Backtrace::force_capture());
    }
    let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
    let msg = info
      .payload()
      .downcast_ref::<String>()
      .cloned()
      .or_else(|| info.payload().downcast_ref::<&str>().map(|s| s.to_string()))
      .unwrap_or_default();
    *LAST_PANIC.lock().unwrap() = Some(format!("{loc}: {}", msg.lines().next().unwrap_or("")));
  }));
  for file in args {
    let data = std::fs::read(&file).unwrap();
    let r = std::panic::catch_unwind(|| match target {
      Target::Roundtrip(opts) => {
        check_roundtrip(&data, opts);
        Ok(())
      }
      Target::Decompress => {
        let Some((&k, data)) = data.split_first() else { return Ok(()) };
        let n = if k & 1 == 0 { 1 } else { 3 };
        leangz::lgz::decompress(Cursor::new(data), n).map(|_| ())
      }
    });
    match r {
      Ok(Ok(())) => println!("ok\t{file}"),
      Ok(Err(e)) => println!("error\t{file}\t{e}"),
      Err(_) =>
        println!("panic\t{file}\t{}", LAST_PANIC.lock().unwrap().take().unwrap_or_default()),
    }
  }
}
