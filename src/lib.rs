#[macro_use] extern crate log;
#[macro_use] extern crate bitflags;
#[cfg(target_os="macos")] extern crate fsevent_sys;
#[cfg(target_os="windows")] extern crate winapi;
extern crate libc;

pub use self::op::Op;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
#[cfg(test)] use std::sync::mpsc::channel;

#[cfg(target_os="macos")] pub use self::fsevent::FsEventWatcher;
#[cfg(target_os="linux")] pub use self::inotify::INotifyWatcher;
#[cfg(target_os="windows")] pub use self::windows::ReadDirectoryChangesWatcher;
pub use self::null::NullWatcher;

#[cfg(target_os="linux")] pub mod inotify;
#[cfg(target_os="macos")] pub mod fsevent;
#[cfg(target_os="windows")] pub mod windows;
pub mod null;

pub mod op {
  bitflags! {
    flags Op: u32 {
      const CHMOD   = 0b00001,
      const CREATE  = 0b00010,
      const REMOVE  = 0b00100,
      const RENAME  = 0b01000,
      const WRITE   = 0b10000,
    }
  }
}

pub struct Event {
  pub path: Option<PathBuf>,
  pub op: Result<Op, Error>,
}

unsafe impl Send for Event {}

#[derive(Debug)]
pub enum Error {
  Generic(String),
  Io(io::Error),
  NotImplemented,
  PathNotFound,
  WatchNotFound,
}

pub trait Watcher {
  fn new(Sender<Event>) -> Result<Self, Error>;
  fn watch(&mut self, &Path) -> Result<(), Error>;
  fn unwatch(&mut self, &Path) -> Result<(), Error>;
}

#[cfg(target_os = "linux")] pub type RecommendedWatcher = INotifyWatcher;
#[cfg(target_os = "macos")] pub type RecommendedWatcher = FsEventWatcher;
#[cfg(target_os = "windows")] pub type RecommendedWatcher = ReadDirectoryChangesWatcher;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))] pub type RecommendedWatcher = NullWatcher;

pub fn new(tx: Sender<Event>) -> Result<RecommendedWatcher, Error> {
  Watcher::new(tx)
}

#[test]
#[cfg(target_os = "linux")]
fn new_inotify() {
  let (tx, _) = channel();
  let w: Result<INotifyWatcher, Error> = Watcher::new(tx);
  match w {
    Ok(_) => assert!(true),
    Err(_) => assert!(false)
  }
}

#[test]
#[cfg(target_os = "macos")]
fn new_fsevent() {
  let (tx, _) = channel();
  let w: Result<FsEventWatcher, Error> = Watcher::new(tx);
  match w {
    Ok(_) => assert!(true),
    Err(_) => assert!(false)
  }
}

#[test]
fn new_null() {
  let (tx, _) = channel();
  let w: Result<NullWatcher, Error> = Watcher::new(tx);
  match w {
    Ok(_) => assert!(true),
    Err(_) => assert!(false)
  }
}

#[test]
fn new_recommended() {
  let (tx, _) = channel();
  let w: Result<RecommendedWatcher, Error> = Watcher::new(tx);
  match w {
    Ok(_) => assert!(true),
    Err(_) => assert!(false)
  }
}
