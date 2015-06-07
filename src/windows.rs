extern crate libc;
extern crate kernel32;
extern crate winapi;

use libc::c_void;

use winapi::{HANDLE, INVALID_HANDLE_VALUE, fileapi, winbase, winnt};
use winapi::minwinbase::{OVERLAPPED, LPOVERLAPPED};
use winapi::winerror::ERROR_OPERATION_ABORTED;

use std::collections::HashMap;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::os::windows::ffi::OsStrExt;
use std::thread;

use super::{Event, Error, op, Op, Watcher};

const BUF_SIZE: u32 = 16384;

enum Action {
    Watch(PathBuf),
    Unwatch(PathBuf),
    Stop
}

// TODO: Does this need repr(c)?
struct ReadDirectoryRequest {
    tx: Sender<Event>,
    buffer: [u8; BUF_SIZE as usize],
    handle: HANDLE
}

struct ReadDirectoryChangesServer {
    rx: Receiver<Action>,
    tx: Sender<Event>,
    watches: HashMap<PathBuf, HANDLE>,
}

impl ReadDirectoryChangesServer {
    fn start(event_tx: Sender<Event>) -> Sender<Action> {
        let (action_tx, action_rx) = channel();
        thread::spawn(move || {
            let server = ReadDirectoryChangesServer {
                tx: event_tx,
                rx: action_rx,
                watches: HashMap::new()
            };
            server.run();
        });
        action_tx
    }

    fn run(mut self) {
        while let Ok(action) = self.rx.recv() {
            match action {
                Action::Watch(path) => self.add_watch(path),
                Action::Unwatch(path) => self.remove_watch(&path),
                Action::Stop => {
                    
                }
            }
        }
    }

    fn add_watch(&mut self, path: PathBuf) {
        let encoded_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle;
        unsafe {
            handle = kernel32::CreateFileW(
                encoded_path.as_ptr(),
                winnt::FILE_LIST_DIRECTORY,
                winnt::FILE_SHARE_READ | winnt::FILE_SHARE_DELETE,
                ptr::null_mut(),
                fileapi::OPEN_EXISTING,
                winbase::FILE_FLAG_BACKUP_SEMANTICS | winbase::FILE_FLAG_OVERLAPPED,
                ptr::null_mut());

            if handle == INVALID_HANDLE_VALUE {
                self.tx.send(Event {
                    path: None,
                    // TODO: Call GetLastError for better error info?
                    op: Err(Error::WatchNotFound)
                });
                return;
            }
        }
        self.watches.insert(path, handle);
        self.read(handle);
    }

    fn read(&mut self, handle: HANDLE) {
        let mut request = Box::new(ReadDirectoryRequest {
            tx: self.tx.clone(),
            handle: handle,
            // TODO: replace with Box<[u8; n]>?
            buffer: [0u8; BUF_SIZE as usize]
        });

        let flags = winnt::FILE_NOTIFY_CHANGE_FILE_NAME
                  | winnt::FILE_NOTIFY_CHANGE_DIR_NAME
                  | winnt::FILE_NOTIFY_CHANGE_ATTRIBUTES
                  | winnt::FILE_NOTIFY_CHANGE_SIZE
                  | winnt::FILE_NOTIFY_CHANGE_LAST_WRITE
                  | winnt::FILE_NOTIFY_CHANGE_CREATION
                  | winnt::FILE_NOTIFY_CHANGE_SECURITY;

        let request_p = &mut request as *mut _ as *mut c_void;

        unsafe {
            let mut overlapped: Box<OVERLAPPED> = Box::new(mem::zeroed());
            // When using callback based async requests, we are allowed to use the hEvent member
            // for our own purposes
            overlapped.hEvent = request_p;

            let success = kernel32::ReadDirectoryChangesW(
                handle,
                request.buffer.as_mut_ptr() as *mut c_void,
                BUF_SIZE,
                1,  // We do want to monitor subdirectories
                flags,
                &mut 0u32 as *mut u32,  // This parameter is not used for async requests
                &mut *overlapped as *mut OVERLAPPED,
                Some(handle_event));

            mem::forget(overlapped);
            mem::forget(request);
        }
    }

    fn remove_watch(&mut self, path: &Path) {
        if let Some(handle) = self.watches.remove(path) {
            unsafe {
                // TODO Handle errors?
                kernel32::CancelIo(handle);
                kernel32::CloseHandle(handle);
            }
        }
    }
}

unsafe extern "system" fn handle_event(errorCode: u32, bytes: u32, overlapped: LPOVERLAPPED) {
    if errorCode == ERROR_OPERATION_ABORTED {
        return;
    }

    // TODO: Use Box::from_raw when it is no longer unstable
    let overlapped: Box<OVERLAPPED> = mem::transmute(overlapped);
    let request: Box<ReadDirectoryRequest> = mem::transmute((*overlapped).hEvent);
}

pub struct ReadDirectoryChangesWatcher {
    tx: Sender<Action>
}

impl Watcher for ReadDirectoryChangesWatcher {
    fn new(event_tx: Sender<Event>) -> Result<ReadDirectoryChangesWatcher, Error> {
        let action_tx = ReadDirectoryChangesServer::start(event_tx);

        return Ok(ReadDirectoryChangesWatcher {
            tx: action_tx
        });
    }

    fn watch(&mut self, path: &Path) -> Result<(), Error> {
        self.tx.send(Action::Watch(path.to_path_buf()));
        Ok(())
    }

    fn unwatch(&mut self, path: &Path) -> Result<(), Error> {
        self.tx.send(Action::Unwatch(path.to_path_buf()));
        Ok(())
    }
}

impl Drop for ReadDirectoryChangesWatcher {
    fn drop(&mut self) {
        self.tx.send(Action::Stop);
    }
}
