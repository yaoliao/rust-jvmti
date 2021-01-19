use super::native::JavaThread;
use serde::__private::fmt::Debug;
use serde::__private::Formatter;
use std::fmt;

///
/// Represents a link between a JVM thread and the Rust code calling the JVMTI API.
///
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct ThreadId {
    pub native_id: JavaThread,
}

/// Marker trait implementation for `Send`
unsafe impl Send for ThreadId {}

/// Marker trait implementation for `Sync`
unsafe impl Sync for ThreadId {}

// #[derive(Debug)]
pub struct Thread {
    pub id: ThreadId,
    pub name: String,
    pub priority: u32,
    pub is_daemon: bool,
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut id = 1 as u32;
        unsafe {
            id = (*self.id.native_id)._hacky_hack_workaround;
        }
        f.debug_struct("java_thread")
            .field("id", &id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("is_daemon", &self.is_daemon)
            .finish()
    }
}
