use std::sync::atomic::{AtomicUsize, Ordering};
use std::{marker, mem};
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

pub struct Weak<F> {
    name: &'static str,
    addr: AtomicUsize,
    _marker: marker::PhantomData<F>,
}

impl<F> Weak<F> {
    pub const fn new(name: &'static str) -> Weak<F> {
        Weak {
            name,
            addr: AtomicUsize::new(1),
            _marker: marker::PhantomData,
        }
    }

    pub fn get(&self) -> Option<&F> {
        assert_eq!(mem::size_of::<F>(), mem::size_of::<usize>());
        unsafe {
            if self.addr.load(Ordering::SeqCst) == 1 {
                let fet = fetch(self.name);
                self.addr.store(fetch(self.name), Ordering::SeqCst);
            }
            if self.addr.load(Ordering::SeqCst) == 0 {
                None
            } else {
                println!("444");
                mem::transmute::<&AtomicUsize, Option<&F>>(&self.addr)
            }
        }
    }
}

unsafe fn fetch(name: &str) -> usize {
    let name = match CString::new(name) {
        Ok(cstr) => cstr,
        Err(..) => return 0,
    };
    find_symbol(name.as_ptr())
}

#[cfg(unix)]
unsafe fn find_symbol(name: *const c_char) -> usize {

    libc::dlsym(libc::RTLD_DEFAULT, name) as usize;

    /// ？？？？ 为什么不写全局路径就获取不找那 ？？？？？？？？
    let jvm_so = CString::new("/Users/yaoliao/devtools/jdk8u272-b10/Contents/Home/jre/lib/server/libjvm.dylib").unwrap();
    // let jvm_so = CString::new("libjvm.dylib").unwrap();

    let handle: *mut c_void = libc::dlopen(jvm_so.as_ptr(), libc::RTLD_LAZY);
    libc::dlsym(handle, name) as usize
}

#[cfg(windows)]
unsafe fn find_symbol(name: *const c_char) -> usize {
    use std::ptr::null;
    use kernel32::{GetModuleHandle, GetProcAddress};
    GetProcAddress(GetModuleHandleA(null()), name) as usize
}
