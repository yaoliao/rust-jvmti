use std::ptr;
use std::slice;

use native::jvmti_native::{jclass, jint, jlong, jvmtiHeapCallbacks, jvmtiHeapReferenceKind, jvmtiHeapReferenceInfo, jvmtiHeapReferenceCallback};

use super::super::capabilities::Capabilities;
use super::super::class::{ClassId, ClassSignature, JavaType};
use super::super::error::{NativeError, wrap_error};
use super::super::event::{EventCallbacks, VMEvent};
use super::super::event_handler::*;
use super::super::mem::MemoryAllocation;
use super::super::method::{MethodId, MethodSignature};
use super::super::native::{JavaClass, JavaInstance, JavaLong, JavaObject, JavaThread, JVMTIEnvPtr, MutByteArray, MutString};
use super::super::native::jvmti_native::{jvmtiCapabilities, Struct__jvmtiThreadInfo};
use super::super::thread::{Thread, ThreadId};
use super::super::util::stringify;
use super::super::version::VersionNumber;
use std::ptr::{null, null_mut};
use std::os::raw::c_void;

pub trait JVMTI {
    ///
    /// Return the JVM TI version number, which includes major, minor and micro version numbers.
    ///
    fn get_version_number(&self) -> VersionNumber;
    /// Set new capabilities by adding the capabilities whose values are set to true in new_caps.
    /// All previous capabilities are retained.
    /// Some virtual machines may allow a limited set of capabilities to be added in the live phase.
    fn add_capabilities(&mut self, new_capabilities: &Capabilities) -> Result<Capabilities, NativeError>;
    fn get_capabilities(&self) -> Capabilities;
    /// Set the functions to be called for each event. The callbacks are specified by supplying a
    /// replacement function table. The function table is copied--changes to the local copy of the
    /// table have no effect. This is an atomic action, all callbacks are set at once. No events
    /// are sent before this function is called. When an entry is None no event is sent.
    /// An event must be enabled and have a callback in order to be sent--the order in which this
    /// function and set_event_notification_mode are called does not affect the result.
    fn set_event_callbacks(&mut self, callbacks: EventCallbacks) -> Option<NativeError>;
    fn set_event_notification_mode(&mut self, event: VMEvent, mode: bool) -> Option<NativeError>;
    fn get_thread_info(&self, thread_id: &JavaThread) -> Result<Thread, NativeError>;
    fn get_method_declaring_class(&self, method_id: &MethodId) -> Result<ClassId, NativeError>;
    fn get_method_name(&self, method_id: &MethodId) -> Result<MethodSignature, NativeError>;
    fn get_class_signature(&self, class_id: &ClassId) -> Result<ClassSignature, NativeError>;
    fn allocate(&self, len: usize) -> Result<MemoryAllocation, NativeError>;
    fn deallocate(&self);

    /// 获取所有已加载的类
    fn get_loaded_classes(&self) -> Result<Vec<ClassSignature>, NativeError>;
}

pub struct JVMTIEnvironment {
    jvmti: JVMTIEnvPtr
}

impl JVMTIEnvironment {
    pub fn new(env_ptr: JVMTIEnvPtr) -> JVMTIEnvironment {
        JVMTIEnvironment { jvmti: env_ptr }
    }
}

impl JVMTI for JVMTIEnvironment {
    fn get_version_number(&self) -> VersionNumber {
        unsafe {
            let mut version: i32 = 0;
            let version_ptr = &mut version;
            (**self.jvmti).GetVersionNumber.unwrap()(self.jvmti, version_ptr);
            let uversion = *version_ptr as u32;
            VersionNumber::from_u32(&uversion)
        }
    }

    fn add_capabilities(&mut self, new_capabilities: &Capabilities) -> Result<Capabilities, NativeError> {
        let native_caps = new_capabilities.to_native();
        let caps_ptr: *const jvmtiCapabilities = &native_caps;

        unsafe {
            match wrap_error((**self.jvmti).AddCapabilities.unwrap()(self.jvmti, caps_ptr)) {
                NativeError::NoError => Ok(self.get_capabilities()),
                err @ _ => Err(err)
            }
        }
    }

    fn get_capabilities(&self) -> Capabilities {
        unsafe {
            let caps = Capabilities::new();
            let mut native_caps = caps.to_native();
            {
                let cap_ptr = &mut native_caps;
                (**self.jvmti).GetCapabilities.unwrap()(self.jvmti, cap_ptr);
            }
            Capabilities::from_native(&native_caps)
        }
    }

    fn set_event_callbacks(&mut self, callbacks: EventCallbacks) -> Option<NativeError> {
        register_vm_init_callback(callbacks.vm_init);
        register_vm_start_callback(callbacks.vm_start);
        register_vm_death_callback(callbacks.vm_death);
        register_vm_object_alloc_callback(callbacks.vm_object_alloc);
        register_method_entry_callback(callbacks.method_entry);
        register_method_exit_callback(callbacks.method_exit);
        register_thread_start_callback(callbacks.thread_start);
        register_thread_end_callback(callbacks.thread_end);
        register_exception_callback(callbacks.exception);
        register_exception_catch_callback(callbacks.exception_catch);
        register_monitor_wait_callback(callbacks.monitor_wait);
        register_monitor_waited_callback(callbacks.monitor_waited);
        register_monitor_contended_enter_callback(callbacks.monitor_contended_enter);
        register_monitor_contended_endered_callback(callbacks.monitor_contended_entered);
        register_field_access_callback(callbacks.field_access);
        register_field_modification_callback(callbacks.field_modification);
        register_garbage_collection_start(callbacks.garbage_collection_start);
        register_garbage_collection_finish(callbacks.garbage_collection_finish);
        register_class_file_load_hook(callbacks.class_file_load_hook);

        let (native_callbacks, callbacks_size) = registered_callbacks();

        unsafe {
            match wrap_error((**self.jvmti).SetEventCallbacks.unwrap()(self.jvmti, &native_callbacks, callbacks_size)) {
                NativeError::NoError => None,
                err @ _ => Some(err)
            }
        }
    }

    fn set_event_notification_mode(&mut self, event: VMEvent, mode: bool) -> Option<NativeError> {
        unsafe {
            let mode_i = match mode {
                true => 1,
                false => 0
            };
            let sptr: JavaObject = ptr::null_mut();

            match wrap_error((**self.jvmti).SetEventNotificationMode.unwrap()(self.jvmti, mode_i, event as u32, sptr)) {
                NativeError::NoError => None,
                err @ _ => Some(err)
            }
        }
    }

    fn get_thread_info(&self, thread_id: &JavaThread) -> Result<Thread, NativeError> {
        let mut info = Struct__jvmtiThreadInfo { name: ptr::null_mut(), priority: 0, is_daemon: 0, thread_group: ptr::null_mut(), context_class_loader: ptr::null_mut() };
        let mut info_ptr = &mut info;

        unsafe {
            match (**self.jvmti).GetThreadInfo {
                Some(func) => {
                    match wrap_error(func(self.jvmti, *thread_id, info_ptr)) {
                        NativeError::NoError => Ok(Thread {
                            id: ThreadId { native_id: *thread_id },
                            name: stringify((*info_ptr).name),
                            priority: (*info_ptr).priority as u32,
                            is_daemon: if (*info_ptr).is_daemon > 0 { true } else { false },
                        }),
                        err @ _ => Err(err)
                    }
                }
                None => Err(NativeError::NoError)
            }
        }
    }

    fn get_method_declaring_class(&self, method_id: &MethodId) -> Result<ClassId, NativeError> {
        let mut jstruct: JavaInstance = JavaInstance { _hacky_hack_workaround: 0 };
        let mut jclass_instance: JavaClass = &mut jstruct;
        let meta_ptr: *mut JavaClass = &mut jclass_instance;

        unsafe {
            match wrap_error((**self.jvmti).GetMethodDeclaringClass.unwrap()(self.jvmti, method_id.native_id, meta_ptr)) {
                NativeError::NoError => Ok(ClassId { native_id: *meta_ptr }),
                err @ _ => Err(err)
            }
        }
    }

    fn get_method_name(&self, method_id: &MethodId) -> Result<MethodSignature, NativeError> {
        let mut method_name = ptr::null_mut();
        let mut method_ptr = &mut method_name;

        let mut signature: MutString = ptr::null_mut();
        let mut signature_ptr = &mut signature;

        let mut generic_sig: MutString = ptr::null_mut();
        let mut generic_sig_ptr = &mut generic_sig;

        unsafe {
            match wrap_error((**self.jvmti).GetMethodName.unwrap()(self.jvmti, method_id.native_id, method_ptr, signature_ptr, generic_sig_ptr)) {
                NativeError::NoError => Ok(MethodSignature::new(stringify(*method_ptr))),
                err @ _ => Err(err)
            }
        }
    }

    fn get_class_signature(&self, class_id: &ClassId) -> Result<ClassSignature, NativeError> {
        unsafe {
            let mut native_sig: MutString = ptr::null_mut();
            let mut sig: MutString = ptr::null_mut();
            let p1: *mut MutString = &mut sig;
            let p2: *mut MutString = &mut native_sig;

            match wrap_error((**self.jvmti).GetClassSignature.unwrap()(self.jvmti, class_id.native_id, p1, p2)) {
                NativeError::NoError => Ok(ClassSignature::new(&JavaType::parse(&stringify(sig)).unwrap())),
                err @ _ => Err(err)
            }
        }
    }

    fn allocate(&self, len: usize) -> Result<MemoryAllocation, NativeError> {
        let size: JavaLong = len as JavaLong;
        let mut ptr: MutByteArray = ptr::null_mut();
        let mem_ptr: *mut MutByteArray = &mut ptr;

        unsafe {
            match wrap_error((**self.jvmti).Allocate.unwrap()(self.jvmti, size, mem_ptr)) {
                NativeError::NoError => Ok(MemoryAllocation { ptr: ptr, len: len }),
                err @ _ => Err(err)
            }
        }
    }

    fn deallocate(&self) {}

    fn get_loaded_classes(&self) -> Result<Vec<ClassSignature>, NativeError> {
        println!("get_loaded_classes ================");
        unsafe {
            let class_count_ptr = &mut 0 as *mut jint;

            //let mut jstruct: JavaInstance = JavaInstance { _hacky_hack_workaround: 0 };
            //let mut jclass_instance: JavaClass = &mut jstruct;
            // let jclass: *mut JavaClass = &mut jclass_instance;
            // let jclass = &mut jclass_instance;


            //let mut classes_ptr = std::ptr::null_mut();
            //let mut classes_ptr = Vec::<*mut jclass>::with_capacity(1024*100).as_mut_ptr();

            /// 完美啊 ！！！！！！！！！！！
            let mut native_sig: *mut jclass = ptr::null_mut();
            let classes_ptr: *mut *mut jclass = &mut native_sig;
            println!("get_loaded_classes 111111 ================");

            (**self.jvmti).GetLoadedClasses.unwrap()(self.jvmti, class_count_ptr, classes_ptr);

            let size = *class_count_ptr as u32;
            println!("================ loaded class : {}", size);

            // 存储 ClassSignature
            let mut vec = Vec::<ClassSignature>::with_capacity(size as usize);

            let class = slice::from_raw_parts_mut(native_sig, size as usize);
            for (index, elem) in class.iter_mut().enumerate() {
                let class_id = ClassId { native_id: *elem };
                let class_signature = self.get_class_signature(&class_id).ok().unwrap();
                println!("index:{}, package: {}, name: {}", index, class_signature.package, class_signature.name);

                vec.push(class_signature);

                // 设置 tag
                let s = (**self.jvmti).SetTag.unwrap()(self.jvmti, *elem, (index + 1) as jlong);
            }

            // 获取 tag
            unsafe {
                for (index, elem) in class.iter_mut().enumerate() {
                    let tag_ptr = &mut 0 as *mut jlong;
                    // 设置 tag
                    let s = (**self.jvmti).GetTag.unwrap()(self.jvmti, *elem, tag_ptr);
                    println!("get tag index: {},  tag: {},  result: {}", index, *tag_ptr, s);
                }
            }
            //  fn(env: *mut jvmtiEnv, heap_filter: jint, klass: jclass, initial_object: jobject, callbacks: *const jvmtiHeapCallbacks, user_data: *const c_void) -> jvmtiError>,

            println!("FollowReferences  =============");

            let mut callback = jvmtiHeapCallbacks::default();
            callback.heap_reference_callback = Some(heap_reference_callback);
            (**self.jvmti).FollowReferences.unwrap()(self.jvmti, 0 as jint, ptr::null_mut(), ptr::null_mut(), &callback, ptr::null());

        }

        Ok(Vec::new())
    }


}

unsafe extern "C" fn heap_reference_callback(reference_kind: jvmtiHeapReferenceKind, reference_info: *const jvmtiHeapReferenceInfo, class_tag: jlong,
                                             referrer_class_tag: jlong, size: jlong, tag_ptr: *mut jlong, referrer_tag_ptr: *mut jlong, length: jint,
                                             user_data: *mut c_void) -> jint {
    println!("====================== call back class tag :{}", class_tag);

    0 as jint
}


