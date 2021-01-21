use native::jvmti_native::*;
use std::os::raw::c_void;
use class::ClassSignature;

unsafe extern "C" fn jvmti_heap_reference_callback<F>(reference_kind: jvmtiHeapReferenceKind, reference_info: *const jvmtiHeapReferenceInfo, class_tag: jlong,
                                                      referrer_class_tag: jlong, size: jlong, tag_ptr: *mut jlong, referrer_tag_ptr: *mut jlong, length: jint,
                                                      user_data: *mut c_void) -> jint
    where F: FnMut(jlong, jlong) {
    //println!("jvmti_heap_reference_callback tag :{},  size:{}", class_tag, size);
    let closure = &mut *(user_data as *mut F);
    // 执行回调
    closure(class_tag, size);
    JVMTI_VISIT_OBJECTS as jint
}

unsafe extern "C" fn jvmti_heap_iteration_callback<F>(class_tag: jlong, size: jlong, tag_ptr: *mut jlong, length: jint, user_data: *mut c_void) -> jint
    where F: FnMut(jlong, jlong) {
    //println!("jvmti_heap_iteration_callback  tag : {}   size: {}", class_tag, size);
    let closure = &mut *(user_data as *mut F);
    // 执行回调
    closure(class_tag, size);
    JVMTI_VISIT_OBJECTS as jint
}


pub fn get_reference_callback<F>(_closure: &F) -> jvmtiHeapReferenceCallback
    where F: FnMut(jlong, jlong) {
    Some(jvmti_heap_reference_callback::<F>)
}

pub fn get_iteration_callback<F>(_closure: &F) -> jvmtiHeapIterationCallback
    where F: FnMut(jlong, jlong) {
    Some(jvmti_heap_iteration_callback::<F>)
}


#[derive(Debug)]
pub struct ClassResultInfo {
    pub class_signature: ClassSignature,
    pub size: jlong,
    pub count: usize,
}

impl ClassResultInfo {
    pub fn to_string(&self) -> String {
        format!("size:{}  count:{}  name:{}", self.size, self.count, self.class_signature.to_string())
    }
}