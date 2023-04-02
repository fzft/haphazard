pub trait Deleter {
    unsafe fn delete(&self, ptr: *mut dyn Reclaim);
}

impl Deleter for unsafe fn(*mut (dyn Reclaim + 'static)) {
    unsafe fn delete(&self, ptr: *mut dyn Reclaim) {
        unsafe { (*self)(ptr) }
    }
}

pub mod deleters {
    use super::*;

    unsafe fn _drop_in_place(ptr: *mut dyn Reclaim) {
        unsafe { std::ptr::drop_in_place(ptr) }
    }

    #[allow(non_upper_case_globals)]
    pub const drop_in_place: unsafe fn(*mut dyn Reclaim) = _drop_in_place;


    unsafe fn _drop_box(ptr: *mut dyn Reclaim) {
        let _ = unsafe { Box::from_raw(ptr) };
    }

    #[allow(non_upper_case_globals)]
    pub const drop_box: unsafe fn(*mut dyn Reclaim) = _drop_box;
}


pub trait Reclaim {}

impl<T> Reclaim for T {}