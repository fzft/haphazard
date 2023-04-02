use std::sync::atomic::{AtomicPtr, Ordering};

use crate::domain::{Global, HazPtrDomain};
use crate::object::HazPtrObject;
use crate::ptr::HazPtr;

pub struct HazPtrHolder<'domain, F> {
    hazard: Option<&'domain HazPtr>,
    domain: &'domain HazPtrDomain<F>,
}

impl HazPtrHolder<'static, Global> {
    pub fn global() -> Self {
        Self::for_domain(HazPtrDomain::global())
    }
}

impl<'domain, F> HazPtrHolder<'domain, F> {
    fn hazptr(&mut self) -> &'domain HazPtr {
        if let Some(hazptr) = self.hazard {
            hazptr
        } else {
            let hazptr = self.domain.acquire();
            self.hazard = Some(hazptr);
            hazptr
        }
    }


    pub unsafe fn load<'l, 'o, T>(&'l mut self, ptr: &'_ AtomicPtr<T>) -> Option<&'l T>
        where T: HazPtrObject<'o, F>,
              'o: 'l,
              F: 'static
    {
        // check holder hazptr reference is exist, if not get from share domain and reserve it in holder
        let hazptr = self.hazptr();

        // get the raw pointer from atomic ptr
        let mut ptr1 = ptr.load(Ordering::SeqCst);
        loop {

            // store the raw pointer uint into haztpr
            // Outer AtomicPtr(ptr1)  ->  HazPtr AtomicPtr(ptr uint)
            hazptr.protect(ptr1 as *mut u8);

            //  get the raw pointer from atomic ptr in the for loop
            let ptr2 = ptr.load(Ordering::SeqCst);

            // compare ptr1 and ptr2 if equal return the ptr reference
            if ptr1 == ptr2 {
                break std::ptr::NonNull::new(ptr1).map(|nn| {
                    unsafe { nn.as_ref() }
                });
            } else {
                ptr1 = ptr2;
            }
        }
    }

    pub fn reset(&mut self) {
        // if the holder hold the Hazptr remove it
        if let Some(hazptr) = self.hazard {
            hazptr.ptr.store(std::ptr::null_mut(), Ordering::SeqCst);
        }
    }

    pub(crate) fn for_domain(domain: &'domain HazPtrDomain<F>) -> Self {
        Self {
            hazard: None,
            domain,
        }
    }
}

impl<F> Drop for HazPtrHolder<'_, F> {
    fn drop(&mut self) {
        self.reset();
        // return self.0 to domain if Some
        if let Some(hazptr) = self.hazard {
            // mark it inactive
            hazptr.active.store(false, Ordering::SeqCst);
        }
    }
}
