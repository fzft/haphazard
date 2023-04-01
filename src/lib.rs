#![feature(arbitrary_self_types)]
#![allow(unused)]

use std::collections::HashSet;
use std::mem::needs_drop;
use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

static SHARED_DOMAIN: HazPtrDomain = HazPtrDomain {
    hazptrs: HazPtrs {
        head: AtomicPtr::new(null_mut())
    },
    retired: RetiredList {
        head: AtomicPtr::new(null_mut()),
        count: AtomicUsize::new(0),
    },
};

pub struct HazPtrHolder(Option<&'static HazPtr>);

impl HazPtrHolder {
    fn hazptr(&mut self) -> &'static HazPtr {
        if let Some(hazptr) = self.0 {
            hazptr
        } else {
            let hazptr = SHARED_DOMAIN.acquire();
            self.0 = Some(hazptr);
            hazptr
        }
    }


    pub unsafe fn load<'l, T>(&'l mut self, ptr: &'_ AtomicPtr<T>) -> Option<&'l T> {
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
        if let Some(hazptr) = self.0 {
            hazptr.ptr.store(std::ptr::null_mut(), Ordering::SeqCst);
        }
    }
}

impl Drop for HazPtrHolder {
    fn drop(&mut self) {
        self.reset();
        // return self.0 to domain if Some
        if let Some(hazptr) = self.0 {
            // mark it inactive
            hazptr.active.store(false, Ordering::SeqCst);
        }
    }
}

impl Default for HazPtrHolder {
    fn default() -> Self {
        HazPtrHolder(None)
    }
}

pub struct HazPtr {
    ptr: AtomicPtr<u8>,
    next: AtomicPtr<HazPtr>,
    active: AtomicBool,
}

impl HazPtr {
    pub fn protect(&self, ptr: *mut u8) {
        self.ptr.store(ptr, Ordering::SeqCst)
    }
}

pub trait Deleter {
    fn delete(&self, ptr: *mut dyn Drop);
}

impl Deleter for fn(*mut (dyn Drop + 'static)) {
    fn delete(&self, ptr: *mut dyn Drop) {
        (*self)(ptr)
    }
}

pub mod deleters {
    use super::*;

    pub fn drop_in_place() -> &'static dyn Deleter {
        fn drop_in_place(ptr: *mut dyn Drop) {
            unsafe { std::ptr::drop_in_place(ptr) }
        }
        pub static DROP_IN_PLACE: fn(*mut dyn Drop) = drop_box;
        &DROP_IN_PLACE
    }


    fn drop_box(ptr: *mut dyn Drop) {
        let _ = unsafe { Box::from_raw(ptr) };
    }

    pub static DROP_BOX: fn(*mut dyn Drop) = drop_box;

    pub struct DropInPlace;

    impl Deleter for DropInPlace {
        fn delete(&self, ptr: *mut dyn Drop) {
            unsafe { std::ptr::drop_in_place(ptr) }
        }
    }


    pub struct DropBox;

    impl Deleter for DropBox {
        fn delete(&self, ptr: *mut dyn Drop) {
            let _ = unsafe { Box::from_raw(ptr) };
        }
    }
}

#[warn(drop_bounds)]
pub trait HazPtrObject
    where
        Self: Sized + Drop + 'static
{
    fn domain(&self) -> &HazPtrDomain;

    unsafe fn retire(self: *mut Self, deleter: &'static dyn Deleter) {
        if !needs_drop::<Self>() {
            return;
        }
        unsafe { &*self }.domain().retire(self as *mut dyn Drop, deleter);
    }
}

pub struct HazPtrObjectWrapper<T> {
    inner: T,
    domain: *const HazPtrDomain,
}

impl<T> HazPtrObjectWrapper<T> {
    fn with_default_domain(t: T) -> Self {
        Self {
            inner: t,
            domain: &SHARED_DOMAIN,
        }
    }
}

impl<T> Drop for HazPtrObjectWrapper<T> {
    fn drop(&mut self) {
    }
}

impl<T: 'static> HazPtrObject for HazPtrObjectWrapper<T> {
    fn domain(&self) -> &HazPtrDomain {
        unsafe { &*self.domain }
    }
}

impl<T> Deref for HazPtrObjectWrapper<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for HazPtrObjectWrapper<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}


// Holds linked list of HazPtr
pub struct HazPtrDomain {
    hazptrs: HazPtrs,
    retired: RetiredList,
}

impl HazPtrDomain {
    fn acquire(&self) -> &'static HazPtr {
        let head_ptr = &self.hazptrs.head;
        let mut node = head_ptr.load(Ordering::SeqCst);
        loop {
            while !node.is_null() && unsafe { &*node }.active.load(Ordering::SeqCst) {
                node = unsafe { &*node }.next.load(Ordering::SeqCst)
            }
            if node.is_null() {
                // No free hazPtrs -- need to allocate a new one
                let hazptr = Box::into_raw(Box::new(HazPtr {
                    ptr: AtomicPtr::new(std::ptr::null_mut()),
                    // hazptr allocated and adding to the head of link list
                    next: AtomicPtr::new(std::ptr::null_mut()),
                    active: AtomicBool::new(true),
                }));

                // And stick it at the head of the linked list
                let mut head = head_ptr.load(Ordering::SeqCst);
                loop {
                    // Safety: hazptr was never shared, so &mut is ok
                    *unsafe { &mut *hazptr }.next.get_mut() = head;
                    match head_ptr.compare_exchange_weak(head, hazptr, Ordering::SeqCst, Ordering::SeqCst) {
                        // Safety: will never be de-allocated
                        Ok(_) => return unsafe { &*hazptr },
                        Err(head_now) => {
                            head = head_now
                        }
                    }
                }
            }
            let node = unsafe { &*node };

            // mark it active
            if node.active.compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                break node;
            } else {
                // someone else grabbed this node right before us
                // keep walking
            }
        }
    }

    fn retire(&self, ptr: *mut dyn Drop, deleter: &'static dyn Deleter) {
        // First, stick ptr onto the list of retired objects
        let retired = Box::into_raw(Box::new(Retired {
            ptr,
            deleter,
            next: AtomicPtr::new(null_mut()),
        }));
        // increment the count _before_ we give anyone a chance to reclaim it.
        self.retired.count.fetch_add(1, Ordering::SeqCst);
        let head_ptr = &self.retired.head;

        // And stick it at the head of the linked list
        let mut head = head_ptr.load(Ordering::SeqCst);
        loop {
            // Safety: retired was never shared, so &mut is ok
            *unsafe { &mut *retired }.next.get_mut() = head;
            match head_ptr.compare_exchange_weak(head, retired, Ordering::SeqCst, Ordering::SeqCst) {
                // Safety: will never be de-allocated
                Ok(_) => break,
                Err(head_now) => {
                    head = head_now
                }
            }
        }

        // Now check if we need to retire
        if self.retired.count.load(Ordering::SeqCst) != 0 {
            self.bulk_reclaim(false);
        }

    }

    fn bulk_reclaim(&self, block: bool)-> usize {
        let steal = self.retired.head.swap(null_mut(), Ordering::SeqCst);
        if steal.is_null() {
            return 0;
        }

        // Find all guarded address
        let mut guard_ptrs = HashSet::new();
        let mut node = self.hazptrs.head.load(Ordering::SeqCst);
        while !node.is_null() {
            // Safety: HazPtrs are never de-allocated
            let n = unsafe { Box::from_raw(node) };
            guard_ptrs.insert(n.ptr.load(Ordering::SeqCst));
            node = n.next.load(Ordering::SeqCst);
        }

        // Reclaim any retired objects that aren't guarded
        let mut node = steal;
        let mut remaining = null_mut();
        let mut tail = None;
        let mut reclaimed = 0;
        while !node.is_null() {
            // Safety: All accessors only access the head, and the head is no longer pointing here
            let mut n = unsafe { Box::from_raw(node) };
            node = *n.next.get_mut();

            // protecting
            if guard_ptrs.contains(&(n.ptr as *mut u8)) {
                // Not safe to reclaim -- still guard
                // put it back
                *n.next.get_mut() = remaining;
                remaining = Box::into_raw(n);
                if tail.is_none() {
                    tail = Some(remaining)
                }
            } else {
                // No longer guarded -- reclaim using deleter
                n.deleter.delete(n.ptr);
                reclaimed += 1
            }
        }

        self.retired.count.fetch_sub(reclaimed, Ordering::SeqCst);

        let tail = if let Some(tail) = tail {
            tail
        } else {
            return reclaimed;
        };

        let head_ptr = &self.retired.head;
        let mut head = head_ptr.load(Ordering::SeqCst);
        loop {
            // Safety: we still have exclusive access to remaining, which includes tail
            *unsafe { &mut *tail }.next.get_mut() = head;
            match head_ptr.compare_exchange_weak(head, remaining, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(head_now) => {
                    head = head_now
                }
            }

        }
        if !remaining.is_null() && block {
            // Caller wants to reclaim _everything_, but some were left, so try again
            std::thread::yield_now();
            return self.bulk_reclaim(true);
        }

        reclaimed
    }

    pub fn eager_reclaim(&self, block: bool) -> usize {
        self.bulk_reclaim(block)
    }
}

impl Drop for HazPtrDomain {
    fn drop(&mut self) {
        // TODO
    }
}

pub struct SharedHazPtrDomain;

// #[derive(Default)]
struct RetiredList {
    head: AtomicPtr<Retired>,
    count: AtomicUsize,
}

struct Retired {
    ptr: *mut dyn Drop,
    deleter: &'static dyn Deleter,
    next: AtomicPtr<Retired>,
}

// linked list
struct HazPtrs {
    head: AtomicPtr<HazPtr>,
}


#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicPtr;

    use super::*;

    #[test]
    fn feels_good() {
        let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_default_domain(42))));
        // As a reader:
        let mut h = HazPtrHolder::default();
        let my_x: &HazPtrObjectWrapper<i32> = unsafe { h.load(&x) }.expect("not null");
        assert_eq!(**my_x, 42);
        h.reset();
        // invalid
        // let _ = **my_x;


        let my_x = unsafe { h.load(&x).expect("not null") };

        //valid
        assert_eq!(**my_x, 42);
        drop(h);

        let mut h = HazPtrHolder::default();
        let my_x = unsafe { h.load(&x).expect("not null") };

        // as a writer
        let old = x.swap(Box::into_raw(Box::new(HazPtrObjectWrapper::with_default_domain(9001))), Ordering::SeqCst);
        assert_eq!(**my_x, 42);

        // Safety:
        // 1. the pointer came from Box
        // 2. old value is no longer accessible
        unsafe { old.retire(&deleters::DROP_BOX) }
        assert_eq!(**my_x, 42);

    }
}
