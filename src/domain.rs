use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use crate::deleter::{Deleter, Reclaim};
use crate::ptr::HazPtr;

static SHARED_DOMAIN: HazPtrDomain<Global> = HazPtrDomain::new();

pub struct Global;

// Holds linked list of HazPtr
pub struct HazPtrDomain<F> {
    pub(crate) hazptrs: HazPtrs,
    pub(crate) retired: RetiredList,
    family: PhantomData<F>
}

impl HazPtrDomain<Global> {
    pub fn global() -> &'static Self {
        &SHARED_DOMAIN
    }
}

impl <F>HazPtrDomain<F> {

    pub const fn new() -> Self {
        Self {
            hazptrs: HazPtrs {
                head: AtomicPtr::new(std::ptr::null_mut())
            },
            retired: RetiredList {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicUsize::new(0),
            },
            family: PhantomData
        }
    }


    pub(crate) fn acquire(&self) -> &HazPtr {
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

    pub(crate) unsafe fn retire<'domain>(&'domain self, ptr: *mut (dyn Reclaim + 'domain), deleter: &'static dyn Deleter) {
        // First, stick ptr onto the list of retired objects
        // Safety:
        // ptr will not be accessed after Domain is dropped
        let retired = Box::into_raw(Box::new(unsafe { Retired::new(self, ptr, deleter) }));
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
            self.bulk_reclaim(0, false);
        }
    }

    pub fn bulk_reclaim(&self, pre_reclaimed: usize, block: bool) -> usize {
        let steal = self.retired.head.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if steal.is_null() {
            return 0;
        }

        // Find all guarded address
        let mut guard_ptrs = HashSet::new();
        let mut node = self.hazptrs.head.load(Ordering::SeqCst);
        while !node.is_null() {
            // Safety: HazPtrs are never de-allocated
            let n = unsafe { Box::from_raw(node) };

            // check the hazptr is active
            if n.active.load(Ordering::SeqCst) {
                guard_ptrs.insert(n.ptr.load(Ordering::SeqCst));
            }
            node = n.next.load(Ordering::SeqCst);
        }

        // Reclaim any retired objects that aren't guarded
        let mut node = steal;
        let mut remaining = std::ptr::null_mut();
        let mut tail = None;
        let mut reclaimed = 0;
        while !node.is_null() {
            // Safety: All accessors only access the head, and the head is no longer pointing here
            let current = node;
            let mut n = unsafe { &*node };
            node = n.next.load(Ordering::SeqCst);

            // protecting
            if guard_ptrs.contains(&(n.ptr as *mut u8)) {
                // Not safe to reclaim -- still guard
                // put it back
                n.next.store(remaining, Ordering::SeqCst);
                remaining = current;
                if tail.is_none() {
                    tail = Some(remaining)
                }
            } else {

                // Safety:
                // - current has no hazard pointers guarding it , so we have the only remaining
                let n = unsafe { Box::from_raw(current) };

                // No longer guarded -- reclaim using deleter
                // Safety: `n.ptr` has not yet been dropped because it's still on the retired list
                // it will not be dropped again because we have removed from `retired list`
                unsafe { n.deleter.delete(n.ptr) };
                reclaimed += 1
            }
        }

        self.retired.count.fetch_sub(reclaimed, Ordering::SeqCst);
        let total_reclaimed = pre_reclaimed + reclaimed;

        let tail = if let Some(tail) = tail {
            tail
        } else {
            return total_reclaimed;
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
            return self.bulk_reclaim(reclaimed, true);
        }

        reclaimed
    }

    pub fn eager_reclaim(&self, block: bool) -> usize {
        self.bulk_reclaim(0, block)
    }
}

impl <F>Drop for HazPtrDomain<F> {
    fn drop(&mut self) {
        let nretired = *self.retired.count.get_mut();
        let nreclaim = self.bulk_reclaim(0, false);
        assert_eq!(nreclaim, nretired);
        assert!(self.retired.head.get_mut().is_null());

        // Also drop all hazard pointers, as no-one should be holding them any
        // not thread safe
        let mut node = *self.hazptrs.head.get_mut();
        while !node.is_null() {
            let mut n = unsafe {Box::from_raw(node)};
            assert!(!*n.active.get_mut());
            node =  *n.next.get_mut();
            drop(n)
        }



        // TODO
    }
}

// #[derive(Default)]
pub struct RetiredList {
    pub(crate) head: AtomicPtr<Retired>,
    pub(crate) count: AtomicUsize,
}

pub struct Retired {
    ptr: *mut dyn Reclaim,
    deleter: &'static dyn Deleter,
    next: AtomicPtr<Retired>,
}

impl Retired {
    unsafe fn new<'domain, F>(_: &'domain HazPtrDomain<F>, ptr: *mut (dyn Reclaim + 'domain), deleter: &'static dyn Deleter) -> Self {
        Retired {
            ptr: unsafe { std::mem::transmute::<_, *mut dyn Reclaim>(ptr) },
            deleter,
            next: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
}

// linked list
pub struct HazPtrs {
    pub(crate) head: AtomicPtr<HazPtr>,
}