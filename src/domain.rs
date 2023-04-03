use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::deleter::{Deleter, Reclaim};
use crate::ptr::HazPtr;

const SYNC_TIME_PERIOD: u64 = Duration::from_nanos(2000000000).as_nanos() as u64;
const RCOUNT_THRESHOLD: usize = 1000;
const HCOUNT_MULTIPLIER: usize = 1000;

#[non_exhaustive]
#[derive(Copy, Clone)]
pub struct Global;

impl Global {
    const fn new() -> Self {
        Global
    }
}

static SHARED_DOMAIN: HazPtrDomain<Global> = HazPtrDomain::new(&Global::new());


// Holds linked list of HazPtr
pub struct HazPtrDomain<F> {
    pub(crate) hazptrs: HazPtrs,
    pub(crate) retired: RetiredList,
    family: PhantomData<F>,
    sync_time: AtomicU64,
    nbulk_reclaims: AtomicUsize,
}

impl HazPtrDomain<Global> {
    pub fn global() -> &'static Self {
        &SHARED_DOMAIN
    }
}

impl<F> HazPtrDomain<F> {
    pub const fn new(_: &F) -> Self
        where F: Copy
    {
        Self {
            hazptrs: HazPtrs {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicUsize::new(0),
            },
            retired: RetiredList {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicUsize::new(0),
            },
            sync_time: AtomicU64::new(0),
            nbulk_reclaims: AtomicUsize::new(0),
            family: PhantomData,
        }
    }


    pub(crate) fn acquire(&self) -> &HazPtr {
        if let Some(hazptr) = self.try_acquire() {
            hazptr
        } else {
            self.acquire_new()
        }
    }

    fn try_acquire(&self) -> Option<&HazPtr> {
        let head_ptr = &self.hazptrs.head;
        let mut node = head_ptr.load(Ordering::Acquire);
        while !node.is_null() {
            let n = unsafe { &*node };
            if n.try_acquire() {
                return Some(n);
            }
            node = n.next.load(Ordering::Acquire)
        }
        None
    }


    fn acquire_new(&self) -> &HazPtr {
        // No free hazPtrs -- need to allocate a new one
        let hazptr = Box::into_raw(Box::new(HazPtr {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            // hazptr allocated and adding to the head of link list
            next: AtomicPtr::new(std::ptr::null_mut()),
            active: AtomicBool::new(true),
        }));
        // And stick it at the head of the linked list
        let mut head = self.hazptrs.head.load(Ordering::Acquire);
        loop {
            // Safety: hazptr was never shared, so &mut is ok
            *unsafe { &mut *hazptr }.next.get_mut() = head;
            match self.hazptrs.head.compare_exchange_weak(head, hazptr, Ordering::Release, Ordering::Acquire) {
                // Safety: will never be de-allocated
                Ok(_) => {
                    self.hazptrs.count.fetch_add(1, Ordering::SeqCst);
                    return unsafe { &*hazptr };
                }
                Err(head_now) => {
                    head = head_now
                }
            }
        }
    }


    pub(crate) unsafe fn retire<'domain>(
        &'domain self,
        ptr: *mut (dyn Reclaim + 'domain),
        deleter: &'static dyn Deleter,
    ) {
        // First, stick ptr onto the list of retired objects
        // Safety:
        // ptr will not be accessed after Domain is dropped
        let retired = Box::into_raw(Box::new(unsafe { Retired::new(self, ptr, deleter) }));
        // increment the count _before_ we give anyone a chance to reclaim it.

        crate::asymmetric_light_barrier();

        let head_ptr = &self.retired.head;
        // And stick it at the head of the linked list
        let mut head = head_ptr.load(Ordering::Acquire);
        loop {
            // Safety: retired was never shared, so &mut is ok
            *unsafe { &mut *retired }.next.get_mut() = head;
            match head_ptr.compare_exchange_weak(head, retired, Ordering::Release, Ordering::Acquire) {
                // Safety: will never be de-allocated
                Ok(_) => break,
                Err(head_now) => {
                    head = head_now
                }
            }
        }

        self.retired.count.fetch_add(1, Ordering::AcqRel);

        self.check_cleanup_and_reclaim();
        self.bulk_reclaim(false);
    }

    pub fn bulk_reclaim(&self, transitive: bool) -> usize {
        self.nbulk_reclaims.fetch_add(1, Ordering::Acquire);

        let mut reclaimed = 0;
        loop {
            let steal = self.retired.head.swap(std::ptr::null_mut(), Ordering::Acquire);

            crate::asymmetric_heavy_barrier(crate::HeavyBarrierKind::Expedited);

            if steal.is_null() {
                return reclaimed;
            }

            // Find all guarded address
            #[allow(clippy::mutable_key_type)]
                let mut guard_ptrs = HashSet::new();
            let mut node = self.hazptrs.head.load(Ordering::SeqCst);
            while !node.is_null() {
                // Safety: HazPtrs are never de-allocated while the domain lives
                let n = unsafe { Box::from_raw(node) };

                // check the hazptr is active
                if n.active.load(Ordering::SeqCst) {
                    guard_ptrs.insert(n.ptr.load(Ordering::SeqCst));
                }
                node = n.next.load(Ordering::Acquire);
            }
            let (reclaimed_now, done) = self.bulk_lookup_and_reclaim(steal, guard_ptrs);
            reclaimed += reclaimed_now;
            if done || !transitive {
                break;
            }
        }
        self.nbulk_reclaims.fetch_sub(1, Ordering::Release);
        reclaimed
    }

    fn bulk_lookup_and_reclaim(&self, steal: *mut Retired, guard_ptrs: HashSet<*mut u8>) -> (usize, bool) {
        // Reclaim any retired objects that aren't guarded
        let mut node = steal;
        let mut remaining = std::ptr::null_mut();
        let mut tail = None;
        let mut reclaimed = 0;
        let mut retired = 0;
        while !node.is_null() {
            // Safety: All accessors only access the head, and the head is no longer pointing here
            let mut n = unsafe { &*node };
            let next = n.next.load(Ordering::Relaxed);
            // debug_assert_ne!(next, node);

            // protecting
            if guard_ptrs.contains(&(n.ptr as *mut u8)) {
                // Not safe to reclaim -- still guard
                // put it back
                n.next.store(remaining, Ordering::Relaxed);
                remaining = node;
                if tail.is_none() {
                    tail = Some(remaining)
                }
                retired += 1
            } else {

                // Safety:
                // - current has no hazard pointers guarding it , so we have the only remaining
                let n = unsafe { Box::from_raw(node) };

                // No longer guarded -- reclaim using deleter
                // Safety: `n.ptr` has not yet been dropped because it's still on the retired list
                // it will not be dropped again because we have removed from `retired list`
                unsafe { n.deleter.delete(n.ptr) };
                reclaimed += 1
            }
            node = next
        }

        let done = self.retired.head.load(Ordering::Acquire).is_null();

        let tail = if let Some(tail) = tail {
            tail
        } else {
            return (reclaimed, done);
        };

        crate::asymmetric_light_barrier();

        let head_ptr = &self.retired.head;
        let mut head = head_ptr.load(Ordering::Acquire);
        loop {
            // Safety: we still have exclusive access to remaining, which includes tail
            *unsafe { &mut *tail }.next.get_mut() = head;
            match head_ptr.compare_exchange_weak(head, remaining, Ordering::Release, Ordering::Acquire) {
                Ok(_) => break,
                Err(head_now) => {
                    head = head_now
                }
            }
        }

        self.retired.count.fetch_add(retired, Ordering::Release);
        (reclaimed, done)
        // let total_reclaimed = pre_reclaimed + reclaimed;

        // if !remaining.is_null() && block {
        //     // Caller wants to reclaim _everything_, but some were left, so try again
        //     std::thread::yield_now();
        //     return self.bulk_reclaim(reclaimed, true);
        // }
        // reclaimed
    }

    pub fn eager_reclaim(&self) -> usize {
        self.bulk_reclaim(true)
    }

    fn check_cleanup_and_reclaim(&self) {
        if self.try_timed_cleanup() {
            return;
        }
        if Self::reached_threshold(self.hazptrs.count.load(Ordering::Acquire), self.retired.count.load(Ordering::Acquire)) {
            self.try_bulk_reclaim();
        }
    }

    fn try_timed_cleanup(&self) -> bool {
        if !self.check_sync_time() {
            return false;
        }
        self.relaxed_cleanup();
        true
    }

    fn try_bulk_reclaim(&self) {
        let hc = self.hazptrs.count.load(Ordering::Acquire);
        let rc = self.retired.count.load(Ordering::Acquire);
        if !Self::reached_threshold(rc, hc) {
            // No need to add 'rc' back to 'self.retired.count'
            // At least one concurrent try_bulk_reclaim will proceed to bulk_reclaim
            return;
        }

        self.bulk_reclaim(false);
    }

    const fn reached_threshold(rc: usize, hc: usize) -> bool {
        rc >= RCOUNT_THRESHOLD && rc >= HCOUNT_MULTIPLIER * hc
    }

    fn check_sync_time(&self) -> bool {
        use std::convert::TryFrom;
        let time = u64::try_from(std::time::SystemTime::now().
            duration_since(std::time::UNIX_EPOCH).expect("system time is set to before the epoch")
            .as_nanos()).expect("system time is too far into the future");

        let sync_time = self.sync_time.load(Ordering::Relaxed);

        // if it's not time to clean yet, or someone else just started cleaning, don't clean.
        time > sync_time
            && self
            .sync_time
            .compare_exchange(
                sync_time,
                time + SYNC_TIME_PERIOD,
                Ordering::Relaxed,
                Ordering::Relaxed)
            .is_ok()
    }

    fn relaxed_cleanup(&self) {
        self.retired.count.store(0, Ordering::Relaxed);
        self.bulk_reclaim(true);
    }
}

impl<F> Drop for HazPtrDomain<F> {
    fn drop(&mut self) {
        let nretired = *self.retired.count.get_mut();
        let nreclaim = self.bulk_reclaim(true);
        assert_eq!(nreclaim, nretired);
        assert!(self.retired.head.get_mut().is_null());

        // Also drop all hazard pointers, as no-one should be holding them any
        // not thread safe
        let mut node = *self.hazptrs.head.get_mut();
        while !node.is_null() {
            let mut n = unsafe { Box::from_raw(node) };
            assert!(!*n.active.get_mut());
            node = n.next.load(Ordering::Acquire);
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
    pub(crate) count: AtomicUsize,
}