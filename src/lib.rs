#![feature(arbitrary_self_types)]
#![allow(unused)]

use std::collections::HashSet;
use std::mem::needs_drop;
use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

pub use deleter::deleters;

use crate::deleter::{Deleter, Reclaim};
use crate::domain::{HazPtrDomain, HazPtrs, RetiredList};
use crate::object::HazPtrObject;
use crate::ptr::HazPtr;

mod holder;
mod ptr;
mod deleter;
mod domain;
mod object;


#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicPtr;

    use crate::domain::Global;
    use crate::holder::HazPtrHolder;
    use crate::object::HazPtrObjectWrapper;

    use super::*;

    #[test]
    fn feels_good() {
        let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_global_domain(42))));
        // As a reader:
        let mut h = HazPtrHolder::global();
        let my_x: &HazPtrObjectWrapper<i32, Global> = unsafe { h.load(&x) }.expect("not null");
        assert_eq!(**my_x, 42);
        h.reset();
        // invalid
        // let _ = **my_x;


        let my_x = unsafe { h.load(&x).expect("not null") };

        //valid
        assert_eq!(**my_x, 42);
        drop(h);

        let mut h = HazPtrHolder::global();
        let my_x = unsafe { h.load(&x).expect("not null") };

        // as a writer
        let old = x.swap(Box::into_raw(Box::new(HazPtrObjectWrapper::with_global_domain(9001))), Ordering::SeqCst);
        assert_eq!(**my_x, 42);

        // Safety:
        // 1. the pointer came from Box
        // 2. old value is no longer accessible
        unsafe { old.retire(&deleters::drop_box) }
        assert_eq!(**my_x, 42);
    }

    #[test]
    #[should_panic]
    fn feels_bad() {
        let dw = HazPtrDomain::<()>::new();
        let dr = HazPtrDomain::<()>::new();

        let drop_42 = Arc::new(AtomicUsize::new(0));

        let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));

        // Reader use a different domain than the writer
        let mut h = HazPtrHolder::for_domain(&dr);

        // Let's hope this cache the error
        let _ = unsafe { h.load(&x) }.expect("not null");
    }
}
