use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicPtr, AtomicUsize};

use crate::deleter::{Deleter, Reclaim};
use crate::domain::{Global, HazPtrDomain, HazPtrs, RetiredList};

pub trait HazPtrObject<'domain, F:'static>
    where
        Self: Sized + 'domain
{
    fn domain(&self) -> &'domain HazPtrDomain<F>;

    unsafe fn retire(self: *mut Self, deleter: &'static dyn Deleter) {
        unsafe { &*self }.domain().retire(self as *mut (dyn Reclaim + 'domain), deleter);
    }
}

pub struct HazPtrObjectWrapper<'domain, T, F> {
    inner: T,
    domain: &'domain HazPtrDomain<F>,
}

impl<T> HazPtrObjectWrapper<'_, T, Global> {
    pub fn with_global_domain(t: T) -> Self {
        HazPtrObjectWrapper::with_domain(HazPtrDomain::global(), t)
    }
}

impl <'domain, T, F> HazPtrObjectWrapper<'domain, T, F> {
    pub fn with_domain(domain: &'domain HazPtrDomain<F>, t: T) -> Self {
        Self { inner: t, domain }
    }
}


impl<'domain, T: 'domain, F: 'static> HazPtrObject<'domain, F> for HazPtrObjectWrapper<'domain, T, F> {

    fn domain(&self) -> &'domain HazPtrDomain<F> {
        self.domain
    }
}

impl<T, F> Deref for HazPtrObjectWrapper<'_, T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, F> DerefMut for HazPtrObjectWrapper<'_, T, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}