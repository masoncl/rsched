//! Safe wrappers for BPF map lookups.
//!
//! # Safety model
//!
//! Converting raw map pointers to Rust references is sound under the BPF
//! execution model:
//!
//! - **Valid memory**: BPF hash maps use pre-allocated entries by default.
//!   `bpf_map_lookup_elem` returns a pointer to an initialized, properly
//!   aligned slot within the map's pre-allocated pool, or null (converted
//!   to `None` by aya). The memory remains valid for the map's lifetime.
//!
//! - **No aliasing within an invocation**: BPF programs are non-preemptible
//!   on each CPU. Within a single tracepoint invocation, there is no
//!   concurrent Rust code that could create conflicting references.
//!
//! - **Cross-CPU access**: Other CPUs may concurrently modify the same map
//!   entry through the BPF runtime. This is outside Rust's single-threaded
//!   memory model and is handled by the volatile read/write operations in
//!   `add_to_u32` / `add_to_u64`.

use aya_ebpf::maps::{HashMap, PerCpuArray};

/// Look up a hash map entry, returning a shared reference.
#[inline(always)]
pub fn get<'a, K, V>(map: &'a HashMap<K, V>, key: &K) -> Option<&'a V> {
    // SAFETY: see module-level safety model
    map.get_ptr(key).map(|p| unsafe { &*p })
}

/// Look up a hash map entry, returning a mutable reference.
#[inline(always)]
pub fn get_mut<'a, K, V>(map: &'a HashMap<K, V>, key: &K) -> Option<&'a mut V> {
    // SAFETY: see module-level safety model
    map.get_ptr_mut(key).map(|p| unsafe { &mut *p })
}

/// Check whether a key exists in the map.
#[inline(always)]
pub fn contains_key<K, V>(map: &HashMap<K, V>, key: &K) -> bool {
    map.get_ptr(key).is_some()
}

/// Look up a per-CPU array entry, returning a shared reference.
#[inline(always)]
pub fn pca_get<V>(map: &PerCpuArray<V>, idx: u32) -> Option<&V> {
    // SAFETY: per-CPU arrays guarantee exclusive CPU access; pre-allocated
    // entries are always valid.
    map.get_ptr(idx).map(|p| unsafe { &*p })
}

/// Look up a per-CPU array entry, returning a mutable reference.
#[inline(always)]
pub fn pca_get_mut<V>(map: &PerCpuArray<V>, idx: u32) -> Option<&mut V> {
    // SAFETY: see pca_get
    map.get_ptr_mut(idx).map(|p| unsafe { &mut *p })
}

/// Volatile add to a `u32` field in a map value.
///
/// Uses volatile read/write to remain correct under concurrent cross-CPU
/// modification of the same map entry. The `&mut` reference guarantees the
/// pointer is valid and aligned.
#[inline(always)]
pub fn add_to_u32(field: &mut u32, val: u32) {
    let ptr = field as *mut u32;
    unsafe {
        let o = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}

/// Volatile add to a `u64` field in a map value.
#[inline(always)]
pub fn add_to_u64(field: &mut u64, val: u64) {
    let ptr = field as *mut u64;
    unsafe {
        let o = core::ptr::read_volatile(ptr);
        core::ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}
