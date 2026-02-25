//! Safe wrappers for BPF map lookups using volatile access.
//!
//! # Safety model
//!
//! ## Hash map values (`MapPtr<V>`)
//!
//! Hash map lookups return [`MapPtr<V>`], a volatile pointer wrapper that
//! never creates Rust references (`&T`/`&mut T`) to map memory. This
//! prevents LLVM from introducing spurious non-volatile loads or assuming
//! exclusive access (the "dereferenceable" attribute on references).
//!
//! BPF hash maps provide NO entry-level locking: another CPU can delete
//! an entry and its memory can be reused for a different key while we
//! hold a pointer to it. For preallocated hash maps (the default, used
//! by rsched), the memory is never freed to the kernel — a stale pointer
//! still addresses valid, aligned memory within the prealloc pool.
//! However, the contents may have been overwritten by a different entry.
//!
//! **In rsched, concurrent deletion and reuse does not occur because:**
//!
//! 1. The BPF program never calls `bpf_map_delete_elem` on histogram or
//!    data maps during normal operation. Timestamp maps (enqueue_time,
//!    oncpu_time, etc.) are deleted, but the pointer is never held across
//!    the delete.
//!
//! 2. The only bulk deletions are in `do_exit` (sched_process_exit),
//!    which fires when a task is exiting. No other tracepoint will fire
//!    for that PID afterward, so there is no concurrent reader.
//!
//! 3. Userspace deletion (the collector reading and clearing maps) runs
//!    on a separate timer and cannot race with a BPF invocation's pointer
//!    use: BPF programs are non-preemptible and complete in microseconds.
//!
//! 4. Each PID's scheduling events are serialized by the kernel
//!    scheduler: a task cannot be simultaneously waking up on one CPU
//!    and being switched on another.
//!
//! ## Per-CPU array values (`&V`/`&mut V`)
//!
//! Per-CPU arrays guarantee exclusive access: BPF programs run with
//! preemption disabled, so only one execution context can access a
//! per-CPU element at a time on each CPU. Returning Rust references
//! is sound.

use core::ptr;

use aya_ebpf::maps::{HashMap, PerCpuArray};

/// A volatile pointer to a BPF hash map value.
///
/// Wraps a raw pointer returned by `bpf_map_lookup_elem` and provides
/// volatile read/write access without ever creating Rust references to
/// the underlying memory. Use [`as_ptr()`](Self::as_ptr) with
/// [`field_ptr!`] for field-level access.
#[derive(Clone, Copy)]
pub struct MapPtr<V> {
    ptr: *mut V,
}

impl<V: Copy> MapPtr<V> {
    /// Volatile read of the entire value.
    #[inline(always)]
    pub fn read(&self) -> V {
        unsafe { ptr::read_volatile(self.ptr) }
    }

    /// Volatile write of the entire value.
    #[inline(always)]
    pub fn write(&self, val: V) {
        unsafe { ptr::write_volatile(self.ptr, val) }
    }
}

impl<V> MapPtr<V> {
    /// Raw pointer for field projection via [`field_ptr!`].
    #[inline(always)]
    pub fn as_ptr(&self) -> *mut V {
        self.ptr
    }
}

/// Look up a hash map entry, returning a volatile pointer.
#[inline(always)]
pub fn get<K, V>(map: &HashMap<K, V>, key: &K) -> Option<MapPtr<V>> {
    map.get_ptr_mut(key).map(|p| MapPtr { ptr: p })
}

/// Check whether a key exists in the map.
#[inline(always)]
pub fn contains_key<K, V>(map: &HashMap<K, V>, key: &K) -> bool {
    map.get_ptr(key).is_some()
}

/// Look up a per-CPU array entry, returning a shared reference.
#[inline(always)]
pub fn pca_get<V>(map: &PerCpuArray<V>, idx: u32) -> Option<&V> {
    // SAFETY: Per-CPU arrays guarantee exclusive CPU access; pre-allocated
    // entries are always valid. BPF runs with preemption disabled.
    map.get_ptr(idx).map(|p| unsafe { &*p })
}

/// Look up a per-CPU array entry, returning a mutable reference.
#[inline(always)]
pub fn pca_get_mut<V>(map: &PerCpuArray<V>, idx: u32) -> Option<&mut V> {
    // SAFETY: see pca_get
    map.get_ptr_mut(idx).map(|p| unsafe { &mut *p })
}

/// Volatile add to a `u32` through a raw pointer.
///
/// # Safety
///
/// `ptr` must point to a valid, aligned `u32` within a map value.
#[inline(always)]
pub unsafe fn add_to_u32(ptr: *mut u32, val: u32) {
    unsafe {
        let o = ptr::read_volatile(ptr);
        ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}

/// Volatile add to a `u64` through a raw pointer.
///
/// # Safety
///
/// `ptr` must point to a valid, aligned `u64` within a map value.
#[inline(always)]
pub unsafe fn add_to_u64(ptr: *mut u64, val: u64) {
    unsafe {
        let o = ptr::read_volatile(ptr);
        ptr::write_volatile(ptr, o.wrapping_add(val));
    }
}

/// Volatile write of a single field through a raw pointer.
///
/// # Safety
///
/// `ptr` must point to a valid, aligned `T` within a map value.
#[inline(always)]
pub unsafe fn volatile_write<T: Copy>(ptr: *mut T, val: T) {
    unsafe { ptr::write_volatile(ptr, val) }
}

/// Project to a field of a [`MapPtr`]'s underlying value.
///
/// Returns a `*mut FieldType` pointer suitable for volatile operations
/// ([`add_to_u32`], [`add_to_u64`], [`volatile_write`]).
///
/// Must be used inside an `unsafe` block.
///
/// # Examples
///
/// ```ignore
/// if let Some(p) = map_ops::get(&HISTS, &pid) {
///     unsafe {
///         add_to_u32(field_ptr!(p, hist.slots[s]), 1);
///         volatile_write(field_ptr!(p, cgroup_id), cg_id);
///     }
/// }
/// ```
#[macro_export]
macro_rules! field_ptr {
    ($map_ptr:expr, $($field:tt)+) => {
        core::ptr::addr_of_mut!((*$map_ptr.as_ptr()).$($field)+)
    }
}
