//! Minimal kernel struct definitions with exact field offsets for this kernel.
//! Generated from pahole output. NOT CO-RE portable across kernel versions.
//!
//! task_struct offsets:
//!   thread_info.cpu: 20
//!   __state:  24
//!   wake_cpu: 116
//!   pid:      1696
//!   comm:     2224 (16 bytes)
//!   cgroups:  2712
//!
//! rq offsets:
//!   nr_running: 4
//!
//! css_set offsets:
//!   dfl_cgrp: 112
//!
//! cgroup offsets:
//!   kn: 256
//!
//! kernfs_node offsets:
//!   id: 96

#[repr(C)]
pub struct thread_info {
    pub flags: u64,
    pub syscall_work: u64,
    pub status: u32,
    pub cpu: u32,
}

#[repr(C)]
pub struct task_struct {
    pub thread_info: thread_info, // offset 0, size 24
    pub __state: u32,             // offset 24
    _pad1: [u8; 88],              // 28 to 116
    pub wake_cpu: i32,            // offset 116
    _pad2: [u8; 1576],            // 120 to 1696
    pub pid: i32,                 // offset 1696
    _pad3: [u8; 524],             // 1700 to 2224
    pub comm: [i8; 16],           // offset 2224
    _pad4: [u8; 472],             // 2240 to 2712
    pub cgroups: *mut css_set,    // offset 2712
}

#[repr(C)]
pub struct rq {
    _pad0: [u8; 4],      // raw_spinlock_t __lock (4 bytes)
    pub nr_running: u32, // offset 4
}

#[repr(C)]
pub struct css_set {
    _pad0: [u8; 112],
    pub dfl_cgrp: *mut cgroup,
}

#[repr(C)]
pub struct cgroup {
    _pad0: [u8; 256],
    pub kn: *mut kernfs_node,
}

#[repr(C)]
pub struct kernfs_node {
    _pad0: [u8; 96],
    pub id: u64,
}
