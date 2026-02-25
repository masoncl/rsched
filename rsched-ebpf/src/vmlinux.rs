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

use crate::bpf_helpers;
use rsched_common::TASK_COMM_LEN;

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

impl task_struct {
    #[inline(always)]
    pub fn pid(&self) -> u32 {
        bpf_helpers::probe_read(&self.pid).unwrap_or(0) as u32
    }

    #[inline(always)]
    pub fn state(&self) -> u32 {
        bpf_helpers::probe_read(&self.__state).unwrap_or(0)
    }

    #[inline(always)]
    pub fn cpu(&self) -> i32 {
        bpf_helpers::probe_read(&self.thread_info.cpu).unwrap_or(0) as i32
    }

    #[inline(always)]
    pub fn wake_cpu(&self) -> i32 {
        bpf_helpers::probe_read(&self.wake_cpu).unwrap_or(-1)
    }

    #[inline(always)]
    pub fn read_comm(&self, buf: &mut [u8; TASK_COMM_LEN]) {
        bpf_helpers::probe_read_str(self.comm.as_ptr() as *const u8, buf);
    }

    #[inline(always)]
    pub fn cgroup_id(&self) -> u64 {
        let cs: *const css_set = match bpf_helpers::probe_read(&self.cgroups) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        let cg: *const cgroup = match bpf_helpers::probe_read(unsafe { &(*cs).dfl_cgrp }) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        let kn: *const kernfs_node = match bpf_helpers::probe_read(unsafe { &(*cg).kn }) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        bpf_helpers::probe_read(unsafe { &(*kn).id }).unwrap_or(0)
    }

    /// Get nr_running via task->se.cfs_rq->nr_running.
    /// Path: se at offset 192, cfs_rq at offset 160 within se (absolute 352).
    /// cfs_rq.nr_running at offset 16.
    #[inline(always)]
    pub fn cfs_rq_nr_running(&self) -> u64 {
        let cfs_rq_ptr_addr =
            unsafe { (self as *const _ as *const u8).add(352) as *const *const u8 };
        let cfs_rq: *const u8 = match bpf_helpers::probe_read(cfs_rq_ptr_addr) {
            Some(p) if !p.is_null() => p,
            _ => return 0,
        };
        let nr_addr = unsafe { cfs_rq.add(16) as *const u32 };
        match bpf_helpers::probe_read(nr_addr) {
            Some(v) => v as u64,
            _ => 0,
        }
    }
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
