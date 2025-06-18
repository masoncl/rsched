// SPDX-License-Identifier: GPL-2.0
use anyhow::{bail, Result};
use libbpf_rs::{Map, MapFlags};
use std::os::unix::io::RawFd;

const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 0x00000008;

#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,

    // This is a 64-bit bitfield in the kernel
    // We'll use a u64 and set bits manually
    flags: u64,

    wakeup_events: u32,
    bp_type: u32,
    bp_addr: u64,
    bp_len: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    __reserved_3: u64,
}

// Bit positions for the flags field
#[allow(dead_code)]
const PERF_ATTR_BIT_DISABLED: u64 = 1 << 0;
#[allow(dead_code)]
const PERF_ATTR_BIT_INHERIT: u64 = 1 << 1;
#[allow(dead_code)]
const PERF_ATTR_BIT_PINNED: u64 = 1 << 2;
#[allow(dead_code)]
const PERF_ATTR_BIT_EXCLUSIVE: u64 = 1 << 3;
const PERF_ATTR_BIT_EXCLUDE_USER: u64 = 1 << 4;
const PERF_ATTR_BIT_EXCLUDE_KERNEL: u64 = 1 << 5;
const PERF_ATTR_BIT_EXCLUDE_HV: u64 = 1 << 6;
const PERF_ATTR_BIT_EXCLUDE_IDLE: u64 = 1 << 7;

impl Default for PerfEventAttr {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// Constants from linux/perf_event.h
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;

// ioctl commands
const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
#[allow(dead_code)]
const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
const PERF_EVENT_IOC_RESET: u64 = 0x2403;

pub struct PerfCounterSetup {
    fds: Vec<Vec<RawFd>>, // [cpu][counter_type]
}

impl Drop for PerfCounterSetup {
    fn drop(&mut self) {
        for cpu_fds in &self.fds {
            for &fd in cpu_fds {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

impl PerfCounterSetup {
    pub fn new() -> Self {
        Self { fds: Vec::new() }
    }

    /// Setup performance counters and attach them to BPF maps
    /// Changed to use the generated RschedMaps type
    pub fn setup_and_attach(&mut self, maps: &crate::RschedMaps) -> Result<()> {
        let num_cpus = num_cpus::get();

        // Get the BPF perf event array maps using the generated accessors
        let user_cycles_map = maps.user_cycles_array();
        let kernel_cycles_map = maps.kernel_cycles_array();
        let user_instructions_map = maps.user_instructions_array();
        let kernel_instructions_map = maps.kernel_instructions_array();

        // Setup counters for each CPU
        for cpu in 0..num_cpus {
            let mut cpu_fds = Vec::new();

            // 1. User cycles (exclude kernel)
            let fd = self.open_perf_event(
                PERF_COUNT_HW_CPU_CYCLES,
                cpu as i32,
                true,  // exclude_kernel
                false, // exclude_user
            )?;

            self.attach_to_map(user_cycles_map, cpu, fd)?;
            cpu_fds.push(fd);

            // 2. Kernel cycles (exclude user)
            let fd = self.open_perf_event(
                PERF_COUNT_HW_CPU_CYCLES,
                cpu as i32,
                false, // exclude_kernel
                true,  // exclude_user
            )?;
            self.attach_to_map(kernel_cycles_map, cpu, fd)?;
            cpu_fds.push(fd);

            // 3. User instructions (exclude kernel)
            let fd = self.open_perf_event(
                PERF_COUNT_HW_INSTRUCTIONS,
                cpu as i32,
                true,  // exclude_kernel
                false, // exclude_user
            )?;
            self.attach_to_map(user_instructions_map, cpu, fd)?;
            cpu_fds.push(fd);

            // 4. Kernel instructions (exclude user)
            let fd = self.open_perf_event(
                PERF_COUNT_HW_INSTRUCTIONS,
                cpu as i32,
                false, // exclude_kernel
                true,  // exclude_user
            )?;
            self.attach_to_map(kernel_instructions_map, cpu, fd)?;
            cpu_fds.push(fd);

            self.fds.push(cpu_fds);
        }

        Ok(())
    }

    fn open_perf_event(
        &self,
        config: u64,
        cpu: i32,
        exclude_kernel: bool,
        exclude_user: bool,
    ) -> Result<RawFd> {
        let mut attr = PerfEventAttr::default();
        attr.type_ = PERF_TYPE_HARDWARE;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = config;

        // Set the exclusion bits in the flags field
        if exclude_kernel {
            attr.flags |= PERF_ATTR_BIT_EXCLUDE_KERNEL;
        }
        if exclude_user {
            attr.flags |= PERF_ATTR_BIT_EXCLUDE_USER;
        }
        // Always exclude hypervisor and idle
        attr.flags |= PERF_ATTR_BIT_EXCLUDE_HV | PERF_ATTR_BIT_EXCLUDE_IDLE;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                -1i32 as libc::pid_t, // pid = -1 means all processes
                cpu,                  // cpu
                -1,                   // group_fd
                PERF_FLAG_FD_CLOEXEC, // flags
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();

            // Try without exclusion flags to see if that's the issue
            if exclude_kernel || exclude_user {
                eprintln!(
                    "Note: CPU {} may not support hardware event exclusion flags",
                    cpu
                );
            }

            bail!(
                "Failed to open perf event (CPU {}, config {}, exclude_kernel={}, exclude_user={}): {}",
                cpu,
                config,
                exclude_kernel,
                exclude_user,
                err
            );
        }

        let fd = fd as RawFd;

        // Enable the counter
        let ret = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE as _, 0) };

        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            bail!(
                "Failed to enable perf event: {}",
                std::io::Error::last_os_error()
            );
        }

        // Reset counter to 0
        let ret = unsafe { libc::ioctl(fd, PERF_EVENT_IOC_RESET as _, 0) };

        if ret < 0 {
            unsafe {
                libc::close(fd);
            }
            bail!(
                "Failed to reset perf event: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(fd)
    }

    fn attach_to_map(&self, map: &Map, cpu: usize, fd: RawFd) -> Result<()> {
        let key_bytes = (cpu as u32).to_ne_bytes();
        let fd_val = fd.to_ne_bytes();
        map.update(&key_bytes, &fd_val, MapFlags::ANY)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_event_attr_size() {
        // Ensure our struct matches the expected size
        assert_eq!(
            std::mem::size_of::<PerfEventAttr>(),
            112, // Expected size on x86_64
            "PerfEventAttr size mismatch"
        );
    }
}
