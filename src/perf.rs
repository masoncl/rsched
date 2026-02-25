// SPDX-License-Identifier: GPL-2.0
use anyhow::{bail, Result};
use aya::maps::MapData;
use std::os::unix::io::{AsFd, AsRawFd, RawFd};

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

    /// Setup IPC performance counters and attach them to BPF perf event array maps.
    /// Takes the 4 perf event array maps by MapData reference.
    pub fn setup_and_attach(
        &mut self,
        user_cycles_map: &mut MapData,
        kernel_cycles_map: &mut MapData,
        user_instructions_map: &mut MapData,
        kernel_instructions_map: &mut MapData,
    ) -> Result<()> {
        let num_cpus = num_cpus::get();

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
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_HARDWARE,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config,
            ..Default::default()
        };

        if exclude_kernel {
            attr.flags |= PERF_ATTR_BIT_EXCLUDE_KERNEL;
        }
        if exclude_user {
            attr.flags |= PERF_ATTR_BIT_EXCLUDE_USER;
        }
        attr.flags |= PERF_ATTR_BIT_EXCLUDE_HV | PERF_ATTR_BIT_EXCLUDE_IDLE;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                -1i32 as libc::pid_t,
                cpu,
                -1,
                PERF_FLAG_FD_CLOEXEC,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if exclude_kernel || exclude_user {
                eprintln!(
                    "Note: CPU {} may not support hardware event exclusion flags",
                    cpu
                );
            }
            bail!(
                "Failed to open perf event (CPU {}, config {}, exclude_kernel={}, exclude_user={}): {}",
                cpu, config, exclude_kernel, exclude_user, err
            );
        }

        let fd = fd as RawFd;

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

    /// Open a perf event with arbitrary type and config.
    fn open_typed_perf_event(&self, perf_type: u32, config: u64, cpu: i32) -> Result<RawFd> {
        let mut attr = PerfEventAttr {
            type_: perf_type,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config,
            ..Default::default()
        };

        attr.flags |= PERF_ATTR_BIT_EXCLUDE_HV | PERF_ATTR_BIT_EXCLUDE_IDLE;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const PerfEventAttr,
                -1i32 as libc::pid_t,
                cpu,
                -1,
                PERF_FLAG_FD_CLOEXEC,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            bail!(
                "Failed to open perf event (CPU {}, type={}, config=0x{:x}): {}",
                cpu,
                perf_type,
                config,
                err
            );
        }

        let fd = fd as RawFd;

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

    /// Setup generic perf events and attach to BPF maps.
    pub fn setup_generic_events(
        &mut self,
        events: &[(u32, u64)],
        maps: &mut [&mut MapData],
    ) -> Result<()> {
        let num_cpus = num_cpus::get();

        for (slot, ((perf_type, config), map)) in events.iter().zip(maps.iter_mut()).enumerate() {
            for cpu in 0..num_cpus {
                let fd = self
                    .open_typed_perf_event(*perf_type, *config, cpu as i32)
                    .map_err(|e| {
                        anyhow::anyhow!("Generic event slot {} on CPU {}: {}", slot, cpu, e)
                    })?;

                self.attach_to_map(map, cpu, fd)?;

                while self.fds.len() <= cpu {
                    self.fds.push(Vec::new());
                }
                self.fds[cpu].push(fd);
            }
        }

        Ok(())
    }

    fn attach_to_map(&self, map: &mut MapData, cpu: usize, fd: RawFd) -> Result<()> {
        // For perf event arrays in aya, we need to use the raw map fd
        // to set the perf event fd at the CPU index
        let map_fd = map.fd().as_fd().as_raw_fd();
        let key = (cpu as u32).to_ne_bytes();
        let value = fd.to_ne_bytes();

        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                2u32, // BPF_MAP_UPDATE_ELEM
                &BpfMapUpdateAttr {
                    map_fd: map_fd as u32,
                    key: key.as_ptr() as u64,
                    value: value.as_ptr() as u64,
                    flags: 0, // BPF_ANY
                } as *const BpfMapUpdateAttr,
                std::mem::size_of::<BpfMapUpdateAttr>(),
            )
        };

        if ret < 0 {
            bail!(
                "Failed to attach perf event fd to map: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(())
    }
}

#[repr(C)]
struct BpfMapUpdateAttr {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_event_attr_size() {
        assert_eq!(
            std::mem::size_of::<PerfEventAttr>(),
            112,
            "PerfEventAttr size mismatch"
        );
    }
}
