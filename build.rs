// SPDX-License-Identifier: GPL-2.0
fn main() {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "rsched-ebpf",
            root_dir: "rsched-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .expect("Failed to build rsched-ebpf eBPF program");
}
