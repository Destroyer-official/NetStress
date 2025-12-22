// Build script for NetStress Titanium v3.0 - Static DPDK PMD linking
// **Validates: Requirements 10.2** - Configure PMD initialization and static linking

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Configure DPDK static linking if feature is enabled
    #[cfg(feature = "dpdk")]
    configure_dpdk_static_linking();

    // Configure platform-specific static linking
    configure_platform_static_linking();

    // Generate bindings if needed
    #[cfg(all(feature = "dpdk", feature = "bindgen"))]
    generate_dpdk_bindings();
}

#[cfg(feature = "dpdk")]
fn configure_dpdk_static_linking() {
    println!("cargo:rustc-cfg=feature=\"dpdk\"");

    // Try to find DPDK installation
    let dpdk_path = env::var("DPDK_PATH")
        .or_else(|_| env::var("RTE_SDK"))
        .unwrap_or_else(|_| "/usr/local".to_string());

    let dpdk_target = env::var("DPDK_TARGET")
        .or_else(|_| env::var("RTE_TARGET"))
        .unwrap_or_else(|_| "x86_64-native-linux-gcc".to_string());

    let lib_path = format!("{}/lib", dpdk_path);
    let include_path = format!("{}/include", dpdk_path);

    println!("cargo:rustc-link-search=native={}", lib_path);
    println!("cargo:rustc-link-search=native={}/dpdk", lib_path);
    println!("cargo:include={}", include_path);

    // Core DPDK libraries (order matters for static linking)
    let dpdk_libs = vec![
        // Core libraries
        "rte_eal",
        "rte_mempool",
        "rte_ring",
        "rte_mbuf",
        "rte_ethdev",
        "rte_net",
        "rte_kvargs",
        "rte_telemetry",
        "rte_log",
        // PMD libraries - Intel
        "rte_pmd_e1000",
        "rte_pmd_ixgbe",
        "rte_pmd_i40e",
        "rte_pmd_ice",
        // PMD libraries - Mellanox
        "rte_pmd_mlx4",
        "rte_pmd_mlx5",
        // PMD libraries - Broadcom
        "rte_pmd_bnxt",
        // PMD libraries - Virtual
        "rte_pmd_virtio",
        "rte_pmd_vmxnet3",
        "rte_pmd_af_packet",
        "rte_pmd_tap",
        "rte_pmd_null",
        // Bus drivers
        "rte_bus_pci",
        "rte_bus_vdev",
        // Memory drivers
        "rte_mempool_ring",
        "rte_mempool_stack",
    ];

    // Link DPDK libraries statically
    for lib in dpdk_libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    // System dependencies for DPDK
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=numa");

    // Platform-specific DPDK dependencies
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=rt");
            println!("cargo:rustc-link-lib=m");
        }
        "freebsd" => {
            println!("cargo:rustc-link-lib=execinfo");
        }
        _ => {}
    }

    println!("cargo:warning=DPDK static linking configured");
}

fn configure_platform_static_linking() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    match target_os.as_str() {
        "windows" => {
            // Windows-specific static linking
            println!("cargo:rustc-link-lib=ws2_32");
            println!("cargo:rustc-link-lib=iphlpapi");
            println!("cargo:rustc-link-lib=kernel32");
            println!("cargo:rustc-link-lib=user32");
            println!("cargo:rustc-link-lib=advapi32");

            // Static CRT linking
            println!("cargo:rustc-link-arg=/NODEFAULTLIB:msvcrt");
            println!("cargo:rustc-link-arg=/DEFAULTLIB:libcmt");
        }
        "linux" => {
            // Linux-specific static linking
            println!("cargo:rustc-link-lib=static=c");

            // Enable static linking for musl
            if env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "musl" {
                println!("cargo:rustc-link-arg=-static");
            }
        }
        "macos" => {
            // macOS-specific frameworks
            println!("cargo:rustc-link-lib=framework=Foundation");
            println!("cargo:rustc-link-lib=framework=Network");
            println!("cargo:rustc-link-lib=framework=SystemConfiguration");

            if target_arch == "aarch64" {
                // Apple Silicon optimizations
                println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=11.0");
            } else {
                println!("cargo:rustc-env=MACOSX_DEPLOYMENT_TARGET=10.15");
            }
        }
        _ => {}
    }
}

#[cfg(all(feature = "dpdk", feature = "bindgen"))]
fn generate_dpdk_bindings() {
    use std::path::PathBuf;

    let dpdk_path = env::var("DPDK_PATH")
        .or_else(|_| env::var("RTE_SDK"))
        .unwrap_or_else(|_| "/usr/local".to_string());

    let include_path = format!("{}/include", dpdk_path);

    // Generate bindings for DPDK headers
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_arg(format!("-I{}", include_path))
        .clang_arg("-I/usr/include")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate DPDK bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("dpdk_bindings.rs"))
        .expect("Couldn't write DPDK bindings");

    println!("cargo:warning=DPDK bindings generated");
}
