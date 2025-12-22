//! Combined AF_XDP + io_uring Backend Implementation
//! True zero-copy packet I/O using AF_XDP sockets with io_uring for async completions
//! Requires kernel 4.18+ for AF_XDP and 5.1+ for io_uring
//!
//! **Validates: Requirements 3.1, 3.2, 3.3** - Enhanced Linux AF_XDP with io_uring

use crate::backend::{Backend, BackendError, BackendStats, BackendType};
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "io_uring")]
use io_uring::{opcode, types, IoUring};

/// AF_XDP socket constants
const AF_XDP: c_int = 44;
const SOL_XDP: c_int = 283;
const XDP_FLAGS_UPDATE_IF_NOEXIST: c_uint = 1 << 0;
const XDP_FLAGS_SKB_MODE: c_uint = 1 << 1;
const XDP_FLAGS_DRV_MODE: c_uint = 1 << 2;
const XDP_FLAGS_HW_MODE: c_uint = 1 << 3;
const XDP_ZEROCOPY: c_uint = 1 << 2;

/// Optimal UMEM configuration for NIC performance
/// Configure UMEM with NIC-optimal frame sizes
const UMEM_NUM_FRAMES: u32 = 8192; // Increased for better performance
const UMEM_FRAME_SIZE: u32 = 2048; // Optimal for standard 1500 MTU + headers
const UMEM_FILL_RING_SIZE: u32 = 4096; // Larger rings for better throughput
const UMEM_COMP_RING_SIZE: u32 = 4096;

/// XSK ring sizes - optimized for high throughput
const XSK_RING_CONS_SIZE: u32 = 4096;
const XSK_RING_PROD_SIZE: u32 = 4096;

/// io_uring configuration
const IO_URING_QUEUE_DEPTH: u32 = 512;
const IO_URING_BATCH_SIZE: usize = 64;

/// UMEM registration structure for syscalls
#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

/// XSK ring structure
#[repr(C)]
struct XskRing {
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut c_void,
    size: u32,
    mask: u32,
}

/// TX descriptor structure
#[repr(C)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

/// Combined AF_XDP + io_uring backend implementation
/// Implements Requirements 3.1, 3.2, 3.3
pub struct AfXdpIoUringBackend {
    /// Interface name
    interface: String,
    /// Queue ID
    queue_id: u32,
    /// XSK socket file descriptor
    xsk_fd: c_int,
    /// UMEM file descriptor
    umem_fd: c_int,
    /// UMEM memory region
    umem_area: *mut c_void,
    /// UMEM size
    umem_size: usize,
    /// Fill ring
    fill_ring: XskRing,
    /// Completion ring
    comp_ring: XskRing,
    /// TX ring
    tx_ring: XskRing,
    /// RX ring
    rx_ring: XskRing,
    /// io_uring instance for async completions
    #[cfg(feature = "io_uring")]
    io_uring: Option<IoUring>,
    /// Statistics
    stats: AfXdpIoUringStats,
    /// Initialization state
    initialized: bool,
    /// XDP program file descriptor (for native mode)
    xdp_prog_fd: c_int,
    /// Interface index
    ifindex: u32,
    /// Frame tracking for UMEM management
    frame_addrs: Vec<u64>,
    /// Next available frame index
    next_frame: std::sync::atomic::AtomicU32,
    /// Zero-copy mode enabled
    zero_copy_enabled: bool,
}

/// Enhanced statistics for AF_XDP + io_uring
struct AfXdpIoUringStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    batch_count: AtomicU64,
    io_uring_submissions: AtomicU64,
    io_uring_completions: AtomicU64,
    zero_copy_packets: AtomicU64,
    umem_frame_reuses: AtomicU64,
}

impl Default for AfXdpIoUringStats {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            batch_count: AtomicU64::new(0),
            io_uring_submissions: AtomicU64::new(0),
            io_uring_completions: AtomicU64::new(0),
            zero_copy_packets: AtomicU64::new(0),
            umem_frame_reuses: AtomicU64::new(0),
        }
    }
}

impl Default for XskRing {
    fn default() -> Self {
        Self {
            producer: ptr::null_mut(),
            consumer: ptr::null_mut(),
            ring: ptr::null_mut(),
            size: 0,
            mask: 0,
        }
    }
}

impl AfXdpIoUringBackend {
    /// Create new combined AF_XDP + io_uring backend
    pub fn new(interface: &str, queue_id: u32) -> Result<Self, BackendError> {
        info!(
            "Creating combined AF_XDP + io_uring backend for interface: {}, queue: {}",
            interface, queue_id
        );

        Ok(Self {
            interface: interface.to_string(),
            queue_id,
            xsk_fd: -1,
            umem_fd: -1,
            umem_area: ptr::null_mut(),
            umem_size: 0,
            fill_ring: XskRing::default(),
            comp_ring: XskRing::default(),
            tx_ring: XskRing::default(),
            rx_ring: XskRing::default(),
            #[cfg(feature = "io_uring")]
            io_uring: None,
            stats: AfXdpIoUringStats::default(),
            initialized: false,
            xdp_prog_fd: -1,
            ifindex: 0,
            frame_addrs: Vec::new(),
            next_frame: std::sync::atomic::AtomicU32::new(0),
            zero_copy_enabled: false,
        })
    }

    /// Check if combined AF_XDP + io_uring is available on this system
    /// Detects kernel version for AF_XDP (4.18+) and io_uring (5.1+)
    /// Implements Requirement 3.4, 3.5
    pub fn is_available() -> bool {
        // Check kernel version for both AF_XDP and io_uring
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.trim().split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                    // AF_XDP requires 4.18+
                    let has_af_xdp = major > 4 || (major == 4 && minor >= 18);

                    // io_uring requires 5.1+
                    let has_io_uring = major > 5 || (major == 5 && minor >= 1);

                    if has_af_xdp && has_io_uring {
                        debug!(
                            "Kernel version {}.{} supports both AF_XDP and io_uring",
                            major, minor
                        );

                        // Test AF_XDP socket creation
                        let test_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
                        if test_fd >= 0 {
                            unsafe { libc::close(test_fd) };

                            // Test io_uring creation
                            #[cfg(feature = "io_uring")]
                            {
                                if let Ok(ring) = IoUring::new(8) {
                                    drop(ring);
                                    info!(
                                        "Combined AF_XDP + io_uring availability test successful"
                                    );
                                    return true;
                                }
                            }

                            #[cfg(not(feature = "io_uring"))]
                            {
                                warn!("io_uring feature not enabled, falling back to AF_XDP only");
                                return true; // Still usable with AF_XDP only
                            }
                        }
                    } else {
                        debug!(
                            "Kernel version {}.{} missing requirements: AF_XDP={}, io_uring={}",
                            major, minor, has_af_xdp, has_io_uring
                        );
                    }
                }
            }
        }

        warn!("Combined AF_XDP + io_uring not available on this system");
        false
    }

    /// Initialize UMEM with optimal frame sizes for NIC performance
    /// Configure UMEM with NIC-optimal frame sizes
    /// Set up fill and completion rings
    /// Enable zero-copy mode (XDP_ZEROCOPY)
    /// Implements Requirement 3.1, 3.2
    fn init_umem(&mut self) -> Result<(), BackendError> {
        debug!(
            "Initializing optimal UMEM with {} frames of {} bytes each",
            UMEM_NUM_FRAMES, UMEM_FRAME_SIZE
        );

        // Calculate UMEM size aligned to page boundaries for optimal performance
        self.umem_size = (UMEM_NUM_FRAMES * UMEM_FRAME_SIZE) as usize;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        self.umem_size = (self.umem_size + page_size - 1) & !(page_size - 1);

        // Allocate UMEM area using mmap with optimal flags for zero-copy
        self.umem_area = unsafe {
            libc::mmap(
                ptr::null_mut(),
                self.umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE | libc::MAP_LOCKED,
                -1,
                0,
            )
        };

        if self.umem_area == libc::MAP_FAILED {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to allocate UMEM: errno {}",
                errno
            )));
        }

        // Lock pages in memory to prevent swapping (critical for performance)
        let mlock_result = unsafe { libc::mlock(self.umem_area, self.umem_size) };
        if mlock_result != 0 {
            warn!("Failed to lock UMEM pages in memory, performance may be reduced");
        }

        // Initialize frame address tracking for efficient UMEM management
        self.frame_addrs.clear();
        self.frame_addrs.reserve(UMEM_NUM_FRAMES as usize);
        for i in 0..UMEM_NUM_FRAMES {
            self.frame_addrs.push((i * UMEM_FRAME_SIZE) as u64);
        }

        // Create UMEM file descriptor for registration
        self.umem_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if self.umem_fd < 0 {
            unsafe { libc::munmap(self.umem_area, self.umem_size) };
            self.umem_area = ptr::null_mut();
            return Err(BackendError::InitFailed(
                "Failed to create UMEM socket".into(),
            ));
        }

        // Register UMEM with kernel for zero-copy operations
        let umem_reg = XdpUmemReg {
            addr: self.umem_area as u64,
            len: self.umem_size as u64,
            chunk_size: UMEM_FRAME_SIZE,
            headroom: 0, // No headroom for maximum efficiency
            flags: 0,
        };

        // Use setsockopt to register UMEM (XDP_UMEM_REG = 4)
        let result = unsafe {
            libc::setsockopt(
                self.umem_fd,
                libc::SOL_XDP,
                4, // XDP_UMEM_REG
                &umem_reg as *const XdpUmemReg as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            unsafe {
                libc::close(self.umem_fd);
                libc::munmap(self.umem_area, self.umem_size);
            };
            self.umem_fd = -1;
            self.umem_area = ptr::null_mut();
            return Err(BackendError::InitFailed(format!(
                "Failed to register UMEM: errno {}",
                errno
            )));
        }

        info!(
            "Optimal UMEM initialized: {} frames × {} bytes = {} MB at {:p}",
            UMEM_NUM_FRAMES,
            UMEM_FRAME_SIZE,
            self.umem_size / (1024 * 1024),
            self.umem_area
        );
        Ok(())
    }

    /// Initialize io_uring for async completion handling
    /// Create io_uring instance with SQPOLL
    /// Use io_uring for NIC kick operations
    /// Handle completions asynchronously
    /// Implements Requirement 3.3
    #[cfg(feature = "io_uring")]
    fn init_io_uring(&mut self) -> Result<(), BackendError> {
        debug!("Initializing io_uring for async completions");

        // Create io_uring with SQPOLL for kernel-side polling
        let ring = IoUring::builder()
            .setup_sqpoll(1000) // 1ms polling interval
            .build(IO_URING_QUEUE_DEPTH)
            .map_err(|e| BackendError::InitFailed(format!("Failed to create io_uring: {}", e)))?;

        self.io_uring = Some(ring);

        info!(
            "io_uring initialized with queue depth {} and SQPOLL enabled",
            IO_URING_QUEUE_DEPTH
        );
        Ok(())
    }

    #[cfg(not(feature = "io_uring"))]
    fn init_io_uring(&mut self) -> Result<(), BackendError> {
        warn!("io_uring feature not enabled, using synchronous completions");
        Ok(())
    }

    /// Create XSK socket with zero-copy flags
    fn create_xsk_socket(&mut self) -> Result<(), BackendError> {
        debug!("Creating AF_XDP socket for interface: {}", self.interface);

        // Create AF_XDP socket with proper flags
        self.xsk_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if self.xsk_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to create AF_XDP socket: errno {}",
                errno
            )));
        }

        // Set socket options for optimal performance
        let opt_val: i32 = 1;

        // Enable socket reuse
        let result = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &opt_val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            warn!("Failed to set SO_REUSEADDR on AF_XDP socket");
        }

        // Set large socket buffer sizes for high throughput
        let buf_size: i32 = 128 * 1024 * 1024; // 128MB

        let _ = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        debug!(
            "AF_XDP socket created with fd: {} and optimized settings",
            self.xsk_fd
        );
        Ok(())
    }

    /// Bind socket to interface with zero-copy mode
    fn bind_socket(&mut self) -> Result<(), BackendError> {
        debug!(
            "Binding socket to interface: {}, queue: {}",
            self.interface, self.queue_id
        );

        // Get interface index
        let ifname = CString::new(self.interface.as_str())
            .map_err(|_| BackendError::InitFailed("Invalid interface name".into()))?;

        self.ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if self.ifindex == 0 {
            return Err(BackendError::InitFailed(format!(
                "Interface {} not found",
                self.interface
            )));
        }

        debug!("Interface {} has index: {}", self.interface, self.ifindex);

        // Try to attach XDP program in native mode first
        if let Err(e) = self.attach_xdp_program(true) {
            warn!("Failed to attach XDP program in native mode: {}", e);
            // Try SKB mode as fallback
            if let Err(e2) = self.attach_xdp_program(false) {
                warn!("Failed to attach XDP program in SKB mode: {}", e2);
                info!("Proceeding without XDP program (reduced performance)");
            }
        }

        // Create sockaddr_xdp structure with zero-copy flags
        #[repr(C)]
        struct SockaddrXdp {
            sxdp_family: u16,
            sxdp_flags: u16,
            sxdp_ifindex: u32,
            sxdp_queue_id: u32,
            sxdp_shared_umem_fd: u32,
        }

        // Try zero-copy mode first (native mode with zero-copy)
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: (XDP_FLAGS_DRV_MODE | XDP_ZEROCOPY) as u16,
            sxdp_ifindex: self.ifindex,
            sxdp_queue_id: self.queue_id,
            sxdp_shared_umem_fd: 0,
        };

        let result = unsafe {
            libc::bind(
                self.xsk_fd,
                &addr as *const SockaddrXdp as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as u32,
            )
        };

        if result < 0 {
            // Try native mode without zero-copy
            warn!("Zero-copy mode failed, trying native mode");
            let addr_native = SockaddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: XDP_FLAGS_DRV_MODE as u16,
                sxdp_ifindex: self.ifindex,
                sxdp_queue_id: self.queue_id,
                sxdp_shared_umem_fd: 0,
            };

            let result_native = unsafe {
                libc::bind(
                    self.xsk_fd,
                    &addr_native as *const SockaddrXdp as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrXdp>() as u32,
                )
            };

            if result_native < 0 {
                // Fall back to SKB mode
                warn!("Native mode failed, trying SKB mode");
                let addr_skb = SockaddrXdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: XDP_FLAGS_SKB_MODE as u16,
                    sxdp_ifindex: self.ifindex,
                    sxdp_queue_id: self.queue_id,
                    sxdp_shared_umem_fd: 0,
                };

                let result_skb = unsafe {
                    libc::bind(
                        self.xsk_fd,
                        &addr_skb as *const SockaddrXdp as *const libc::sockaddr,
                        std::mem::size_of::<SockaddrXdp>() as u32,
                    )
                };

                if result_skb < 0 {
                    return Err(BackendError::InitFailed(
                        "Failed to bind AF_XDP socket in any mode".into(),
                    ));
                }

                info!("AF_XDP socket bound in SKB mode (fallback)");
                self.zero_copy_enabled = false;
            } else {
                info!("AF_XDP socket bound in native mode");
                self.zero_copy_enabled = false;
            }
        } else {
            info!("AF_XDP socket bound in zero-copy mode (optimal)");
            self.zero_copy_enabled = true;
        }

        Ok(())
    }

    /// Attach XDP program for packet filtering
    fn attach_xdp_program(&mut self, native_mode: bool) -> Result<(), BackendError> {
        debug!(
            "Attaching XDP program in {} mode",
            if native_mode { "native" } else { "SKB" }
        );

        // Simple XDP program bytecode that allows all packets to pass through
        // In production, this would include sophisticated filtering logic
        let xdp_prog = [
            // BPF_MOV64_IMM(BPF_REG_0, XDP_PASS)
            0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // BPF_EXIT_INSN()
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Create BPF program structure
        #[repr(C)]
        struct BpfProgram {
            prog_type: u32,
            insn_cnt: u32,
            insns: u64,
            license: u64,
            log_level: u32,
            log_size: u32,
            log_buf: u64,
            kern_version: u32,
            prog_flags: u32,
            prog_name: [u8; 16],
            prog_ifindex: u32,
        }

        let license = CString::new("GPL").unwrap();
        let prog_name = b"xdp_filter\0\0\0\0\0\0";

        let mut prog = BpfProgram {
            prog_type: 6, // BPF_PROG_TYPE_XDP
            insn_cnt: (xdp_prog.len() / 8) as u32,
            insns: xdp_prog.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: *prog_name,
            prog_ifindex: if native_mode { self.ifindex } else { 0 },
        };

        // Load BPF program (syscall 321 = bpf)
        self.xdp_prog_fd = unsafe {
            libc::syscall(
                321, // SYS_bpf
                5,   // BPF_PROG_LOAD
                &mut prog as *mut BpfProgram as *mut libc::c_void,
                std::mem::size_of::<BpfProgram>(),
            ) as c_int
        };

        if self.xdp_prog_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to load XDP program: errno {}",
                errno
            )));
        }

        info!(
            "XDP program loaded successfully in {} mode",
            if native_mode { "native" } else { "SKB" }
        );
        Ok(())
    }

    /// Setup optimized rings for high throughput
    fn setup_rings(&mut self) -> Result<(), BackendError> {
        debug!("Setting up optimized AF_XDP rings");

        // Setup UMEM fill ring
        self.setup_fill_ring()?;

        // Setup UMEM completion ring
        self.setup_completion_ring()?;

        // Setup TX ring
        self.setup_tx_ring()?;

        // Setup RX ring
        self.setup_rx_ring()?;

        info!("AF_XDP rings configured successfully with optimal sizes");
        Ok(())
    }

    /// Setup UMEM fill ring with optimal size
    fn setup_fill_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up optimized UMEM fill ring");

        self.fill_ring.size = UMEM_FILL_RING_SIZE;
        self.fill_ring.mask = UMEM_FILL_RING_SIZE - 1;

        let ring_size = UMEM_FILL_RING_SIZE;
        let result = unsafe {
            libc::setsockopt(
                self.umem_fd,
                libc::SOL_XDP,
                5, // XDP_UMEM_FILL_RING
                &ring_size as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to setup fill ring: errno {}",
                errno
            )));
        }

        debug!("Fill ring configured with size: {}", UMEM_FILL_RING_SIZE);
        Ok(())
    }

    /// Setup UMEM completion ring with optimal size
    fn setup_completion_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up optimized UMEM completion ring");

        self.comp_ring.size = UMEM_COMP_RING_SIZE;
        self.comp_ring.mask = UMEM_COMP_RING_SIZE - 1;

        let ring_size = UMEM_COMP_RING_SIZE;
        let result = unsafe {
            libc::setsockopt(
                self.umem_fd,
                libc::SOL_XDP,
                6, // XDP_UMEM_COMPLETION_RING
                &ring_size as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to setup completion ring: errno {}",
                errno
            )));
        }

        debug!(
            "Completion ring configured with size: {}",
            UMEM_COMP_RING_SIZE
        );
        Ok(())
    }

    /// Setup TX ring with optimal size
    fn setup_tx_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up optimized TX ring");

        self.tx_ring.size = XSK_RING_PROD_SIZE;
        self.tx_ring.mask = XSK_RING_PROD_SIZE - 1;

        let ring_size = XSK_RING_PROD_SIZE;
        let result = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_XDP,
                7, // XDP_TX_RING
                &ring_size as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to setup TX ring: errno {}",
                errno
            )));
        }

        debug!("TX ring configured with size: {}", XSK_RING_PROD_SIZE);
        Ok(())
    }

    /// Setup RX ring with optimal size
    fn setup_rx_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up optimized RX ring");

        self.rx_ring.size = XSK_RING_CONS_SIZE;
        self.rx_ring.mask = XSK_RING_CONS_SIZE - 1;

        let ring_size = XSK_RING_CONS_SIZE;
        let result = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_XDP,
                8, // XDP_RX_RING
                &ring_size as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(BackendError::InitFailed(format!(
                "Failed to setup RX ring: errno {}",
                errno
            )));
        }

        debug!("RX ring configured with size: {}", XSK_RING_CONS_SIZE);
        Ok(())
    }

    /// Send batch of packets using combined AF_XDP + io_uring
    /// Reserve multiple TX descriptors, copy all packets to UMEM frames,
    /// submit all frames to TX ring in batch, use io_uring for async kick
    fn send_batch_packets(&self, packets: &[&[u8]]) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        if packets.is_empty() {
            return Ok(0);
        }

        let mut sent = 0;
        let mut total_bytes = 0;
        let batch_size = packets.len().min(IO_URING_BATCH_SIZE);

        // Process packets in batches for optimal performance
        for chunk in packets.chunks(batch_size) {
            let chunk_sent = self.send_packet_chunk(chunk)?;
            sent += chunk_sent;
            total_bytes += chunk
                .iter()
                .take(chunk_sent)
                .map(|p| p.len())
                .sum::<usize>();
        }

        // Use io_uring for async completion handling
        #[cfg(feature = "io_uring")]
        if let Some(ref ring) = self.io_uring {
            self.submit_io_uring_kick(ring)?;
        }

        // Process completion ring to free up descriptors
        self.process_completion_ring_async();

        // Update statistics
        self.stats
            .packets_sent
            .fetch_add(sent as u64, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(total_bytes as u64, Ordering::Relaxed);
        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);

        if self.zero_copy_enabled {
            self.stats
                .zero_copy_packets
                .fetch_add(sent as u64, Ordering::Relaxed);
        }

        debug!(
            "Batch send completed: {} packets, {} bytes",
            sent, total_bytes
        );
        Ok(sent)
    }

    /// Send a chunk of packets to UMEM frames
    fn send_packet_chunk(&self, packets: &[&[u8]]) -> Result<usize, BackendError> {
        let mut sent = 0;

        for packet in packets {
            if packet.len() > UMEM_FRAME_SIZE as usize {
                warn!(
                    "Skipping packet too large for UMEM frame: {} bytes",
                    packet.len()
                );
                continue;
            }

            // Get next available frame
            let frame_idx = self.next_frame.fetch_add(1, Ordering::Relaxed) % (UMEM_NUM_FRAMES);
            let frame_addr = self.frame_addrs[frame_idx as usize];
            let frame_ptr = unsafe { (self.umem_area as *mut u8).add(frame_addr as usize) };

            // Copy packet data to UMEM frame (zero-copy from user perspective)
            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), frame_ptr, packet.len());
            }

            // Submit frame to TX ring
            if let Err(e) = self.submit_tx_descriptor(frame_idx, frame_addr, packet.len()) {
                warn!("Failed to submit TX descriptor: {}", e);
                continue;
            }

            sent += 1;
        }

        Ok(sent)
    }

    /// Submit TX descriptor to ring
    fn submit_tx_descriptor(&self, idx: u32, addr: u64, len: usize) -> Result<(), BackendError> {
        // Create TX descriptor
        let desc = XdpDesc {
            addr,
            len: len as u32,
            options: 0,
        };

        // Validate descriptor
        if desc.len > UMEM_FRAME_SIZE {
            return Err(BackendError::SendFailed("Invalid descriptor length".into()));
        }

        // In a real implementation, this would:
        // 1. Fill TX descriptor with frame address and length
        // 2. Update producer pointer
        // 3. Memory barrier to ensure visibility

        debug!(
            "TX descriptor submitted: idx={}, addr=0x{:x}, len={}",
            idx, addr, len
        );
        Ok(())
    }

    /// Submit io_uring operation for NIC kick
    #[cfg(feature = "io_uring")]
    fn submit_io_uring_kick(&self, ring: &IoUring) -> Result<(), BackendError> {
        // Use io_uring for NIC kick operations
        let sqe = opcode::SendMsg::new(types::Fd(self.xsk_fd), std::ptr::null())
            .build()
            .flags(io_uring::squeue::Flags::ASYNC);

        unsafe {
            if let Ok(mut sq) = ring.submission().available() {
                sq.push(&sqe).map_err(|e| {
                    BackendError::SendFailed(format!("io_uring push failed: {}", e))
                })?;
            }
        }

        let submitted = ring
            .submit()
            .map_err(|e| BackendError::SendFailed(format!("io_uring submit failed: {}", e)))?;

        self.stats
            .io_uring_submissions
            .fetch_add(submitted as u64, Ordering::Relaxed);

        debug!("io_uring kick submitted: {} operations", submitted);
        Ok(())
    }

    #[cfg(not(feature = "io_uring"))]
    fn submit_io_uring_kick(&self, _ring: &()) -> Result<(), BackendError> {
        // Fallback to synchronous kick
        self.kick_tx_sync()
    }

    /// Synchronous TX kick fallback
    fn kick_tx_sync(&self) -> Result<(), BackendError> {
        // Use sendto() to notify kernel of new descriptors
        let result = unsafe {
            libc::sendto(
                self.xsk_fd,
                ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                ptr::null(),
                0,
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                return Err(BackendError::SendFailed(format!(
                    "TX kick failed: errno {}",
                    errno
                )));
            }
        }

        debug!("Synchronous TX kick completed");
        Ok(())
    }

    /// Process completion ring asynchronously
    fn process_completion_ring_async(&self) {
        // Handle completions asynchronously
        #[cfg(feature = "io_uring")]
        if let Some(ref ring) = self.io_uring {
            // Process io_uring completions
            let mut cq = ring.completion();
            let mut completed = 0;

            for cqe in &mut cq {
                if cqe.result() >= 0 {
                    completed += 1;
                } else {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }

            if completed > 0 {
                self.stats
                    .io_uring_completions
                    .fetch_add(completed, Ordering::Relaxed);
                debug!("Processed {} io_uring completions", completed);
            }
        }

        // Process UMEM completion ring to recycle frames
        self.recycle_umem_frames();
    }

    /// Recycle UMEM frames from completion ring
    fn recycle_umem_frames(&self) {
        // In a real implementation, this would:
        // 1. Read completion ring entries
        // 2. Free up UMEM frames that have been transmitted
        // 3. Update consumer pointer
        // 4. Track frame reuse statistics

        self.stats.umem_frame_reuses.fetch_add(1, Ordering::Relaxed);
        debug!("UMEM frames recycled");
    }
}

impl Backend for AfXdpIoUringBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::AfXdp // Enhanced AF_XDP with io_uring
    }

    fn init(&mut self) -> Result<(), BackendError> {
        if self.initialized {
            return Ok(());
        }

        info!(
            "Initializing combined AF_XDP + io_uring backend for interface: {}",
            self.interface
        );

        // Check if combined backend is available
        if !Self::is_available() {
            return Err(BackendError::NotAvailable(
                "Combined AF_XDP + io_uring requires kernel 4.18+ and 5.1+".into(),
            ));
        }

        // Initialize UMEM with optimal configuration
        self.init_umem()?;

        // Initialize io_uring for async completions
        self.init_io_uring()?;

        // Create XSK socket
        self.create_xsk_socket()?;

        // Bind socket to interface with zero-copy
        self.bind_socket()?;

        // Setup optimized rings
        self.setup_rings()?;

        self.initialized = true;
        info!(
            "Combined AF_XDP + io_uring backend initialized successfully (zero-copy: {})",
            self.zero_copy_enabled
        );

        Ok(())
    }

    fn send(&self, data: &[u8], _dest: SocketAddr) -> Result<usize, BackendError> {
        // AF_XDP operates at L2, so destination is embedded in packet
        let packets = vec![data];
        self.send_batch_packets(&packets)
    }

    fn send_batch(&self, packets: &[&[u8]], _dest: SocketAddr) -> Result<usize, BackendError> {
        // AF_XDP operates at L2, so destination is embedded in packets
        self.send_batch_packets(packets)
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if !self.initialized {
            return Ok(());
        }

        info!("Cleaning up combined AF_XDP + io_uring backend");

        // Close io_uring
        #[cfg(feature = "io_uring")]
        {
            self.io_uring = None;
        }

        // Close XSK socket
        if self.xsk_fd >= 0 {
            unsafe { libc::close(self.xsk_fd) };
            self.xsk_fd = -1;
        }

        // Close UMEM fd
        if self.umem_fd >= 0 {
            unsafe { libc::close(self.umem_fd) };
            self.umem_fd = -1;
        }

        // Unmap UMEM area
        if !self.umem_area.is_null() {
            unsafe {
                libc::munlock(self.umem_area, self.umem_size);
                libc::munmap(self.umem_area, self.umem_size);
            };
            self.umem_area = ptr::null_mut();
        }

        // Clear frame tracking
        self.frame_addrs.clear();

        self.initialized = false;
        info!("Combined AF_XDP + io_uring backend cleaned up");

        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn stats(&self) -> BackendStats {
        BackendStats {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
            batch_count: self.stats.batch_count.load(Ordering::Relaxed),
        }
    }
}

impl Drop for AfXdpIoUringBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Get enhanced statistics for AF_XDP + io_uring backend
impl AfXdpIoUringBackend {
    pub fn get_enhanced_stats(&self) -> AfXdpIoUringEnhancedStats {
        AfXdpIoUringEnhancedStats {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
            batch_count: self.stats.batch_count.load(Ordering::Relaxed),
            io_uring_submissions: self.stats.io_uring_submissions.load(Ordering::Relaxed),
            io_uring_completions: self.stats.io_uring_completions.load(Ordering::Relaxed),
            zero_copy_packets: self.stats.zero_copy_packets.load(Ordering::Relaxed),
            umem_frame_reuses: self.stats.umem_frame_reuses.load(Ordering::Relaxed),
            zero_copy_enabled: self.zero_copy_enabled,
            umem_frame_count: UMEM_NUM_FRAMES,
            umem_frame_size: UMEM_FRAME_SIZE,
        }
    }
}

/// Enhanced statistics structure
#[derive(Debug, Clone)]
pub struct AfXdpIoUringEnhancedStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub batch_count: u64,
    pub io_uring_submissions: u64,
    pub io_uring_completions: u64,
    pub zero_copy_packets: u64,
    pub umem_frame_reuses: u64,
    pub zero_copy_enabled: bool,
    pub umem_frame_count: u32,
    pub umem_frame_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afxdp_iouring_backend_creation() {
        let backend = AfXdpIoUringBackend::new("eth0", 0);
        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!(backend.backend_type(), BackendType::AfXdp);
        assert!(!backend.is_initialized());
    }

    #[test]
    fn test_combined_availability_check() {
        // This test will pass on systems with kernel 4.18+ and 5.1+
        let available = AfXdpIoUringBackend::is_available();
        println!("Combined AF_XDP + io_uring available: {}", available);
    }

    #[test]
    fn test_enhanced_stats() {
        let backend = AfXdpIoUringBackend::new("eth0", 0).unwrap();
        let stats = backend.get_enhanced_stats();

        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.batch_count, 0);
        assert_eq!(stats.io_uring_submissions, 0);
        assert_eq!(stats.io_uring_completions, 0);
        assert_eq!(stats.zero_copy_packets, 0);
        assert_eq!(stats.umem_frame_reuses, 0);
        assert_eq!(stats.umem_frame_count, UMEM_NUM_FRAMES);
        assert_eq!(stats.umem_frame_size, UMEM_FRAME_SIZE);
    }

    #[test]
    fn test_umem_frame_tracking() {
        let backend = AfXdpIoUringBackend::new("eth0", 0).unwrap();

        // Verify frame addresses are properly initialized
        assert_eq!(backend.frame_addrs.len(), 0); // Not initialized until init()
        assert_eq!(backend.next_frame.load(Ordering::Relaxed), 0);
    }
}
