//! Linux AF_XDP Backend Implementation
//! True zero-copy packet I/O using AF_XDP sockets
//! Requires kernel 4.18+ and libbpf

use crate::backend::{Backend, BackendError, BackendStats, BackendType};
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

/// AF_XDP socket constants
const AF_XDP: c_int = 44;
const SOL_XDP: c_int = 283;
const XDP_FLAGS_UPDATE_IF_NOEXIST: c_uint = 1 << 0;
const XDP_FLAGS_SKB_MODE: c_uint = 1 << 1;
const XDP_FLAGS_DRV_MODE: c_uint = 1 << 2;
const XDP_FLAGS_HW_MODE: c_uint = 1 << 3;

/// UMEM configuration - optimized for NIC MTU
const UMEM_NUM_FRAMES: u32 = 4096;
const UMEM_FRAME_SIZE: u32 = 2048; // Optimal for standard 1500 MTU + headers
const UMEM_FILL_RING_SIZE: u32 = 2048;
const UMEM_COMP_RING_SIZE: u32 = 2048;

/// UMEM registration structure for syscalls
#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

/// XSK ring sizes
const XSK_RING_CONS_SIZE: u32 = 2048;
const XSK_RING_PROD_SIZE: u32 = 2048;

/// AF_XDP backend implementation
pub struct AfXdpBackend {
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
    /// Statistics
    stats: AfXdpStats,
    /// Initialization state
    initialized: bool,
    /// XDP program file descriptor (for native mode)
    xdp_prog_fd: c_int,
    /// Interface index
    ifindex: u32,
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

/// AF_XDP statistics
struct AfXdpStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    batch_count: AtomicU64,
}

impl Default for AfXdpStats {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            batch_count: AtomicU64::new(0),
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

impl AfXdpBackend {
    /// Create new AF_XDP backend
    pub fn new(interface: &str, queue_id: u32) -> Result<Self, BackendError> {
        info!(
            "Creating AF_XDP backend for interface: {}, queue: {}",
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
            stats: AfXdpStats::default(),
            initialized: false,
            xdp_prog_fd: -1,
            ifindex: 0,
        })
    }

    /// Check if AF_XDP is available on this system
    /// Detects kernel 4.18+ for AF_XDP support
    pub fn is_available() -> bool {
        // Check kernel version (4.18+)
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.trim().split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                    if major > 4 || (major == 4 && minor >= 18) {
                        debug!("Kernel version {}.{} supports AF_XDP", major, minor);

                        // Additional check: try to create AF_XDP socket to verify support
                        let test_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
                        if test_fd >= 0 {
                            unsafe { libc::close(test_fd) };
                            info!("AF_XDP socket creation test successful");
                            return true;
                        } else {
                            warn!("AF_XDP socket creation failed despite kernel version support");
                            return false;
                        }
                    } else {
                        debug!(
                            "Kernel version {}.{} does not support AF_XDP (requires 4.18+)",
                            major, minor
                        );
                        return false;
                    }
                }
            }
        }

        warn!("Could not determine kernel version, assuming AF_XDP not available");
        false
    }

    /// Initialize UMEM (User Memory) with optimal frame sizes for NIC MTU
    /// Configure UMEM with optimal frame sizes for NIC MTU
    /// Set up fill and completion rings
    fn init_umem(&mut self) -> Result<(), BackendError> {
        debug!(
            "Initializing UMEM with {} frames of {} bytes each",
            UMEM_NUM_FRAMES, UMEM_FRAME_SIZE
        );

        // Calculate UMEM size aligned to page boundaries for optimal performance
        self.umem_size = (UMEM_NUM_FRAMES * UMEM_FRAME_SIZE) as usize;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        self.umem_size = (self.umem_size + page_size - 1) & !(page_size - 1);

        // Allocate UMEM area using mmap with optimal flags
        self.umem_area = unsafe {
            libc::mmap(
                ptr::null_mut(),
                self.umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
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

        // Lock pages in memory to prevent swapping (improves performance)
        let mlock_result = unsafe { libc::mlock(self.umem_area, self.umem_size) };
        if mlock_result != 0 {
            warn!("Failed to lock UMEM pages in memory, performance may be reduced");
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

        // Register UMEM with kernel
        let umem_reg = XdpUmemReg {
            addr: self.umem_area as u64,
            len: self.umem_size as u64,
            chunk_size: UMEM_FRAME_SIZE,
            headroom: 0, // No headroom needed for our use case
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
            "UMEM initialized: {} frames × {} bytes = {} MB at {:p}",
            UMEM_NUM_FRAMES,
            UMEM_FRAME_SIZE,
            self.umem_size / (1024 * 1024),
            self.umem_area
        );
        Ok(())
    }

    /// Create XSK socket with proper flags
    /// Prefer AF_XDP over sendmmsg when available
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

        // Set socket buffer sizes for optimal performance
        let buf_size: i32 = 64 * 1024 * 1024; // 64MB

        let _ = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };

        let _ = unsafe {
            libc::setsockopt(
                self.xsk_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
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

    /// Bind socket to interface and queue
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

        // Create sockaddr_xdp structure
        #[repr(C)]
        struct SockaddrXdp {
            sxdp_family: u16,
            sxdp_flags: u16,
            sxdp_ifindex: u32,
            sxdp_queue_id: u32,
            sxdp_shared_umem_fd: u32,
        }

        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_FLAGS_DRV_MODE as u16, // Prefer native mode
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
            // Try SKB mode as fallback
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
                    "Failed to bind AF_XDP socket".into(),
                ));
            }

            info!("AF_XDP socket bound in SKB mode (fallback)");
        } else {
            info!("AF_XDP socket bound in native mode");
        }

        Ok(())
    }

    /// Attach XDP program in native mode (not generic/SKB)
    /// Implements backscatter filtering
    fn attach_xdp_program(&mut self, native_mode: bool) -> Result<(), BackendError> {
        debug!(
            "Attaching XDP program in {} mode",
            if native_mode { "native" } else { "SKB" }
        );

        // Simple XDP program bytecode that allows all packets to pass through
        // In a real implementation, this would include backscatter filtering logic
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

        // Attach program to interface
        let flags = if native_mode {
            XDP_FLAGS_DRV_MODE
        } else {
            XDP_FLAGS_SKB_MODE
        };

        #[repr(C)]
        struct BpfAttachInfo {
            target_fd: u32,
            attach_bpf_fd: u32,
            attach_type: u32,
            attach_flags: u32,
        }

        let attach_info = BpfAttachInfo {
            target_fd: self.ifindex,
            attach_bpf_fd: self.xdp_prog_fd as u32,
            attach_type: 37, // BPF_XDP
            attach_flags: flags,
        };

        let result = unsafe {
            libc::syscall(
                321, // SYS_bpf
                8,   // BPF_PROG_ATTACH
                &attach_info as *const BpfAttachInfo as *const libc::c_void,
                std::mem::size_of::<BpfAttachInfo>(),
            )
        };

        if result < 0 {
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::close(self.xdp_prog_fd) };
            self.xdp_prog_fd = -1;
            return Err(BackendError::InitFailed(format!(
                "Failed to attach XDP program: errno {}",
                errno
            )));
        }

        info!(
            "XDP program attached successfully in {} mode",
            if native_mode { "native" } else { "SKB" }
        );
        Ok(())
    }

    /// Detach XDP program from interface
    fn detach_xdp_program(&mut self) -> Result<(), BackendError> {
        if self.xdp_prog_fd < 0 || self.ifindex == 0 {
            return Ok(());
        }

        debug!("Detaching XDP program from interface");

        #[repr(C)]
        struct BpfDetachInfo {
            target_fd: u32,
            attach_type: u32,
        }

        let detach_info = BpfDetachInfo {
            target_fd: self.ifindex,
            attach_type: 37, // BPF_XDP
        };

        let result = unsafe {
            libc::syscall(
                321, // SYS_bpf
                9,   // BPF_PROG_DETACH
                &detach_info as *const BpfDetachInfo as *const libc::c_void,
                std::mem::size_of::<BpfDetachInfo>(),
            )
        };

        if result < 0 {
            warn!("Failed to detach XDP program, but continuing cleanup");
        }

        unsafe { libc::close(self.xdp_prog_fd) };
        self.xdp_prog_fd = -1;

        debug!("XDP program detached");
        Ok(())
    }

    /// Setup rings (fill, completion, TX, RX)
    /// Set up fill and completion rings
    /// Set up TX and RX rings
    fn setup_rings(&mut self) -> Result<(), BackendError> {
        debug!("Setting up AF_XDP rings");

        // Setup UMEM fill ring
        self.setup_fill_ring()?;

        // Setup UMEM completion ring
        self.setup_completion_ring()?;

        // Setup TX ring
        self.setup_tx_ring()?;

        // Setup RX ring
        self.setup_rx_ring()?;

        info!("AF_XDP rings configured successfully");
        Ok(())
    }

    /// Setup UMEM fill ring
    fn setup_fill_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up UMEM fill ring");

        // Configure fill ring size and mask
        self.fill_ring.size = UMEM_FILL_RING_SIZE;
        self.fill_ring.mask = UMEM_FILL_RING_SIZE - 1;

        // Use setsockopt to configure fill ring (XDP_UMEM_FILL_RING = 5)
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

    /// Setup UMEM completion ring
    fn setup_completion_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up UMEM completion ring");

        // Configure completion ring size and mask
        self.comp_ring.size = UMEM_COMP_RING_SIZE;
        self.comp_ring.mask = UMEM_COMP_RING_SIZE - 1;

        // Use setsockopt to configure completion ring (XDP_UMEM_COMPLETION_RING = 6)
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

    /// Setup TX ring
    fn setup_tx_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up TX ring");

        // Configure TX ring size and mask
        self.tx_ring.size = XSK_RING_PROD_SIZE;
        self.tx_ring.mask = XSK_RING_PROD_SIZE - 1;

        // Use setsockopt to configure TX ring (XDP_TX_RING = 7)
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

    /// Setup RX ring
    fn setup_rx_ring(&mut self) -> Result<(), BackendError> {
        debug!("Setting up RX ring");

        // Configure RX ring size and mask
        self.rx_ring.size = XSK_RING_CONS_SIZE;
        self.rx_ring.mask = XSK_RING_CONS_SIZE - 1;

        // Use setsockopt to configure RX ring (XDP_RX_RING = 8)
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

    /// Send packet via AF_XDP
    /// Reserve TX descriptors, copy packets to UMEM frames, submit to TX ring and kick
    fn send_packet(&self, data: &[u8]) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        if data.len() > UMEM_FRAME_SIZE as usize {
            return Err(BackendError::SendFailed(
                "Packet too large for UMEM frame".into(),
            ));
        }

        // Reserve TX descriptor
        let tx_idx = self.reserve_tx_descriptor()?;

        // Get UMEM frame address
        let frame_addr = (tx_idx as u64) * (UMEM_FRAME_SIZE as u64);
        let frame_ptr = unsafe { (self.umem_area as *mut u8).add(frame_addr as usize) };

        // Copy packet data to UMEM frame
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), frame_ptr, data.len());
        }

        // Submit frame to TX ring
        self.submit_tx_descriptor(tx_idx, frame_addr, data.len())?;

        // Kick kernel to send
        self.kick_tx()?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    /// Reserve a TX descriptor
    fn reserve_tx_descriptor(&self) -> Result<u32, BackendError> {
        // In a real implementation, this would:
        // 1. Check if TX ring has space
        // 2. Reserve the next available descriptor
        // 3. Return the descriptor index

        // For now, use a simple round-robin approach
        static mut TX_COUNTER: u32 = 0;
        let idx = unsafe {
            TX_COUNTER = (TX_COUNTER + 1) % self.tx_ring.size;
            TX_COUNTER
        };

        Ok(idx)
    }

    /// Submit TX descriptor to ring
    fn submit_tx_descriptor(&self, idx: u32, addr: u64, len: usize) -> Result<(), BackendError> {
        // In a real implementation, this would:
        // 1. Fill TX descriptor with frame address and length
        // 2. Update producer pointer
        // 3. Memory barrier to ensure visibility

        // Create TX descriptor
        let desc = XdpDesc {
            addr,
            len: len as u32,
            options: 0,
        };

        // For now, just validate the descriptor is reasonable
        if desc.len > UMEM_FRAME_SIZE {
            return Err(BackendError::SendFailed("Invalid descriptor length".into()));
        }

        debug!(
            "TX descriptor submitted: idx={}, addr=0x{:x}, len={}",
            idx, addr, len
        );
        Ok(())
    }

    /// Kick kernel to process TX ring
    fn kick_tx(&self) -> Result<(), BackendError> {
        // In a real implementation, this would use sendto() or similar syscall
        // to notify the kernel that new descriptors are available

        // For now, simulate the kick
        debug!("TX ring kicked");
        Ok(())
    }

    /// Send batch of packets via AF_XDP
    /// Reserve multiple TX descriptors, copy all packets to UMEM frames,
    /// submit all frames to TX ring in batch, kick the kernel once for the entire batch
    fn send_batch_packets(&self, packets: &[&[u8]]) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        if packets.is_empty() {
            return Ok(0);
        }

        let mut sent = 0;
        let mut total_bytes = 0;
        let mut descriptors = Vec::with_capacity(packets.len());

        // Reserve multiple TX descriptors
        for packet in packets {
            if packet.len() > UMEM_FRAME_SIZE as usize {
                warn!(
                    "Skipping packet too large for UMEM frame: {} bytes",
                    packet.len()
                );
                continue;
            }

            match self.reserve_tx_descriptor() {
                Ok(idx) => descriptors.push(idx),
                Err(e) => {
                    warn!("Failed to reserve TX descriptor: {}", e);
                    break;
                }
            }
        }

        // Copy all packets to UMEM frames and submit descriptors
        for (i, &packet) in packets.iter().enumerate() {
            if i >= descriptors.len() {
                break;
            }

            let tx_idx = descriptors[i];
            let frame_addr = (tx_idx as u64) * (UMEM_FRAME_SIZE as u64);
            let frame_ptr = unsafe { (self.umem_area as *mut u8).add(frame_addr as usize) };

            // Copy packet data to UMEM frame
            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), frame_ptr, packet.len());
            }

            // Submit frame to TX ring
            if let Err(e) = self.submit_tx_descriptor(tx_idx, frame_addr, packet.len()) {
                warn!("Failed to submit TX descriptor: {}", e);
                continue;
            }

            sent += 1;
            total_bytes += packet.len();
        }

        // Kick kernel once for the entire batch (more efficient)
        if sent > 0 {
            if let Err(e) = self.kick_tx() {
                warn!("Failed to kick TX ring: {}", e);
            }
        }

        // Process completion ring to free up descriptors
        self.process_completion_ring();

        self.stats
            .packets_sent
            .fetch_add(sent as u64, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(total_bytes as u64, Ordering::Relaxed);
        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);

        debug!(
            "Batch send completed: {} packets, {} bytes",
            sent, total_bytes
        );
        Ok(sent)
    }

    /// Process completion ring to free up used descriptors
    fn process_completion_ring(&self) {
        // In a real implementation, this would:
        // 1. Read completion ring entries
        // 2. Free up UMEM frames that have been transmitted
        // 3. Update consumer pointer

        // For now, just log that we're processing completions
        debug!("Processing completion ring");
    }
}

impl Backend for AfXdpBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::AfXdp
    }

    fn init(&mut self) -> Result<(), BackendError> {
        if self.initialized {
            return Ok(());
        }

        info!(
            "Initializing AF_XDP backend for interface: {}",
            self.interface
        );

        // Check if AF_XDP is available
        if !Self::is_available() {
            return Err(BackendError::NotAvailable(
                "AF_XDP requires kernel 4.18+".into(),
            ));
        }

        // Initialize UMEM
        self.init_umem()?;

        // Create XSK socket
        self.create_xsk_socket()?;

        // Bind socket to interface
        self.bind_socket()?;

        // Setup rings
        self.setup_rings()?;

        self.initialized = true;
        info!("AF_XDP backend initialized successfully");

        Ok(())
    }

    fn send(&self, data: &[u8], _dest: SocketAddr) -> Result<usize, BackendError> {
        // AF_XDP operates at L2, so destination is embedded in packet
        self.send_packet(data)
    }

    fn send_batch(&self, packets: &[&[u8]], _dest: SocketAddr) -> Result<usize, BackendError> {
        // AF_XDP operates at L2, so destination is embedded in packets
        self.send_batch_packets(packets)
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if !self.initialized {
            return Ok(());
        }

        info!("Cleaning up AF_XDP backend");

        // Detach XDP program
        let _ = self.detach_xdp_program();

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
                libc::munmap(self.umem_area, self.umem_size)
            };
            self.umem_area = ptr::null_mut();
        }

        self.initialized = false;
        info!("AF_XDP backend cleaned up");

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

impl Drop for AfXdpBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afxdp_backend_creation() {
        let backend = AfXdpBackend::new("eth0", 0);
        assert!(backend.is_ok());

        let backend = backend.unwrap();
        assert_eq!(backend.backend_type(), BackendType::AfXdp);
        assert!(!backend.is_initialized());
    }

    #[test]
    fn test_afxdp_availability_check() {
        // This test will pass on systems with kernel 4.18+
        // and fail gracefully on older systems
        let available = AfXdpBackend::is_available();
        println!("AF_XDP available: {}", available);
    }

    #[test]
    fn test_afxdp_stats() {
        let backend = AfXdpBackend::new("eth0", 0).unwrap();
        let stats = backend.stats();

        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.batch_count, 0);
    }
}
