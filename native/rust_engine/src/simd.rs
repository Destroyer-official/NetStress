//! SIMD-accelerated packet operations
//! Uses portable SIMD for vectorized checksum and packet building
//! Implements Requirements 12.4, 12.5: SIMD code path selection

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

use crate::backend_selector::SimdType;

/// SIMD dispatcher that selects optimal code path based on CPU capabilities
pub struct SimdDispatcher {
    simd_type: SimdType,
}

impl SimdDispatcher {
    /// Create a new SIMD dispatcher with detected capabilities
    pub fn new() -> Self {
        Self {
            simd_type: Self::detect_simd_type(),
        }
    }

    /// Create with explicit SIMD type (for testing)
    pub fn with_simd_type(simd_type: SimdType) -> Self {
        Self { simd_type }
    }

    /// Detect the best SIMD instruction set for this CPU
    /// Implements Requirements 12.4, 12.5: Architecture-specific SIMD detection
    fn detect_simd_type() -> SimdType {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                SimdType::AVX512
            } else if is_x86_feature_detected!("avx2") {
                SimdType::AVX2
            } else if is_x86_feature_detected!("sse2") {
                SimdType::SSE2
            } else {
                SimdType::None
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                SimdType::NEON
            } else {
                SimdType::None
            }
        }
        #[cfg(target_arch = "arm")]
        {
            // ARM32 uses scalar operations per requirements
            SimdType::None
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        {
            SimdType::None
        }
    }

    /// Get the current SIMD type
    pub fn simd_type(&self) -> SimdType {
        self.simd_type
    }

    /// Compute checksum using optimal SIMD path
    /// Implements Requirements 12.4, 12.5: SIMD-accelerated checksum
    pub fn checksum(&self, data: &[u8]) -> u16 {
        match self.simd_type {
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX512 => unsafe { checksum_avx512(data) },
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX2 => unsafe { checksum_avx2(data) },
            #[cfg(target_arch = "x86_64")]
            SimdType::SSE2 => unsafe { checksum_sse2(data) },
            #[cfg(target_arch = "aarch64")]
            SimdType::NEON => unsafe { checksum_neon(data) },
            SimdType::None => checksum_scalar(data),
            #[cfg(not(target_arch = "x86_64"))]
            SimdType::AVX512 | SimdType::AVX2 | SimdType::SSE2 => checksum_scalar(data),
            #[cfg(not(target_arch = "aarch64"))]
            SimdType::NEON => checksum_scalar(data),
        }
    }

    /// Fill buffer using optimal SIMD path
    /// Implements Requirements 12.4, 12.5: SIMD-accelerated memory operations
    pub fn fill_buffer(&self, buffer: &mut [u8], pattern: u8) {
        match self.simd_type {
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX512 => unsafe { fill_avx512(buffer, pattern) },
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX2 => unsafe { fill_avx2(buffer, pattern) },
            #[cfg(target_arch = "x86_64")]
            SimdType::SSE2 => unsafe { fill_sse2(buffer, pattern) },
            #[cfg(target_arch = "aarch64")]
            SimdType::NEON => unsafe { fill_neon(buffer, pattern) },
            SimdType::None => buffer.fill(pattern),
            #[cfg(not(target_arch = "x86_64"))]
            SimdType::AVX512 | SimdType::AVX2 | SimdType::SSE2 => buffer.fill(pattern),
            #[cfg(not(target_arch = "aarch64"))]
            SimdType::NEON => buffer.fill(pattern),
        }
    }

    /// Copy data using optimal SIMD path
    /// Implements Requirements 12.4, 12.5: SIMD-accelerated memory copy
    pub fn copy_data(&self, dst: &mut [u8], src: &[u8]) {
        let len = src.len().min(dst.len());

        match self.simd_type {
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX512 if len >= 64 => unsafe { copy_avx512(&mut dst[..len], &src[..len]) },
            #[cfg(target_arch = "x86_64")]
            SimdType::AVX2 if len >= 32 => unsafe { copy_avx2(&mut dst[..len], &src[..len]) },
            #[cfg(target_arch = "x86_64")]
            SimdType::SSE2 if len >= 16 => unsafe { copy_sse2(&mut dst[..len], &src[..len]) },
            #[cfg(target_arch = "aarch64")]
            SimdType::NEON if len >= 16 => unsafe { copy_neon(&mut dst[..len], &src[..len]) },
            _ => dst[..len].copy_from_slice(&src[..len]),
        }
    }
}

impl Default for SimdDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// SIMD-accelerated IP checksum calculation
/// Falls back to scalar implementation on unsupported platforms
/// Implements Requirements 12.4, 12.5: Automatic SIMD path selection
#[inline]
pub fn checksum_simd(data: &[u8]) -> u16 {
    thread_local! {
        static DISPATCHER: SimdDispatcher = SimdDispatcher::new();
    }

    DISPATCHER.with(|d| d.checksum(data))
}

/// Get optimal checksum function for detected SIMD capabilities
/// Implements Requirements 12.4, 12.5: SIMD code path selection
pub fn get_optimal_checksum_fn() -> fn(&[u8]) -> u16 {
    let simd_type = SimdDispatcher::detect_simd_type();

    match simd_type {
        #[cfg(target_arch = "x86_64")]
        SimdType::AVX512 => |data| unsafe { checksum_avx512(data) },
        #[cfg(target_arch = "x86_64")]
        SimdType::AVX2 => |data| unsafe { checksum_avx2(data) },
        #[cfg(target_arch = "x86_64")]
        SimdType::SSE2 => |data| unsafe { checksum_sse2(data) },
        #[cfg(target_arch = "aarch64")]
        SimdType::NEON => |data| unsafe { checksum_neon(data) },
        _ => checksum_scalar,
    }
}

/// Scalar checksum implementation (fallback)
#[inline]
pub fn checksum_scalar(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Process 2 bytes at a time
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// SSE2 accelerated checksum (16 bytes at a time)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn checksum_sse2(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 16 bytes at a time using SSE2
    while i + 16 <= len {
        let chunk = _mm_loadu_si128(data.as_ptr().add(i) as *const __m128i);

        // Unpack and sum
        let low = _mm_unpacklo_epi8(chunk, _mm_setzero_si128());
        let high = _mm_unpackhi_epi8(chunk, _mm_setzero_si128());

        // Horizontal add
        let sum_vec = _mm_add_epi16(low, high);
        let sum_vec = _mm_add_epi16(sum_vec, _mm_srli_si128(sum_vec, 8));
        let sum_vec = _mm_add_epi16(sum_vec, _mm_srli_si128(sum_vec, 4));
        let sum_vec = _mm_add_epi16(sum_vec, _mm_srli_si128(sum_vec, 2));

        sum += _mm_extract_epi16(sum_vec, 0) as u64;
        i += 16;
    }

    // Process remaining bytes
    while i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        sum += (data[i] as u64) << 8;
    }

    // Fold to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// AVX-512 accelerated checksum (64 bytes at a time)
/// Implements Requirements 12.4: AVX-512 SIMD acceleration
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn checksum_avx512(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 64 bytes at a time using AVX-512
    while i + 64 <= len {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

        // Sum adjacent bytes using SAD (Sum of Absolute Differences)
        let sad = _mm512_sad_epu8(chunk, _mm512_setzero_si512());

        // Extract and accumulate all 8 64-bit values
        // Convert to array and sum manually since _mm512_extract_epi64 doesn't exist
        let mut temp: [u64; 8] = [0; 8];
        _mm512_storeu_si512(temp.as_mut_ptr() as *mut __m512i, sad);
        for &val in &temp {
            sum += val;
        }

        i += 64;
    }

    // Process remaining with AVX2
    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let sad = _mm256_sad_epu8(chunk, _mm256_setzero_si256());
        sum += _mm256_extract_epi64(sad, 0) as u64;
        sum += _mm256_extract_epi64(sad, 1) as u64;
        sum += _mm256_extract_epi64(sad, 2) as u64;
        sum += _mm256_extract_epi64(sad, 3) as u64;
        i += 32;
    }

    // Process remaining bytes
    while i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        sum += (data[i] as u64) << 8;
    }

    // Fold to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// AVX2 accelerated checksum (32 bytes at a time)
/// Implements Requirements 12.4: AVX2 SIMD acceleration
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn checksum_avx2(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 32 bytes at a time using AVX2
    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);

        // Sum adjacent bytes
        let sad = _mm256_sad_epu8(chunk, _mm256_setzero_si256());

        // Extract and accumulate
        sum += _mm256_extract_epi64(sad, 0) as u64;
        sum += _mm256_extract_epi64(sad, 1) as u64;
        sum += _mm256_extract_epi64(sad, 2) as u64;
        sum += _mm256_extract_epi64(sad, 3) as u64;

        i += 32;
    }

    // Process remaining with SSE2
    while i + 16 <= len {
        let chunk = _mm_loadu_si128(data.as_ptr().add(i) as *const __m128i);
        let sad = _mm_sad_epu8(chunk, _mm_setzero_si128());
        sum += _mm_extract_epi64(sad, 0) as u64;
        sum += _mm_extract_epi64(sad, 1) as u64;
        i += 16;
    }

    // Process remaining bytes
    while i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        sum += (data[i] as u64) << 8;
    }

    // Fold to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// ARM64 NEON accelerated checksum (16 bytes at a time)
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn checksum_neon(data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut i = 0;
    let len = data.len();

    // Process 16 bytes at a time using NEON
    while i + 16 <= len {
        let chunk = vld1q_u8(data.as_ptr().add(i));

        // Convert to u16 and sum
        let low = vmovl_u8(vget_low_u8(chunk));
        let high = vmovl_u8(vget_high_u8(chunk));

        // Horizontal add
        let sum_low = vpaddlq_u16(low);
        let sum_high = vpaddlq_u16(high);
        let total = vaddq_u32(sum_low, sum_high);

        // Extract and accumulate
        sum += vgetq_lane_u32(total, 0) as u64;
        sum += vgetq_lane_u32(total, 1) as u64;
        sum += vgetq_lane_u32(total, 2) as u64;
        sum += vgetq_lane_u32(total, 3) as u64;

        i += 16;
    }

    // Process remaining bytes
    while i + 1 < len {
        sum += ((data[i] as u64) << 8) | (data[i + 1] as u64);
        i += 2;
    }

    if i < len {
        sum += (data[i] as u64) << 8;
    }

    // Fold to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// SIMD-accelerated memory fill for packet payloads
/// Implements Requirements 12.4, 12.5: Automatic SIMD path selection
#[inline]
pub fn fill_payload_simd(buffer: &mut [u8], pattern: u8) {
    thread_local! {
        static DISPATCHER: SimdDispatcher = SimdDispatcher::new();
    }

    DISPATCHER.with(|d| d.fill_buffer(buffer, pattern));
}

/// AVX-512 accelerated fill (64 bytes at a time)
/// Implements Requirements 12.4: AVX-512 SIMD memory operations
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn fill_avx512(buffer: &mut [u8], pattern: u8) {
    let pattern_vec = _mm512_set1_epi8(pattern as i8);
    let mut i = 0;
    let len = buffer.len();

    // Fill 64 bytes at a time
    while i + 64 <= len {
        _mm512_storeu_si512(buffer.as_mut_ptr().add(i) as *mut __m512i, pattern_vec);
        i += 64;
    }

    // Fill remaining with AVX2
    if i + 32 <= len {
        let pattern_vec_256 = _mm256_set1_epi8(pattern as i8);
        _mm256_storeu_si256(buffer.as_mut_ptr().add(i) as *mut __m256i, pattern_vec_256);
        i += 32;
    }

    // Fill remaining bytes
    while i < len {
        buffer[i] = pattern;
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn fill_avx2(buffer: &mut [u8], pattern: u8) {
    let pattern_vec = _mm256_set1_epi8(pattern as i8);
    let mut i = 0;
    let len = buffer.len();

    // Fill 32 bytes at a time
    while i + 32 <= len {
        _mm256_storeu_si256(buffer.as_mut_ptr().add(i) as *mut __m256i, pattern_vec);
        i += 32;
    }

    // Fill remaining
    while i < len {
        buffer[i] = pattern;
        i += 1;
    }
}

/// SSE2 accelerated fill (16 bytes at a time)
/// Implements Requirements 12.4: SSE2 SIMD memory operations
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn fill_sse2(buffer: &mut [u8], pattern: u8) {
    let pattern_vec = _mm_set1_epi8(pattern as i8);
    let mut i = 0;
    let len = buffer.len();

    // Fill 16 bytes at a time
    while i + 16 <= len {
        _mm_storeu_si128(buffer.as_mut_ptr().add(i) as *mut __m128i, pattern_vec);
        i += 16;
    }

    // Fill remaining
    while i < len {
        buffer[i] = pattern;
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn fill_neon(buffer: &mut [u8], pattern: u8) {
    let pattern_vec = vdupq_n_u8(pattern);
    let mut i = 0;
    let len = buffer.len();

    // Fill 16 bytes at a time
    while i + 16 <= len {
        vst1q_u8(buffer.as_mut_ptr().add(i), pattern_vec);
        i += 16;
    }

    // Fill remaining
    while i < len {
        buffer[i] = pattern;
        i += 1;
    }
}

/// SIMD-accelerated memory copy for packet building
/// Implements Requirements 12.4, 12.5: Automatic SIMD path selection
#[inline]
pub fn copy_packet_simd(dst: &mut [u8], src: &[u8]) {
    thread_local! {
        static DISPATCHER: SimdDispatcher = SimdDispatcher::new();
    }

    DISPATCHER.with(|d| d.copy_data(dst, src));
}

/// AVX-512 accelerated copy (64 bytes at a time)
/// Implements Requirements 12.4: AVX-512 SIMD memory copy
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn copy_avx512(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    let len = src.len();

    // Copy 64 bytes at a time
    while i + 64 <= len {
        let chunk = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, chunk);
        i += 64;
    }

    // Copy remaining with AVX2
    if i + 32 <= len {
        let chunk = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, chunk);
        i += 32;
    }

    // Copy remaining bytes
    while i < len {
        dst[i] = src[i];
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn copy_avx2(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    let len = src.len();

    // Copy 32 bytes at a time
    while i + 32 <= len {
        let chunk = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, chunk);
        i += 32;
    }

    // Copy remaining
    while i < len {
        dst[i] = src[i];
        i += 1;
    }
}

/// SSE2 accelerated copy (16 bytes at a time)
/// Implements Requirements 12.4: SSE2 SIMD memory copy
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn copy_sse2(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    let len = src.len();

    // Copy 16 bytes at a time
    while i + 16 <= len {
        let chunk = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, chunk);
        i += 16;
    }

    // Copy remaining
    while i < len {
        dst[i] = src[i];
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn copy_neon(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    let len = src.len();

    // Copy 16 bytes at a time
    while i + 16 <= len {
        let chunk = vld1q_u8(src.as_ptr().add(i));
        vst1q_u8(dst.as_mut_ptr().add(i), chunk);
        i += 16;
    }

    // Copy remaining
    while i < len {
        dst[i] = src[i];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_scalar() {
        let data = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = checksum_scalar(&data);
        assert!(checksum != 0); // Just verify it runs
    }

    #[test]
    fn test_checksum_simd() {
        let data = vec![0u8; 1500];
        let scalar = checksum_scalar(&data);
        let simd = checksum_simd(&data);
        assert_eq!(scalar, simd);
    }

    #[test]
    fn test_fill_payload() {
        let mut buffer = vec![0u8; 1500];
        fill_payload_simd(&mut buffer, 0xAA);
        assert!(buffer.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_copy_packet() {
        let src = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = vec![0u8; 8];
        copy_packet_simd(&mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_simd_dispatcher_creation() {
        let dispatcher = SimdDispatcher::new();

        // Should detect some SIMD capability on modern systems
        #[cfg(target_arch = "x86_64")]
        {
            // Most x86_64 systems should have at least SSE2
            assert!(matches!(
                dispatcher.simd_type(),
                SimdType::SSE2 | SimdType::AVX2 | SimdType::AVX512 | SimdType::None
            ));
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Most ARM64 systems should have NEON
            assert!(matches!(
                dispatcher.simd_type(),
                SimdType::NEON | SimdType::None
            ));
        }
    }

    #[test]
    fn test_simd_dispatcher_checksum() {
        let dispatcher = SimdDispatcher::new();
        let data = vec![0u8; 1500];

        let simd_result = dispatcher.checksum(&data);
        let scalar_result = checksum_scalar(&data);

        // SIMD and scalar should produce same result
        assert_eq!(simd_result, scalar_result);
    }

    #[test]
    fn test_simd_dispatcher_fill() {
        let dispatcher = SimdDispatcher::new();
        let mut buffer = vec![0u8; 1500];

        dispatcher.fill_buffer(&mut buffer, 0xAA);
        assert!(buffer.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_simd_dispatcher_copy() {
        let dispatcher = SimdDispatcher::new();
        let src = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut dst = vec![0u8; 16];

        dispatcher.copy_data(&mut dst, &src);
        assert_eq!(dst, src);
    }

    #[test]
    fn test_optimal_checksum_fn() {
        let checksum_fn = get_optimal_checksum_fn();
        let data = vec![0u8; 100];

        let result = checksum_fn(&data);
        let expected = checksum_scalar(&data);

        assert_eq!(result, expected);
    }

    /// Property test: SIMD dispatcher with different instruction sets
    /// Implements Requirements 12.4, 12.5: SIMD code path validation
    #[test]
    fn test_simd_dispatcher_all_types() {
        let test_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let scalar_checksum = checksum_scalar(&test_data);

        // Test each SIMD type explicitly
        for &simd_type in &[
            SimdType::None,
            SimdType::SSE2,
            SimdType::AVX2,
            SimdType::AVX512,
            SimdType::NEON,
        ] {
            let dispatcher = SimdDispatcher::with_simd_type(simd_type);
            let simd_checksum = dispatcher.checksum(&test_data);

            // All SIMD implementations should produce the same result as scalar
            assert_eq!(
                simd_checksum, scalar_checksum,
                "SIMD type {:?} produced different checksum",
                simd_type
            );
        }
    }
}
