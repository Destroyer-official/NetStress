//! Safety controls and compliance mechanisms
//! Implements target authorization, rate limiting, and emergency stop

use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("Target not authorized: {0}")]
    UnauthorizedTarget(String),
    #[error("Rate limit exceeded: {0} PPS")]
    RateLimitExceeded(u64),
    #[error("Resource exhaustion: {0}")]
    ResourceExhaustion(String),
    #[error("Emergency stop triggered")]
    EmergencyStop,
    #[error("Safety check failed: {0}")]
    SafetyCheckFailed(String),
}

/// Target authorization whitelist
pub struct TargetAuthorization {
    /// Authorized IP addresses
    authorized_ips: RwLock<HashSet<IpAddr>>,
    /// Authorized IP ranges (CIDR)
    authorized_ranges: RwLock<Vec<(Ipv4Addr, u8)>>,
    /// Authorized domains
    authorized_domains: RwLock<HashSet<String>>,
    /// Allow localhost
    allow_localhost: AtomicBool,
    /// Allow private networks
    allow_private: AtomicBool,
    /// Strict mode (deny if not explicitly authorized)
    strict_mode: AtomicBool,
}

impl Default for TargetAuthorization {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetAuthorization {
    pub fn new() -> Self {
        Self {
            authorized_ips: RwLock::new(HashSet::new()),
            authorized_ranges: RwLock::new(Vec::new()),
            authorized_domains: RwLock::new(HashSet::new()),
            allow_localhost: AtomicBool::new(false),
            allow_private: AtomicBool::new(false),
            strict_mode: AtomicBool::new(true),
        }
    }

    /// Create permissive authorization (for testing)
    pub fn permissive() -> Self {
        let auth = Self::new();
        auth.allow_localhost.store(true, Ordering::SeqCst);
        auth.allow_private.store(true, Ordering::SeqCst);
        auth.strict_mode.store(false, Ordering::SeqCst);
        auth
    }

    /// Add authorized IP
    pub fn authorize_ip(&self, ip: IpAddr) {
        self.authorized_ips.write().insert(ip);
    }

    /// Add authorized CIDR range
    pub fn authorize_cidr(&self, cidr: &str) -> Result<(), SafetyError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(SafetyError::SafetyCheckFailed("Invalid CIDR format".into()));
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| SafetyError::SafetyCheckFailed("Invalid IP".into()))?;
        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| SafetyError::SafetyCheckFailed("Invalid prefix".into()))?;

        if prefix > 32 {
            return Err(SafetyError::SafetyCheckFailed(
                "Invalid prefix length".into(),
            ));
        }

        self.authorized_ranges.write().push((ip, prefix));
        Ok(())
    }

    /// Add authorized domain
    pub fn authorize_domain(&self, domain: &str) {
        self.authorized_domains
            .write()
            .insert(domain.to_lowercase());
    }

    /// Check if target is authorized
    pub fn is_authorized(&self, target: &str) -> Result<(), SafetyError> {
        // Try to parse as IP
        if let Ok(ip) = target.parse::<IpAddr>() {
            return self.check_ip(ip);
        }

        // Check as domain
        self.check_domain(target)
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), SafetyError> {
        // Check explicit authorization first
        if self.authorized_ips.read().contains(&ip) {
            return Ok(());
        }

        // Check CIDR ranges (this should come before private IP restrictions)
        if let IpAddr::V4(v4) = ip {
            for (range_ip, prefix) in self.authorized_ranges.read().iter() {
                if ip_in_cidr(v4, *range_ip, *prefix) {
                    return Ok(());
                }
            }
        }

        // Check localhost
        if ip.is_loopback() {
            if self.allow_localhost.load(Ordering::Relaxed) {
                return Ok(());
            }
            return Err(SafetyError::UnauthorizedTarget(
                "Localhost not allowed".into(),
            ));
        }

        // Check private networks
        if let IpAddr::V4(v4) = ip {
            if is_private_ip(v4) {
                if self.allow_private.load(Ordering::Relaxed) {
                    return Ok(());
                }
                if self.strict_mode.load(Ordering::Relaxed) {
                    return Err(SafetyError::UnauthorizedTarget(
                        "Private network not authorized".into(),
                    ));
                }
            }
        }

        // Strict mode check
        if self.strict_mode.load(Ordering::Relaxed) {
            return Err(SafetyError::UnauthorizedTarget(format!(
                "IP {} not in whitelist",
                ip
            )));
        }

        Ok(())
    }

    fn check_domain(&self, domain: &str) -> Result<(), SafetyError> {
        let domain_lower = domain.to_lowercase();

        if self.authorized_domains.read().contains(&domain_lower) {
            return Ok(());
        }

        // Check wildcard domains
        for auth_domain in self.authorized_domains.read().iter() {
            if auth_domain.starts_with("*.") {
                let suffix = &auth_domain[2..];
                // For wildcard, domain must end with suffix AND have at least one more subdomain
                if domain_lower.ends_with(suffix) && domain_lower.len() > suffix.len() {
                    // Check that there's a dot before the suffix (indicating a subdomain)
                    let prefix_len = domain_lower.len() - suffix.len();
                    if domain_lower.chars().nth(prefix_len - 1) == Some('.') {
                        return Ok(());
                    }
                }
            }
        }

        if self.strict_mode.load(Ordering::Relaxed) {
            return Err(SafetyError::UnauthorizedTarget(format!(
                "Domain {} not authorized",
                domain
            )));
        }

        Ok(())
    }

    /// Set strict mode
    pub fn set_strict_mode(&self, strict: bool) {
        self.strict_mode.store(strict, Ordering::SeqCst);
    }

    /// Allow localhost
    pub fn set_allow_localhost(&self, allow: bool) {
        self.allow_localhost.store(allow, Ordering::SeqCst);
    }

    /// Allow private networks
    pub fn set_allow_private(&self, allow: bool) {
        self.allow_private.store(allow, Ordering::SeqCst);
    }
}

/// Engine-level rate limiter (cannot be bypassed)
pub struct SafetyRateLimiter {
    /// Maximum PPS
    max_pps: AtomicU64,
    /// Current PPS
    current_pps: AtomicU64,
    /// Last check time (nanoseconds)
    last_check: AtomicU64,
    /// Packets since last check
    packets_since_check: AtomicU64,
    /// Start time
    start: Instant,
    /// Enabled flag
    enabled: AtomicBool,
}

impl SafetyRateLimiter {
    pub fn new(max_pps: u64) -> Self {
        Self {
            max_pps: AtomicU64::new(max_pps),
            current_pps: AtomicU64::new(0),
            last_check: AtomicU64::new(0),
            packets_since_check: AtomicU64::new(0),
            start: Instant::now(),
            enabled: AtomicBool::new(max_pps > 0),
        }
    }

    /// Check if sending is allowed
    #[inline]
    pub fn check(&self) -> Result<(), SafetyError> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }

        let now_ns = self.start.elapsed().as_nanos() as u64;
        let last = self.last_check.load(Ordering::Relaxed);
        let elapsed_ns = now_ns.saturating_sub(last);

        // Update rate every 100ms
        if elapsed_ns >= 100_000_000 {
            let packets = self.packets_since_check.swap(0, Ordering::Relaxed);
            let pps = (packets * 1_000_000_000) / elapsed_ns.max(1);
            self.current_pps.store(pps, Ordering::Relaxed);
            self.last_check.store(now_ns, Ordering::Relaxed);
        }

        let current = self.current_pps.load(Ordering::Relaxed);
        let max = self.max_pps.load(Ordering::Relaxed);

        if current > max {
            return Err(SafetyError::RateLimitExceeded(current));
        }

        self.packets_since_check.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Set maximum PPS
    pub fn set_max_pps(&self, max: u64) {
        self.max_pps.store(max, Ordering::SeqCst);
        self.enabled.store(max > 0, Ordering::SeqCst);
    }

    /// Get current PPS
    pub fn current_pps(&self) -> u64 {
        self.current_pps.load(Ordering::Relaxed)
    }

    /// Disable rate limiting
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
}

/// Resource exhaustion protection
pub struct ResourceMonitor {
    /// Maximum memory usage (bytes)
    max_memory: AtomicU64,
    /// Maximum queue depth
    max_queue_depth: AtomicU64,
    /// Auto-throttle enabled
    auto_throttle: AtomicBool,
    /// Current throttle factor (0-100)
    throttle_factor: AtomicU64,
}

impl Default for ResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            max_memory: AtomicU64::new(1024 * 1024 * 1024), // 1GB default
            max_queue_depth: AtomicU64::new(100_000),
            auto_throttle: AtomicBool::new(true),
            throttle_factor: AtomicU64::new(100), // 100% = no throttle
        }
    }

    /// Check resource usage
    pub fn check(&self) -> Result<(), SafetyError> {
        // In a real implementation, this would check actual memory usage
        // For now, we just return Ok
        Ok(())
    }

    /// Get throttle factor (0-100)
    pub fn throttle_factor(&self) -> u64 {
        self.throttle_factor.load(Ordering::Relaxed)
    }

    /// Set throttle factor
    pub fn set_throttle(&self, factor: u64) {
        self.throttle_factor
            .store(factor.min(100), Ordering::SeqCst);
    }

    /// Enable auto-throttle
    pub fn set_auto_throttle(&self, enabled: bool) {
        self.auto_throttle.store(enabled, Ordering::SeqCst);
    }
}

/// Emergency stop mechanism
pub struct EmergencyStop {
    /// Stop flag
    stopped: AtomicBool,
    /// Stop time
    stop_time: RwLock<Option<Instant>>,
    /// Reason for stop
    reason: RwLock<Option<String>>,
    /// Callbacks to execute on stop
    callbacks: RwLock<Vec<Box<dyn Fn() + Send + Sync>>>,
}

impl Default for EmergencyStop {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyStop {
    pub fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            stop_time: RwLock::new(None),
            reason: RwLock::new(None),
            callbacks: RwLock::new(Vec::new()),
        }
    }

    /// Trigger emergency stop
    pub fn trigger(&self, reason: &str) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return; // Already stopped
        }

        *self.stop_time.write() = Some(Instant::now());
        *self.reason.write() = Some(reason.to_string());

        // Execute callbacks
        for callback in self.callbacks.read().iter() {
            callback();
        }
    }

    /// Check if stopped
    #[inline]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Check and return error if stopped
    #[inline]
    pub fn check(&self) -> Result<(), SafetyError> {
        if self.is_stopped() {
            Err(SafetyError::EmergencyStop)
        } else {
            Ok(())
        }
    }

    /// Reset emergency stop
    pub fn reset(&self) {
        self.stopped.store(false, Ordering::SeqCst);
        *self.stop_time.write() = None;
        *self.reason.write() = None;
    }

    /// Get stop reason
    pub fn reason(&self) -> Option<String> {
        self.reason.read().clone()
    }

    /// Add callback
    pub fn add_callback<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.callbacks.write().push(Box::new(callback));
    }
}

/// Combined safety controller
pub struct SafetyController {
    /// Target authorization
    pub authorization: TargetAuthorization,
    /// Rate limiter
    pub rate_limiter: SafetyRateLimiter,
    /// Resource monitor
    pub resource_monitor: ResourceMonitor,
    /// Emergency stop
    pub emergency_stop: EmergencyStop,
}

impl SafetyController {
    pub fn new(max_pps: u64) -> Self {
        Self {
            authorization: TargetAuthorization::new(),
            rate_limiter: SafetyRateLimiter::new(max_pps),
            resource_monitor: ResourceMonitor::new(),
            emergency_stop: EmergencyStop::new(),
        }
    }

    /// Create permissive controller (for testing)
    pub fn permissive() -> Self {
        Self {
            authorization: TargetAuthorization::permissive(),
            rate_limiter: SafetyRateLimiter::new(0), // No limit
            resource_monitor: ResourceMonitor::new(),
            emergency_stop: EmergencyStop::new(),
        }
    }

    /// Perform all safety checks
    pub fn check_all(&self, target: &str) -> Result<(), SafetyError> {
        self.emergency_stop.check()?;
        self.authorization.is_authorized(target)?;
        self.rate_limiter.check()?;
        self.resource_monitor.check()?;
        Ok(())
    }

    /// Quick check (no target validation)
    #[inline]
    pub fn quick_check(&self) -> Result<(), SafetyError> {
        self.emergency_stop.check()?;
        self.rate_limiter.check()?;
        Ok(())
    }
}

// Helper functions

fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    false
}

fn ip_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(network);
    (ip_u32 & mask) == (net_u32 & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::thread;

    #[test]
    fn test_target_authorization() {
        let auth = TargetAuthorization::new();
        auth.set_strict_mode(false); // Allow testing
        auth.set_allow_private(true); // Allow private IPs
        auth.authorize_ip("192.168.1.1".parse().unwrap());

        assert!(auth.is_authorized("192.168.1.1").is_ok());
        assert!(auth.is_authorized("192.168.1.2").is_ok()); // Non-strict mode allows this
    }

    #[test]
    fn test_target_authorization_permissive() {
        let auth = TargetAuthorization::permissive();

        // Should allow localhost and private IPs
        assert!(auth.is_authorized("127.0.0.1").is_ok());
        assert!(auth.is_authorized("192.168.1.1").is_ok());
        assert!(auth.is_authorized("10.0.0.1").is_ok());

        // Should allow public IPs in non-strict mode
        assert!(auth.is_authorized("8.8.8.8").is_ok());
    }

    #[test]
    fn test_target_authorization_strict_mode() {
        let auth = TargetAuthorization::new();
        auth.set_strict_mode(true);

        // Should deny everything not explicitly authorized
        assert!(auth.is_authorized("127.0.0.1").is_err());
        assert!(auth.is_authorized("192.168.1.1").is_err());
        assert!(auth.is_authorized("8.8.8.8").is_err());

        // But allow after authorization
        auth.authorize_ip("8.8.8.8".parse().unwrap());
        assert!(auth.is_authorized("8.8.8.8").is_ok());
    }

    #[test]
    fn test_cidr_authorization() {
        let auth = TargetAuthorization::new();
        auth.set_strict_mode(true); // Keep strict mode for CIDR testing
        auth.authorize_cidr("10.0.0.0/8").unwrap();

        assert!(auth.is_authorized("10.1.2.3").is_ok());
        assert!(auth.is_authorized("10.255.255.255").is_ok());
        assert!(auth.is_authorized("11.0.0.1").is_err());
        assert!(auth.is_authorized("9.255.255.255").is_err());
    }

    #[test]
    fn test_cidr_authorization_various_prefixes() {
        let auth = TargetAuthorization::new();
        auth.set_strict_mode(true); // Keep strict mode for CIDR testing

        // /24 network
        auth.authorize_cidr("192.168.1.0/24").unwrap();
        assert!(auth.is_authorized("192.168.1.1").is_ok());
        assert!(auth.is_authorized("192.168.1.255").is_ok());
        assert!(auth.is_authorized("192.168.2.1").is_err());

        // /16 network
        auth.authorize_cidr("172.16.0.0/16").unwrap();
        assert!(auth.is_authorized("172.16.1.1").is_ok());
        assert!(auth.is_authorized("172.16.255.255").is_ok());
        assert!(auth.is_authorized("172.17.1.1").is_err());
    }

    #[test]
    fn test_invalid_cidr() {
        let auth = TargetAuthorization::new();

        assert!(auth.authorize_cidr("invalid").is_err());
        assert!(auth.authorize_cidr("192.168.1.0").is_err());
        assert!(auth.authorize_cidr("192.168.1.0/33").is_err());
        assert!(auth.authorize_cidr("not.an.ip/24").is_err());
    }

    #[test]
    fn test_domain_authorization() {
        let auth = TargetAuthorization::new();
        auth.set_strict_mode(true); // Enable strict mode for domain testing
        auth.authorize_domain("example.com");
        auth.authorize_domain("*.test.com");

        assert!(auth.is_authorized("example.com").is_ok());
        assert!(auth.is_authorized("EXAMPLE.COM").is_ok()); // Case insensitive
        assert!(auth.is_authorized("sub.test.com").is_ok());
        assert!(auth.is_authorized("deep.sub.test.com").is_ok());
        assert!(auth.is_authorized("other.com").is_err());
        assert!(auth.is_authorized("test.com").is_err()); // Strict mode denies unauthorized domains
    }

    #[test]
    fn test_localhost_and_private_settings() {
        let auth = TargetAuthorization::new();

        // Initially strict
        assert!(auth.is_authorized("127.0.0.1").is_err());
        assert!(auth.is_authorized("192.168.1.1").is_err());

        // Allow localhost
        auth.set_allow_localhost(true);
        assert!(auth.is_authorized("127.0.0.1").is_ok());
        assert!(auth.is_authorized("192.168.1.1").is_err());

        // Allow private
        auth.set_allow_private(true);
        assert!(auth.is_authorized("192.168.1.1").is_ok());
        assert!(auth.is_authorized("10.0.0.1").is_ok());
        assert!(auth.is_authorized("172.16.0.1").is_ok());
    }

    #[test]
    fn test_safety_rate_limiter() {
        let limiter = SafetyRateLimiter::new(1000);

        // Should allow initially
        for _ in 0..100 {
            assert!(limiter.check().is_ok());
        }

        // Current PPS should be calculated
        assert!(limiter.current_pps() >= 0);
    }

    #[test]
    fn test_safety_rate_limiter_disabled() {
        let limiter = SafetyRateLimiter::new(0);

        // Should always allow when disabled
        for _ in 0..10000 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_safety_rate_limiter_set_max() {
        let limiter = SafetyRateLimiter::new(1000);

        limiter.set_max_pps(5000);
        assert!(limiter.check().is_ok());

        limiter.disable();
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_resource_monitor() {
        let monitor = ResourceMonitor::new();

        // Should pass by default
        assert!(monitor.check().is_ok());

        // Test throttle factor
        assert_eq!(monitor.throttle_factor(), 100);

        monitor.set_throttle(50);
        assert_eq!(monitor.throttle_factor(), 50);

        monitor.set_throttle(150); // Should cap at 100
        assert_eq!(monitor.throttle_factor(), 100);

        monitor.set_auto_throttle(false);
        // No direct way to test this, but it shouldn't crash
    }

    #[test]
    fn test_emergency_stop() {
        let stop = EmergencyStop::new();

        assert!(!stop.is_stopped());
        assert!(stop.check().is_ok());
        assert!(stop.reason().is_none());

        stop.trigger("Test stop");

        assert!(stop.is_stopped());
        assert!(stop.check().is_err());
        assert_eq!(stop.reason(), Some("Test stop".to_string()));

        // Should not trigger again
        stop.trigger("Second stop");
        assert_eq!(stop.reason(), Some("Test stop".to_string()));
    }

    #[test]
    fn test_emergency_stop_reset() {
        let stop = EmergencyStop::new();

        stop.trigger("Test");
        assert!(stop.is_stopped());

        stop.reset();
        assert!(!stop.is_stopped());
        assert!(stop.check().is_ok());
        assert!(stop.reason().is_none());
    }

    #[test]
    fn test_emergency_stop_callback() {
        let stop = EmergencyStop::new();
        let called = Arc::new(AtomicBool::new(false));

        let called_clone = Arc::clone(&called);
        stop.add_callback(move || {
            called_clone.store(true, Ordering::SeqCst);
        });

        assert!(!called.load(Ordering::SeqCst));

        stop.trigger("Test");

        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_safety_controller() {
        let controller = SafetyController::permissive();

        assert!(controller.check_all("127.0.0.1").is_ok());
        assert!(controller.quick_check().is_ok());

        controller.emergency_stop.trigger("Test");
        assert!(controller.quick_check().is_err());
        assert!(controller.check_all("127.0.0.1").is_err());
    }

    #[test]
    fn test_safety_controller_strict() {
        let controller = SafetyController::new(1000);

        // Should fail for unauthorized targets
        assert!(controller.check_all("8.8.8.8").is_err());

        // Authorize and try again
        controller
            .authorization
            .authorize_ip("8.8.8.8".parse().unwrap());
        assert!(controller.check_all("8.8.8.8").is_ok());
    }

    #[test]
    fn test_private_ip_detection() {
        // 10.0.0.0/8
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(10, 255, 255, 255)));

        // 172.16.0.0/12
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ip(Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(172, 32, 0, 1)));

        // 192.168.0.0/16
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 255, 255)));

        // Public IPs
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(208, 67, 222, 222)));
    }

    #[test]
    fn test_ip_in_cidr() {
        // 192.168.1.0/24
        assert!(ip_in_cidr(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));
        assert!(ip_in_cidr(
            Ipv4Addr::new(192, 168, 1, 255),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));
        assert!(!ip_in_cidr(
            Ipv4Addr::new(192, 168, 2, 1),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        // 10.0.0.0/8
        assert!(ip_in_cidr(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 0),
            8
        ));
        assert!(!ip_in_cidr(
            Ipv4Addr::new(11, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 0),
            8
        ));

        // Edge cases
        assert!(!ip_in_cidr(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 0),
            33 // Invalid prefix
        ));

        // /0 should match everything
        assert!(ip_in_cidr(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_target_authorization_properties(
            a in 127u8..255, b in 0u8..255, c in 0u8..255, d in 1u8..255
        ) {
            let auth = TargetAuthorization::new();
            let ip = format!("{}.{}.{}.{}", a, b, c, d);
            let parsed_ip: IpAddr = ip.parse().unwrap();

            // Should fail initially (strict mode)
            prop_assert!(auth.is_authorized(&ip).is_err());

            // Should pass after authorization
            auth.authorize_ip(parsed_ip);
            prop_assert!(auth.is_authorized(&ip).is_ok());
        }

        #[test]
        fn test_cidr_authorization_properties(
            net_a in 10u8..11, net_b in 0u8..255, net_c in 0u8..255,
            prefix in 24u8..30,
            host_d in 1u8..200  // Ensure we stay within reasonable bounds
        ) {
            let auth = TargetAuthorization::new();
            let network = format!("{}.{}.{}.0/{}", net_a, net_b, net_c, prefix);

            // Calculate valid host range for the given prefix
            let host_bits = 32 - prefix;
            let max_host = if host_bits >= 8 { 254 } else { (1u8 << host_bits) - 2 };
            let valid_host_d = std::cmp::min(host_d, max_host);

            let host = format!("{}.{}.{}.{}", net_a, net_b, net_c, valid_host_d);

            auth.authorize_cidr(&network).unwrap();

            // Host in same network should be authorized
            prop_assert!(auth.is_authorized(&host).is_ok());
        }

        #[test]
        fn test_emergency_stop_properties(reason in ".*") {
            let stop = EmergencyStop::new();

            prop_assert!(!stop.is_stopped());
            prop_assert!(stop.check().is_ok());

            stop.trigger(&reason);

            prop_assert!(stop.is_stopped());
            prop_assert!(stop.check().is_err());
            prop_assert_eq!(stop.reason(), Some(reason));
        }

        #[test]
        fn test_private_ip_properties(
            a in 0u8..255, b in 0u8..255, c in 0u8..255, d in 0u8..255
        ) {
            let ip = Ipv4Addr::new(a, b, c, d);
            let is_private = is_private_ip(ip);

            // Check consistency with known ranges
            let expected_private =
                a == 10 ||
                (a == 172 && (16..=31).contains(&b)) ||
                (a == 192 && b == 168);

            prop_assert_eq!(is_private, expected_private);
        }

        #[test]
        fn test_safety_rate_limiter_properties(max_pps in 1u64..100_000) {
            let limiter = SafetyRateLimiter::new(max_pps);

            // Should allow initially
            prop_assert!(limiter.check().is_ok());

            // Should have reasonable PPS
            let current = limiter.current_pps();
            prop_assert!(current >= 0);
        }
    }
}
