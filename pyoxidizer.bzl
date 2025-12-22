# PyOxidizer Configuration for NetStress Titanium v3.0 - Static Binary Deployment
# Single standalone binary with embedded Python + Rust engine
# **Validates: Requirements 10.3** - Embed Python interpreter, include all modules, include Rust extension
#
# Build commands:
#   pyoxidizer build --release
#   pyoxidizer build install --release
#
# Output: dist/netstress.exe (Windows) or dist/netstress (Linux/macOS)

def make_exe():
    # Use standalone static distribution for zero dependencies
    dist = default_python_distribution(
        flavor = "standalone_static",
        python_version = "3.11",
    )

    # Create Python interpreter configuration
    policy = dist.make_python_interpreter_config()
    
    # Configure entry point - runs ddos.py main() on startup
    policy.run_command = """
import sys
import os

# Set up environment for embedded execution
os.environ['NETSTRESS_EMBEDDED'] = '1'
os.environ['NETSTRESS_STATIC_BINARY'] = '1'
sys.frozen = True

# Add current directory to path for module imports
sys.path.insert(0, os.path.dirname(sys.executable))

# Import and run main entry point
try:
    from ddos import main
    main()
except ImportError as e:
    # Fallback to CLI if ddos.py not available
    try:
        from core.interfaces.cli import main as cli_main
        cli_main()
    except ImportError as e2:
        print(f"NetStress Titanium - Failed to start: {e}")
        print(f"Fallback also failed: {e2}")
        print("Available modules:", list(sys.modules.keys()))
        sys.exit(1)
"""
    
    # Optimization settings for static binary
    policy.optimization_level = 2  # Maximum bytecode optimization
    policy.sys_frozen = True
    policy.filesystem_importer = False  # Force in-memory imports
    policy.write_modules_directory_env = None  # No module directory
    
    # Create packaging policy for static embedding
    python_config = dist.make_python_packaging_policy()
    
    # Optimize for single binary - everything in memory
    python_config.include_distribution_sources = False
    python_config.include_distribution_resources = False
    python_config.include_test = False
    python_config.include_non_distribution_sources = False
    python_config.allow_in_memory_shared_library_loading = True
    
    # Store ALL resources in memory (fileless execution)
    python_config.resources_location = "in-memory"
    python_config.resources_location_fallback = "in-memory"
    
    # Extension module handling for static linking
    python_config.extension_module_filter = "all"
    python_config.allow_files = False  # No file extraction
    python_config.file_scanner_emit_files = False
    python_config.file_scanner_classify_files = False
    
    # Create the executable
    exe = dist.to_python_executable(
        name = "netstress",
        packaging_policy = python_config,
        config = policy,
    )
    
    # =========================================================================
    # CORE DEPENDENCIES - Embedded in binary
    # =========================================================================
    exe.add_python_resources(exe.pip_install([
        # Network & Async
        "aiohttp>=3.9.0",
        "asyncio>=3.4.3",
        "websockets>=12.0",
        
        # Packet crafting
        "scapy>=2.5.0",
        
        # Data & ML
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        
        # Security
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        
        # System
        "psutil>=5.9.0",
        "colorama>=0.4.6",
        
        # Utilities
        "faker>=22.0.0",
        "pyyaml>=6.0.1",
        "requests>=2.31.0",
        "urllib3>=2.1.0",
        
        # DNS
        "dnspython>=2.4.0",
        
        # P2P and networking
        "libp2p>=0.1.0",
        
        # Machine Learning (optional)
        "scikit-learn>=1.3.0",
        "torch>=2.0.0",
        
        # Testing framework
        "pytest>=7.4.0",
        "hypothesis>=6.82.0",
    ]))
    
    # =========================================================================
    # NETSTRESS CORE MODULES
    # =========================================================================
    exe.add_python_resources(exe.read_package_root(
        path = ".",
        packages = ["core"],
    ))
    
    # Add main entry point
    exe.add_python_resources(exe.read_python_file("ddos.py"))
    
    # Add configuration files
    exe.add_python_resources(exe.read_files(
        path = "config",
        include = ["*.json", "*.yaml", "*.conf"],
    ))
    
    # =========================================================================
    # NATIVE RUST ENGINE - Static linking
    # =========================================================================
    # Build and embed the Rust engine as a Python extension
    # This requires the Rust engine to be built first with maturin
    
    # Check if pre-built wheel exists
    import os
    import glob
    
    wheel_pattern = "./native/rust_engine/target/wheels/netstress_engine-*.whl"
    wheels = glob.glob(wheel_pattern)
    
    if wheels:
        # Add the most recent wheel
        latest_wheel = max(wheels, key=os.path.getctime)
        exe.add_python_resources(exe.pip_install([latest_wheel]))
        print(f"Added Rust engine: {latest_wheel}")
    else:
        print("Warning: Rust engine wheel not found. Build with: cd native/rust_engine && maturin build --release")
        print("The binary will work but without native acceleration")
    
    # =========================================================================
    # STATIC BINARY CONFIGURATION
    # =========================================================================
    # Configure for maximum portability and minimal dependencies
    
    # Size optimization settings
    if VARS.get("OPTIMIZE_SIZE", "false").lower() == "true":
        # Use size-optimized Python distribution
        dist = default_python_distribution(
            flavor = "standalone_static",
            python_version = "3.11",
        )
        
        # More aggressive size optimization
        python_config.include_distribution_sources = False
        python_config.include_distribution_resources = False
        python_config.include_test = False
        python_config.include_non_distribution_sources = False
        python_config.bytecode_optimize_level_zero = False
        python_config.bytecode_optimize_level_one = True
        python_config.bytecode_optimize_level_two = True
    
    # Windows-specific configuration
    if VARS.get("target_triple", "").contains("windows"):
        # Static MSVC runtime
        exe.windows_runtime_dlls_mode = "never"
        exe.windows_subsystem = "console"
        
        # Embed manifest for Windows compatibility
        exe.windows_manifest_template = """
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="3.0.0.0" processorArchitecture="*" name="NetStress.Titanium" type="win32"/>
  <description>NetStress Titanium - Military-grade network stress testing framework</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
    </application>
  </compatibility>
</assembly>
"""
    
    return exe

def make_embedded_resources(exe):
    """Generate embedded resources for the executable"""
    return exe.to_embedded_resources()

def make_install(exe):
    """Create installation layout with single binary"""
    files = FileManifest()
    
    # Add the main executable
    files.add_python_resource(".", exe)
    
    return files

def make_msi(exe):
    """Windows MSI installer configuration"""
    return exe.to_wix_msi_builder(
        "netstress",
        "NetStress Titanium",
        "3.0.0",
        "NetStress Team",
        "Military-grade network stress testing framework with zero dependencies",
        "https://github.com/Destroyer-official/-NetStress-"
    )

def make_macos_app(exe):
    """macOS .app bundle configuration"""
    bundle = exe.to_macos_application_bundle_builder(
        "NetStress",
        "com.netstress.titanium",
        "NetStress Titanium - Network Stress Testing Framework",
    )
    
    # macOS-specific configuration
    bundle.set_info_plist_key("CFBundleVersion", "3.0.0")
    bundle.set_info_plist_key("CFBundleShortVersionString", "3.0.0")
    bundle.set_info_plist_key("LSMinimumSystemVersion", "10.15")
    bundle.set_info_plist_key("NSHighResolutionCapable", True)
    
    return bundle

def make_linux_appimage(exe):
    """Linux AppImage configuration"""
    # AppImage creation requires additional tooling
    # For now, just return the executable
    return exe

# =========================================================================
# BUILD TARGETS
# =========================================================================
# Usage:
#   pyoxidizer build exe --release          # Build executable only
#   pyoxidizer build install --release      # Build and install
#   pyoxidizer build msi --release          # Build Windows installer
#   pyoxidizer run --release                # Build and run

register_target("exe", make_exe)
register_target("resources", make_embedded_resources, depends=["exe"], default_build_script=True)
register_target("install", make_install, depends=["exe"], default=True)
register_target("msi", make_msi, depends=["exe"])
register_target("macos_app", make_macos_app, depends=["exe"])

# Resolve default target
resolve_targets()

# =========================================================================
# BUILD INSTRUCTIONS
# =========================================================================
#
# Prerequisites:
#   1. Install PyOxidizer: cargo install pyoxidizer
#   2. Build Rust engine: cd native/rust_engine && maturin build --release
#   3. Ensure Python 3.11+ is available
#
# Build single binary:
#   pyoxidizer build --release
#
# Build with all features:
#   pyoxidizer build --release --var ENABLE_ALL_FEATURES true
#
# The output will be in:
#   - Windows: build/x86_64-pc-windows-msvc/release/install/netstress.exe
#   - Linux:   build/x86_64-unknown-linux-gnu/release/install/netstress
#   - macOS:   build/x86_64-apple-darwin/release/install/netstress
#
# Binary characteristics:
#   - Fully static (no runtime dependencies)
#   - Embedded Python interpreter
#   - All modules loaded from memory
#   - Native Rust engine included
#   - Single file deployment
#   - Target size: <150MB per platform
#
