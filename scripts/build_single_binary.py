#!/usr/bin/env python3
"""
NetStress Titan - Single Binary Build Script

This script automates the creation of a standalone single-file executable
that includes:
- Python interpreter (embedded)
- All NetStress core modules
- Native Rust engine (if available)
- All dependencies

Usage:
    python scripts/build_single_binary.py [--release] [--with-rust]

Output:
    dist/netstress.exe (Windows)
    dist/netstress (Linux/macOS)
"""

import os
import sys
import shutil
import subprocess
import platform
import argparse
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_status(msg, status="info"):
    colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED
    }
    color = colors.get(status, Colors.RESET)
    print(f"{color}[{status.upper()}]{Colors.RESET} {msg}")

def check_prerequisites():
    """Check if required tools are installed"""
    print_status("Checking prerequisites...", "info")
    
    missing = []
    
    # Check Python version
    if sys.version_info < (3, 8):
        missing.append("Python 3.8+ required")
        
    # Check PyOxidizer
    try:
        result = subprocess.run(["pyoxidizer", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print_status(f"PyOxidizer: {result.stdout.strip()}", "success")
        else:
            missing.append("PyOxidizer not found")
    except FileNotFoundError:
        missing.append("PyOxidizer not installed (cargo install pyoxidizer)")
        
    # Check Rust/Cargo (optional, for native engine)
    try:
        result = subprocess.run(["cargo", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print_status(f"Cargo: {result.stdout.strip()}", "success")
    except FileNotFoundError:
        print_status("Cargo not found (optional, for Rust engine)", "warning")
        
    # Check maturin (optional, for Rust engine)
    try:
        result = subprocess.run(["maturin", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print_status(f"Maturin: {result.stdout.strip()}", "success")
    except FileNotFoundError:
        print_status("Maturin not found (optional, for Rust engine)", "warning")
        
    if missing:
        print_status("Missing prerequisites:", "error")
        for item in missing:
            print(f"  - {item}")
        return False
        
    return True

def build_rust_engine(release=True):
    """Build the native Rust engine"""
    print_status("Building Rust native engine...", "info")
    
    rust_dir = Path("native/rust_engine")
    if not rust_dir.exists():
        print_status("Rust engine directory not found", "warning")
        return False
        
    try:
        # Build with maturin
        cmd = ["maturin", "build"]
        if release:
            cmd.append("--release")
            
        result = subprocess.run(cmd, cwd=rust_dir, capture_output=True, text=True)
        
        if result.returncode == 0:
            print_status("Rust engine built successfully", "success")
            return True
        else:
            print_status(f"Rust engine build failed: {result.stderr}", "error")
            return False
            
    except Exception as e:
        print_status(f"Failed to build Rust engine: {e}", "error")
        return False

def build_pyoxidizer(release=True):
    """Build the single binary with PyOxidizer"""
    print_status("Building single binary with PyOxidizer...", "info")
    
    try:
        cmd = ["pyoxidizer", "build"]
        if release:
            cmd.append("--release")
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print_status("PyOxidizer build successful", "success")
            return True
        else:
            print_status(f"PyOxidizer build failed: {result.stderr}", "error")
            return False
            
    except Exception as e:
        print_status(f"Failed to run PyOxidizer: {e}", "error")
        return False

def copy_to_dist():
    """Copy the built binary to dist/ directory"""
    print_status("Copying binary to dist/...", "info")
    
    # Determine platform-specific paths
    system = platform.system()
    if system == "Windows":
        arch = "x86_64-pc-windows-msvc"
        binary_name = "netstress.exe"
    elif system == "Linux":
        arch = "x86_64-unknown-linux-gnu"
        binary_name = "netstress"
    elif system == "Darwin":
        arch = "x86_64-apple-darwin"
        binary_name = "netstress"
    else:
        print_status(f"Unsupported platform: {system}", "error")
        return False
        
    # Find the built binary
    build_path = Path(f"build/{arch}/release/install/{binary_name}")
    if not build_path.exists():
        # Try debug build
        build_path = Path(f"build/{arch}/debug/install/{binary_name}")
        
    if not build_path.exists():
        print_status(f"Built binary not found at {build_path}", "error")
        return False
        
    # Create dist directory
    dist_dir = Path("dist")
    dist_dir.mkdir(exist_ok=True)
    
    # Copy binary
    dest_path = dist_dir / binary_name
    shutil.copy2(build_path, dest_path)
    
    # Get file size
    size_mb = dest_path.stat().st_size / (1024 * 1024)
    
    print_status(f"Binary created: {dest_path} ({size_mb:.1f} MB)", "success")
    return True

def main():
    parser = argparse.ArgumentParser(description="Build NetStress single binary")
    parser.add_argument("--release", action="store_true", default=True,
                       help="Build in release mode (default)")
    parser.add_argument("--debug", action="store_true",
                       help="Build in debug mode")
    parser.add_argument("--with-rust", action="store_true",
                       help="Build and include Rust native engine")
    parser.add_argument("--skip-checks", action="store_true",
                       help="Skip prerequisite checks")
    args = parser.parse_args()
    
    release = not args.debug
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  NetStress Titan - Single Binary Builder{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    
    # Check prerequisites
    if not args.skip_checks:
        if not check_prerequisites():
            print_status("Please install missing prerequisites and try again", "error")
            sys.exit(1)
            
    print()
    
    # Build Rust engine if requested
    if args.with_rust:
        if not build_rust_engine(release):
            print_status("Continuing without Rust engine...", "warning")
            
    print()
    
    # Build with PyOxidizer
    if not build_pyoxidizer(release):
        print_status("Build failed", "error")
        sys.exit(1)
        
    print()
    
    # Copy to dist
    if not copy_to_dist():
        print_status("Failed to copy binary", "error")
        sys.exit(1)
        
    print()
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}  BUILD COMPLETE!{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print()
    print("  The single binary is ready at: dist/netstress")
    print("  Just copy this file to any machine and run it!")
    print()
    print("  Usage:")
    print("    ./netstress --help")
    print("    ./netstress -t <target> -p <port> -m <method>")
    print()

if __name__ == "__main__":
    main()
