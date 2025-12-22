#!/usr/bin/env python3
"""
NetStress Native Engine Installer

Automatically downloads and installs the pre-built native engine
for your platform. No Rust or C compiler needed!

Usage:
    python scripts/install_native.py
"""

import os
import sys
import platform
import subprocess
import urllib.request
import json
from pathlib import Path

# GitHub repo info
REPO_OWNER = "Destroyer-official"
REPO_NAME = "NetStress"
PACKAGE_NAME = "netstress_engine"

def get_platform_tag():
    """Get the wheel platform tag for current system"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "windows":
        if machine in ("amd64", "x86_64"):
            return "win_amd64"
        elif machine in ("x86", "i386", "i686"):
            return "win32"
    elif system == "linux":
        if machine in ("x86_64", "amd64"):
            return "manylinux_2_17_x86_64.manylinux2014_x86_64"
        elif machine == "aarch64":
            return "manylinux_2_17_aarch64.manylinux2014_aarch64"
    elif system == "darwin":
        if machine == "arm64":
            return "macosx_11_0_arm64"
        else:
            return "macosx_10_9_x86_64"
    
    return None

def get_python_tag():
    """Get Python version tag"""
    major = sys.version_info.major
    minor = sys.version_info.minor
    return f"cp{major}{minor}"

def get_latest_release():
    """Get latest release info from GitHub"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
    try:
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Error fetching release info: {e}")
        return None

def find_matching_wheel(release, platform_tag, python_tag):
    """Find a wheel that matches our platform"""
    if not release or "assets" not in release:
        return None
    
    # Try exact match first
    for asset in release["assets"]:
        name = asset["name"]
        if name.endswith(".whl"):
            # Check if it's an abi3 wheel (works with any Python 3.8+)
            if "abi3" in name and platform_tag in name:
                return asset["browser_download_url"]
            # Check for exact Python version match
            if python_tag in name and platform_tag in name:
                return asset["browser_download_url"]
    
    return None

def download_and_install(url):
    """Download wheel and install it"""
    filename = url.split("/")[-1]
    temp_path = Path(f"/tmp/{filename}" if platform.system() != "Windows" else f"{os.environ['TEMP']}\\{filename}")
    
    print(f"Downloading {filename}...")
    urllib.request.urlretrieve(url, temp_path)
    
    print(f"Installing {filename}...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", str(temp_path)], 
                          capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✅ Native engine installed successfully!")
        temp_path.unlink()  # Clean up
        return True
    else:
        print(f"❌ Installation failed: {result.stderr}")
        return False

def check_existing_installation():
    """Check if native engine is already installed"""
    try:
        import netstress_engine
        print(f"✅ Native engine already installed: {netstress_engine.__version__ if hasattr(netstress_engine, '__version__') else 'unknown version'}")
        return True
    except ImportError:
        return False

def main():
    print("=" * 60)
    print("NetStress Native Engine Installer")
    print("=" * 60)
    print()
    
    # Check if already installed
    if check_existing_installation():
        response = input("Reinstall? (y/N): ").strip().lower()
        if response != 'y':
            return
    
    # Get platform info
    platform_tag = get_platform_tag()
    python_tag = get_python_tag()
    
    print(f"Platform: {platform.system()} {platform.machine()}")
    print(f"Python: {sys.version}")
    print(f"Looking for: {platform_tag}")
    print()
    
    if not platform_tag:
        print("❌ Unsupported platform")
        print("You can build from source:")
        print("  cd native/rust_engine")
        print("  pip install maturin")
        print("  maturin develop --release")
        return
    
    # Get latest release
    print("Fetching latest release...")
    release = get_latest_release()
    
    if not release:
        print("❌ Could not fetch release info")
        print("Try manual installation from GitHub releases")
        return
    
    print(f"Latest version: {release.get('tag_name', 'unknown')}")
    
    # Find matching wheel
    wheel_url = find_matching_wheel(release, platform_tag, python_tag)
    
    if not wheel_url:
        print(f"❌ No pre-built wheel found for {platform_tag}")
        print()
        print("Options:")
        print("1. Check GitHub releases for available wheels")
        print("2. Build from source:")
        print("   cd native/rust_engine")
        print("   pip install maturin")
        print("   maturin develop --release")
        return
    
    # Download and install
    if download_and_install(wheel_url):
        print()
        print("🚀 Native engine ready!")
        print("Run: python ddos.py --status")
    else:
        print()
        print("Try manual installation or build from source")

if __name__ == "__main__":
    main()
