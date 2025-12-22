#!/usr/bin/env python3
"""
NetStress Titanium - Automated Build System
"Click-to-Weaponize" - One command to build everything

This script auto-detects your system capabilities and compiles
the native Rust engine for maximum performance.

Usage:
    python build.py              # Auto-detect and build
    python build.py --release    # Build optimized release
    python build.py --check      # Check dependencies only
    python build.py --clean      # Clean build artifacts

Requirements:
    - Rust/Cargo (for native engine)
    - CUDA Toolkit (optional, for GPU acceleration)
    - Python 3.8+
"""

import os
import sys
import subprocess
import platform
import shutil
import argparse
from pathlib import Path
from typing import Optional, Dict, List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    """Print NetStress build banner"""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║     NetStress Titanium v3.0 - Automated Build System          ║
║              "Click-to-Weaponize" Builder                     ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}""")


def run_command(cmd: List[str], cwd: Optional[str] = None, capture: bool = False) -> Tuple[int, str]:
    """Run a command and return exit code and output"""
    try:
        if capture:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
            return result.returncode, result.stdout + result.stderr
        else:
            result = subprocess.run(cmd, cwd=cwd)
            return result.returncode, ""
    except FileNotFoundError:
        return -1, f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, str(e)


def check_command(cmd: str) -> bool:
    """Check if a command is available"""
    return shutil.which(cmd) is not None


def get_rust_version() -> Optional[str]:
    """Get installed Rust version"""
    code, output = run_command(['rustc', '--version'], capture=True)
    if code == 0:
        return output.strip()
    return None


def get_cargo_version() -> Optional[str]:
    """Get installed Cargo version"""
    code, output = run_command(['cargo', '--version'], capture=True)
    if code == 0:
        return output.strip()
    return None


def get_cuda_version() -> Optional[str]:
    """Get installed CUDA version"""
    code, output = run_command(['nvcc', '--version'], capture=True)
    if code == 0:
        for line in output.split('\n'):
            if 'release' in line.lower():
                return line.strip()
    return None


def get_python_version() -> str:
    """Get Python version"""
    return f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def check_dependencies() -> Dict[str, Dict]:
    """Check all build dependencies"""
    deps = {
        'python': {
            'required': True,
            'found': True,
            'version': get_python_version(),
            'install': 'https://python.org'
        },
        'rust': {
            'required': True,
            'found': check_command('rustc'),
            'version': get_rust_version(),
            'install': 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh'
        },
        'cargo': {
            'required': True,
            'found': check_command('cargo'),
            'version': get_cargo_version(),
            'install': 'Installed with Rust'
        },
        'cuda': {
            'required': False,
            'found': check_command('nvcc'),
            'version': get_cuda_version(),
            'install': 'https://developer.nvidia.com/cuda-downloads'
        },
        'maturin': {
            'required': True,
            'found': check_command('maturin'),
            'version': None,
            'install': 'pip install maturin'
        }
    }
    return deps


def print_dependency_status(deps: Dict[str, Dict]):
    """Print dependency status table"""
    print(f"\n{Colors.BOLD}Dependency Check:{Colors.END}")
    print("-" * 60)
    
    for name, info in deps.items():
        status = f"{Colors.GREEN}✓{Colors.END}" if info['found'] else f"{Colors.RED}✗{Colors.END}"
        req = "(required)" if info['required'] else "(optional)"
        version = info['version'] or "Not found"
        
        if info['found']:
            print(f"  {status} {name:12} {req:12} {version}")
        else:
            print(f"  {status} {name:12} {req:12} {Colors.YELLOW}Install: {info['install']}{Colors.END}")
    
    print("-" * 60)


def install_maturin():
    """Install maturin if not present"""
    print(f"\n{Colors.YELLOW}Installing maturin...{Colors.END}")
    code, _ = run_command([sys.executable, '-m', 'pip', 'install', 'maturin'])
    return code == 0


def build_rust_engine(release: bool = True) -> bool:
    """Build the Rust native engine"""
    rust_dir = Path('native/rust_engine')
    
    if not rust_dir.exists():
        print(f"{Colors.RED}Error: Rust engine directory not found: {rust_dir}{Colors.END}")
        return False
    
    print(f"\n{Colors.CYAN}Building Rust Native Engine...{Colors.END}")
    print(f"  Directory: {rust_dir.absolute()}")
    
    # Build with maturin
    cmd = ['maturin', 'build']
    if release:
        cmd.append('--release')
    
    print(f"  Command: {' '.join(cmd)}")
    code, output = run_command(cmd, cwd=str(rust_dir))
    
    if code != 0:
        print(f"{Colors.RED}Build failed!{Colors.END}")
        if output:
            print(output)
        return False
    
    print(f"{Colors.GREEN}Rust engine built successfully!{Colors.END}")
    
    # Find and install the wheel
    wheels_dir = rust_dir / 'target' / 'wheels'
    if wheels_dir.exists():
        wheels = list(wheels_dir.glob('*.whl'))
        if wheels:
            latest_wheel = max(wheels, key=lambda p: p.stat().st_mtime)
            print(f"\n{Colors.CYAN}Installing wheel: {latest_wheel.name}{Colors.END}")
            code, _ = run_command([sys.executable, '-m', 'pip', 'install', str(latest_wheel), '--force-reinstall'])
            if code == 0:
                print(f"{Colors.GREEN}Native engine installed!{Colors.END}")
                return True
    
    return True


def build_pyoxidizer() -> bool:
    """Build single binary with PyOxidizer"""
    if not check_command('pyoxidizer'):
        print(f"{Colors.YELLOW}PyOxidizer not found. Install with: cargo install pyoxidizer{Colors.END}")
        return False
    
    print(f"\n{Colors.CYAN}Building single binary with PyOxidizer...{Colors.END}")
    code, _ = run_command(['pyoxidizer', 'build', '--release'])
    
    if code == 0:
        print(f"{Colors.GREEN}Single binary built successfully!{Colors.END}")
        return True
    
    return False


def clean_build():
    """Clean build artifacts"""
    print(f"\n{Colors.YELLOW}Cleaning build artifacts...{Colors.END}")
    
    dirs_to_clean = [
        'native/rust_engine/target',
        'build',
        'dist',
        '*.egg-info',
    ]
    
    for pattern in dirs_to_clean:
        for path in Path('.').glob(pattern):
            if path.is_dir():
                print(f"  Removing: {path}")
                shutil.rmtree(path, ignore_errors=True)
    
    print(f"{Colors.GREEN}Clean complete!{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description='NetStress Titanium Build System')
    parser.add_argument('--release', action='store_true', help='Build optimized release')
    parser.add_argument('--check', action='store_true', help='Check dependencies only')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts')
    parser.add_argument('--pyoxidizer', action='store_true', help='Build single binary')
    args = parser.parse_args()
    
    print_banner()
    
    # Check dependencies
    deps = check_dependencies()
    print_dependency_status(deps)
    
    if args.check:
        # Just check dependencies
        missing_required = [name for name, info in deps.items() if info['required'] and not info['found']]
        if missing_required:
            print(f"\n{Colors.RED}Missing required dependencies: {', '.join(missing_required)}{Colors.END}")
            sys.exit(1)
        else:
            print(f"\n{Colors.GREEN}All required dependencies found!{Colors.END}")
            sys.exit(0)
    
    if args.clean:
        clean_build()
        sys.exit(0)
    
    # Check required dependencies
    if not deps['rust']['found'] or not deps['cargo']['found']:
        print(f"\n{Colors.RED}Error: Rust and Cargo are required to build the native engine.{Colors.END}")
        print(f"Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
        sys.exit(1)
    
    # Install maturin if needed
    if not deps['maturin']['found']:
        if not install_maturin():
            print(f"{Colors.RED}Failed to install maturin{Colors.END}")
            sys.exit(1)
    
    # Build Rust engine
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Building NetStress Titanium Native Engine{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    
    if not build_rust_engine(release=args.release or True):
        print(f"\n{Colors.RED}Build failed!{Colors.END}")
        sys.exit(1)
    
    # Optionally build PyOxidizer single binary
    if args.pyoxidizer:
        build_pyoxidizer()
    
    # Summary
    print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}BUILD COMPLETE!{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    
    print(f"""
{Colors.CYAN}Next steps:{Colors.END}
  1. Run NetStress: python ddos.py --help
  2. Build single binary: python build.py --pyoxidizer
  
{Colors.YELLOW}Performance Note:{Colors.END}
  With native engine: 1M-50M+ PPS (depending on hardware)
  Without native engine: 50K-500K PPS (Python fallback)
""")


if __name__ == '__main__':
    main()
