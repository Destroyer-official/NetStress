#!/usr/bin/env python3
"""
NetStress Titanium v3.0 - Static Binary Builder
**Validates: Requirements 10.3** - Automated static binary build with embedded Python

This script automates the complete build process for creating a fully static
NetStress binary with embedded Python interpreter and Rust engine.

Usage:
    python scripts/build_static_binary.py [--platform all|windows|linux|macos] [--optimize-size]
"""

import os
import sys
import subprocess
import shutil
import platform
import argparse
import json
from pathlib import Path
from typing import List, Optional

class StaticBinaryBuilder:
    def __init__(self, target_platform: str = "current", optimize_size: bool = False):
        self.target_platform = target_platform
        self.optimize_size = optimize_size
        self.project_root = Path(__file__).parent.parent
        self.rust_engine_path = self.project_root / "native" / "rust_engine"
        self.build_dir = self.project_root / "build"
        self.dist_dir = self.project_root / "dist"
        
        # Platform-specific configurations
        self.platform_configs = {
            "windows": {
                "target": "x86_64-pc-windows-msvc",
                "binary_name": "netstress.exe",
                "rust_target": "x86_64-pc-windows-msvc",
                "pyoxidizer_target": "x86_64-pc-windows-msvc",
            },
            "linux": {
                "target": "x86_64-unknown-linux-gnu",
                "binary_name": "netstress",
                "rust_target": "x86_64-unknown-linux-gnu",
                "pyoxidizer_target": "x86_64-unknown-linux-gnu",
            },
            "linux-musl": {
                "target": "x86_64-unknown-linux-musl",
                "binary_name": "netstress",
                "rust_target": "x86_64-unknown-linux-musl",
                "pyoxidizer_target": "x86_64-unknown-linux-musl",
            },
            "macos": {
                "target": "x86_64-apple-darwin",
                "binary_name": "netstress",
                "rust_target": "x86_64-apple-darwin",
                "pyoxidizer_target": "x86_64-apple-darwin",
            },
            "macos-arm": {
                "target": "aarch64-apple-darwin",
                "binary_name": "netstress",
                "rust_target": "aarch64-apple-darwin",
                "pyoxidizer_target": "aarch64-apple-darwin",
            },
        }
    
    def detect_current_platform(self) -> str:
        """Detect the current platform for building"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "windows":
            return "windows"
        elif system == "linux":
            # Check if we're on musl
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read()
                    if "alpine" in content.lower():
                        return "linux-musl"
            except:
                pass
            return "linux"
        elif system == "darwin":
            if machine in ["arm64", "aarch64"]:
                return "macos-arm"
            else:
                return "macos"
        else:
            raise ValueError(f"Unsupported platform: {system}")
    
    def check_prerequisites(self) -> bool:
        """Check if all build prerequisites are available"""
        print("🔍 Checking build prerequisites...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8+ required")
            return False
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}")
        
        # Check Rust
        try:
            result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Rust: {result.stdout.strip()}")
            else:
                print("❌ Rust not found")
                return False
        except FileNotFoundError:
            print("❌ Rust not found")
            return False
        
        # Check PyOxidizer
        try:
            result = subprocess.run(["pyoxidizer", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ PyOxidizer: {result.stdout.strip()}")
            else:
                print("❌ PyOxidizer not found. Install with: cargo install pyoxidizer")
                return False
        except FileNotFoundError:
            print("❌ PyOxidizer not found. Install with: cargo install pyoxidizer")
            return False
        
        # Check maturin
        try:
            result = subprocess.run(["maturin", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Maturin: {result.stdout.strip()}")
            else:
                print("❌ Maturin not found. Install with: pip install maturin")
                return False
        except FileNotFoundError:
            print("❌ Maturin not found. Install with: pip install maturin")
            return False
        
        return True
    
    def build_rust_engine(self, target_platform: str) -> bool:
        """Build the Rust engine with static linking"""
        print(f"🦀 Building Rust engine for {target_platform}...")
        
        config = self.platform_configs[target_platform]
        rust_target = config["rust_target"]
        
        # Change to Rust engine directory
        original_cwd = os.getcwd()
        os.chdir(self.rust_engine_path)
        
        try:
            # Install target if needed
            subprocess.run([
                "rustup", "target", "add", rust_target
            ], check=False)  # Don't fail if already installed
            
            # Build command
            build_cmd = [
                "maturin", "build",
                "--release",
                "--target", rust_target,
                "--features", "titanium",  # Enable all features
            ]
            
            if self.optimize_size:
                build_cmd.extend(["--profile", "release-size"])
            
            # Set environment for static linking
            env = os.environ.copy()
            env["RUSTFLAGS"] = "-C target-feature=+crt-static"
            
            if target_platform == "linux-musl":
                env["CC"] = "musl-gcc"
                env["RUSTFLAGS"] += " -C link-arg=-static"
            
            result = subprocess.run(build_cmd, env=env, check=True)
            
            print("✅ Rust engine built successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Rust engine build failed: {e}")
            return False
        finally:
            os.chdir(original_cwd)
    
    def build_python_binary(self, target_platform: str) -> bool:
        """Build the Python binary with PyOxidizer"""
        print(f"🐍 Building Python binary for {target_platform}...")
        
        config = self.platform_configs[target_platform]
        pyoxidizer_target = config["pyoxidizer_target"]
        
        try:
            # Build command
            build_cmd = [
                "pyoxidizer", "build",
                "--release",
                "--target-triple", pyoxidizer_target,
            ]
            
            if self.optimize_size:
                build_cmd.extend(["--var", "OPTIMIZE_SIZE", "true"])
            
            # Set environment for static linking
            env = os.environ.copy()
            env["NETSTRESS_STATIC_BUILD"] = "1"
            
            result = subprocess.run(build_cmd, env=env, check=True, cwd=self.project_root)
            
            print("✅ Python binary built successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Python binary build failed: {e}")
            return False
    
    def optimize_binary(self, binary_path: Path, target_platform: str) -> bool:
        """Optimize the binary for size and performance"""
        print(f"⚡ Optimizing binary: {binary_path}")
        
        if not binary_path.exists():
            print(f"❌ Binary not found: {binary_path}")
            return False
        
        original_size = binary_path.stat().st_size
        print(f"📏 Original size: {original_size / 1024 / 1024:.1f} MB")
        
        try:
            if target_platform.startswith("linux"):
                # Strip debug symbols on Linux
                subprocess.run(["strip", str(binary_path)], check=True)
                print("✅ Stripped debug symbols")
                
                # Optionally use UPX compression
                if self.optimize_size and shutil.which("upx"):
                    subprocess.run(["upx", "--best", str(binary_path)], check=True)
                    print("✅ Applied UPX compression")
            
            elif target_platform == "windows":
                # Windows optimization would require additional tools
                print("ℹ️  Windows binary optimization skipped (requires additional tools)")
            
            elif target_platform.startswith("macos"):
                # Strip debug symbols on macOS
                subprocess.run(["strip", str(binary_path)], check=True)
                print("✅ Stripped debug symbols")
            
            final_size = binary_path.stat().st_size
            print(f"📏 Final size: {final_size / 1024 / 1024:.1f} MB")
            print(f"💾 Size reduction: {(original_size - final_size) / 1024 / 1024:.1f} MB")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"⚠️  Binary optimization failed: {e}")
            return False  # Non-fatal
    
    def verify_binary(self, binary_path: Path, target_platform: str) -> bool:
        """Verify the binary has no runtime dependencies"""
        print(f"🔍 Verifying binary dependencies: {binary_path}")
        
        if not binary_path.exists():
            print(f"❌ Binary not found: {binary_path}")
            return False
        
        try:
            if target_platform.startswith("linux"):
                # Check with ldd
                result = subprocess.run(["ldd", str(binary_path)], 
                                      capture_output=True, text=True, check=False)
                
                if "not a dynamic executable" in result.stderr:
                    print("✅ Fully static binary (no dynamic dependencies)")
                    return True
                elif result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    dynamic_deps = [line for line in lines if "=>" in line and "linux-vdso" not in line]
                    
                    if not dynamic_deps:
                        print("✅ No external dynamic dependencies")
                        return True
                    else:
                        print("⚠️  Dynamic dependencies found:")
                        for dep in dynamic_deps:
                            print(f"    {dep}")
                        return False
                else:
                    print(f"❌ ldd failed: {result.stderr}")
                    return False
            
            elif target_platform == "windows":
                # Check with dumpbin (if available) or just verify it runs
                print("ℹ️  Windows dependency check limited (requires Visual Studio tools)")
                return True
            
            elif target_platform.startswith("macos"):
                # Check with otool
                result = subprocess.run(["otool", "-L", str(binary_path)], 
                                      capture_output=True, text=True, check=True)
                
                lines = result.stdout.strip().split('\n')[1:]  # Skip first line (binary name)
                external_deps = [line.strip() for line in lines 
                               if not line.strip().startswith("/usr/lib/system/") 
                               and not line.strip().startswith("/System/Library/")]
                
                if not external_deps:
                    print("✅ No external dynamic dependencies")
                    return True
                else:
                    print("⚠️  External dependencies found:")
                    for dep in external_deps:
                        print(f"    {dep}")
                    return False
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Dependency verification failed: {e}")
            return False
    
    def copy_to_dist(self, source_path: Path, target_platform: str) -> Path:
        """Copy the final binary to dist directory"""
        config = self.platform_configs[target_platform]
        binary_name = config["binary_name"]
        
        # Create dist directory
        self.dist_dir.mkdir(exist_ok=True)
        
        # Target path with platform suffix
        target_name = f"netstress-{target_platform}"
        if target_platform == "windows":
            target_name += ".exe"
        
        target_path = self.dist_dir / target_name
        
        # Copy binary
        shutil.copy2(source_path, target_path)
        
        # Make executable on Unix systems
        if not target_platform == "windows":
            target_path.chmod(0o755)
        
        print(f"📦 Binary copied to: {target_path}")
        return target_path
    
    def build_platform(self, target_platform: str) -> bool:
        """Build for a specific platform"""
        print(f"\n🚀 Building NetStress Titanium for {target_platform}")
        print("=" * 60)
        
        config = self.platform_configs[target_platform]
        
        # Step 1: Build Rust engine
        if not self.build_rust_engine(target_platform):
            return False
        
        # Step 2: Build Python binary
        if not self.build_python_binary(target_platform):
            return False
        
        # Step 3: Find the built binary
        pyoxidizer_target = config["pyoxidizer_target"]
        binary_name = config["binary_name"]
        
        binary_path = (self.build_dir / pyoxidizer_target / "release" / "install" / binary_name)
        
        if not binary_path.exists():
            print(f"❌ Built binary not found at: {binary_path}")
            return False
        
        # Step 4: Optimize binary
        self.optimize_binary(binary_path, target_platform)
        
        # Step 5: Verify binary
        if not self.verify_binary(binary_path, target_platform):
            print("⚠️  Binary verification failed, but continuing...")
        
        # Step 6: Copy to dist
        final_path = self.copy_to_dist(binary_path, target_platform)
        
        # Step 7: Final size check
        final_size = final_path.stat().st_size / 1024 / 1024
        target_size = 150  # MB
        
        if final_size <= target_size:
            print(f"✅ Binary size OK: {final_size:.1f} MB (target: {target_size} MB)")
        else:
            print(f"⚠️  Binary size large: {final_size:.1f} MB (target: {target_size} MB)")
        
        print(f"🎉 Build completed successfully for {target_platform}")
        return True
    
    def build(self) -> bool:
        """Main build function"""
        print("🏗️  NetStress Titanium v3.0 - Static Binary Builder")
        print("=" * 60)
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Determine platforms to build
        if self.target_platform == "all":
            platforms = ["windows", "linux", "linux-musl", "macos", "macos-arm"]
        elif self.target_platform == "current":
            platforms = [self.detect_current_platform()]
        else:
            platforms = [self.target_platform]
        
        # Build for each platform
        success_count = 0
        for platform in platforms:
            if platform not in self.platform_configs:
                print(f"❌ Unsupported platform: {platform}")
                continue
            
            try:
                if self.build_platform(platform):
                    success_count += 1
                else:
                    print(f"❌ Build failed for {platform}")
            except Exception as e:
                print(f"❌ Build error for {platform}: {e}")
        
        # Summary
        print("\n" + "=" * 60)
        print(f"📊 Build Summary: {success_count}/{len(platforms)} platforms successful")
        
        if success_count > 0:
            print(f"📦 Binaries available in: {self.dist_dir}")
            for file in self.dist_dir.glob("netstress-*"):
                size = file.stat().st_size / 1024 / 1024
                print(f"    {file.name}: {size:.1f} MB")
        
        return success_count == len(platforms)

def main():
    parser = argparse.ArgumentParser(description="Build static NetStress binaries")
    parser.add_argument("--platform", 
                       choices=["all", "current", "windows", "linux", "linux-musl", "macos", "macos-arm"],
                       default="current",
                       help="Target platform(s) to build for")
    parser.add_argument("--optimize-size", action="store_true",
                       help="Optimize for binary size over performance")
    
    args = parser.parse_args()
    
    builder = StaticBinaryBuilder(args.platform, args.optimize_size)
    success = builder.build()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()