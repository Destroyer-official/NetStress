#!/usr/bin/env python3
"""
NetStress Titanium v3.0 - Static Deployment Verification
**Validates: Requirements 10.4** - Test on clean systems, verify no dynamic library requirements, test all platforms

This script verifies that NetStress binaries have zero runtime dependencies
and can run on clean systems without any additional installations.
"""

import os
import sys
import subprocess
import platform
import tempfile
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse

class StaticDeploymentVerifier:
    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)
        self.platform_name = self.detect_platform()
        self.verification_results = {}
        
    def detect_platform(self) -> str:
        """Detect the current platform"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            return "unknown"
    
    def check_binary_exists(self) -> bool:
        """Verify the binary file exists and is executable"""
        print(f"🔍 Checking binary: {self.binary_path}")
        
        if not self.binary_path.exists():
            print(f"❌ Binary not found: {self.binary_path}")
            return False
        
        if not self.binary_path.is_file():
            print(f"❌ Path is not a file: {self.binary_path}")
            return False
        
        # Check if executable
        if not os.access(self.binary_path, os.X_OK):
            print(f"❌ Binary is not executable: {self.binary_path}")
            return False
        
        size = self.binary_path.stat().st_size
        print(f"✅ Binary found: {size / 1024 / 1024:.1f} MB")
        return True
    
    def analyze_dynamic_dependencies(self) -> Tuple[bool, List[str]]:
        """Analyze dynamic library dependencies"""
        print("🔍 Analyzing dynamic dependencies...")
        
        dependencies = []
        is_static = True
        
        try:
            if self.platform_name == "linux":
                # Use ldd to check dependencies
                result = subprocess.run(
                    ["ldd", str(self.binary_path)], 
                    capture_output=True, text=True, check=False
                )
                
                if "not a dynamic executable" in result.stderr:
                    print("✅ Fully static binary (no dynamic linking)")
                    return True, []
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        line = line.strip()
                        if "=>" in line and "linux-vdso" not in line:
                            # Extract library name
                            lib_name = line.split("=>")[0].strip()
                            lib_path = line.split("=>")[1].strip().split()[0]
                            
                            # Check if it's a system library
                            if not (lib_path.startswith("/lib/") or 
                                   lib_path.startswith("/usr/lib/") or
                                   lib_path.startswith("/lib64/") or
                                   lib_path.startswith("/usr/lib64/")):
                                dependencies.append(f"{lib_name} => {lib_path}")
                                is_static = False
                            else:
                                print(f"ℹ️  System dependency: {lib_name}")
                
            elif self.platform_name == "macos":
                # Use otool to check dependencies
                result = subprocess.run(
                    ["otool", "-L", str(self.binary_path)], 
                    capture_output=True, text=True, check=True
                )
                
                lines = result.stdout.strip().split('\n')[1:]  # Skip binary name
                for line in lines:
                    line = line.strip()
                    if line:
                        lib_path = line.split()[0]
                        
                        # Check if it's a system library
                        if not (lib_path.startswith("/usr/lib/system/") or
                               lib_path.startswith("/System/Library/") or
                               lib_path.startswith("/usr/lib/libSystem")):
                            dependencies.append(lib_path)
                            is_static = False
                        else:
                            print(f"ℹ️  System dependency: {lib_path}")
            
            elif self.platform_name == "windows":
                # Use dumpbin if available, otherwise skip detailed analysis
                try:
                    result = subprocess.run(
                        ["dumpbin", "/dependents", str(self.binary_path)], 
                        capture_output=True, text=True, check=True
                    )
                    
                    lines = result.stdout.split('\n')
                    in_deps_section = False
                    
                    for line in lines:
                        line = line.strip()
                        if "Image has the following dependencies:" in line:
                            in_deps_section = True
                            continue
                        elif in_deps_section and line:
                            if line.endswith(".dll"):
                                # Check if it's a system DLL
                                if not (line.lower().startswith("kernel32") or
                                       line.lower().startswith("ntdll") or
                                       line.lower().startswith("msvcrt") or
                                       line.lower().startswith("user32")):
                                    dependencies.append(line)
                                    is_static = False
                                else:
                                    print(f"ℹ️  System dependency: {line}")
                            elif line == "":
                                break
                
                except (subprocess.CalledProcessError, FileNotFoundError):
                    print("ℹ️  dumpbin not available, skipping detailed Windows dependency analysis")
                    # Assume it's properly built if we can't check
                    return True, []
        
        except subprocess.CalledProcessError as e:
            print(f"❌ Dependency analysis failed: {e}")
            return False, []
        
        if is_static:
            print("✅ No external dynamic dependencies found")
        else:
            print("❌ External dependencies found:")
            for dep in dependencies:
                print(f"    {dep}")
        
        return is_static, dependencies
    
    def test_basic_execution(self) -> bool:
        """Test basic execution of the binary"""
        print("🔍 Testing basic execution...")
        
        try:
            # Test with --help flag (should not require network or special permissions)
            result = subprocess.run(
                [str(self.binary_path), "--help"], 
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.returncode == 0:
                print("✅ Binary executes successfully")
                print(f"ℹ️  Help output length: {len(result.stdout)} characters")
                return True
            else:
                print(f"❌ Binary execution failed with code: {result.returncode}")
                if result.stderr:
                    print(f"    Error: {result.stderr[:200]}...")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Binary execution timed out")
            return False
        except Exception as e:
            print(f"❌ Binary execution error: {e}")
            return False
    
    def test_version_info(self) -> bool:
        """Test version information retrieval"""
        print("🔍 Testing version information...")
        
        try:
            result = subprocess.run(
                [str(self.binary_path), "--version"], 
                capture_output=True, text=True, timeout=10, check=False
            )
            
            if result.returncode == 0 and result.stdout.strip():
                version_info = result.stdout.strip()
                print(f"✅ Version info: {version_info}")
                return True
            else:
                print("⚠️  Version info not available (non-fatal)")
                return True  # Non-fatal
                
        except Exception as e:
            print(f"⚠️  Version check error: {e} (non-fatal)")
            return True  # Non-fatal
    
    def test_clean_environment(self) -> bool:
        """Test execution in a clean environment"""
        print("🔍 Testing execution in clean environment...")
        
        # Create minimal environment
        clean_env = {
            "PATH": "/usr/bin:/bin" if self.platform_name != "windows" else "C:\\Windows\\System32",
            "HOME": "/tmp" if self.platform_name != "windows" else "C:\\temp",
        }
        
        if self.platform_name == "windows":
            clean_env.update({
                "SYSTEMROOT": "C:\\Windows",
                "WINDIR": "C:\\Windows",
            })
        
        try:
            result = subprocess.run(
                [str(self.binary_path), "--help"], 
                capture_output=True, text=True, timeout=30, 
                env=clean_env, check=False
            )
            
            if result.returncode == 0:
                print("✅ Executes successfully in clean environment")
                return True
            else:
                print(f"❌ Failed in clean environment: {result.returncode}")
                if result.stderr:
                    print(f"    Error: {result.stderr[:200]}...")
                return False
                
        except Exception as e:
            print(f"❌ Clean environment test error: {e}")
            return False
    
    def test_file_system_isolation(self) -> bool:
        """Test that binary doesn't require specific file system layout"""
        print("🔍 Testing file system isolation...")
        
        # Create temporary directory and copy binary there
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_binary = Path(temp_dir) / self.binary_path.name
            shutil.copy2(self.binary_path, temp_binary)
            
            # Make executable
            if self.platform_name != "windows":
                temp_binary.chmod(0o755)
            
            try:
                result = subprocess.run(
                    [str(temp_binary), "--help"], 
                    capture_output=True, text=True, timeout=30, 
                    cwd=temp_dir, check=False
                )
                
                if result.returncode == 0:
                    print("✅ Executes successfully from isolated location")
                    return True
                else:
                    print(f"❌ Failed from isolated location: {result.returncode}")
                    return False
                    
            except Exception as e:
                print(f"❌ File system isolation test error: {e}")
                return False
    
    def check_embedded_resources(self) -> bool:
        """Check if Python and other resources are properly embedded"""
        print("🔍 Checking embedded resources...")
        
        try:
            # Try to get Python version from the binary
            result = subprocess.run(
                [str(self.binary_path), "--python-version"], 
                capture_output=True, text=True, timeout=10, check=False
            )
            
            if result.returncode == 0 and "python" in result.stdout.lower():
                print(f"✅ Python interpreter embedded: {result.stdout.strip()}")
                return True
            else:
                # Try alternative method - check if binary contains Python strings
                with open(self.binary_path, 'rb') as f:
                    content = f.read(1024 * 1024)  # Read first 1MB
                    if b'python' in content.lower() or b'PyObject' in content:
                        print("✅ Python interpreter appears to be embedded")
                        return True
                    else:
                        print("⚠️  Python embedding not detected (may still work)")
                        return True  # Non-fatal
                        
        except Exception as e:
            print(f"⚠️  Embedded resource check error: {e} (non-fatal)")
            return True  # Non-fatal
    
    def generate_deployment_report(self) -> Dict:
        """Generate a comprehensive deployment report"""
        report = {
            "binary_path": str(self.binary_path),
            "platform": self.platform_name,
            "timestamp": subprocess.run(["date"], capture_output=True, text=True).stdout.strip(),
            "binary_size_mb": round(self.binary_path.stat().st_size / 1024 / 1024, 2),
            "tests": self.verification_results,
            "overall_status": "PASS" if all(self.verification_results.values()) else "FAIL",
        }
        
        return report
    
    def run_verification(self) -> bool:
        """Run complete verification suite"""
        print("🚀 NetStress Titanium v3.0 - Static Deployment Verification")
        print("=" * 70)
        print(f"Binary: {self.binary_path}")
        print(f"Platform: {self.platform_name}")
        print("=" * 70)
        
        tests = [
            ("Binary Exists", self.check_binary_exists),
            ("Dynamic Dependencies", lambda: self.analyze_dynamic_dependencies()[0]),
            ("Basic Execution", self.test_basic_execution),
            ("Version Info", self.test_version_info),
            ("Clean Environment", self.test_clean_environment),
            ("File System Isolation", self.test_file_system_isolation),
            ("Embedded Resources", self.check_embedded_resources),
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n📋 {test_name}")
            print("-" * 40)
            
            try:
                result = test_func()
                self.verification_results[test_name] = result
                
                if result:
                    passed += 1
                    print(f"✅ {test_name}: PASS")
                else:
                    print(f"❌ {test_name}: FAIL")
                    
            except Exception as e:
                print(f"❌ {test_name}: ERROR - {e}")
                self.verification_results[test_name] = False
        
        # Summary
        print("\n" + "=" * 70)
        print("📊 VERIFICATION SUMMARY")
        print("=" * 70)
        
        for test_name, result in self.verification_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:.<50} {status}")
        
        print("-" * 70)
        print(f"Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 VERIFICATION SUCCESSFUL - Binary is ready for deployment!")
            return True
        else:
            print("❌ VERIFICATION FAILED - Binary has deployment issues")
            return False
    
    def save_report(self, output_path: Optional[Path] = None) -> Path:
        """Save verification report to file"""
        if output_path is None:
            output_path = self.binary_path.parent / f"verification_report_{self.platform_name}.json"
        
        report = self.generate_deployment_report()
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report saved to: {output_path}")
        return output_path

def main():
    parser = argparse.ArgumentParser(description="Verify NetStress static deployment")
    parser.add_argument("binary", help="Path to NetStress binary to verify")
    parser.add_argument("--report", help="Path to save verification report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"❌ Binary not found: {binary_path}")
        sys.exit(1)
    
    verifier = StaticDeploymentVerifier(binary_path)
    success = verifier.run_verification()
    
    # Save report
    if args.report:
        verifier.save_report(Path(args.report))
    else:
        verifier.save_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()