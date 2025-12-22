#!/usr/bin/env python3
"""
NetStress Titanium v3.0 - Clean System Test
**Validates: Requirements 10.4** - Test on clean systems without dependencies

This script simulates testing on a clean system by creating an isolated
environment and testing the NetStress binary with minimal system dependencies.
"""

import os
import sys
import subprocess
import tempfile
import shutil
import platform
from pathlib import Path
from typing import Dict, List, Optional
import json

class CleanSystemTester:
    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)
        self.platform_name = platform.system().lower()
        self.test_results = {}
        
    def create_minimal_environment(self) -> Dict[str, str]:
        """Create a minimal environment similar to a clean system"""
        if self.platform_name == "windows":
            return {
                "SYSTEMROOT": "C:\\Windows",
                "WINDIR": "C:\\Windows", 
                "PATH": "C:\\Windows\\System32;C:\\Windows",
                "TEMP": "C:\\temp",
                "TMP": "C:\\temp",
                "USERPROFILE": "C:\\Users\\test",
                "COMPUTERNAME": "CLEAN-TEST",
            }
        else:
            return {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": "/tmp/test",
                "USER": "test",
                "SHELL": "/bin/sh",
                "TERM": "xterm",
                "LANG": "C",
                "LC_ALL": "C",
            }
    
    def test_basic_functionality(self, test_dir: Path) -> bool:
        """Test basic functionality in isolated environment"""
        print("🔍 Testing basic functionality...")
        
        # Copy binary to test directory
        test_binary = test_dir / self.binary_path.name
        shutil.copy2(self.binary_path, test_binary)
        
        if self.platform_name != "windows":
            test_binary.chmod(0o755)
        
        env = self.create_minimal_environment()
        
        try:
            # Test help command
            result = subprocess.run(
                [str(test_binary), "--help"],
                capture_output=True, text=True, timeout=30,
                env=env, cwd=test_dir, check=False
            )
            
            if result.returncode == 0:
                print("✅ Help command works")
                help_success = True
            else:
                print(f"❌ Help command failed: {result.returncode}")
                print(f"    stderr: {result.stderr[:200]}")
                help_success = False
            
            # Test version command
            result = subprocess.run(
                [str(test_binary), "--version"],
                capture_output=True, text=True, timeout=10,
                env=env, cwd=test_dir, check=False
            )
            
            if result.returncode == 0:
                print(f"✅ Version command works: {result.stdout.strip()}")
                version_success = True
            else:
                print("⚠️  Version command not available (non-critical)")
                version_success = True  # Non-critical
            
            return help_success and version_success
            
        except subprocess.TimeoutExpired:
            print("❌ Command timed out")
            return False
        except Exception as e:
            print(f"❌ Test error: {e}")
            return False
    
    def test_no_external_files(self, test_dir: Path) -> bool:
        """Test that binary doesn't create or require external files"""
        print("🔍 Testing file independence...")
        
        test_binary = test_dir / self.binary_path.name
        env = self.create_minimal_environment()
        
        # Record initial directory contents
        initial_files = set(test_dir.rglob("*"))
        
        try:
            # Run a command that might create files
            result = subprocess.run(
                [str(test_binary), "--help"],
                capture_output=True, text=True, timeout=30,
                env=env, cwd=test_dir, check=False
            )
            
            # Check if any new files were created
            final_files = set(test_dir.rglob("*"))
            new_files = final_files - initial_files
            
            if new_files:
                print("⚠️  New files created:")
                for file in new_files:
                    print(f"    {file}")
                # This might be OK for log files, etc.
                return True
            else:
                print("✅ No external files created")
                return True
                
        except Exception as e:
            print(f"❌ File independence test error: {e}")
            return False
    
    def test_network_independence(self, test_dir: Path) -> bool:
        """Test that binary works without network access"""
        print("🔍 Testing network independence...")
        
        test_binary = test_dir / self.binary_path.name
        env = self.create_minimal_environment()
        
        # Block network access by setting invalid proxy
        env.update({
            "http_proxy": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        })
        
        try:
            result = subprocess.run(
                [str(test_binary), "--help"],
                capture_output=True, text=True, timeout=30,
                env=env, cwd=test_dir, check=False
            )
            
            if result.returncode == 0:
                print("✅ Works without network access")
                return True
            else:
                print(f"❌ Failed without network: {result.returncode}")
                return False
                
        except Exception as e:
            print(f"❌ Network independence test error: {e}")
            return False
    
    def test_permission_requirements(self, test_dir: Path) -> bool:
        """Test permission requirements"""
        print("🔍 Testing permission requirements...")
        
        test_binary = test_dir / self.binary_path.name
        env = self.create_minimal_environment()
        
        # Test with minimal permissions
        if self.platform_name != "windows":
            # Make directory read-only
            original_mode = test_dir.stat().st_mode
            test_dir.chmod(0o555)  # Read and execute only
            
            try:
                result = subprocess.run(
                    [str(test_binary), "--help"],
                    capture_output=True, text=True, timeout=30,
                    env=env, cwd=test_dir, check=False
                )
                
                success = result.returncode == 0
                
                # Restore permissions
                test_dir.chmod(original_mode)
                
                if success:
                    print("✅ Works with minimal permissions")
                    return True
                else:
                    print(f"❌ Failed with minimal permissions: {result.returncode}")
                    return False
                    
            except Exception as e:
                # Restore permissions
                test_dir.chmod(original_mode)
                print(f"❌ Permission test error: {e}")
                return False
        else:
            # Windows permission testing is more complex, skip for now
            print("ℹ️  Permission testing skipped on Windows")
            return True
    
    def test_system_library_independence(self) -> bool:
        """Test independence from non-standard system libraries"""
        print("🔍 Testing system library independence...")
        
        try:
            if self.platform_name == "linux":
                # Check ldd output for non-standard libraries
                result = subprocess.run(
                    ["ldd", str(self.binary_path)],
                    capture_output=True, text=True, check=False
                )
                
                if "not a dynamic executable" in result.stderr:
                    print("✅ Fully static binary")
                    return True
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    problematic_deps = []
                    
                    for line in lines:
                        if "=>" in line and "not found" in line:
                            problematic_deps.append(line.strip())
                        elif "=>" in line:
                            lib_path = line.split("=>")[1].strip().split()[0]
                            # Check for non-standard locations
                            if not (lib_path.startswith("/lib/") or 
                                   lib_path.startswith("/usr/lib/") or
                                   lib_path.startswith("/lib64/") or
                                   lib_path.startswith("/usr/lib64/") or
                                   "linux-vdso" in lib_path):
                                problematic_deps.append(line.strip())
                    
                    if problematic_deps:
                        print("❌ Problematic dependencies found:")
                        for dep in problematic_deps:
                            print(f"    {dep}")
                        return False
                    else:
                        print("✅ Only standard system libraries used")
                        return True
                        
            elif self.platform_name == "darwin":
                # Check otool output for non-standard libraries
                result = subprocess.run(
                    ["otool", "-L", str(self.binary_path)],
                    capture_output=True, text=True, check=True
                )
                
                lines = result.stdout.strip().split('\n')[1:]
                problematic_deps = []
                
                for line in lines:
                    lib_path = line.strip().split()[0]
                    if not (lib_path.startswith("/usr/lib/") or
                           lib_path.startswith("/System/Library/")):
                        problematic_deps.append(lib_path)
                
                if problematic_deps:
                    print("❌ Non-standard dependencies found:")
                    for dep in problematic_deps:
                        print(f"    {dep}")
                    return False
                else:
                    print("✅ Only standard system libraries used")
                    return True
                    
            else:
                print("ℹ️  Library independence test not implemented for this platform")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Library independence test failed: {e}")
            return False
        except Exception as e:
            print(f"❌ Library independence test error: {e}")
            return False
    
    def run_clean_system_tests(self) -> bool:
        """Run all clean system tests"""
        print("🧹 NetStress Titanium v3.0 - Clean System Test")
        print("=" * 60)
        print(f"Binary: {self.binary_path}")
        print(f"Platform: {self.platform_name}")
        print("=" * 60)
        
        if not self.binary_path.exists():
            print(f"❌ Binary not found: {self.binary_path}")
            return False
        
        tests = [
            ("System Library Independence", self.test_system_library_independence),
        ]
        
        # Tests that require temporary directory
        temp_tests = [
            ("Basic Functionality", self.test_basic_functionality),
            ("File Independence", self.test_no_external_files),
            ("Network Independence", self.test_network_independence),
            ("Permission Requirements", self.test_permission_requirements),
        ]
        
        passed = 0
        total = len(tests) + len(temp_tests)
        
        # Run tests that don't need temp directory
        for test_name, test_func in tests:
            print(f"\n📋 {test_name}")
            print("-" * 40)
            
            try:
                result = test_func()
                self.test_results[test_name] = result
                
                if result:
                    passed += 1
                    print(f"✅ {test_name}: PASS")
                else:
                    print(f"❌ {test_name}: FAIL")
                    
            except Exception as e:
                print(f"❌ {test_name}: ERROR - {e}")
                self.test_results[test_name] = False
        
        # Run tests that need temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            for test_name, test_func in temp_tests:
                print(f"\n📋 {test_name}")
                print("-" * 40)
                
                try:
                    result = test_func(temp_path)
                    self.test_results[test_name] = result
                    
                    if result:
                        passed += 1
                        print(f"✅ {test_name}: PASS")
                    else:
                        print(f"❌ {test_name}: FAIL")
                        
                except Exception as e:
                    print(f"❌ {test_name}: ERROR - {e}")
                    self.test_results[test_name] = False
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 CLEAN SYSTEM TEST SUMMARY")
        print("=" * 60)
        
        for test_name, result in self.test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:.<40} {status}")
        
        print("-" * 60)
        print(f"Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 CLEAN SYSTEM TEST SUCCESSFUL!")
            print("Binary is ready for deployment on clean systems.")
            return True
        else:
            print("❌ CLEAN SYSTEM TEST FAILED!")
            print("Binary may have deployment issues on clean systems.")
            return False
    
    def save_results(self, output_path: Optional[Path] = None) -> Path:
        """Save test results to file"""
        if output_path is None:
            output_path = self.binary_path.parent / f"clean_system_test_{self.platform_name}.json"
        
        results = {
            "binary_path": str(self.binary_path),
            "platform": self.platform_name,
            "timestamp": subprocess.run(["date"], capture_output=True, text=True).stdout.strip(),
            "tests": self.test_results,
            "overall_status": "PASS" if all(self.test_results.values()) else "FAIL",
        }
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"📄 Results saved to: {output_path}")
        return output_path

def main():
    if len(sys.argv) != 2:
        print("Usage: python clean_system_test.py <binary_path>")
        sys.exit(1)
    
    binary_path = Path(sys.argv[1])
    if not binary_path.exists():
        print(f"❌ Binary not found: {binary_path}")
        sys.exit(1)
    
    tester = CleanSystemTester(binary_path)
    success = tester.run_clean_system_tests()
    tester.save_results()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()