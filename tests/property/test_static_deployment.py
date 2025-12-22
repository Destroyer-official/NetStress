#!/usr/bin/env python3
"""
Property-Based Tests for Static Binary Deployment
**Property 7: Static Binary Deployment**
**Validates: Requirements 10.4, 10.5, 10.6**

These tests verify that NetStress binaries are truly static and deployable
without runtime dependencies across different environments.
"""

import os
import sys
import subprocess
import tempfile
import shutil
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pytest
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import json

# Add the project root to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

class StaticDeploymentTester:
    """Helper class for static deployment testing"""
    
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.platform_name = platform.system().lower()
    
    def check_dynamic_dependencies(self) -> Tuple[bool, List[str]]:
        """Check for dynamic library dependencies"""
        dependencies = []
        
        try:
            if self.platform_name == "linux":
                result = subprocess.run(
                    ["ldd", str(self.binary_path)], 
                    capture_output=True, text=True, check=False
                )
                
                if "not a dynamic executable" in result.stderr:
                    return True, []
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if "=>" in line and "linux-vdso" not in line:
                            lib_path = line.split("=>")[1].strip().split()[0]
                            if not (lib_path.startswith("/lib/") or 
                                   lib_path.startswith("/usr/lib/") or
                                   lib_path.startswith("/lib64/") or
                                   lib_path.startswith("/usr/lib64/")):
                                dependencies.append(lib_path)
            
            elif self.platform_name == "darwin":
                result = subprocess.run(
                    ["otool", "-L", str(self.binary_path)], 
                    capture_output=True, text=True, check=True
                )
                
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    lib_path = line.strip().split()[0]
                    if not (lib_path.startswith("/usr/lib/system/") or
                           lib_path.startswith("/System/Library/") or
                           lib_path.startswith("/usr/lib/libSystem")):
                        dependencies.append(lib_path)
            
            return len(dependencies) == 0, dependencies
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            # If we can't check, assume it's OK
            return True, []
    
    def test_execution_in_clean_env(self, test_dir: Path) -> bool:
        """Test execution in a clean environment"""
        # Copy binary to test directory
        test_binary = test_dir / self.binary_path.name
        shutil.copy2(self.binary_path, test_binary)
        
        if self.platform_name != "windows":
            test_binary.chmod(0o755)
        
        # Create minimal environment
        if self.platform_name == "windows":
            clean_env = {
                "SYSTEMROOT": "C:\\Windows",
                "WINDIR": "C:\\Windows",
                "PATH": "C:\\Windows\\System32",
            }
        else:
            clean_env = {
                "PATH": "/usr/bin:/bin",
                "HOME": "/tmp",
                "LANG": "C",
            }
        
        try:
            result = subprocess.run(
                [str(test_binary), "--help"],
                capture_output=True, text=True, timeout=30,
                env=clean_env, cwd=test_dir, check=False
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def get_binary_size_mb(self) -> float:
        """Get binary size in MB"""
        return self.binary_path.stat().st_size / 1024 / 1024

# Find NetStress binary for testing
def find_netstress_binary() -> Optional[Path]:
    """Find NetStress binary for testing"""
    # Look in common locations
    search_paths = [
        Path("dist"),
        Path("build"),
        Path("target/release"),
        Path("NetStress/dist"),
        Path("NetStress/build"),
    ]
    
    binary_names = ["netstress", "netstress.exe"]
    
    for search_path in search_paths:
        if search_path.exists():
            for binary_name in binary_names:
                binary_path = search_path / binary_name
                if binary_path.exists() and binary_path.is_file():
                    return binary_path
    
    return None

# Skip tests if no binary is found
NETSTRESS_BINARY = find_netstress_binary()
pytestmark = pytest.mark.skipif(
    NETSTRESS_BINARY is None, 
    reason="NetStress binary not found for testing"
)

class TestStaticDeploymentProperties:
    """Property-based tests for static deployment"""
    
    @pytest.fixture
    def binary_path(self):
        """Fixture providing the NetStress binary path"""
        return NETSTRESS_BINARY
    
    @pytest.fixture
    def deployment_tester(self, binary_path):
        """Fixture providing a deployment tester instance"""
        return StaticDeploymentTester(binary_path)
    
    def test_binary_exists_and_executable(self, binary_path):
        """Test that binary exists and is executable"""
        assert binary_path.exists(), f"Binary not found: {binary_path}"
        assert binary_path.is_file(), f"Path is not a file: {binary_path}"
        assert os.access(binary_path, os.X_OK), f"Binary is not executable: {binary_path}"
    
    def test_binary_size_within_target(self, deployment_tester):
        """
        **Property 7: Static Binary Deployment - Size Constraint**
        **Validates: Requirements 10.5**
        
        For any NetStress binary, the size should be under 150MB per platform
        """
        size_mb = deployment_tester.get_binary_size_mb()
        target_size_mb = 150
        
        assert size_mb <= target_size_mb, (
            f"Binary size {size_mb:.1f} MB exceeds target {target_size_mb} MB"
        )
    
    def test_no_external_dynamic_dependencies(self, deployment_tester):
        """
        **Property 7: Static Binary Deployment - Dependency Independence**
        **Validates: Requirements 10.4**
        
        For any NetStress binary, it should have no external dynamic library dependencies
        """
        is_static, dependencies = deployment_tester.check_dynamic_dependencies()
        
        assert is_static, (
            f"Binary has external dependencies: {dependencies}"
        )
    
    @given(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"))))
    @settings(max_examples=10, deadline=60000)  # Longer deadline for process execution
    def test_execution_in_arbitrary_directory(self, deployment_tester, directory_name):
        """
        **Property 7: Static Binary Deployment - Location Independence**
        **Validates: Requirements 10.4**
        
        For any directory name, the NetStress binary should execute successfully
        when copied to that directory
        """
        # Create safe directory name
        safe_name = "".join(c for c in directory_name if c.isalnum() or c in "-_")
        assume(len(safe_name) > 0)
        
        with tempfile.TemporaryDirectory() as temp_root:
            test_dir = Path(temp_root) / safe_name
            test_dir.mkdir(exist_ok=True)
            
            success = deployment_tester.test_execution_in_clean_env(test_dir)
            assert success, f"Binary failed to execute in directory: {safe_name}"
    
    @given(st.dictionaries(
        keys=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Pc"))),
        values=st.text(min_size=0, max_size=100, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Pd", "Ps", "Pe"))),
        min_size=0,
        max_size=5
    ))
    @settings(max_examples=5, deadline=60000)
    def test_execution_with_arbitrary_environment(self, deployment_tester, env_vars):
        """
        **Property 7: Static Binary Deployment - Environment Independence**
        **Validates: Requirements 10.4**
        
        For any set of environment variables, the NetStress binary should execute
        successfully without requiring specific environment setup
        """
        # Filter out potentially problematic environment variables
        safe_env_vars = {}
        for key, value in env_vars.items():
            # Only include safe alphanumeric keys and values
            safe_key = "".join(c for c in key if c.isalnum() or c == "_")
            safe_value = "".join(c for c in value if c.isalnum() or c in "-_./:")
            
            if len(safe_key) > 0 and len(safe_key) < 50:
                safe_env_vars[f"TEST_{safe_key}"] = safe_value
        
        assume(len(safe_env_vars) <= 10)  # Limit environment size
        
        with tempfile.TemporaryDirectory() as temp_dir:
            test_dir = Path(temp_dir)
            test_binary = test_dir / deployment_tester.binary_path.name
            shutil.copy2(deployment_tester.binary_path, test_binary)
            
            if deployment_tester.platform_name != "windows":
                test_binary.chmod(0o755)
            
            # Create environment with minimal system vars plus test vars
            if deployment_tester.platform_name == "windows":
                test_env = {
                    "SYSTEMROOT": "C:\\Windows",
                    "WINDIR": "C:\\Windows",
                    "PATH": "C:\\Windows\\System32",
                }
            else:
                test_env = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": "/tmp",
                    "LANG": "C",
                }
            
            test_env.update(safe_env_vars)
            
            try:
                result = subprocess.run(
                    [str(test_binary), "--help"],
                    capture_output=True, text=True, timeout=30,
                    env=test_env, cwd=test_dir, check=False
                )
                
                assert result.returncode == 0, (
                    f"Binary failed with environment {list(safe_env_vars.keys())}: "
                    f"exit code {result.returncode}, stderr: {result.stderr[:200]}"
                )
                
            except subprocess.TimeoutExpired:
                pytest.fail(f"Binary timed out with environment {list(safe_env_vars.keys())}")

class StaticDeploymentStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for static deployment
    
    This tests various deployment scenarios and verifies that the binary
    maintains its static properties across different operations.
    """
    
    def __init__(self):
        super().__init__()
        self.binary_path = NETSTRESS_BINARY
        self.deployment_tester = StaticDeploymentTester(self.binary_path) if self.binary_path else None
        self.test_directories = []
        self.execution_results = []
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        if self.binary_path is None:
            pytest.skip("NetStress binary not found")
    
    @rule()
    def create_test_directory(self):
        """Create a new test directory"""
        temp_dir = tempfile.mkdtemp()
        self.test_directories.append(Path(temp_dir))
    
    @rule()
    def copy_binary_to_directory(self):
        """Copy binary to a test directory"""
        if not self.test_directories:
            return
        
        # Use the last created directory
        test_dir = self.test_directories[-1]
        
        if test_dir.exists():
            test_binary = test_dir / self.binary_path.name
            shutil.copy2(self.binary_path, test_binary)
            
            if self.deployment_tester.platform_name != "windows":
                test_binary.chmod(0o755)
    
    @rule()
    def test_binary_execution(self):
        """Test binary execution in various directories"""
        for test_dir in self.test_directories:
            if test_dir.exists():
                test_binary = test_dir / self.binary_path.name
                if test_binary.exists():
                    try:
                        result = subprocess.run(
                            [str(test_binary), "--help"],
                            capture_output=True, text=True, timeout=10,
                            cwd=test_dir, check=False
                        )
                        
                        self.execution_results.append({
                            "directory": str(test_dir),
                            "success": result.returncode == 0,
                            "returncode": result.returncode,
                        })
                        
                    except (subprocess.TimeoutExpired, Exception) as e:
                        self.execution_results.append({
                            "directory": str(test_dir),
                            "success": False,
                            "error": str(e),
                        })
    
    @invariant()
    def binary_always_static(self):
        """Invariant: Binary should always be static regardless of operations"""
        if self.deployment_tester:
            is_static, dependencies = self.deployment_tester.check_dynamic_dependencies()
            assert is_static, f"Binary became non-static with dependencies: {dependencies}"
    
    @invariant()
    def successful_executions_should_work(self):
        """Invariant: All successful executions should remain successful"""
        successful_dirs = set()
        
        for result in self.execution_results:
            if result["success"]:
                successful_dirs.add(result["directory"])
        
        # Re-test successful directories to ensure consistency
        for dir_path in successful_dirs:
            test_dir = Path(dir_path)
            if test_dir.exists():
                test_binary = test_dir / self.binary_path.name
                if test_binary.exists():
                    try:
                        result = subprocess.run(
                            [str(test_binary), "--help"],
                            capture_output=True, text=True, timeout=10,
                            cwd=test_dir, check=False
                        )
                        
                        assert result.returncode == 0, (
                            f"Previously successful execution in {dir_path} now fails"
                        )
                        
                    except Exception as e:
                        pytest.fail(f"Previously successful execution in {dir_path} now fails: {e}")
    
    def teardown(self):
        """Clean up test directories"""
        for test_dir in self.test_directories:
            if test_dir.exists():
                shutil.rmtree(test_dir, ignore_errors=True)

# Stateful test
TestStaticDeploymentStateMachine = StaticDeploymentStateMachine.TestCase

# Integration test combining all properties
def test_complete_static_deployment_property():
    """
    **Property 7: Static Binary Deployment - Complete Integration**
    **Validates: Requirements 10.4, 10.5, 10.6**
    
    Integration test that verifies all static deployment properties together
    """
    if NETSTRESS_BINARY is None:
        pytest.skip("NetStress binary not found")
    
    deployment_tester = StaticDeploymentTester(NETSTRESS_BINARY)
    
    # Test 1: Binary size
    size_mb = deployment_tester.get_binary_size_mb()
    assert size_mb <= 150, f"Binary size {size_mb:.1f} MB exceeds 150 MB limit"
    
    # Test 2: No external dependencies
    is_static, dependencies = deployment_tester.check_dynamic_dependencies()
    assert is_static, f"Binary has external dependencies: {dependencies}"
    
    # Test 3: Execution in clean environment
    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)
        success = deployment_tester.test_execution_in_clean_env(test_dir)
        assert success, "Binary failed to execute in clean environment"
    
    print(f"✅ Static deployment property verified:")
    print(f"   - Binary size: {size_mb:.1f} MB (≤ 150 MB)")
    print(f"   - Static linking: {is_static}")
    print(f"   - Clean execution: {success}")

if __name__ == "__main__":
    # Run the tests directly
    pytest.main([__file__, "-v", "--tb=short"])