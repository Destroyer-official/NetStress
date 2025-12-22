#!/usr/bin/env python3
"""
Integration Test Runner for Military-Grade Transformation
Runs comprehensive integration tests for the Python → Rust → C flow

**Feature: military-grade-transformation**
**Validates: All integration requirements**
"""

import sys
import os
import subprocess
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_test_suite(test_file, description):
    """Run a specific test suite"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"File: {test_file}")
    print('='*60)
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            test_file, 
            "-v", "-s", "--tb=short"
        ], capture_output=True, text=True, timeout=300)
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        return result.returncode == 0
    
    except subprocess.TimeoutExpired:
        print(f"❌ Test suite timed out: {test_file}")
        return False
    except Exception as e:
        print(f"❌ Error running test suite: {e}")
        return False

def check_dependencies():
    """Check if required dependencies are available"""
    print("Checking dependencies...")
    
    dependencies = {
        'pytest': 'pytest',
        'psutil': 'psutil (for performance tests)',
        'zmq': 'pyzmq (for telemetry tests)',
    }
    
    missing = []
    available = []
    
    for module, description in dependencies.items():
        try:
            __import__(module)
            available.append(description)
        except ImportError:
            missing.append(description)
    
    print(f"✓ Available: {', '.join(available)}")
    if missing:
        print(f"⚠ Missing (tests may be skipped): {', '.join(missing)}")
    
    return len(available) > 0

def main():
    """Main test runner"""
    print("Military-Grade Transformation Integration Test Suite")
    print("="*60)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ No test dependencies available")
        return 1
    
    # Define test suites
    test_suites = [
        ("test_military_grade_integration.py", "Core Military-Grade Integration Tests"),
        ("test_tls_precision_integration.py", "TLS/JA3 and Precision Timing Tests"),
        ("test_native_engine.py", "Native Engine Integration Tests"),
        ("test_rust_python_integration.py", "Rust-Python Binding Tests"),
        ("test_c_driver_integration.py", "C Driver Integration Tests"),
    ]
    
    # Track results
    results = {}
    start_time = time.time()
    
    # Run each test suite
    for test_file, description in test_suites:
        test_path = Path(__file__).parent / test_file
        
        if test_path.exists():
            success = run_test_suite(str(test_path), description)
            results[test_file] = success
        else:
            print(f"⚠ Test file not found: {test_file}")
            results[test_file] = None
    
    # Print summary
    total_time = time.time() - start_time
    
    print(f"\n{'='*60}")
    print("INTEGRATION TEST SUMMARY")
    print('='*60)
    
    passed = sum(1 for result in results.values() if result is True)
    failed = sum(1 for result in results.values() if result is False)
    skipped = sum(1 for result in results.values() if result is None)
    
    for test_file, result in results.items():
        if result is True:
            print(f"✓ PASSED: {test_file}")
        elif result is False:
            print(f"❌ FAILED: {test_file}")
        else:
            print(f"⚠ SKIPPED: {test_file}")
    
    print(f"\nResults: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"Total time: {total_time:.1f} seconds")
    
    # Overall result
    if failed > 0:
        print("\n❌ Some integration tests failed!")
        return 1
    elif passed > 0:
        print("\n✅ All available integration tests passed!")
        return 0
    else:
        print("\n⚠ No tests were run successfully")
        return 1

if __name__ == "__main__":
    sys.exit(main())