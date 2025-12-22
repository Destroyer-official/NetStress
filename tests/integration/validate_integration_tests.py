#!/usr/bin/env python3
"""
Integration Test Validation Script
Validates that all required integration tests are implemented and complete

**Feature: military-grade-transformation**
**Task: 21.3 Add Python integration tests**
"""

import os
import re
import sys
from pathlib import Path

def check_file_exists(filename, description=""):
    """Check if a file exists and return status"""
    if os.path.exists(filename):
        print(f"  ✓ {description}: {filename}")
        return True
    else:
        print(f"  ✗ {description}: {filename} (MISSING)")
        return False

def check_test_functions_in_file(filename, min_tests=3):
    """Check if a test file has sufficient test functions"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Count test functions
            test_functions = re.findall(r'def\s+test_\w+\s*\(', content)
            test_classes = re.findall(r'class\s+Test\w+.*:', content)
            
            print(f"  ✓ Test functions: {len(test_functions)} in {len(test_classes)} classes")
            
            if len(test_functions) >= min_tests:
                return True
            else:
                print(f"  ⚠ Only {len(test_functions)} test functions (minimum {min_tests})")
                return False
                
    except FileNotFoundError:
        print(f"  ✗ File not found: {filename}")
        return False

def check_requirement_coverage(filename):
    """Check if test file covers military-grade requirements"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Look for requirement references
            req_matches = re.findall(r'Requirements?\s+([\d\.,\s]+)', content)
            validates_matches = re.findall(r'Validates:\s*Requirements?\s+([\d\.,\s]+)', content)
            
            requirements_found = set()
            for match in req_matches + validates_matches:
                individual_reqs = re.findall(r'(\d+\.\d+)', match)
                requirements_found.update(individual_reqs)
            
            if requirements_found:
                print(f"  ✓ Requirements covered: {', '.join(sorted(requirements_found))}")
                return True
            else:
                print(f"  ⚠ No explicit requirement references found")
                return False
                
    except FileNotFoundError:
        return False

def check_integration_patterns(filename):
    """Check for integration test patterns"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            patterns = {
                'mock_usage': r'Mock|patch|MagicMock',
                'threading': r'threading|Thread',
                'performance': r'time\.perf_counter|psutil',
                'error_handling': r'pytest\.raises|except|try:',
                'skip_conditions': r'pytest\.skip',
                'imports': r'import.*netstress_engine|from.*core\.',
            }
            
            found_patterns = []
            for pattern_name, pattern in patterns.items():
                if re.search(pattern, content):
                    found_patterns.append(pattern_name)
            
            print(f"  ✓ Integration patterns: {', '.join(found_patterns)}")
            return len(found_patterns) >= 3
            
    except FileNotFoundError:
        return False

def validate_core_integration_tests():
    """Validate core integration test files"""
    print("1. Core Integration Tests:")
    
    all_passed = True
    
    # Main military-grade integration test
    test_file = "test_military_grade_integration.py"
    all_passed &= check_file_exists(test_file, "Military-Grade Integration Tests")
    if os.path.exists(test_file):
        all_passed &= check_test_functions_in_file(test_file, 15)
        all_passed &= check_requirement_coverage(test_file)
        all_passed &= check_integration_patterns(test_file)
    
    # TLS and timing integration
    test_file = "test_tls_precision_integration.py"
    all_passed &= check_file_exists(test_file, "TLS/Precision Integration Tests")
    if os.path.exists(test_file):
        all_passed &= check_test_functions_in_file(test_file, 10)
        all_passed &= check_requirement_coverage(test_file)
        all_passed &= check_integration_patterns(test_file)
    
    return all_passed

def validate_existing_integration_tests():
    """Validate existing integration test files"""
    print("\n2. Existing Integration Tests:")
    
    all_passed = True
    
    existing_tests = [
        ("test_native_engine.py", "Native Engine Integration"),
        ("test_rust_python_integration.py", "Rust-Python Bindings"),
        ("test_c_driver_integration.py", "C Driver Integration"),
    ]
    
    for test_file, description in existing_tests:
        if os.path.exists(test_file):
            print(f"  ✓ {description}: {test_file}")
            all_passed &= check_test_functions_in_file(test_file, 5)
            all_passed &= check_integration_patterns(test_file)
        else:
            print(f"  ⚠ {description}: {test_file} (not found, may be optional)")
    
    return all_passed

def validate_test_infrastructure():
    """Validate test infrastructure"""
    print("\n3. Test Infrastructure:")
    
    all_passed = True
    
    # Test runner
    all_passed &= check_file_exists("run_integration_tests.py", "Integration Test Runner")
    
    # Test validation
    all_passed &= check_file_exists("validate_integration_tests.py", "Test Validation Script")
    
    # Check for pytest configuration
    pytest_files = ["pytest.ini", "pyproject.toml", "setup.cfg"]
    pytest_found = any(os.path.exists(f"../{f}") for f in pytest_files)
    
    if pytest_found:
        print("  ✓ Pytest configuration found")
    else:
        print("  ⚠ No pytest configuration found")
        all_passed = False
    
    return all_passed

def validate_test_coverage_areas():
    """Validate that all required test coverage areas are addressed"""
    print("\n4. Test Coverage Areas:")
    
    coverage_areas = {
        "Python → Rust → C Flow": [
            "test_military_grade_integration.py",
            "test_native_engine.py"
        ],
        "Distributed Coordination": [
            "test_military_grade_integration.py",
            "test_distributed.py"
        ],
        "Telemetry Streaming": [
            "test_military_grade_integration.py",
            "test_native_stats_integration.py"
        ],
        "TLS/JA3 Spoofing": [
            "test_tls_precision_integration.py",
            "test_attacks_advanced.py"
        ],
        "Precision Timing": [
            "test_tls_precision_integration.py"
        ],
        "Backend Selection": [
            "test_military_grade_integration.py",
            "test_native_engine.py"
        ],
        "Error Handling": [
            "test_military_grade_integration.py",
            "test_rust_python_integration.py"
        ],
        "Performance Testing": [
            "test_military_grade_integration.py"
        ]
    }
    
    all_passed = True
    
    for area, test_files in coverage_areas.items():
        found_files = [f for f in test_files if os.path.exists(f)]
        
        if found_files:
            print(f"  ✓ {area}: {', '.join(found_files)}")
        else:
            print(f"  ✗ {area}: No test files found")
            all_passed = False
    
    return all_passed

def validate_requirements_mapping():
    """Validate that tests map to military-grade requirements"""
    print("\n5. Requirements Mapping:")
    
    # Expected requirements for integration tests
    expected_requirements = {
        "1.1": "Rust engine JSON configuration",
        "1.2": "Multi-threading without GIL",
        "1.3": "PyO3 bindings",
        "1.4": "1M+ PPS throughput",
        "1.5": "Zero-copy data transfer",
        "2.1": "Browser fingerprint matching",
        "2.2": "TLS handshake control",
        "2.3": "Chrome 120 JA3 hash",
        "2.4": "Firefox 121 JA3 hash",
        "2.5": "Safari 17 JA3 hash",
        "2.6": "iPhone 15 JA3 hash",
        "3.1": "Microsecond timing precision",
        "3.2": "TSC hardware timing",
        "3.3": "Traffic pattern support",
        "3.4": "100μs timing variance",
        "3.5": "Nanosecond rate limiting",
        "7.1": "Unix timestamp coordination",
        "7.2": "Millisecond precision scheduling",
        "7.3": "Sub-millisecond synchronization",
        "8.1": "Shared memory stats",
        "8.2": "Zero IPC overhead",
        "8.3": "Microsecond update frequency"
    }
    
    # Check which requirements are covered
    covered_requirements = set()
    
    test_files = [
        "test_military_grade_integration.py",
        "test_tls_precision_integration.py"
    ]
    
    for test_file in test_files:
        if os.path.exists(test_file):
            try:
                with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Find requirement references
                    req_matches = re.findall(r'(\d+\.\d+)', content)
                    covered_requirements.update(req_matches)
                    
            except Exception:
                pass
    
    # Report coverage
    for req_id, description in expected_requirements.items():
        if req_id in covered_requirements:
            print(f"  ✓ Requirement {req_id}: {description}")
        else:
            print(f"  ⚠ Requirement {req_id}: {description} (not explicitly covered)")
    
    coverage_percentage = len(covered_requirements) / len(expected_requirements) * 100
    print(f"\nRequirement coverage: {len(covered_requirements)}/{len(expected_requirements)} ({coverage_percentage:.1f}%)")
    
    return coverage_percentage >= 80  # 80% coverage threshold

def main():
    """Main validation function"""
    print("=== Integration Test Validation ===\n")
    
    # Change to tests directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    all_passed = True
    
    # Run all validation checks
    all_passed &= validate_core_integration_tests()
    all_passed &= validate_existing_integration_tests()
    all_passed &= validate_test_infrastructure()
    all_passed &= validate_test_coverage_areas()
    all_passed &= validate_requirements_mapping()
    
    # Summary
    print("\n" + "="*50)
    if all_passed:
        print("✅ ALL VALIDATION CHECKS PASSED!")
        print("\nIntegration Test Suite Summary:")
        print("- ✓ Core military-grade integration tests implemented")
        print("- ✓ TLS/JA3 and precision timing tests implemented")
        print("- ✓ Python → Rust → C flow testing")
        print("- ✓ Distributed coordination testing")
        print("- ✓ Telemetry streaming testing")
        print("- ✓ Error handling and edge cases")
        print("- ✓ Performance and memory testing")
        print("- ✓ Requirements traceability")
        
        print("\nNext Steps:")
        print("1. Run integration tests: python run_integration_tests.py")
        print("2. Check test results and fix any failures")
        print("3. Run on target platforms (Linux with DPDK/XDP)")
        print("4. Validate performance benchmarks")
        
        return 0
    else:
        print("❌ SOME VALIDATION CHECKS FAILED!")
        print("\nPlease address the failed checks above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())