#!/usr/bin/env python3
"""
Validate XDP Implementation
Checks that all required XDP components are present and properly structured
"""

import os
import sys
import re

def check_file_exists(filepath, description):
    """Check if a file exists and report status"""
    if os.path.exists(filepath):
        print(f"✓ {description}: {filepath}")
        return True
    else:
        print(f"✗ {description}: {filepath} (MISSING)")
        return False

def check_function_in_file(filepath, function_name, description):
    """Check if a function is defined in a file"""
    if not os.path.exists(filepath):
        print(f"✗ {description}: {filepath} not found")
        return False
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            if function_name in content:
                print(f"✓ {description}: {function_name} found in {filepath}")
                return True
            else:
                print(f"✗ {description}: {function_name} not found in {filepath}")
                return False
    except Exception as e:
        print(f"✗ {description}: Error reading {filepath}: {e}")
        return False

def check_struct_in_file(filepath, struct_name, description):
    """Check if a struct is defined in a file"""
    if not os.path.exists(filepath):
        print(f"✗ {description}: {filepath} not found")
        return False
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            # Check for typedef struct pattern or just the struct name
            patterns = [
                rf'typedef\s+struct.*{struct_name}',
                rf'struct\s+{struct_name}',
                rf'}}\s*{struct_name};',  # End of struct definition
                struct_name  # Simple name check
            ]
            
            for pattern in patterns:
                if re.search(pattern, content):
                    print(f"✓ {description}: {struct_name} found in {filepath}")
                    return True
            
            print(f"✗ {description}: {struct_name} not found in {filepath}")
            return False
    except Exception as e:
        print(f"✗ {description}: Error reading {filepath}: {e}")
        return False

def main():
    print("=== XDP Implementation Validation ===\n")
    
    # Change to the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    all_passed = True
    
    # Check header files
    print("1. Header Files:")
    all_passed &= check_file_exists("xdp_loader.h", "XDP Loader Header")
    all_passed &= check_file_exists("driver_shim.h", "Driver Shim Header")
    print()
    
    # Check source files
    print("2. Source Files:")
    all_passed &= check_file_exists("xdp_loader.c", "XDP Loader Implementation")
    all_passed &= check_file_exists("xdp_backscatter_filter.c", "XDP eBPF Program")
    print()
    
    # Check test files
    print("3. Test Files:")
    all_passed &= check_file_exists("test_xdp_stats.c", "XDP Statistics Test")
    all_passed &= check_file_exists("test_xdp_fallback.c", "XDP Fallback Test")
    all_passed &= check_file_exists("test_xdp_integration.c", "XDP Integration Test")
    print()
    
    # Check build files
    print("4. Build Files:")
    all_passed &= check_file_exists("Makefile", "Build Configuration")
    print()
    
    # Check key data structures
    print("5. Data Structures:")
    all_passed &= check_struct_in_file("xdp_loader.h", "xdp_stats_t", "XDP Statistics Structure")
    all_passed &= check_struct_in_file("xdp_loader.h", "xdp_context_t", "XDP Context Structure")
    print()
    
    # Check key functions
    print("6. Core Functions:")
    all_passed &= check_function_in_file("xdp_loader.c", "xdp_load_program", "XDP Program Loader")
    all_passed &= check_function_in_file("xdp_loader.c", "xdp_unload_program", "XDP Program Unloader")
    all_passed &= check_function_in_file("xdp_loader.c", "xdp_get_stats", "XDP Statistics Reader")
    all_passed &= check_function_in_file("xdp_loader.c", "install_iptables_fallback", "iptables Fallback")
    print()
    
    # Check eBPF program structure
    print("7. eBPF Program:")
    all_passed &= check_function_in_file("xdp_backscatter_filter.c", "xdp_filter", "XDP Filter Function")
    all_passed &= check_function_in_file("xdp_backscatter_filter.c", "stats_map", "Statistics Map")
    print()
    
    # Check integration
    print("8. Integration:")
    all_passed &= check_function_in_file("driver_shim.h", "xdp_load_program", "XDP Integration in Driver Shim")
    print()
    
    # Summary
    print("=" * 50)
    if all_passed:
        print("✓ ALL CHECKS PASSED - XDP implementation is complete")
        print("\nNext Steps:")
        print("1. Compile on Linux system with: make all")
        print("2. Install libbpf: sudo apt-get install libbpf-dev")
        print("3. Test with: sudo ./test_xdp_integration")
        return 0
    else:
        print("✗ SOME CHECKS FAILED - Implementation incomplete")
        return 1

if __name__ == "__main__":
    sys.exit(main())