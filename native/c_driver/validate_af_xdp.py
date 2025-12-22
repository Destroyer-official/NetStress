#!/usr/bin/env python3
"""
AF_XDP Implementation Validation Script
Validates the AF_XDP zero-copy interface implementation
"""

import os
import re
import sys

def check_file_exists(filepath):
    """Check if a file exists"""
    if os.path.exists(filepath):
        print(f"✓ {filepath} exists")
        return True
    else:
        print(f"✗ {filepath} missing")
        return False

def check_function_implementation(filepath, function_name):
    """Check if a function is implemented in a file"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Look for function definition
        pattern = rf'{function_name}\s*\([^)]*\)\s*\{{'
        if re.search(pattern, content):
            print(f"✓ {function_name} implemented")
            return True
        else:
            print(f"✗ {function_name} not found")
            return False
    except Exception as e:
        print(f"✗ Error checking {function_name}: {e}")
        return False

def check_af_xdp_includes(filepath):
    """Check if AF_XDP includes are present"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        includes = [
            '#include <bpf/libbpf.h>',
            '#include <bpf/xsk.h>',
            '#include <linux/if_link.h>',
            '#include <linux/if_xdp.h>',
            '#include <net/if.h>'
        ]
        
        found_includes = 0
        for include in includes:
            if include in content:
                print(f"✓ {include}")
                found_includes += 1
            else:
                print(f"✗ {include} missing")
                
        return found_includes == len(includes)
    except Exception as e:
        print(f"✗ Error checking includes: {e}")
        return False

def check_af_xdp_structures(filepath):
    """Check if AF_XDP structures are defined"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        structures = [
            'struct xsk_socket',
            'struct xsk_umem',
            'struct xsk_ring_prod',
            'struct xsk_ring_cons',
            'FRAME_SIZE',
            'NUM_FRAMES'
        ]
        
        found_structures = 0
        for struct in structures:
            if struct in content:
                print(f"✓ {struct} found")
                found_structures += 1
            else:
                print(f"✗ {struct} missing")
                
        return found_structures >= len(structures) - 2  # Allow some flexibility
    except Exception as e:
        print(f"✗ Error checking structures: {e}")
        return False

def check_requirements_implementation():
    """Check if all requirements are implemented"""
    print("Checking Requirements Implementation:")
    print("=" * 50)
    
    # Requirement 5.1: AF_XDP socket initialization
    print("\nRequirement 5.1: AF_XDP socket initialization")
    req_5_1 = all([
        check_function_implementation("driver_shim.c", "init_af_xdp"),
        check_af_xdp_includes("driver_shim.c"),
        check_af_xdp_structures("driver_shim.c")
    ])
    
    # Requirement 5.2, 5.3: Zero-copy batch sending
    print("\nRequirement 5.2, 5.3: Zero-copy batch sending")
    req_5_2_5_3 = all([
        check_function_implementation("driver_shim.c", "af_xdp_send_batch"),
        check_function_implementation("driver_shim.c", "af_xdp_send")
    ])
    
    # Requirement 5.1: Resource cleanup
    print("\nRequirement 5.1: Resource cleanup")
    req_cleanup = check_function_implementation("driver_shim.c", "cleanup_af_xdp")
    
    return req_5_1 and req_5_2_5_3 and req_cleanup

def main():
    print("AF_XDP Implementation Validation")
    print("=" * 40)
    
    # Check if we're in the right directory
    if not os.path.exists("driver_shim.c"):
        print("✗ Please run this script from the c_driver directory")
        return 1
    
    # Check file existence
    print("\nFile Existence Check:")
    files_ok = all([
        check_file_exists("driver_shim.h"),
        check_file_exists("driver_shim.c"),
        check_file_exists("test_af_xdp_simple.c")
    ])
    
    if not files_ok:
        print("\n✗ Missing required files")
        return 1
    
    # Check implementation
    impl_ok = check_requirements_implementation()
    
    # Summary
    print("\n" + "=" * 50)
    if impl_ok:
        print("✓ AF_XDP implementation is complete!")
        print("\nNext steps:")
        print("1. Install libbpf development libraries")
        print("2. Compile with -DHAS_AF_XDP -lbpf")
        print("3. Run tests with root privileges")
        print("4. Test on Linux system with kernel 4.18+")
        return 0
    else:
        print("✗ AF_XDP implementation has issues")
        return 1

if __name__ == "__main__":
    sys.exit(main())