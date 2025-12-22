#!/usr/bin/env python3
"""
NetStress Release Script

Creates a new release by:
1. Updating version numbers
2. Creating a git tag
3. Pushing to trigger GitHub Actions build

Usage:
    python scripts/release.py v3.0.1
    python scripts/release.py v3.0.1 --push
"""

import argparse
import subprocess
import sys
import re
from pathlib import Path


def run_command(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return result"""
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def validate_version(version: str) -> bool:
    """Validate version format (vX.Y.Z)"""
    pattern = r'^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$'
    return bool(re.match(pattern, version))


def update_version_in_file(filepath: Path, version: str):
    """Update version string in a file"""
    if not filepath.exists():
        return False
        
    content = filepath.read_text()
    
    # Common version patterns
    patterns = [
        (r'version\s*=\s*["\'][^"\']+["\']', f'version = "{version.lstrip("v")}"'),
        (r'__version__\s*=\s*["\'][^"\']+["\']', f'__version__ = "{version.lstrip("v")}"'),
        (r'VERSION\s*=\s*["\'][^"\']+["\']', f'VERSION = "{version.lstrip("v")}"'),
    ]
    
    updated = False
    for pattern, replacement in patterns:
        if re.search(pattern, content):
            content = re.sub(pattern, replacement, content)
            updated = True
            
    if updated:
        filepath.write_text(content)
        print(f"  Updated {filepath}")
        
    return updated


def main():
    parser = argparse.ArgumentParser(description='Create NetStress release')
    parser.add_argument('version', help='Version tag (e.g., v3.0.1)')
    parser.add_argument('--push', action='store_true', help='Push tag to trigger build')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done')
    args = parser.parse_args()
    
    version = args.version
    
    # Validate version
    if not validate_version(version):
        print(f"Error: Invalid version format '{version}'")
        print("Expected format: vX.Y.Z (e.g., v3.0.1)")
        sys.exit(1)
    
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║     NetStress Release Script                                  ║
╚═══════════════════════════════════════════════════════════════╝

Version: {version}
Dry Run: {args.dry_run}
""")
    
    if args.dry_run:
        print("DRY RUN - No changes will be made\n")
    
    # Step 1: Update version in files
    print("[1/4] Updating version numbers...")
    
    version_files = [
        Path('pyproject.toml'),
        Path('setup.py'),
        Path('core/__init__.py'),
        Path('ddos.py'),
    ]
    
    for filepath in version_files:
        if not args.dry_run:
            update_version_in_file(filepath, version)
        else:
            print(f"  Would update {filepath}")
    
    # Step 2: Git add changes
    print("\n[2/4] Staging changes...")
    
    if not args.dry_run:
        run_command(['git', 'add', '-A'])
    else:
        print("  Would run: git add -A")
    
    # Step 3: Create commit and tag
    print("\n[3/4] Creating commit and tag...")
    
    commit_msg = f"Release {version}"
    
    if not args.dry_run:
        # Check if there are changes to commit
        result = run_command(['git', 'status', '--porcelain'], check=False)
        if result.stdout.strip():
            run_command(['git', 'commit', '-m', commit_msg])
        else:
            print("  No changes to commit")
            
        # Create tag
        run_command(['git', 'tag', '-a', version, '-m', f'NetStress Titanium {version}'])
        print(f"  Created tag: {version}")
    else:
        print(f"  Would run: git commit -m '{commit_msg}'")
        print(f"  Would run: git tag -a {version} -m 'NetStress Titanium {version}'")
    
    # Step 4: Push (optional)
    print("\n[4/4] Pushing to remote...")
    
    if args.push:
        if not args.dry_run:
            run_command(['git', 'push', 'origin', 'main'])
            run_command(['git', 'push', 'origin', version])
            print(f"\n✅ Release {version} pushed!")
            print("   GitHub Actions will now build and publish binaries.")
        else:
            print("  Would run: git push origin main")
            print(f"  Would run: git push origin {version}")
    else:
        print("  Skipped (use --push to push)")
        print(f"\n  To push manually:")
        print(f"    git push origin main")
        print(f"    git push origin {version}")
    
    print(f"""
═══════════════════════════════════════════════════════════════
Release {version} {'created' if not args.dry_run else 'would be created'}!

Next steps:
1. {'Push the tag to trigger CI build' if not args.push else 'Wait for GitHub Actions to complete'}
2. Check releases at: https://github.com/YOUR_REPO/releases
3. Download binaries and verify checksums
═══════════════════════════════════════════════════════════════
""")


if __name__ == '__main__':
    main()
