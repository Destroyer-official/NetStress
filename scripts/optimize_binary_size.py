#!/usr/bin/env python3
"""
NetStress Titanium v3.0 - Binary Size Optimizer
**Validates: Requirements 10.5** - Strip debug symbols, use UPX compression, target under 150MB

This script optimizes NetStress binaries for size while maintaining functionality.
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse
import json

class BinarySizeOptimizer:
    def __init__(self, binary_path: Path, target_size_mb: int = 150):
        self.binary_path = Path(binary_path)
        self.target_size_mb = target_size_mb
        self.platform_name = platform.system().lower()
        self.optimization_log = []
        self.original_size = 0
        self.current_size = 0
        
    def log_step(self, step: str, size_before: int, size_after: int, success: bool):
        """Log an optimization step"""
        size_diff = size_before - size_after
        size_diff_mb = size_diff / 1024 / 1024
        
        entry = {
            "step": step,
            "size_before_mb": round(size_before / 1024 / 1024, 2),
            "size_after_mb": round(size_after / 1024 / 1024, 2),
            "size_reduction_mb": round(size_diff_mb, 2),
            "success": success,
        }
        
        self.optimization_log.append(entry)
        
        status = "✅" if success else "❌"
        if size_diff > 0:
            print(f"{status} {step}: {size_diff_mb:.1f} MB saved")
        else:
            print(f"{status} {step}: No size reduction")
    
    def get_file_size(self) -> int:
        """Get current file size"""
        return self.binary_path.stat().st_size
    
    def backup_binary(self) -> Path:
        """Create a backup of the original binary"""
        backup_path = self.binary_path.with_suffix(self.binary_path.suffix + ".backup")
        shutil.copy2(self.binary_path, backup_path)
        print(f"📋 Backup created: {backup_path}")
        return backup_path
    
    def strip_debug_symbols(self) -> bool:
        """Strip debug symbols from the binary"""
        print("🔧 Stripping debug symbols...")
        
        size_before = self.get_file_size()
        
        try:
            if self.platform_name == "linux":
                # Use strip command
                result = subprocess.run(
                    ["strip", "--strip-all", str(self.binary_path)],
                    capture_output=True, text=True, check=True
                )
                
            elif self.platform_name == "darwin":
                # Use strip command on macOS
                result = subprocess.run(
                    ["strip", "-x", str(self.binary_path)],
                    capture_output=True, text=True, check=True
                )
                
            elif self.platform_name == "windows":
                # Windows doesn't have strip, but we can try other tools
                print("ℹ️  Debug symbol stripping not available on Windows")
                self.log_step("Strip Debug Symbols", size_before, size_before, True)
                return True
            
            size_after = self.get_file_size()
            self.log_step("Strip Debug Symbols", size_before, size_after, True)
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Strip failed: {e}")
            self.log_step("Strip Debug Symbols", size_before, size_before, False)
            return False
        except FileNotFoundError:
            print("❌ Strip command not found")
            self.log_step("Strip Debug Symbols", size_before, size_before, False)
            return False
    
    def apply_upx_compression(self, compression_level: str = "--best") -> bool:
        """Apply UPX compression to the binary"""
        print(f"📦 Applying UPX compression ({compression_level})...")
        
        # Check if UPX is available
        if not shutil.which("upx"):
            print("❌ UPX not found. Install with: apt install upx (Linux) or brew install upx (macOS)")
            size_current = self.get_file_size()
            self.log_step("UPX Compression", size_current, size_current, False)
            return False
        
        size_before = self.get_file_size()
        
        try:
            # UPX command
            cmd = ["upx", compression_level, str(self.binary_path)]
            
            # UPX can be finicky with some binaries, so we'll try different approaches
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False
            )
            
            if result.returncode == 0:
                size_after = self.get_file_size()
                self.log_step("UPX Compression", size_before, size_after, True)
                return True
            else:
                print(f"❌ UPX failed: {result.stderr}")
                
                # Try with --force flag
                print("🔄 Retrying UPX with --force...")
                cmd_force = ["upx", "--force", compression_level, str(self.binary_path)]
                result = subprocess.run(
                    cmd_force, capture_output=True, text=True, check=False
                )
                
                if result.returncode == 0:
                    size_after = self.get_file_size()
                    self.log_step("UPX Compression (forced)", size_before, size_after, True)
                    return True
                else:
                    print(f"❌ UPX with --force also failed: {result.stderr}")
                    self.log_step("UPX Compression", size_before, size_before, False)
                    return False
                    
        except Exception as e:
            print(f"❌ UPX error: {e}")
            self.log_step("UPX Compression", size_before, size_before, False)
            return False
    
    def remove_unused_sections(self) -> bool:
        """Remove unused sections from the binary"""
        print("🗑️  Removing unused sections...")
        
        size_before = self.get_file_size()
        
        try:
            if self.platform_name == "linux":
                # Use objcopy to remove unused sections
                sections_to_remove = [
                    ".comment",
                    ".note",
                    ".note.ABI-tag",
                    ".note.gnu.build-id",
                    ".gnu.version",
                ]
                
                success = True
                for section in sections_to_remove:
                    try:
                        subprocess.run([
                            "objcopy", "--remove-section", section, str(self.binary_path)
                        ], capture_output=True, check=True)
                    except subprocess.CalledProcessError:
                        # Section might not exist, continue
                        pass
                
                size_after = self.get_file_size()
                self.log_step("Remove Unused Sections", size_before, size_after, success)
                return success
                
            else:
                print("ℹ️  Section removal not implemented for this platform")
                self.log_step("Remove Unused Sections", size_before, size_before, True)
                return True
                
        except FileNotFoundError:
            print("❌ objcopy not found")
            self.log_step("Remove Unused Sections", size_before, size_before, False)
            return False
        except Exception as e:
            print(f"❌ Section removal error: {e}")
            self.log_step("Remove Unused Sections", size_before, size_before, False)
            return False
    
    def optimize_with_sstrip(self) -> bool:
        """Use sstrip for more aggressive stripping (if available)"""
        print("🔪 Applying aggressive stripping with sstrip...")
        
        if not shutil.which("sstrip"):
            print("ℹ️  sstrip not available (optional optimization)")
            size_current = self.get_file_size()
            self.log_step("Aggressive Strip (sstrip)", size_current, size_current, True)
            return True
        
        size_before = self.get_file_size()
        
        try:
            result = subprocess.run(
                ["sstrip", str(self.binary_path)],
                capture_output=True, text=True, check=True
            )
            
            size_after = self.get_file_size()
            self.log_step("Aggressive Strip (sstrip)", size_before, size_after, True)
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ sstrip failed: {e}")
            self.log_step("Aggressive Strip (sstrip)", size_before, size_before, False)
            return False
    
    def verify_binary_still_works(self) -> bool:
        """Verify the binary still works after optimization"""
        print("🔍 Verifying binary functionality...")
        
        try:
            # Test basic execution
            result = subprocess.run(
                [str(self.binary_path), "--help"],
                capture_output=True, text=True, timeout=30, check=False
            )
            
            if result.returncode == 0:
                print("✅ Binary still functional after optimization")
                return True
            else:
                print(f"❌ Binary broken after optimization: {result.returncode}")
                print(f"    Error: {result.stderr[:200]}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Binary timed out after optimization")
            return False
        except Exception as e:
            print(f"❌ Binary verification error: {e}")
            return False
    
    def restore_from_backup(self, backup_path: Path) -> bool:
        """Restore binary from backup"""
        print("🔄 Restoring from backup...")
        
        try:
            shutil.copy2(backup_path, self.binary_path)
            print("✅ Binary restored from backup")
            return True
        except Exception as e:
            print(f"❌ Failed to restore from backup: {e}")
            return False
    
    def optimize(self, use_upx: bool = True, aggressive: bool = False) -> bool:
        """Run complete optimization process"""
        print("⚡ NetStress Titanium v3.0 - Binary Size Optimizer")
        print("=" * 60)
        print(f"Binary: {self.binary_path}")
        print(f"Platform: {self.platform_name}")
        print(f"Target size: {self.target_size_mb} MB")
        print("=" * 60)
        
        if not self.binary_path.exists():
            print(f"❌ Binary not found: {self.binary_path}")
            return False
        
        # Record original size
        self.original_size = self.get_file_size()
        print(f"📏 Original size: {self.original_size / 1024 / 1024:.1f} MB")
        
        # Create backup
        backup_path = self.backup_binary()
        
        # Optimization steps
        optimization_steps = [
            ("Strip Debug Symbols", self.strip_debug_symbols),
            ("Remove Unused Sections", self.remove_unused_sections),
        ]
        
        if aggressive:
            optimization_steps.append(("Aggressive Strip", self.optimize_with_sstrip))
        
        if use_upx:
            optimization_steps.append(("UPX Compression", lambda: self.apply_upx_compression("--best")))
        
        # Run optimization steps
        for step_name, step_func in optimization_steps:
            print(f"\n🔧 {step_name}")
            print("-" * 40)
            
            try:
                step_func()
                
                # Verify binary still works after each step
                if not self.verify_binary_still_works():
                    print(f"❌ Binary broken after {step_name}, restoring backup...")
                    if not self.restore_from_backup(backup_path):
                        print("❌ Failed to restore backup!")
                        return False
                    break
                    
            except Exception as e:
                print(f"❌ {step_name} error: {e}")
                continue
        
        # Final size check
        self.current_size = self.get_file_size()
        final_size_mb = self.current_size / 1024 / 1024
        total_reduction = (self.original_size - self.current_size) / 1024 / 1024
        
        print("\n" + "=" * 60)
        print("📊 OPTIMIZATION SUMMARY")
        print("=" * 60)
        
        for entry in self.optimization_log:
            status = "✅" if entry["success"] else "❌"
            reduction = entry["size_reduction_mb"]
            print(f"{entry['step']:.<40} {status} {reduction:>6.1f} MB")
        
        print("-" * 60)
        print(f"Original size: {self.original_size / 1024 / 1024:.1f} MB")
        print(f"Final size:    {final_size_mb:.1f} MB")
        print(f"Total saved:   {total_reduction:.1f} MB ({total_reduction/self.original_size*1024*1024*100:.1f}%)")
        
        # Check if target size is met
        if final_size_mb <= self.target_size_mb:
            print(f"🎉 TARGET SIZE MET: {final_size_mb:.1f} MB ≤ {self.target_size_mb} MB")
            success = True
        else:
            print(f"⚠️  TARGET SIZE EXCEEDED: {final_size_mb:.1f} MB > {self.target_size_mb} MB")
            success = False
        
        # Clean up backup if successful
        if success and backup_path.exists():
            backup_path.unlink()
            print("🗑️  Backup removed")
        
        return success
    
    def save_optimization_report(self, output_path: Optional[Path] = None) -> Path:
        """Save optimization report"""
        if output_path is None:
            output_path = self.binary_path.parent / f"optimization_report_{self.platform_name}.json"
        
        report = {
            "binary_path": str(self.binary_path),
            "platform": self.platform_name,
            "target_size_mb": self.target_size_mb,
            "original_size_mb": round(self.original_size / 1024 / 1024, 2),
            "final_size_mb": round(self.current_size / 1024 / 1024, 2),
            "total_reduction_mb": round((self.original_size - self.current_size) / 1024 / 1024, 2),
            "target_met": self.current_size / 1024 / 1024 <= self.target_size_mb,
            "optimization_steps": self.optimization_log,
            "timestamp": subprocess.run(["date"], capture_output=True, text=True).stdout.strip(),
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report saved to: {output_path}")
        return output_path

def main():
    parser = argparse.ArgumentParser(description="Optimize NetStress binary size")
    parser.add_argument("binary", help="Path to NetStress binary to optimize")
    parser.add_argument("--target-size", type=int, default=150, 
                       help="Target size in MB (default: 150)")
    parser.add_argument("--no-upx", action="store_true", 
                       help="Skip UPX compression")
    parser.add_argument("--aggressive", action="store_true",
                       help="Use aggressive optimization (may break some features)")
    parser.add_argument("--report", help="Path to save optimization report")
    
    args = parser.parse_args()
    
    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"❌ Binary not found: {binary_path}")
        sys.exit(1)
    
    optimizer = BinarySizeOptimizer(binary_path, args.target_size)
    success = optimizer.optimize(use_upx=not args.no_upx, aggressive=args.aggressive)
    
    # Save report
    if args.report:
        optimizer.save_optimization_report(Path(args.report))
    else:
        optimizer.save_optimization_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()