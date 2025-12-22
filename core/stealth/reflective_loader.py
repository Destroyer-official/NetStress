"""Reflective DLL/SO loader for in-memory module loading."""

import ctypes
import logging
import mmap
import platform
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

PLATFORM = platform.system()
IS_WINDOWS = PLATFORM == 'Windows'
IS_LINUX = PLATFORM == 'Linux'
IS_MACOS = PLATFORM == 'Darwin'
IS_64BIT = struct.calcsize('P') * 8 == 64

REFLECTIVE_LOADING_AVAILABLE = False


@dataclass
class MemoryModule:
    """Represents a module loaded in memory."""
    name: str
    base_address: int
    size: int
    entry_point: Optional[int]
    exports: Dict[str, int]
    is_loaded: bool = False


class ReflectiveLoaderBase:
    """Base class for reflective loading."""
    
    def __init__(self):
        self.loaded_modules: Dict[str, MemoryModule] = {}
        self._memory_regions: list = []
    
    def load_from_bytes(self, module_bytes: bytes, module_name: str) -> Optional[MemoryModule]:
        raise NotImplementedError
    
    def get_export(self, module: MemoryModule, export_name: str) -> Optional[int]:
        return module.exports.get(export_name)
    
    def unload(self, module: MemoryModule) -> bool:
        raise NotImplementedError
    
    def cleanup(self):
        for module in list(self.loaded_modules.values()):
            self.unload(module)
        self.loaded_modules.clear()


if IS_WINDOWS:
    try:
        import ctypes.wintypes as wintypes
        
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        MEM_RELEASE = 0x8000
        PAGE_EXECUTE_READWRITE = 0x40
        
        IMAGE_DOS_SIGNATURE = 0x5A4D
        IMAGE_NT_SIGNATURE = 0x4550
        
        kernel32 = ctypes.windll.kernel32
        
        VirtualAlloc = kernel32.VirtualAlloc
        VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        VirtualAlloc.restype = wintypes.LPVOID
        
        VirtualFree = kernel32.VirtualFree
        VirtualFree.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
        VirtualFree.restype = wintypes.BOOL
        
        class WindowsReflectiveLoader(ReflectiveLoaderBase):
            """Windows PE loader."""
            
            def __init__(self):
                super().__init__()
                self._allocated_memory: list = []
            
            def _parse_pe_header(self, data: bytes) -> Optional[Dict[str, Any]]:
                if len(data) < 64:
                    return None
                
                dos_sig = struct.unpack('<H', data[0:2])[0]
                if dos_sig != IMAGE_DOS_SIGNATURE:
                    return None
                
                pe_offset = struct.unpack('<I', data[60:64])[0]
                if len(data) < pe_offset + 24:
                    return None
                
                pe_sig = struct.unpack('<I', data[pe_offset:pe_offset+4])[0]
                if pe_sig != IMAGE_NT_SIGNATURE:
                    return None
                
                num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
                opt_header_offset = pe_offset + 24
                magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]
                is_pe64 = magic == 0x20b
                
                if is_pe64:
                    image_base = struct.unpack('<Q', data[opt_header_offset+24:opt_header_offset+32])[0]
                    size_of_image = struct.unpack('<I', data[opt_header_offset+56:opt_header_offset+60])[0]
                    entry_point_rva = struct.unpack('<I', data[opt_header_offset+16:opt_header_offset+20])[0]
                    opt_header_size = 240
                else:
                    image_base = struct.unpack('<I', data[opt_header_offset+28:opt_header_offset+32])[0]
                    size_of_image = struct.unpack('<I', data[opt_header_offset+56:opt_header_offset+60])[0]
                    entry_point_rva = struct.unpack('<I', data[opt_header_offset+16:opt_header_offset+20])[0]
                    opt_header_size = 224
                
                sections_offset = opt_header_offset + opt_header_size
                sections = []
                
                for i in range(num_sections):
                    sec_offset = sections_offset + (i * 40)
                    if len(data) < sec_offset + 40:
                        break
                    
                    name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    virtual_size = struct.unpack('<I', data[sec_offset+8:sec_offset+12])[0]
                    virtual_addr = struct.unpack('<I', data[sec_offset+12:sec_offset+16])[0]
                    raw_size = struct.unpack('<I', data[sec_offset+16:sec_offset+20])[0]
                    raw_addr = struct.unpack('<I', data[sec_offset+20:sec_offset+24])[0]
                    
                    sections.append({
                        'name': name,
                        'virtual_size': virtual_size,
                        'virtual_addr': virtual_addr,
                        'raw_size': raw_size,
                        'raw_addr': raw_addr,
                    })
                
                return {
                    'is_pe64': is_pe64,
                    'image_base': image_base,
                    'size_of_image': size_of_image,
                    'entry_point_rva': entry_point_rva,
                    'sections': sections,
                }
            
            def load_from_bytes(self, module_bytes: bytes, module_name: str) -> Optional[MemoryModule]:
                try:
                    pe_info = self._parse_pe_header(module_bytes)
                    if not pe_info:
                        logger.error(f"Failed to parse PE header for {module_name}")
                        return None
                    
                    size_of_image = pe_info['size_of_image']
                    base_addr = VirtualAlloc(None, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
                    
                    if not base_addr:
                        logger.error(f"Failed to allocate memory for {module_name}")
                        return None
                    
                    self._allocated_memory.append((base_addr, size_of_image))
                    
                    header_size = pe_info['sections'][0]['raw_addr'] if pe_info['sections'] else 0x1000
                    ctypes.memmove(base_addr, module_bytes[:header_size], header_size)
                    
                    for section in pe_info['sections']:
                        if section['raw_size'] > 0:
                            src = module_bytes[section['raw_addr']:section['raw_addr'] + section['raw_size']]
                            dst = base_addr + section['virtual_addr']
                            ctypes.memmove(dst, src, len(src))
                    
                    entry_point = base_addr + pe_info['entry_point_rva'] if pe_info['entry_point_rva'] else None
                    
                    module = MemoryModule(
                        name=module_name,
                        base_address=base_addr,
                        size=size_of_image,
                        entry_point=entry_point,
                        exports={},
                        is_loaded=True
                    )
                    
                    self.loaded_modules[module_name] = module
                    logger.info(f"Loaded {module_name} at 0x{base_addr:x}")
                    return module
                    
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")
                    return None
            
            def unload(self, module: MemoryModule) -> bool:
                try:
                    if module.base_address:
                        ctypes.memset(module.base_address, 0, module.size)
                        VirtualFree(module.base_address, 0, MEM_RELEASE)
                    
                    if module.name in self.loaded_modules:
                        del self.loaded_modules[module.name]
                    
                    module.is_loaded = False
                    return True
                except Exception as e:
                    logger.error(f"Failed to unload module {module.name}: {e}")
                    return False
        
        ReflectiveLoader = WindowsReflectiveLoader
        REFLECTIVE_LOADING_AVAILABLE = True
        
    except Exception as e:
        logger.warning(f"Windows reflective loading not available: {e}")
        ReflectiveLoader = ReflectiveLoaderBase

elif IS_LINUX or IS_MACOS:
    try:
        import ctypes.util
        
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        MAP_PRIVATE = 0x02
        MAP_ANONYMOUS = 0x20 if IS_LINUX else 0x1000
        MAP_FAILED = -1
        
        ELF_MAGIC = b'\x7fELF'
        
        class UnixReflectiveLoader(ReflectiveLoaderBase):
            """Unix ELF loader."""
            
            def __init__(self):
                super().__init__()
                self._mmap_regions: list = []
            
            def _parse_elf_header(self, data: bytes) -> Optional[Dict[str, Any]]:
                if len(data) < 64 or data[:4] != ELF_MAGIC:
                    return None
                
                elf_class = data[4]
                is_64bit = elf_class == 2
                endian = '<' if data[5] == 1 else '>'
                
                if is_64bit:
                    e_entry = struct.unpack(f'{endian}Q', data[24:32])[0]
                else:
                    e_entry = struct.unpack(f'{endian}I', data[24:28])[0]
                
                return {'is_64bit': is_64bit, 'entry': e_entry}
            
            def load_from_bytes(self, module_bytes: bytes, module_name: str) -> Optional[MemoryModule]:
                try:
                    elf_info = self._parse_elf_header(module_bytes)
                    if not elf_info:
                        logger.error(f"Failed to parse ELF header for {module_name}")
                        return None
                    
                    total_size = len(module_bytes)
                    
                    addr = libc.mmap(None, total_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
                    
                    if addr == MAP_FAILED:
                        logger.error(f"mmap failed for {module_name}")
                        return None
                    
                    self._mmap_regions.append((addr, total_size))
                    ctypes.memmove(addr, module_bytes, total_size)
                    
                    module = MemoryModule(
                        name=module_name,
                        base_address=addr,
                        size=total_size,
                        entry_point=addr + elf_info['entry'] if elf_info['entry'] else None,
                        exports={},
                        is_loaded=True
                    )
                    
                    self.loaded_modules[module_name] = module
                    logger.info(f"Loaded {module_name} at 0x{addr:x}")
                    return module
                    
                except Exception as e:
                    logger.error(f"Failed to load module {module_name}: {e}")
                    return None
            
            def unload(self, module: MemoryModule) -> bool:
                try:
                    if module.base_address:
                        ctypes.memset(module.base_address, 0, module.size)
                        libc.munmap(module.base_address, module.size)
                    
                    if module.name in self.loaded_modules:
                        del self.loaded_modules[module.name]
                    
                    module.is_loaded = False
                    return True
                except Exception as e:
                    logger.error(f"Failed to unload module {module.name}: {e}")
                    return False
        
        ReflectiveLoader = UnixReflectiveLoader
        REFLECTIVE_LOADING_AVAILABLE = True
        
    except Exception as e:
        logger.warning(f"Unix reflective loading not available: {e}")
        ReflectiveLoader = ReflectiveLoaderBase
else:
    ReflectiveLoader = ReflectiveLoaderBase


def load_module_from_memory(module_bytes: bytes, module_name: str) -> Optional[MemoryModule]:
    """Load a module from raw bytes into memory."""
    loader = ReflectiveLoader()
    return loader.load_from_bytes(module_bytes, module_name)


def is_reflective_loading_available() -> bool:
    """Check if reflective loading is available on this platform."""
    return REFLECTIVE_LOADING_AVAILABLE


def load_native_engine_reflectively() -> bool:
    """Attempt to load the netstress_engine module reflectively."""
    if not REFLECTIVE_LOADING_AVAILABLE:
        logger.warning("Reflective loading not available")
        return False
    
    try:
        if IS_WINDOWS:
            ext = '.pyd'
        elif IS_MACOS:
            ext = '.dylib'
        else:
            ext = '.so'
        
        search_paths = [
            Path(__file__).parent.parent.parent / 'native' / 'rust_engine' / 'target' / 'release',
            Path(__file__).parent.parent.parent / 'native' / 'rust_engine' / 'target' / 'debug',
            Path(sys.prefix) / 'lib',
            Path.cwd(),
        ]
        
        module_path = None
        for search_path in search_paths:
            candidate = search_path / f'netstress_engine{ext}'
            if candidate.exists():
                module_path = candidate
                break
        
        if not module_path:
            logger.warning("Native engine not found")
            return False
        
        with open(module_path, 'rb') as f:
            module_bytes = f.read()
        
        loader = ReflectiveLoader()
        module = loader.load_from_bytes(module_bytes, 'netstress_engine')
        
        return module is not None and module.is_loaded
        
    except Exception as e:
        logger.error(f"Failed to load native engine reflectively: {e}")
        return False


__all__ = [
    'ReflectiveLoader',
    'MemoryModule',
    'load_module_from_memory',
    'is_reflective_loading_available',
    'load_native_engine_reflectively',
    'REFLECTIVE_LOADING_AVAILABLE',
]
