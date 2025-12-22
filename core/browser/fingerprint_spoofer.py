"""
Fingerprint Spoofer

Implements Canvas and WebGL fingerprint spoofing to match browser profiles
and avoid detection based on hardware/software fingerprinting.
"""

import base64
import hashlib
import json
import logging
import random
import time
from typing import Dict, List, Optional, Any, Tuple
from PIL import Image, ImageDraw, ImageFont
import io


class CanvasFingerprint:
    """Generates consistent Canvas fingerprints"""
    
    def __init__(self, profile_name: str = 'chrome_120_windows'):
        self.profile_name = profile_name
        self.logger = logging.getLogger(__name__)
        
        # Pre-defined fingerprint data for different browser profiles
        self.profiles = {
            'chrome_120_windows': {
                'canvas_hash': 'a1b2c3d4e5f6789012345678901234567890abcd',
                'text_metrics': {
                    'width': 104.5,
                    'actualBoundingBoxLeft': 0,
                    'actualBoundingBoxRight': 104.5,
                    'actualBoundingBoxAscent': 11,
                    'actualBoundingBoxDescent': 3
                },
                'font_list': [
                    'Arial', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas',
                    'Georgia', 'Impact', 'Lucida Console', 'Segoe UI', 'Tahoma',
                    'Times New Roman', 'Trebuchet MS', 'Verdana'
                ],
                'canvas_data': None  # Will be generated
            },
            'firefox_121_windows': {
                'canvas_hash': 'b2c3d4e5f6789012345678901234567890abcdef',
                'text_metrics': {
                    'width': 105.2,
                    'actualBoundingBoxLeft': 0,
                    'actualBoundingBoxRight': 105.2,
                    'actualBoundingBoxAscent': 11,
                    'actualBoundingBoxDescent': 3
                },
                'font_list': [
                    'Arial', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas',
                    'Georgia', 'Impact', 'Lucida Console', 'Segoe UI', 'Tahoma',
                    'Times New Roman', 'Trebuchet MS', 'Verdana'
                ],
                'canvas_data': None
            },
            'safari_17_macos': {
                'canvas_hash': 'c3d4e5f6789012345678901234567890abcdef12',
                'text_metrics': {
                    'width': 103.8,
                    'actualBoundingBoxLeft': 0,
                    'actualBoundingBoxRight': 103.8,
                    'actualBoundingBoxAscent': 10,
                    'actualBoundingBoxDescent': 2
                },
                'font_list': [
                    'Arial', 'Helvetica', 'Times', 'Courier', 'Verdana',
                    'Georgia', 'Palatino', 'Times New Roman', 'Monaco',
                    'Menlo', 'SF Pro Display', 'SF Pro Text'
                ],
                'canvas_data': None
            }
        }
        
        self.current_profile = self.profiles.get(profile_name, self.profiles['chrome_120_windows'])
        self._generate_canvas_data()
    
    def _generate_canvas_data(self):
        """Generate consistent canvas fingerprint data"""
        try:
            # Create a canvas-like image
            width, height = 280, 60
            image = Image.new('RGB', (width, height), color='white')
            draw = ImageDraw.Draw(image)
            
            # Draw text (common fingerprinting technique)
            text = "BrowserLeaks,com <canvas> 1.0"
            try:
                # Try to use a system font
                font = ImageFont.truetype("arial.ttf", 14)
            except:
                # Fallback to default font
                font = ImageFont.load_default()
            
            # Draw text with specific positioning
            draw.text((4, 17), text, fill='rgb(102, 204, 0)', font=font)
            
            # Draw some geometric shapes (another common technique)
            draw.rectangle([125, 1, 62, 20], fill='rgb(0, 0, 0)')
            draw.arc([129, 5, 139, 15], 0, 360, fill='rgb(0, 255, 0)')
            
            # Add some noise based on profile
            seed = hash(self.profile_name) % 1000
            random.seed(seed)
            
            for _ in range(10):
                x = random.randint(0, width-1)
                y = random.randint(0, height-1)
                color = (
                    random.randint(0, 255),
                    random.randint(0, 255), 
                    random.randint(0, 255)
                )
                draw.point((x, y), fill=color)
            
            # Convert to base64 data URL
            buffer = io.BytesIO()
            image.save(buffer, format='PNG')
            image_data = buffer.getvalue()
            
            base64_data = base64.b64encode(image_data).decode('utf-8')
            self.current_profile['canvas_data'] = f"data:image/png;base64,{base64_data}"
            
        except Exception as e:
            self.logger.error(f"Error generating canvas data: {e}")
            # Fallback to a minimal base64 image
            self.current_profile['canvas_data'] = (
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
            )
    
    def get_canvas_data_url(self) -> str:
        """Get the canvas data URL"""
        return self.current_profile['canvas_data']
    
    def get_canvas_hash(self) -> str:
        """Get the canvas fingerprint hash"""
        return self.current_profile['canvas_hash']
    
    def get_text_metrics(self) -> Dict[str, float]:
        """Get text measurement metrics"""
        return self.current_profile['text_metrics'].copy()
    
    def get_font_list(self) -> List[str]:
        """Get available font list"""
        return self.current_profile['font_list'].copy()


class WebGLFingerprint:
    """Generates consistent WebGL fingerprints"""
    
    def __init__(self, profile_name: str = 'chrome_120_windows'):
        self.profile_name = profile_name
        self.logger = logging.getLogger(__name__)
        
        # Pre-defined WebGL parameters for different profiles
        self.profiles = {
            'chrome_120_windows': {
                'renderer': 'ANGLE (NVIDIA GeForce RTX 3070, or similar)',
                'vendor': 'Google Inc. (NVIDIA)',
                'version': 'WebGL 1.0 (OpenGL ES 2.0 Chromium)',
                'shading_language_version': 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)',
                'max_texture_size': 16384,
                'max_cube_map_texture_size': 16384,
                'max_renderbuffer_size': 16384,
                'max_viewport_dims': [16384, 16384],
                'max_vertex_attribs': 16,
                'max_vertex_uniform_vectors': 1024,
                'max_fragment_uniform_vectors': 1024,
                'max_varying_vectors': 30,
                'aliased_line_width_range': [1, 1],
                'aliased_point_size_range': [1, 1024],
                'extensions': [
                    'ANGLE_instanced_arrays',
                    'EXT_blend_minmax',
                    'EXT_color_buffer_half_float',
                    'EXT_disjoint_timer_query',
                    'EXT_float_blend',
                    'EXT_frag_depth',
                    'EXT_shader_texture_lod',
                    'EXT_texture_compression_bptc',
                    'EXT_texture_compression_rgtc',
                    'EXT_texture_filter_anisotropic',
                    'WEBKIT_EXT_texture_filter_anisotropic',
                    'EXT_sRGB',
                    'OES_element_index_uint',
                    'OES_fbo_render_mipmap',
                    'OES_standard_derivatives',
                    'OES_texture_float',
                    'OES_texture_float_linear',
                    'OES_texture_half_float',
                    'OES_texture_half_float_linear',
                    'OES_vertex_array_object',
                    'WEBGL_color_buffer_float',
                    'WEBGL_compressed_texture_s3tc',
                    'WEBKIT_WEBGL_compressed_texture_s3tc',
                    'WEBGL_compressed_texture_s3tc_srgb',
                    'WEBGL_debug_renderer_info',
                    'WEBGL_debug_shaders',
                    'WEBGL_depth_texture',
                    'WEBKIT_WEBGL_depth_texture',
                    'WEBGL_draw_buffers',
                    'WEBGL_lose_context',
                    'WEBKIT_WEBGL_lose_context'
                ]
            },
            'firefox_121_windows': {
                'renderer': 'NVIDIA GeForce RTX 3070/PCIe/SSE2',
                'vendor': 'NVIDIA Corporation',
                'version': 'WebGL 1.0',
                'shading_language_version': 'WebGL GLSL ES 1.0',
                'max_texture_size': 16384,
                'max_cube_map_texture_size': 16384,
                'max_renderbuffer_size': 16384,
                'max_viewport_dims': [16384, 16384],
                'max_vertex_attribs': 16,
                'max_vertex_uniform_vectors': 1024,
                'max_fragment_uniform_vectors': 1024,
                'max_varying_vectors': 30,
                'aliased_line_width_range': [1, 1],
                'aliased_point_size_range': [1, 1024],
                'extensions': [
                    'ANGLE_instanced_arrays',
                    'EXT_blend_minmax',
                    'EXT_color_buffer_half_float',
                    'EXT_float_blend',
                    'EXT_frag_depth',
                    'EXT_shader_texture_lod',
                    'EXT_texture_filter_anisotropic',
                    'EXT_sRGB',
                    'OES_element_index_uint',
                    'OES_standard_derivatives',
                    'OES_texture_float',
                    'OES_texture_float_linear',
                    'OES_texture_half_float',
                    'OES_texture_half_float_linear',
                    'OES_vertex_array_object',
                    'WEBGL_color_buffer_float',
                    'WEBGL_compressed_texture_s3tc',
                    'WEBGL_debug_renderer_info',
                    'WEBGL_debug_shaders',
                    'WEBGL_depth_texture',
                    'WEBGL_draw_buffers',
                    'WEBGL_lose_context'
                ]
            },
            'safari_17_macos': {
                'renderer': 'Apple M2 Pro',
                'vendor': 'Apple Inc.',
                'version': 'WebGL 1.0 (OpenGL ES 2.0 Metal - 83.1)',
                'shading_language_version': 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Metal - 83.1)',
                'max_texture_size': 16384,
                'max_cube_map_texture_size': 16384,
                'max_renderbuffer_size': 16384,
                'max_viewport_dims': [16384, 16384],
                'max_vertex_attribs': 16,
                'max_vertex_uniform_vectors': 1024,
                'max_fragment_uniform_vectors': 1024,
                'max_varying_vectors': 31,
                'aliased_line_width_range': [1, 1],
                'aliased_point_size_range': [1, 511],
                'extensions': [
                    'EXT_blend_minmax',
                    'EXT_color_buffer_half_float',
                    'EXT_frag_depth',
                    'EXT_shader_texture_lod',
                    'EXT_texture_filter_anisotropic',
                    'EXT_sRGB',
                    'OES_element_index_uint',
                    'OES_standard_derivatives',
                    'OES_texture_float',
                    'OES_texture_float_linear',
                    'OES_texture_half_float',
                    'OES_texture_half_float_linear',
                    'OES_vertex_array_object',
                    'WEBGL_color_buffer_float',
                    'WEBGL_compressed_texture_s3tc',
                    'WEBGL_debug_renderer_info',
                    'WEBGL_debug_shaders',
                    'WEBGL_depth_texture',
                    'WEBGL_draw_buffers',
                    'WEBGL_lose_context'
                ]
            }
        }
        
        self.current_profile = self.profiles.get(profile_name, self.profiles['chrome_120_windows'])
    
    def get_parameter(self, parameter: int) -> Any:
        """Get WebGL parameter value"""
        # WebGL parameter constants
        GL_VENDOR = 7936
        GL_RENDERER = 7937
        GL_VERSION = 7938
        GL_SHADING_LANGUAGE_VERSION = 35724
        GL_MAX_TEXTURE_SIZE = 3379
        GL_MAX_CUBE_MAP_TEXTURE_SIZE = 34076
        GL_MAX_RENDERBUFFER_SIZE = 34024
        GL_MAX_VIEWPORT_DIMS = 3386
        GL_MAX_VERTEX_ATTRIBS = 34921
        GL_MAX_VERTEX_UNIFORM_VECTORS = 36347
        GL_MAX_FRAGMENT_UNIFORM_VECTORS = 36349
        GL_MAX_VARYING_VECTORS = 36348
        GL_ALIASED_LINE_WIDTH_RANGE = 33902
        GL_ALIASED_POINT_SIZE_RANGE = 33901
        
        parameter_map = {
            GL_VENDOR: self.current_profile['vendor'],
            GL_RENDERER: self.current_profile['renderer'],
            GL_VERSION: self.current_profile['version'],
            GL_SHADING_LANGUAGE_VERSION: self.current_profile['shading_language_version'],
            GL_MAX_TEXTURE_SIZE: self.current_profile['max_texture_size'],
            GL_MAX_CUBE_MAP_TEXTURE_SIZE: self.current_profile['max_cube_map_texture_size'],
            GL_MAX_RENDERBUFFER_SIZE: self.current_profile['max_renderbuffer_size'],
            GL_MAX_VIEWPORT_DIMS: self.current_profile['max_viewport_dims'],
            GL_MAX_VERTEX_ATTRIBS: self.current_profile['max_vertex_attribs'],
            GL_MAX_VERTEX_UNIFORM_VECTORS: self.current_profile['max_vertex_uniform_vectors'],
            GL_MAX_FRAGMENT_UNIFORM_VECTORS: self.current_profile['max_fragment_uniform_vectors'],
            GL_MAX_VARYING_VECTORS: self.current_profile['max_varying_vectors'],
            GL_ALIASED_LINE_WIDTH_RANGE: self.current_profile['aliased_line_width_range'],
            GL_ALIASED_POINT_SIZE_RANGE: self.current_profile['aliased_point_size_range'],
        }
        
        return parameter_map.get(parameter, '')
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of supported WebGL extensions"""
        return self.current_profile['extensions'].copy()
    
    def get_extension(self, name: str) -> Optional[Dict[str, Any]]:
        """Get WebGL extension object"""
        if name in self.current_profile['extensions']:
            # Return a mock extension object
            return {'name': name, 'supported': True}
        return None
    
    def generate_webgl_hash(self) -> str:
        """Generate a consistent WebGL fingerprint hash"""
        # Combine key WebGL parameters into a hash
        fingerprint_data = {
            'vendor': self.current_profile['vendor'],
            'renderer': self.current_profile['renderer'],
            'version': self.current_profile['version'],
            'extensions': sorted(self.current_profile['extensions']),
            'max_texture_size': self.current_profile['max_texture_size'],
            'max_viewport_dims': self.current_profile['max_viewport_dims']
        }
        
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:32]


class FingerprintSpoofer:
    """Main fingerprint spoofing coordinator"""
    
    def __init__(self, profile_name: str = 'chrome_120_windows'):
        self.profile_name = profile_name
        self.logger = logging.getLogger(__name__)
        
        self.canvas_fingerprint = CanvasFingerprint(profile_name)
        self.webgl_fingerprint = WebGLFingerprint(profile_name)
        
        # Audio context fingerprinting (basic implementation)
        self.audio_fingerprint = self._generate_audio_fingerprint()
        
        # Screen and hardware fingerprinting
        self.screen_fingerprint = self._generate_screen_fingerprint()
    
    def _generate_audio_fingerprint(self) -> Dict[str, Any]:
        """Generate consistent audio context fingerprint"""
        profiles = {
            'chrome_120_windows': {
                'sample_rate': 48000,
                'max_channel_count': 2,
                'number_of_inputs': 1,
                'number_of_outputs': 1,
                'channel_count': 2,
                'channel_count_mode': 'max',
                'channel_interpretation': 'speakers'
            },
            'firefox_121_windows': {
                'sample_rate': 48000,
                'max_channel_count': 2,
                'number_of_inputs': 1,
                'number_of_outputs': 1,
                'channel_count': 2,
                'channel_count_mode': 'max',
                'channel_interpretation': 'speakers'
            },
            'safari_17_macos': {
                'sample_rate': 44100,
                'max_channel_count': 2,
                'number_of_inputs': 1,
                'number_of_outputs': 1,
                'channel_count': 2,
                'channel_count_mode': 'max',
                'channel_interpretation': 'speakers'
            }
        }
        
        return profiles.get(self.profile_name, profiles['chrome_120_windows'])
    
    def _generate_screen_fingerprint(self) -> Dict[str, Any]:
        """Generate consistent screen fingerprint"""
        profiles = {
            'chrome_120_windows': {
                'width': 1920,
                'height': 1080,
                'color_depth': 24,
                'pixel_depth': 24,
                'available_width': 1920,
                'available_height': 1040,
                'device_pixel_ratio': 1.0,
                'orientation': {'type': 'landscape-primary', 'angle': 0}
            },
            'firefox_121_windows': {
                'width': 1920,
                'height': 1080,
                'color_depth': 24,
                'pixel_depth': 24,
                'available_width': 1920,
                'available_height': 1040,
                'device_pixel_ratio': 1.0,
                'orientation': {'type': 'landscape-primary', 'angle': 0}
            },
            'safari_17_macos': {
                'width': 2560,
                'height': 1440,
                'color_depth': 30,
                'pixel_depth': 30,
                'available_width': 2560,
                'available_height': 1415,
                'device_pixel_ratio': 2.0,
                'orientation': {'type': 'landscape-primary', 'angle': 0}
            }
        }
        
        return profiles.get(self.profile_name, profiles['chrome_120_windows'])
    
    def get_canvas_fingerprint(self) -> Dict[str, Any]:
        """Get complete canvas fingerprint data"""
        return {
            'data_url': self.canvas_fingerprint.get_canvas_data_url(),
            'hash': self.canvas_fingerprint.get_canvas_hash(),
            'text_metrics': self.canvas_fingerprint.get_text_metrics(),
            'fonts': self.canvas_fingerprint.get_font_list()
        }
    
    def get_webgl_fingerprint(self) -> Dict[str, Any]:
        """Get complete WebGL fingerprint data"""
        return {
            'vendor': self.webgl_fingerprint.get_parameter(7936),
            'renderer': self.webgl_fingerprint.get_parameter(7937),
            'version': self.webgl_fingerprint.get_parameter(7938),
            'shading_language_version': self.webgl_fingerprint.get_parameter(35724),
            'extensions': self.webgl_fingerprint.get_supported_extensions(),
            'parameters': {
                'max_texture_size': self.webgl_fingerprint.get_parameter(3379),
                'max_viewport_dims': self.webgl_fingerprint.get_parameter(3386),
                'max_vertex_attribs': self.webgl_fingerprint.get_parameter(34921)
            },
            'hash': self.webgl_fingerprint.generate_webgl_hash()
        }
    
    def get_audio_fingerprint(self) -> Dict[str, Any]:
        """Get audio context fingerprint"""
        return self.audio_fingerprint.copy()
    
    def get_screen_fingerprint(self) -> Dict[str, Any]:
        """Get screen fingerprint"""
        return self.screen_fingerprint.copy()
    
    def inject_fingerprint_overrides(self, js_engine) -> str:
        """Generate JavaScript code to override fingerprinting APIs"""
        canvas_data = self.get_canvas_fingerprint()
        webgl_data = self.get_webgl_fingerprint()
        audio_data = self.get_audio_fingerprint()
        screen_data = self.get_screen_fingerprint()
        
        override_code = f"""
            // Canvas fingerprint override
            (function() {{
                const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
                
                HTMLCanvasElement.prototype.toDataURL = function() {{
                    return '{canvas_data["data_url"]}';
                }};
                
                CanvasRenderingContext2D.prototype.getImageData = function() {{
                    // Return consistent image data
                    const data = new Uint8ClampedArray(4);
                    data[0] = 102; data[1] = 204; data[2] = 0; data[3] = 255;
                    return {{ data: data, width: 1, height: 1 }};
                }};
                
                CanvasRenderingContext2D.prototype.measureText = function(text) {{
                    return {json.dumps(canvas_data["text_metrics"])};
                }};
            }})();
            
            // WebGL fingerprint override
            (function() {{
                const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
                const originalGetSupportedExtensions = WebGLRenderingContext.prototype.getSupportedExtensions;
                const originalGetExtension = WebGLRenderingContext.prototype.getExtension;
                
                const webglParams = {{
                    7936: '{webgl_data["vendor"]}',
                    7937: '{webgl_data["renderer"]}',
                    7938: '{webgl_data["version"]}',
                    35724: '{webgl_data["shading_language_version"]}',
                    3379: {webgl_data["parameters"]["max_texture_size"]},
                    3386: {json.dumps(webgl_data["parameters"]["max_viewport_dims"])},
                    34921: {webgl_data["parameters"]["max_vertex_attribs"]}
                }};
                
                WebGLRenderingContext.prototype.getParameter = function(parameter) {{
                    if (parameter in webglParams) {{
                        return webglParams[parameter];
                    }}
                    return originalGetParameter.call(this, parameter);
                }};
                
                WebGLRenderingContext.prototype.getSupportedExtensions = function() {{
                    return {json.dumps(webgl_data["extensions"])};
                }};
                
                WebGLRenderingContext.prototype.getExtension = function(name) {{
                    const supportedExtensions = {json.dumps(webgl_data["extensions"])};
                    if (supportedExtensions.includes(name)) {{
                        return {{ name: name }};
                    }}
                    return null;
                }};
            }})();
            
            // Audio context override
            (function() {{
                if (typeof AudioContext !== 'undefined') {{
                    const originalAudioContext = AudioContext;
                    window.AudioContext = function() {{
                        const ctx = new originalAudioContext();
                        Object.defineProperty(ctx, 'sampleRate', {{
                            value: {audio_data["sample_rate"]},
                            writable: false
                        }});
                        return ctx;
                    }};
                }}
            }})();
            
            // Screen fingerprint override
            Object.defineProperty(screen, 'width', {{
                value: {screen_data["width"]},
                writable: false
            }});
            Object.defineProperty(screen, 'height', {{
                value: {screen_data["height"]},
                writable: false
            }});
            Object.defineProperty(screen, 'colorDepth', {{
                value: {screen_data["color_depth"]},
                writable: false
            }});
            Object.defineProperty(screen, 'pixelDepth', {{
                value: {screen_data["pixel_depth"]},
                writable: false
            }});
            Object.defineProperty(screen, 'availWidth', {{
                value: {screen_data["available_width"]},
                writable: false
            }});
            Object.defineProperty(screen, 'availHeight', {{
                value: {screen_data["available_height"]},
                writable: false
            }});
            
            Object.defineProperty(window, 'devicePixelRatio', {{
                value: {screen_data["device_pixel_ratio"]},
                writable: false
            }});
        """
        
        return override_code
    
    def switch_profile(self, profile_name: str):
        """Switch to a different browser profile"""
        self.profile_name = profile_name
        self.canvas_fingerprint = CanvasFingerprint(profile_name)
        self.webgl_fingerprint = WebGLFingerprint(profile_name)
        self.audio_fingerprint = self._generate_audio_fingerprint()
        self.screen_fingerprint = self._generate_screen_fingerprint()
        
        self.logger.info(f"Switched to profile: {profile_name}")
    
    def get_available_profiles(self) -> List[str]:
        """Get list of available browser profiles"""
        return list(self.canvas_fingerprint.profiles.keys())
    
    def generate_fingerprint_report(self) -> Dict[str, Any]:
        """Generate a complete fingerprint report"""
        return {
            'profile': self.profile_name,
            'canvas': self.get_canvas_fingerprint(),
            'webgl': self.get_webgl_fingerprint(),
            'audio': self.get_audio_fingerprint(),
            'screen': self.get_screen_fingerprint(),
            'timestamp': time.time()
        }
    
    def validate_fingerprint_consistency(self) -> bool:
        """Validate that all fingerprint components are consistent"""
        try:
            canvas_fp = self.get_canvas_fingerprint()
            webgl_fp = self.get_webgl_fingerprint()
            
            # Basic consistency checks
            if not canvas_fp['data_url'].startswith('data:image/png;base64,'):
                return False
            
            if not webgl_fp['vendor'] or not webgl_fp['renderer']:
                return False
            
            if len(webgl_fp['extensions']) == 0:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Fingerprint validation error: {e}")
            return False