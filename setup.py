#!/usr/bin/env python3
"""
Destroyer-DoS Framework - Setup Script
"""

from setuptools import setup, find_packages
import platform

# Core requirements
CORE_REQUIREMENTS = [
    'aiohttp>=3.8.0',
    'numpy>=1.21.0',
    'scapy>=2.4.5',
    'cryptography>=3.4.8',
    'pyyaml>=6.0',
    'faker>=13.0.0',
    'psutil>=5.8.0',
    'colorama>=0.4.4',
    'requests>=2.27.0',
]

# Development requirements
DEV_REQUIREMENTS = [
    'pytest>=7.0.0',
    'pytest-asyncio>=0.18.0',
    'black>=22.0.0',
    'flake8>=4.0.0',
]

# Optional ML requirements
ML_REQUIREMENTS = [
    'scikit-learn>=1.0.0',
    'tensorflow>=2.8.0',
    'torch>=1.11.0',
]

setup(
    name='netstress',
    version='2.0.0',
    description='Military-grade network stress testing framework with true cross-platform support',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Destroyer-official',
    url='https://github.com/Destroyer-official/-NetStress-',
    license='MIT',
    
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    
    install_requires=CORE_REQUIREMENTS,
    extras_require={
        'dev': DEV_REQUIREMENTS,
        'ml': ML_REQUIREMENTS,
    },
    
    entry_points={
        'console_scripts': [
            'destroyer-dos=ddos:main',
        ],
    },
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
    ],
    
    python_requires='>=3.8',
)
